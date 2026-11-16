//! One P2P connection: the version handshake, pings answered, requests sent
//! one at a time and matched with the messages that answer them, and every
//! other message passed on as an event.

use super::message::{
    decode_version, encode_message, encode_version, read_message, FrameError, RawMessage,
    VersionInfo,
};
use super::socks::{connect, ConnectError, PeerAddr, Transport};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

/// Why a peer request failed.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("{0} timed out")]
    Timeout(String),
    #[error("the peer disconnected")]
    Disconnected,
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("the peer does not have {0}")]
    NotFound(String),
    #[error("invalid reply: {0}")]
    Invalid(String),
}

/// How a request treats a message that arrives while it waits.
pub enum Step {
    /// Not part of the answer.
    Skip,
    /// Part of the answer; more must follow.
    More,
    /// The last part of the answer.
    Done,
}

type Collector = Box<dyn FnMut(&RawMessage) -> Step + Send>;

enum Command {
    Send(&'static str, Vec<u8>),
    Request {
        command: &'static str,
        payload: Vec<u8>,
        collect: Collector,
        timeout: Duration,
        reply: oneshot::Sender<Result<Vec<RawMessage>, PeerError>>,
    },
}

/// A message the peer sent that no request took.
#[derive(Debug)]
pub struct PeerEvent {
    pub peer: u64,
    pub message: RawMessage,
}

/// Settings of a connection.
#[derive(Debug, Clone)]
pub struct PeerOptions {
    pub magic: [u8; 4],
    pub user_agent: String,
    /// Ask the peer to relay all its transactions to us.
    pub relay: bool,
    pub transport: Transport,
    /// Give the connection its own proxy circuit.
    pub isolate: bool,
    pub connect_timeout: Duration,
}

/// A live connection.
pub struct Peer {
    pub id: u64,
    pub addr: PeerAddr,
    pub info: VersionInfo,
    commands: mpsc::Sender<Command>,
    alive: Arc<AtomicBool>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl Peer {
    /// Connects and completes the version handshake.
    pub async fn connect(
        addr: PeerAddr,
        options: &PeerOptions,
        events: Option<mpsc::Sender<PeerEvent>>,
    ) -> Result<Peer, PeerError> {
        let stream = connect(
            &addr,
            &options.transport,
            options.isolate,
            options.connect_timeout,
        )
        .await?;
        let (mut read, mut write) = stream.into_split();
        let magic = options.magic;
        write
            .write_all(&encode_message(
                magic,
                "version",
                &encode_version(&options.user_agent, options.relay),
            ))
            .await
            .map_err(FrameError::from)?;
        let handshake = async {
            let mut info = None;
            let mut verack = false;
            while info.is_none() || !verack {
                let msg = read_message(&mut read, magic, || {}).await?;
                match msg.command.as_str() {
                    "version" => {
                        let v = decode_version(&msg.payload)
                            .map_err(|e| PeerError::Handshake(e.to_string()))?;
                        write
                            .write_all(&encode_message(magic, "verack", &[]))
                            .await
                            .map_err(FrameError::from)?;
                        info = Some(v);
                    }
                    "verack" => verack = true,
                    "ping" => {
                        write
                            .write_all(&encode_message(magic, "pong", &msg.payload))
                            .await
                            .map_err(FrameError::from)?;
                    }
                    _ => {}
                }
            }
            Ok::<_, PeerError>(info.expect("loop ends with a version"))
        };
        let info = tokio::time::timeout(options.connect_timeout, handshake)
            .await
            .map_err(|_| PeerError::Timeout("handshake".into()))??;
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let (commands, command_rx) = mpsc::channel(256);
        let (frames_tx, frames_rx) = mpsc::channel(64);
        let alive = Arc::new(AtomicBool::new(true));
        let start = Instant::now();
        let activity = Arc::new(AtomicU64::new(0));
        let reader_activity = activity.clone();
        let reader = tokio::spawn(async move {
            loop {
                let result = read_message(&mut read, magic, || {
                    reader_activity.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                })
                .await;
                reader_activity.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                let failed = result.is_err();
                if frames_tx.send(result).await.is_err() || failed {
                    break;
                }
            }
        });
        let actor = Actor {
            id,
            magic,
            write,
            events,
            queue: VecDeque::new(),
            current: None,
            start,
            activity,
        };
        let actor_alive = alive.clone();
        let name = addr.to_string();
        tokio::spawn(async move {
            let reason = actor.run(command_rx, frames_rx).await;
            debug!(peer = %name, %reason, "connection closed");
            actor_alive.store(false, Ordering::Relaxed);
            reader.abort();
        });
        let peer = Peer {
            id,
            addr,
            info,
            commands,
            alive,
        };
        peer.send("sendheaders", Vec::new());
        Ok(peer)
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Sends a message that expects no answer.
    pub fn send(&self, command: &'static str, payload: Vec<u8>) {
        // A full queue or a closed connection drops the message, as the network would.
        let _ = self.commands.try_send(Command::Send(command, payload));
    }

    /// Sends a request and collects the messages `collect` takes as its answer.
    /// The timeout restarts whenever bytes arrive.
    pub async fn request(
        &self,
        command: &'static str,
        payload: Vec<u8>,
        timeout: Duration,
        collect: impl FnMut(&RawMessage) -> Step + Send + 'static,
    ) -> Result<Vec<RawMessage>, PeerError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Request {
                command,
                payload,
                collect: Box::new(collect),
                timeout,
                reply,
            })
            .await
            .map_err(|_| PeerError::Disconnected)?;
        answer.await.map_err(|_| PeerError::Disconnected)?
    }

    /// Closes the connection.
    pub fn close(&self) {
        self.alive.store(false, Ordering::Relaxed);
        let _ = self.commands.try_send(Command::Send("", Vec::new()));
    }
}

struct Active {
    command: &'static str,
    collect: Collector,
    timeout: Duration,
    reply: oneshot::Sender<Result<Vec<RawMessage>, PeerError>>,
    taken: Vec<RawMessage>,
    deadline: tokio::time::Instant,
}

struct Actor {
    id: u64,
    magic: [u8; 4],
    write: OwnedWriteHalf,
    events: Option<mpsc::Sender<PeerEvent>>,
    queue: VecDeque<Command>,
    current: Option<Active>,
    start: Instant,
    activity: Arc<AtomicU64>,
}

impl Actor {
    async fn run(
        mut self,
        mut commands: mpsc::Receiver<Command>,
        mut frames: mpsc::Receiver<Result<RawMessage, FrameError>>,
    ) -> String {
        let reason = loop {
            let deadline = self.current.as_ref().map(|a| a.deadline);
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else { break "dropped".to_string() };
                    if let Command::Send("", _) = command {
                        break "closed".to_string();
                    }
                    self.queue.push_back(command);
                }
                frame = frames.recv() => {
                    match frame {
                        Some(Ok(message)) => {
                            if let Err(e) = self.on_message(message).await {
                                break e.to_string();
                            }
                        }
                        Some(Err(e)) => break e.to_string(),
                        None => break "reader stopped".to_string(),
                    }
                }
                _ = sleep_until(deadline) => {
                    let active = self.current.as_mut().expect("a deadline means a request");
                    let idle_since = Duration::from_millis(self.activity.load(Ordering::Relaxed));
                    let now = self.start.elapsed();
                    if now.saturating_sub(idle_since) < active.timeout {
                        active.deadline = tokio::time::Instant::now() + active.timeout - now.saturating_sub(idle_since);
                        continue;
                    }
                    let active = self.current.take().expect("checked above");
                    let what = format!("{} request", active.command);
                    let _ = active.reply.send(Err(PeerError::Timeout(what.clone())));
                    // A late answer could be taken for the next request's.
                    break format!("{what} timed out");
                }
            }
            if let Err(e) = self.pump().await {
                break e.to_string();
            }
        };
        if let Some(active) = self.current.take() {
            let _ = active.reply.send(Err(PeerError::Disconnected));
        }
        for command in self.queue.drain(..) {
            if let Command::Request { reply, .. } = command {
                let _ = reply.send(Err(PeerError::Disconnected));
            }
        }
        reason
    }

    async fn write(&mut self, command: &str, payload: &[u8]) -> Result<(), FrameError> {
        let bytes = encode_message(self.magic, command, payload);
        match tokio::time::timeout(Duration::from_secs(60), self.write.write_all(&bytes)).await {
            Ok(result) => Ok(result?),
            Err(_) => Err(FrameError::Io(std::io::ErrorKind::TimedOut.into())),
        }
    }

    /// Sends queued messages and starts the next request when none is active.
    async fn pump(&mut self) -> Result<(), FrameError> {
        while let Some(command) = self.queue.front() {
            match command {
                Command::Send(..) => {
                    let Some(Command::Send(cmd, payload)) = self.queue.pop_front() else {
                        unreachable!()
                    };
                    self.write(cmd, &payload).await?;
                }
                Command::Request { .. } if self.current.is_some() => break,
                Command::Request { .. } => {
                    let Some(Command::Request {
                        command,
                        payload,
                        collect,
                        timeout,
                        reply,
                    }) = self.queue.pop_front()
                    else {
                        unreachable!()
                    };
                    if reply.is_closed() {
                        continue;
                    }
                    self.write(command, &payload).await?;
                    self.activity
                        .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
                    self.current = Some(Active {
                        command,
                        collect,
                        timeout,
                        reply,
                        taken: Vec::new(),
                        deadline: tokio::time::Instant::now() + timeout,
                    });
                }
            }
        }
        Ok(())
    }

    async fn on_message(&mut self, message: RawMessage) -> Result<(), FrameError> {
        if message.command == "ping" {
            return self.write("pong", &message.payload).await;
        }
        // A light client has no blocks to offer; nodes wait for an answer
        // to getheaders and drop a peer that gives none.
        if message.command == "getheaders" {
            return self.write("headers", &[0]).await;
        }
        if let Some(active) = self.current.as_mut() {
            match (active.collect)(&message) {
                Step::Skip => {}
                Step::More => {
                    active.taken.push(message);
                    return Ok(());
                }
                Step::Done => {
                    let mut active = self.current.take().expect("checked above");
                    active.taken.push(message);
                    let _ = active.reply.send(Ok(active.taken));
                    return Ok(());
                }
            }
        }
        if let Some(events) = &self.events {
            // A full event queue drops the message: it is only a hint.
            let _ = events.try_send(PeerEvent {
                peer: self.id,
                message,
            });
        }
        Ok(())
    }
}

async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}
