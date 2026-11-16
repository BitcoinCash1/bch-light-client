//! The peers a client keeps: a few long-lived service connections for
//! headers, filters and transaction relay, and short-lived connections made
//! for one block download each when block downloads are isolated.

use super::message::{NODE_BLOOM, NODE_CF_BCH, NODE_COMPACT_FILTERS};
use super::peer::{Peer, PeerError, PeerEvent, PeerOptions};
use super::socks::PeerAddr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Notify};
use tracing::{debug, info};

pub struct Pool {
    addrs: Vec<PeerAddr>,
    options: PeerOptions,
    want: usize,
    service: RwLock<Vec<Arc<Peer>>>,
    next: AtomicUsize,
    next_isolated: AtomicUsize,
    retry_at: Mutex<HashMap<PeerAddr, (Instant, Duration)>>,
    events: mpsc::Sender<PeerEvent>,
    connected: Notify,
}

impl Pool {
    pub fn new(
        addrs: Vec<PeerAddr>,
        options: PeerOptions,
        want: usize,
    ) -> (Arc<Pool>, mpsc::Receiver<PeerEvent>) {
        let (events, rx) = mpsc::channel(4096);
        let pool = Pool {
            addrs,
            options,
            want: want.max(1),
            service: RwLock::new(Vec::new()),
            next: AtomicUsize::new(0),
            next_isolated: AtomicUsize::new(rand::random::<usize>() % 1024),
            retry_at: Mutex::new(HashMap::new()),
            events,
            connected: Notify::new(),
        };
        (Arc::new(pool), rx)
    }

    pub fn options(&self) -> &PeerOptions {
        &self.options
    }

    /// Keeps the service connections up until `shutdown` turns true.
    pub fn spawn_maintainer(self: &Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                pool.maintain().await;
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                    _ = shutdown.changed() => break,
                }
                if *shutdown.borrow() {
                    break;
                }
            }
            for peer in pool.service.write().expect("pool lock").drain(..) {
                peer.close();
            }
        });
    }

    async fn maintain(&self) {
        let connected: Vec<PeerAddr> = {
            let mut service = self.service.write().expect("pool lock");
            service.retain(|p| p.is_alive());
            service.iter().map(|p| p.addr.clone()).collect()
        };
        if connected.len() >= self.want.min(self.addrs.len()) {
            return;
        }
        let now = Instant::now();
        let candidates: Vec<PeerAddr> = {
            let retry = self.retry_at.lock().expect("retry lock");
            self.addrs
                .iter()
                .filter(|a| !connected.contains(a))
                .filter(|a| !matches!(retry.get(*a), Some((at, _)) if *at > now))
                .cloned()
                .collect()
        };
        let Some(addr) = candidates.first().cloned() else {
            return;
        };
        match Peer::connect(addr.clone(), &self.options, Some(self.events.clone())).await {
            Ok(peer) => {
                info!(peer = %addr, agent = %peer.info.user_agent, height = peer.info.start_height, "connected");
                if peer.info.services & (NODE_CF_BCH | NODE_COMPACT_FILTERS) == 0 {
                    debug!(peer = %addr, "peer does not advertise compact filters");
                }
                // Every transaction the peer has, not those of interest: the mempool message.
                if self.options.relay && peer.info.services & NODE_BLOOM != 0 {
                    peer.send("mempool", Vec::new());
                }
                self.retry_at.lock().expect("retry lock").remove(&addr);
                self.service
                    .write()
                    .expect("pool lock")
                    .push(Arc::new(peer));
                self.connected.notify_waiters();
            }
            Err(e) => {
                debug!(peer = %addr, error = %e, "connect failed");
                let mut retry = self.retry_at.lock().expect("retry lock");
                let backoff = retry.get(&addr).map_or(Duration::from_secs(1), |(_, b)| {
                    (*b * 2).min(Duration::from_secs(60))
                });
                retry.insert(addr, (Instant::now() + backoff, backoff));
            }
        }
    }

    /// The live service connections.
    pub fn peers(&self) -> Vec<Arc<Peer>> {
        self.service
            .read()
            .expect("pool lock")
            .iter()
            .filter(|p| p.is_alive())
            .cloned()
            .collect()
    }

    /// The next service connection, in turn.
    pub fn next_peer(&self) -> Option<Arc<Peer>> {
        let peers = self.peers();
        if peers.is_empty() {
            return None;
        }
        let i = self.next.fetch_add(1, Ordering::Relaxed);
        Some(peers[i % peers.len()].clone())
    }

    /// Waits up to `timeout` for a service connection.
    pub async fn wait_peer(&self, timeout: Duration) -> Option<Arc<Peer>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.connected.notified();
            if let Some(peer) = self.next_peer() {
                return Some(peer);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.next_peer();
            }
        }
    }

    /// A new connection of its own, to the next configured peer in turn,
    /// with no transaction relay and, through a proxy, its own circuit.
    pub async fn connect_isolated(&self) -> Result<Peer, PeerError> {
        let start = self.next_isolated.fetch_add(1, Ordering::Relaxed);
        let mut options = self.options.clone();
        options.relay = false;
        options.isolate = true;
        let mut last = PeerError::Disconnected;
        for i in 0..self.addrs.len().min(3) {
            let addr = self.addrs[(start + i) % self.addrs.len()].clone();
            match Peer::connect(addr, &options, None).await {
                Ok(peer) => return Ok(peer),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}
