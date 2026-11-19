//! One wallet connection: newline-delimited JSON-RPC, requests answered
//! concurrently, and subscriptions notified from the library's events.

use crate::methods;
use bch_light_client::filter::FilterKey;
use bch_light_client::{Event, LightClient, Network, Target, Txid};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, Semaphore};
use tracing::{debug, info};

/// What every session shares.
pub struct Shared {
    pub client: LightClient,
    pub network: Network,
    pub banner: String,
    pub donation_address: String,
    /// Whether blockchain.rpa.* are answered.
    pub rpa: bool,
}

/// A JSON-RPC error.
#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn params(message: impl Into<String>) -> Self {
        Self::new(-32602, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(-32601, message)
    }

    /// An application error, as Electrum servers send for bad requests.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(1, message)
    }
}

impl From<bch_light_client::Error> for RpcError {
    fn from(e: bch_light_client::Error) -> Self {
        RpcError::bad_request(e.to_string())
    }
}

/// A script subscription: the names it was subscribed under and its last status.
pub struct ScriptSub {
    pub target: Target,
    /// (notification method, first parameter) for each way it was subscribed.
    pub aliases: Vec<(&'static str, String)>,
    pub status: Option<String>,
}

pub struct SessionState {
    pub version: (u32, u32, u32),
    pub version_sent: bool,
    pub headers: bool,
    pub scripts: HashMap<FilterKey, ScriptSub>,
    pub txs: HashMap<Txid, Value>,
    /// Transactions whose double-spend proofs are followed, with the last status.
    pub dsproofs: HashMap<Txid, Value>,
}

pub struct Session {
    pub shared: Arc<Shared>,
    pub out: mpsc::Sender<String>,
    pub state: Mutex<SessionState>,
}

impl Session {
    pub fn notify(&self, method: &str, params: Value) {
        let line = json!({"jsonrpc": "2.0", "method": method, "params": params}).to_string();
        let _ = self.out.try_send(line);
    }
}

const MAX_LINE: usize = 16 << 20;

pub async fn run(shared: Arc<Shared>, stream: TcpStream) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let (read, mut write) = stream.into_split();
    let (out, mut lines) = mpsc::channel::<String>(1024);
    let session = Arc::new(Session {
        shared: shared.clone(),
        out,
        state: Mutex::new(SessionState {
            version: (1, 4, 0),
            version_sent: false,
            headers: false,
            scripts: HashMap::new(),
            txs: HashMap::new(),
            dsproofs: HashMap::new(),
        }),
    });
    let writer = tokio::spawn(async move {
        while let Some(mut line) = lines.recv().await {
            line.push('\n');
            if write.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let events = tokio::spawn(follow_events(session.clone(), shared.client.subscribe()));
    let slots = Arc::new(Semaphore::new(64));
    let mut reader = BufReader::new(read);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = match (&mut reader)
            .take(MAX_LINE as u64)
            .read_until(b'\n', &mut buf)
            .await
        {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 || (buf.last() != Some(&b'\n') && buf.len() >= MAX_LINE) {
            break;
        }
        let text = String::from_utf8_lossy(&buf).trim().to_string();
        if text.is_empty() {
            continue;
        }
        let Ok(permit) = slots.clone().acquire_owned().await else {
            break;
        };
        let session = session.clone();
        tokio::spawn(async move {
            let reply = handle_line(&session, &text).await;
            if let Some(reply) = reply {
                let _ = session.out.send(reply).await;
            }
            drop(permit);
        });
    }
    events.abort();
    writer.abort();
    info!(%peer, "wallet disconnected");
}

async fn handle_line(session: &Arc<Session>, text: &str) -> Option<String> {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            return Some(error_reply(Value::Null, RpcError::new(-32700, "parse error")).to_string())
        }
    };
    match parsed {
        Value::Array(requests) => {
            if requests.is_empty() {
                return Some(
                    error_reply(Value::Null, RpcError::new(-32600, "empty batch")).to_string(),
                );
            }
            let mut replies = Vec::with_capacity(requests.len());
            for request in requests {
                if let Some(reply) = handle_request(session, request).await {
                    replies.push(reply);
                }
            }
            (!replies.is_empty()).then(|| Value::Array(replies).to_string())
        }
        request => handle_request(session, request)
            .await
            .map(|r| r.to_string()),
    }
}

fn error_reply(id: Value, e: RpcError) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": e.code, "message": e.message}})
}

async fn handle_request(session: &Arc<Session>, request: Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Some(error_reply(
            id.unwrap_or(Value::Null),
            RpcError::new(-32600, "invalid request"),
        ));
    };
    // Named parameters (daemon.passthrough takes them on Fulcrum) arrive as
    // one positional argument; a method that wants positional ones refuses it.
    let params = match request.get("params") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(object @ Value::Object(_)) => vec![object.clone()],
        Some(_) => {
            return id.map(|id| {
                error_reply(
                    id,
                    RpcError::params("parameters must be a list or an object"),
                )
            });
        }
    };
    debug!(method, "request");
    let result = methods::call(session, method, &params).await;
    // A request without an id is a notification and gets no answer.
    let id = id?;
    Some(match result {
        Ok(value) => json!({"jsonrpc": "2.0", "id": id, "result": value}),
        Err(e) => error_reply(id, e),
    })
}

/// Turns the library's events into the notifications this session subscribed to.
async fn follow_events(session: Arc<Session>, mut events: broadcast::Receiver<Event>) {
    loop {
        let event = match events.recv().await {
            Ok(e) => e,
            Err(broadcast::error::RecvError::Lagged(_)) => {
                refresh_all(&session).await;
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => break,
        };
        match event {
            Event::Tip { height, .. } => {
                if session.state.lock().expect("session lock").headers {
                    if let Some(header) = session.shared.client.header(height) {
                        let tip = json!({"height": height, "hex": hex::encode(header.to_bytes())});
                        session.notify("blockchain.headers.subscribe", json!([tip]));
                    }
                }
            }
            Event::TargetChanged { target } => refresh_script(&session, target.key()).await,
            Event::Block { height, txids, .. } => {
                let hits: Vec<Txid> = {
                    let state = session.state.lock().expect("session lock");
                    txids
                        .iter()
                        .filter(|t| state.txs.contains_key(t))
                        .copied()
                        .collect()
                };
                for txid in hits {
                    set_tx_status(&session, txid, json!(height));
                }
            }
            Event::MempoolTx { txid } => {
                if session
                    .state
                    .lock()
                    .expect("session lock")
                    .txs
                    .contains_key(&txid)
                {
                    set_tx_status(&session, txid, json!(0));
                }
            }
            Event::Reorg { .. } => refresh_all(&session).await,
            Event::DoubleSpendProof { .. } => refresh_dsproofs(&session),
        }
    }
}

fn set_tx_status(session: &Session, txid: Txid, status: Value) {
    let changed = {
        let mut state = session.state.lock().expect("session lock");
        match state.txs.get_mut(&txid) {
            Some(old) if *old != status => {
                *old = status.clone();
                true
            }
            _ => false,
        }
    };
    if changed {
        session.notify(
            "blockchain.transaction.subscribe",
            json!([txid.to_hex(), status]),
        );
    }
}

async fn refresh_script(session: &Arc<Session>, key: FilterKey) {
    let target = {
        let state = session.state.lock().expect("session lock");
        match state.scripts.get(&key) {
            Some(sub) => sub.target.clone(),
            None => return,
        }
    };
    let Ok(status) = methods::status(&session.shared.client, &target).await else {
        return;
    };
    let notify: Vec<(&'static str, String)> = {
        let mut state = session.state.lock().expect("session lock");
        let Some(sub) = state.scripts.get_mut(&key) else {
            return;
        };
        if sub.status == status {
            return;
        }
        sub.status = status.clone();
        sub.aliases.clone()
    };
    for (method, name) in notify {
        session.notify(method, json!([name, status]));
    }
}

/// Sends the new proof status of each followed transaction that changed.
fn refresh_dsproofs(session: &Session) {
    let followed: Vec<Txid> = session
        .state
        .lock()
        .expect("session lock")
        .dsproofs
        .keys()
        .copied()
        .collect();
    for txid in followed {
        let status = session
            .shared
            .client
            .ds_proof(txid.0)
            .map_or(Value::Null, |p| methods::dsproof_json(&p));
        let changed = {
            let mut state = session.state.lock().expect("session lock");
            match state.dsproofs.get_mut(&txid) {
                Some(old) if *old != status => {
                    *old = status.clone();
                    true
                }
                _ => false,
            }
        };
        if changed {
            session.notify(
                "blockchain.transaction.dsproof.subscribe",
                json!([txid.to_hex(), status]),
            );
        }
    }
}

async fn refresh_all(session: &Arc<Session>) {
    let keys: Vec<FilterKey> = session
        .state
        .lock()
        .expect("session lock")
        .scripts
        .keys()
        .copied()
        .collect();
    for key in keys {
        refresh_script(session, key).await;
    }
    let txids: Vec<Txid> = session
        .state
        .lock()
        .expect("session lock")
        .txs
        .keys()
        .copied()
        .collect();
    for txid in txids {
        let status = methods::tx_status(&session.shared.client, txid).await;
        set_tx_status(session, txid, status);
    }
}
