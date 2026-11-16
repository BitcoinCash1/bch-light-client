//! Whole-block downloads.
//!
//! With isolation on (the default behind a proxy), every block comes over a
//! connection of its own, to the next peer in turn, and through a proxy on a
//! circuit of its own, so that no peer can tell that two blocks were fetched
//! by the same client. Without isolation, blocks go round the service
//! connections, a different peer for each block in turn.

use crate::block::{merkle_root, Block};
use crate::error::{Error, ErrorKind, Result};
use crate::hash::{sha256d, BlockHash};
use crate::p2p::message::{decode_inv, encode_inv, Inv, INV_BLOCK};
use crate::p2p::peer::{Peer, PeerError, Step};
use crate::p2p::pool::Pool;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{oneshot, Semaphore};
use tracing::debug;

type Waiters = Vec<oneshot::Sender<std::result::Result<Arc<Block>, String>>>;

pub struct BlockFetcher {
    pool: Arc<Pool>,
    isolate: bool,
    timeout: Duration,
    slots: Semaphore,
    cache: Mutex<BlockCache>,
    inflight: Mutex<HashMap<BlockHash, Waiters>>,
}

struct BlockCache {
    blocks: HashMap<BlockHash, Arc<Block>>,
    order: VecDeque<BlockHash>,
    bytes: usize,
    max_bytes: usize,
}

impl BlockCache {
    fn get(&self, hash: &BlockHash) -> Option<Arc<Block>> {
        self.blocks.get(hash).cloned()
    }

    fn insert(&mut self, block: Arc<Block>) {
        let hash = block.hash();
        if self.blocks.contains_key(&hash) {
            return;
        }
        self.bytes += block.size;
        self.order.push_back(hash);
        self.blocks.insert(hash, block);
        while self.bytes > self.max_bytes && self.order.len() > 1 {
            let Some(old) = self.order.pop_front() else { break };
            if let Some(b) = self.blocks.remove(&old) {
                self.bytes -= b.size;
            }
        }
    }
}

impl BlockFetcher {
    pub fn new(pool: Arc<Pool>, isolate: bool, parallel: usize, timeout: Duration, cache_bytes: usize) -> Self {
        Self {
            pool,
            isolate,
            timeout,
            slots: Semaphore::new(parallel.max(1)),
            cache: Mutex::new(BlockCache {
                blocks: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
                max_bytes: cache_bytes,
            }),
            inflight: Mutex::new(HashMap::new()),
        }
    }

    pub fn cached(&self, hash: &BlockHash) -> Option<Arc<Block>> {
        self.cache.lock().expect("cache lock").get(hash)
    }

    /// A block, checked against its hash and Merkle root, from the cache or downloaded.
    pub async fn get(&self, hash: BlockHash) -> Result<Arc<Block>> {
        if let Some(block) = self.cached(&hash) {
            return Ok(block);
        }
        let waiter = {
            let mut inflight = self.inflight.lock().expect("inflight lock");
            match inflight.get_mut(&hash) {
                Some(waiters) => {
                    let (tx, rx) = oneshot::channel();
                    waiters.push(tx);
                    Some(rx)
                }
                None => {
                    inflight.insert(hash, Vec::new());
                    None
                }
            }
        };
        if let Some(rx) = waiter {
            return match rx.await {
                Ok(Ok(block)) => Ok(block),
                Ok(Err(message)) => Err(Error::new(ErrorKind::Unavailable, message)),
                Err(_) => Err(Error::new(ErrorKind::Stopped, "block download abandoned")),
            };
        }
        let result = self.download(hash).await;
        if let Ok(block) = &result {
            self.cache.lock().expect("cache lock").insert(block.clone());
        }
        let waiters = self.inflight.lock().expect("inflight lock").remove(&hash).unwrap_or_default();
        for w in waiters {
            let _ = w.send(result.as_ref().map(Arc::clone).map_err(|e| e.to_string()));
        }
        result
    }

    async fn download(&self, hash: BlockHash) -> Result<Arc<Block>> {
        let _slot = self.slots.acquire().await.map_err(|_| Error::new(ErrorKind::Stopped, "stopped"))?;
        let mut last = Error::new(ErrorKind::Unavailable, format!("no peer served block {hash}"));
        for _attempt in 0..4 {
            let outcome = if self.isolate {
                match self.pool.connect_isolated().await {
                    Ok(peer) => {
                        let result = self.request(&peer, hash).await;
                        peer.close();
                        result
                    }
                    Err(e) => Err(e),
                }
            } else {
                match self.pool.wait_peer(self.timeout).await {
                    Some(peer) => self.request(&peer, hash).await,
                    None => Err(PeerError::Disconnected),
                }
            };
            match outcome {
                Ok(raw) => {
                    let block = tokio::task::spawn_blocking(move || Block::from_bytes(&raw))
                        .await
                        .map_err(|e| Error::new(ErrorKind::Stopped, e.to_string()))?
                        .map_err(|e| Error::with_source(ErrorKind::InvalidData, format!("block {hash}"), e))?;
                    check_block(&block, hash)?;
                    return Ok(Arc::new(block));
                }
                Err(e) => {
                    debug!(block = %hash, error = %e, "block download failed");
                    last = Error::with_source(ErrorKind::Unavailable, format!("block {hash}"), e);
                }
            }
        }
        Err(last)
    }

    async fn request(&self, peer: &Peer, hash: BlockHash) -> std::result::Result<Vec<u8>, PeerError> {
        let mut answer = peer
            .request("getdata", encode_inv(&[Inv::block(hash)]), self.timeout, move |m| match m.command.as_str() {
                "block" if m.payload.len() >= 80 && sha256d(&m.payload[..80]) == hash.0 => Step::Done,
                "notfound" => match decode_inv(&m.payload) {
                    Ok(items) if items.iter().any(|i| i.kind == INV_BLOCK && i.hash == hash.0) => Step::Done,
                    _ => Step::Skip,
                },
                _ => Step::Skip,
            })
            .await?;
        let message = answer.pop().ok_or(PeerError::Disconnected)?;
        if message.command == "notfound" {
            return Err(PeerError::NotFound(format!("block {hash}")));
        }
        Ok(message.payload)
    }
}

/// A block must hash to the requested hash and its transactions to its
/// header's Merkle root, without the duplicate-transaction mutation.
pub fn check_block(block: &Block, hash: BlockHash) -> Result<()> {
    if block.hash() != hash {
        return Err(Error::new(ErrorKind::InvalidData, format!("block {hash} has another hash")));
    }
    let (root, mutated) = merkle_root(&block.txids());
    if root != block.header.merkle_root || mutated || block.txs.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, format!("block {hash} does not match its Merkle root")));
    }
    Ok(())
}
