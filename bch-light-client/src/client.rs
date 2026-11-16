//! The light client: the tasks that keep headers, filters, the mempool copy
//! and the watched histories current, and the API a wallet calls.

use crate::block::{merkle_branch, Block, BlockHeader};
use crate::chain::{Accepted, HeaderChain};
use crate::error::{Error, ErrorKind, Result};
use crate::fetch::BlockFetcher;
use crate::filter::{
    check_block, filter_header_from_hash, script_is_filtered, FilterKey, SCRIPT_FILTER_TYPE,
};
use crate::filterstore::FilterStore;
use crate::hash::{sha256d, BlockHash, Txid};
use crate::history::{Coin, ConfirmedTx, Received, Spent, Target, TargetState};
use crate::mempool::Mempool;
use crate::p2p::message::{
    decode_cfcheckpt, decode_cfheaders, decode_cfilter, decode_feefilter, decode_headers,
    decode_inv, decode_reject, encode_getcf, encode_getcfcheckpt, encode_getheaders, encode_inv,
    Inv, INV_BLOCK, INV_TX, MAX_CFHEADERS_PER_MSG, MAX_CFILTERS_PER_MSG, MAX_HEADERS_PER_MSG,
};
use crate::p2p::peer::{Peer, PeerEvent, PeerOptions, Step};
use crate::p2p::pool::Pool;
use crate::p2p::socks::{PeerAddr, Transport};
use crate::params::Network;
use crate::scan::{scan, ScanKey};
use crate::tx::{OutPoint, TokenData, Transaction};
use rand::Rng;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, watch, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// How the client reaches the network and how much it downloads.
#[derive(Debug, Clone)]
pub struct Config {
    pub network: Network,
    /// Where headers and filters are kept; a folder per network is made in it.
    pub data_dir: PathBuf,
    /// Peers as `host:port` (a missing port takes the network's default).
    pub peers: Vec<String>,
    /// A SOCKS5 proxy (`host:port`), such as Tor's.
    pub proxy: Option<String>,
    /// Download each block over a connection of its own (with a proxy, a
    /// circuit of its own). Default: on when a proxy is set.
    pub isolate_block_downloads: Option<bool>,
    /// Random extra blocks downloaded with each block a scan needs.
    pub decoy_blocks: usize,
    /// Download every block of a scanned range, not only those the filters
    /// point to: peers learn nothing from which blocks are fetched.
    pub download_all_blocks: bool,
    /// Long-lived connections for headers, filters and transaction relay.
    pub service_peers: usize,
    /// Blocks downloaded at once.
    pub parallel_downloads: usize,
    /// Threads that match filters; 0 for one per core.
    pub scan_threads: usize,
    pub user_agent: String,
    /// How long a request may wait with nothing arriving.
    pub request_timeout: Duration,
    pub block_cache_bytes: usize,
    pub mempool_max_bytes: usize,
}

impl Config {
    pub fn new(network: Network, data_dir: impl Into<PathBuf>, peers: Vec<String>) -> Self {
        Self {
            network,
            data_dir: data_dir.into(),
            peers,
            proxy: None,
            isolate_block_downloads: None,
            decoy_blocks: 0,
            download_all_blocks: false,
            service_peers: 2,
            parallel_downloads: 4,
            scan_threads: 0,
            user_agent: format!("/bch-light-client:{}/", env!("CARGO_PKG_VERSION")),
            request_timeout: Duration::from_secs(60),
            block_cache_bytes: 64 << 20,
            mempool_max_bytes: 256 << 20,
        }
    }
}

/// Something that changed, for wallets that follow the client.
#[derive(Debug, Clone)]
pub enum Event {
    /// The headers and filters reach a new tip.
    Tip { height: u32, hash: BlockHash },
    /// Blocks above `fork_height` were replaced.
    Reorg { fork_height: u32 },
    /// A new block was downloaded while following the tip.
    Block {
        height: u32,
        hash: BlockHash,
        txids: Arc<[Txid]>,
    },
    /// A transaction entered the mempool copy.
    MempoolTx { txid: Txid },
    /// A watched target's history, confirmed or unconfirmed, changed.
    TargetChanged { target: Target },
}

/// Where the client stands.
#[derive(Debug, Clone)]
pub struct Status {
    pub network: Network,
    pub header_height: u32,
    pub filter_height: Option<u32>,
    pub peers: usize,
    /// Headers and filters have caught up with the peers.
    pub synced: bool,
    /// Whether the peers' filters hold transaction keys, once a block has shown it.
    pub txid_keys: Option<bool>,
}

/// A target's transaction in the mempool.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MempoolEntry {
    pub txid: Txid,
    /// It spends an output of another mempool transaction.
    pub unconfirmed_parent: bool,
    pub fee: Option<u64>,
    pub received: Vec<Received>,
    pub spent: Vec<Spent>,
}

/// A target's history.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct History {
    /// Blocks up to this height are in `confirmed`.
    pub synced_height: Option<u32>,
    /// In chain order.
    pub confirmed: Vec<ConfirmedTx>,
    /// Without unconfirmed parents first, then by transaction ID.
    pub mempool: Vec<MempoolEntry>,
}

/// An unspent output.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub token: Option<TokenData>,
    pub script: Vec<u8>,
    /// None while in the mempool.
    pub height: Option<u32>,
}

/// Which outputs a balance or list counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenFilter {
    #[default]
    Include,
    Exclude,
    Only,
}

impl TokenFilter {
    fn keeps(self, token: &Option<TokenData>) -> bool {
        match self {
            TokenFilter::Include => true,
            TokenFilter::Exclude => token.is_none(),
            TokenFilter::Only => token.is_some(),
        }
    }
}

/// Confirmed and unconfirmed value, in satoshis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Balance {
    /// Unspent confirmed outputs, mempool spends not deducted.
    pub confirmed: u64,
    /// What the mempool adds minus what it spends.
    pub unconfirmed: i64,
}

/// Where a transaction is confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Confirmation {
    pub height: u32,
    pub block_hash: BlockHash,
    pub position: u32,
}

/// A transaction and where it stands.
#[derive(Debug, Clone)]
pub struct TxInfo {
    pub tx: Transaction,
    /// None while in the mempool.
    pub confirmation: Option<Confirmation>,
}

/// A transaction's Merkle branch to its block header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub txid: Txid,
    pub height: u32,
    pub block_hash: BlockHash,
    pub position: u32,
    /// Sibling hashes from the bottom, internal byte order.
    pub branch: Vec<[u8; 32]>,
}

/// An unspent output found by its outpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputInfo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script: Vec<u8>,
    pub token: Option<TokenData>,
    /// None while in the mempool.
    pub height: Option<u32>,
}

/// Fee rates in satoshis per 1000 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FeeEstimate {
    /// The lowest rate peers relay: the highest feefilter they sent, or 1000.
    pub relay: u64,
    /// The median rate of recent transactions whose fee is known, at least `relay`.
    pub estimate: u64,
}

/// The mempool copy at a glance.
#[derive(Debug, Clone)]
pub struct MempoolSummary {
    pub tx_count: usize,
    pub bytes: usize,
    /// Fee rate (satoshis per byte) and size of each transaction whose fee is known.
    pub fee_rates: Vec<(f64, usize)>,
}

/// The default relay fee of Bitcoin Cash nodes, satoshis per 1000 bytes.
const DEFAULT_RELAY_FEE: u64 = 1000;
const CHECKPOINT_INTERVAL: u32 = 1000;
const LIVE_WINDOW: u32 = 12;
const RECENT_BLOCKS: usize = 24;

#[derive(Debug, Clone, Default)]
struct SyncState {
    synced: bool,
    header_tip: u32,
    filter_tip: Option<u32>,
}

#[derive(Default)]
struct Recent {
    outputs: HashMap<OutPoint, u64>,
    blocks: VecDeque<Vec<OutPoint>>,
    fee_rates: VecDeque<u64>,
}

struct Inner {
    config: Config,
    pool: Arc<Pool>,
    fetcher: BlockFetcher,
    chain: RwLock<HeaderChain>,
    filters: RwLock<FilterStore>,
    generation: AtomicU64,
    targets: Mutex<HashMap<FilterKey, TargetState>>,
    mempool: RwLock<Mempool>,
    recent: Mutex<Recent>,
    peer_fees: Mutex<HashMap<u64, u64>>,
    events: broadcast::Sender<Event>,
    state: watch::Sender<SyncState>,
    wake: Notify,
    history_lock: tokio::sync::Mutex<()>,
    sync_lock: tokio::sync::Mutex<()>,
    txid_keys: Mutex<Option<bool>>,
    live_tip: Mutex<Option<u32>>,
    /// The tip last announced with `Event::Tip`.
    announced_tip: Mutex<Option<(u32, BlockHash)>>,
    requested: Mutex<HashSet<Txid>>,
    shutdown: watch::Sender<bool>,
}

/// A Bitcoin Cash light client. Cheap to clone; call [`LightClient::shutdown`] to stop it.
#[derive(Clone)]
pub struct LightClient {
    inner: Arc<Inner>,
}

fn storage_error(what: &str, e: std::io::Error) -> Error {
    Error::with_source(ErrorKind::Storage, what.to_string(), e)
}

impl LightClient {
    /// Opens the stores and starts connecting and syncing in the background.
    pub async fn start(config: Config) -> Result<LightClient> {
        let params = config.network.params();
        if config.peers.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "no peers given"));
        }
        let peers = config
            .peers
            .iter()
            .map(|p| PeerAddr::parse(p, params.default_port))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::with_source(ErrorKind::InvalidInput, "bad peer address", e))?;
        let transport = match &config.proxy {
            Some(p) => Transport::Socks5 {
                proxy: PeerAddr::parse(p, 9050).map_err(|e| {
                    Error::with_source(ErrorKind::InvalidInput, "bad proxy address", e)
                })?,
            },
            None => Transport::Direct,
        };
        let dir = config.data_dir.join(params.name);
        std::fs::create_dir_all(&dir).map_err(|e| storage_error("data folder", e))?;
        let chain = HeaderChain::open(&dir.join("headers.dat"), params)
            .map_err(|e| storage_error("headers", e))?;
        let filters = FilterStore::open(&dir, |h| chain.hash_at(h))
            .map_err(|e| storage_error("filters", e))?;
        info!(
            network = params.name,
            headers = chain.tip_height(),
            filters = filters.len(),
            "stores opened"
        );
        let isolate = config
            .isolate_block_downloads
            .unwrap_or(config.proxy.is_some());
        let options = PeerOptions {
            magic: params.magic,
            user_agent: config.user_agent.clone(),
            relay: true,
            isolate: matches!(transport, Transport::Socks5 { .. }),
            transport,
            connect_timeout: config.request_timeout.min(Duration::from_secs(30)),
        };
        let (pool, peer_events) = Pool::new(peers, options, config.service_peers);
        let fetcher = BlockFetcher::new(
            pool.clone(),
            isolate,
            config.parallel_downloads,
            config.request_timeout,
            config.block_cache_bytes,
        );
        let (shutdown, _) = watch::channel(false);
        let (events, _) = broadcast::channel(4096);
        let filter_tip = filters.tip();
        let header_tip = chain.tip_height();
        let inner = Arc::new(Inner {
            pool,
            fetcher,
            chain: RwLock::new(chain),
            filters: RwLock::new(filters),
            generation: AtomicU64::new(0),
            targets: Mutex::new(HashMap::new()),
            mempool: RwLock::new(Mempool::new(config.mempool_max_bytes)),
            recent: Mutex::new(Recent::default()),
            peer_fees: Mutex::new(HashMap::new()),
            events,
            state: watch::channel(SyncState {
                synced: false,
                header_tip,
                filter_tip,
            })
            .0,
            wake: Notify::new(),
            history_lock: tokio::sync::Mutex::new(()),
            sync_lock: tokio::sync::Mutex::new(()),
            txid_keys: Mutex::new(None),
            live_tip: Mutex::new(None),
            announced_tip: Mutex::new(None),
            requested: Mutex::new(HashSet::new()),
            shutdown,
            config,
        });
        inner.pool.spawn_maintainer(inner.shutdown.subscribe());
        tokio::spawn(event_loop(inner.clone(), peer_events));
        tokio::spawn(sync_loop(inner.clone()));
        Ok(LightClient { inner })
    }

    /// Stops the background tasks and closes the connections.
    pub fn shutdown(&self) {
        let _ = self.inner.shutdown.send(true);
        self.inner.wake.notify_waiters();
    }

    /// Changes as they happen. A receiver that falls behind gets `Lagged`
    /// and should read what it follows again.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    pub fn status(&self) -> Status {
        let state = self.inner.state.borrow().clone();
        Status {
            network: self.inner.config.network,
            header_height: state.header_tip,
            filter_height: state.filter_tip,
            peers: self.inner.pool.peers().len(),
            synced: state.synced,
            txid_keys: *self.inner.txid_keys.lock().expect("lock"),
        }
    }

    /// Waits until headers and filters have caught up with the peers.
    pub async fn wait_synced(&self, timeout: Duration) -> Result<Status> {
        let mut rx = self.inner.state.subscribe();
        let wait = rx.wait_for(|s| s.synced);
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Error::new(ErrorKind::Unavailable, "not synced in time"))?
            .map_err(|_| Error::new(ErrorKind::Stopped, "client stopped"))?;
        Ok(self.status())
    }

    /// Asks the client to look for new blocks now.
    pub fn poke(&self) {
        self.inner.wake.notify_one();
    }

    // ---- headers

    /// The tip of the headers that have filters too.
    pub fn tip(&self) -> Option<(u32, BlockHeader)> {
        let tip = self.inner.state.borrow().filter_tip?;
        self.header(tip).map(|h| (tip, h))
    }

    pub fn header(&self, height: u32) -> Option<BlockHeader> {
        self.inner
            .chain
            .read()
            .expect("chain lock")
            .header_at(height)
    }

    pub fn header_by_hash(&self, hash: &BlockHash) -> Option<(u32, BlockHeader)> {
        let chain = self.inner.chain.read().expect("chain lock");
        chain
            .height_of(hash)
            .and_then(|h| chain.header_at(h).map(|hd| (h, hd)))
    }

    pub fn headers(&self, from: u32, count: u32) -> Vec<BlockHeader> {
        let chain = self.inner.chain.read().expect("chain lock");
        (from..from.saturating_add(count))
            .map_while(|h| chain.header_at(h))
            .collect()
    }

    /// The Merkle branch of block `height`'s hash in the tree of the block
    /// hashes 0 to `cp_height`, and that tree's root.
    pub fn header_branch(&self, height: u32, cp_height: u32) -> Result<(Vec<[u8; 32]>, [u8; 32])> {
        let chain = self.inner.chain.read().expect("chain lock");
        if height > cp_height || cp_height > chain.tip_height() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "height must be at most cp_height, at most the tip",
            ));
        }
        let leaves: Vec<[u8; 32]> = (0..=cp_height)
            .map(|h| chain.hash_at(h).expect("below tip").0)
            .collect();
        drop(chain);
        let branch = merkle_branch(&leaves, height as usize);
        let root = crate::block::merkle_fold(leaves[height as usize], height as usize, &branch);
        Ok((branch, root))
    }

    // ---- watching

    /// Adds targets to watch and brings their histories up to the tip.
    pub async fn watch(&self, targets: impl IntoIterator<Item = Target>) -> Result<()> {
        {
            let mut states = self.inner.targets.lock().expect("targets lock");
            for target in targets {
                states
                    .entry(target.key())
                    .or_insert_with(|| TargetState::new(target));
            }
        }
        catch_up(&self.inner).await
    }

    /// Stops watching; returns whether the target was watched.
    pub fn unwatch(&self, target: &Target) -> bool {
        self.inner
            .targets
            .lock()
            .expect("targets lock")
            .remove(&target.key())
            .is_some()
    }

    /// The watched targets.
    pub fn watched(&self) -> Vec<Target> {
        self.inner
            .targets
            .lock()
            .expect("targets lock")
            .values()
            .map(|s| s.target.clone())
            .collect()
    }

    async fn ready(&self, target: &Target) -> Result<()> {
        let key = target.key();
        let tip = self.inner.state.borrow().filter_tip;
        let current = {
            let states = self.inner.targets.lock().expect("targets lock");
            states
                .get(&key)
                .map(|s| s.synced_to == tip || tip.is_none())
        };
        match current {
            Some(true) => Ok(()),
            Some(false) => catch_up(&self.inner).await,
            None => self.watch([target.clone()]).await,
        }
    }

    /// A target's confirmed and unconfirmed history.
    pub async fn history(&self, target: &Target) -> Result<History> {
        self.ready(target).await?;
        let states = self.inner.targets.lock().expect("targets lock");
        let state = states
            .get(&target.key())
            .ok_or_else(|| Error::new(ErrorKind::Stopped, "target removed"))?;
        let mempool = self.inner.mempool.read().expect("mempool lock");
        Ok(History {
            synced_height: state.synced_to,
            confirmed: state.txs.clone(),
            mempool: mempool_entries(state, &mempool),
        })
    }

    pub async fn balance(&self, target: &Target, tokens: TokenFilter) -> Result<Balance> {
        self.ready(target).await?;
        let states = self.inner.targets.lock().expect("targets lock");
        let state = states
            .get(&target.key())
            .ok_or_else(|| Error::new(ErrorKind::Stopped, "target removed"))?;
        let mempool = self.inner.mempool.read().expect("mempool lock");
        let confirmed = state
            .unspent()
            .filter(|c| tokens.keeps(&c.token))
            .map(|c| c.value)
            .sum();
        let mut unconfirmed = 0i64;
        for entry in mempool_entries(state, &mempool) {
            unconfirmed += entry
                .received
                .iter()
                .filter(|r| tokens.keeps(&r.token))
                .map(|r| r.value as i64)
                .sum::<i64>();
            unconfirmed -= entry
                .spent
                .iter()
                .filter(|s| tokens.keeps(&s.token))
                .map(|s| s.value as i64)
                .sum::<i64>();
        }
        Ok(Balance {
            confirmed,
            unconfirmed,
        })
    }

    /// Unspent outputs, confirmed (by height) first, then unconfirmed;
    /// outputs a mempool transaction spends are left out.
    pub async fn unspent(&self, target: &Target, tokens: TokenFilter) -> Result<Vec<Utxo>> {
        self.ready(target).await?;
        let states = self.inner.targets.lock().expect("targets lock");
        let state = states
            .get(&target.key())
            .ok_or_else(|| Error::new(ErrorKind::Stopped, "target removed"))?;
        let mempool = self.inner.mempool.read().expect("mempool lock");
        let mut out: Vec<Utxo> = state
            .unspent()
            .filter(|c| tokens.keeps(&c.token) && mempool.spender(&c.outpoint).is_none())
            .map(|c| Utxo {
                outpoint: c.outpoint,
                value: c.value,
                token: c.token.clone(),
                script: c.script.clone(),
                height: Some(c.height),
            })
            .collect();
        out.sort_by_cached_key(|u| (u.height, u.outpoint.txid.to_hex(), u.outpoint.vout));
        for entry in mempool_entries(state, &mempool) {
            for r in &entry.received {
                let outpoint = OutPoint::new(entry.txid, r.vout);
                if tokens.keeps(&r.token) && mempool.spender(&outpoint).is_none() {
                    out.push(Utxo {
                        outpoint,
                        value: r.value,
                        token: r.token.clone(),
                        script: r.script.clone(),
                        height: None,
                    });
                }
            }
        }
        Ok(out)
    }

    /// The first transaction of a target: confirmed if any, else unconfirmed.
    pub async fn first_use(&self, target: &Target) -> Result<Option<(Txid, Option<Confirmation>)>> {
        let history = self.history(target).await?;
        if let Some(first) = history.confirmed.first() {
            return Ok(Some((
                first.txid,
                Some(Confirmation {
                    height: first.height,
                    block_hash: first.block_hash,
                    position: first.position,
                }),
            )));
        }
        Ok(history.mempool.first().map(|e| (e.txid, None)))
    }

    // ---- transactions

    /// A transaction by ID: from the mempool, from a watched history, from
    /// the block at `height_hint`, or by its transaction key in the filters.
    pub async fn transaction(&self, txid: Txid, height_hint: Option<u32>) -> Result<TxInfo> {
        if let Some(entry) = self.inner.mempool.read().expect("mempool lock").get(&txid) {
            return Ok(TxInfo {
                tx: entry.tx.clone(),
                confirmation: None,
            });
        }
        let (block, height) = locate(&self.inner, txid, height_hint).await?;
        let position = block
            .txs
            .iter()
            .position(|t| t.txid() == txid)
            .expect("located");
        Ok(TxInfo {
            tx: block.txs[position].clone(),
            confirmation: Some(Confirmation {
                height,
                block_hash: block.hash(),
                position: position as u32,
            }),
        })
    }

    /// The Merkle branch of a confirmed transaction.
    pub async fn merkle_proof(&self, txid: Txid, height_hint: Option<u32>) -> Result<MerkleProof> {
        let (block, height) = locate(&self.inner, txid, height_hint).await?;
        let leaves: Vec<[u8; 32]> = block.txs.iter().map(|t| t.txid().0).collect();
        let position = leaves.iter().position(|l| *l == txid.0).expect("located");
        Ok(MerkleProof {
            txid,
            height,
            block_hash: block.hash(),
            position: position as u32,
            branch: merkle_branch(&leaves, position),
        })
    }

    /// The transaction at `position` of the block at `height`, with its Merkle branch.
    pub async fn transaction_at(
        &self,
        height: u32,
        position: u32,
    ) -> Result<(Transaction, MerkleProof)> {
        let block = block_at(&self.inner, height).await?;
        let tx = block.txs.get(position as usize).cloned().ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                format!("no transaction at position {position} of block {height}"),
            )
        })?;
        let leaves: Vec<[u8; 32]> = block.txs.iter().map(|t| t.txid().0).collect();
        let proof = MerkleProof {
            txid: tx.txid(),
            height,
            block_hash: block.hash(),
            position,
            branch: merkle_branch(&leaves, position as usize),
        };
        Ok((tx, proof))
    }

    /// An unspent output by outpoint, or None when it is spent.
    pub async fn output(
        &self,
        outpoint: OutPoint,
        height_hint: Option<u32>,
    ) -> Result<Option<OutputInfo>> {
        let info = self.transaction(outpoint.txid, height_hint).await?;
        let output = info
            .tx
            .outputs
            .get(outpoint.vout as usize)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("{outpoint} does not exist")))?;
        if self
            .inner
            .mempool
            .read()
            .expect("mempool lock")
            .spender(&outpoint)
            .is_some()
        {
            return Ok(None);
        }
        let result = OutputInfo {
            outpoint,
            value: output.value,
            script: output.script.clone(),
            token: output.token.clone(),
            height: info.confirmation.map(|c| c.height),
        };
        let Some(confirmation) = info.confirmation else {
            return Ok(Some(result));
        };
        // A spend puts the spent script (or the token category) in the spending block's filter.
        let key = if script_is_filtered(&output.script) {
            FilterKey::script(&output.script)
        } else if let Some(token) = &output.token {
            FilterKey::category(&token.category)
        } else {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "an output without a filtered script or token cannot be followed",
            ));
        };
        let heights = matching_heights(&self.inner, key, confirmation.height).await?;
        for height in heights {
            let block = block_at(&self.inner, height).await?;
            if block
                .txs
                .iter()
                .skip(1)
                .any(|t| t.inputs.iter().any(|i| i.prevout == outpoint))
            {
                return Ok(None);
            }
        }
        Ok(Some(result))
    }

    /// Sends a transaction to a peer and waits for it to be accepted.
    pub async fn broadcast(&self, raw: &[u8]) -> Result<Txid> {
        let tx = Transaction::from_bytes(raw)
            .map_err(|e| Error::with_source(ErrorKind::InvalidInput, "not a transaction", e))?;
        let txid = tx.txid();
        let inner = &self.inner;
        // Through a proxy the transaction goes out on a circuit of its own.
        let isolate = inner.fetcher_isolates();
        let peer: Arc<Peer> = if isolate {
            Arc::new(inner.pool.connect_isolated().await?)
        } else {
            inner
                .pool
                .wait_peer(inner.config.request_timeout)
                .await
                .ok_or_else(|| Error::new(ErrorKind::Unavailable, "no peer connected"))?
        };
        peer.send("tx", raw.to_vec());
        let answer = peer
            .request(
                "getdata",
                encode_inv(&[Inv::tx(txid)]),
                inner.config.request_timeout,
                move |m| match m.command.as_str() {
                    "tx" if sha256d(&m.payload) == txid.0 => Step::Done,
                    "notfound" => match decode_inv(&m.payload) {
                        Ok(items) if items.iter().any(|i| i.hash == txid.0) => Step::Done,
                        _ => Step::Skip,
                    },
                    "reject" => match decode_reject(&m.payload) {
                        Ok(r) if r.hash == Some(txid.0) => Step::Done,
                        _ => Step::Skip,
                    },
                    _ => Step::Skip,
                },
            )
            .await;
        if isolate {
            peer.close();
        }
        let message = answer?
            .pop()
            .ok_or_else(|| Error::new(ErrorKind::Unavailable, "no answer"))?;
        match message.command.as_str() {
            "tx" => {
                on_mempool_tx(inner, tx);
                Ok(txid)
            }
            "reject" => {
                let reason = decode_reject(&message.payload)
                    .map(|r| r.reason)
                    .unwrap_or_default();
                Err(Error::new(
                    ErrorKind::Rejected,
                    format!("the transaction was rejected: {reason}"),
                ))
            }
            _ => Err(Error::new(
                ErrorKind::Rejected,
                "the peer did not accept the transaction",
            )),
        }
    }

    // ---- fees and mempool

    pub fn fee_estimate(&self) -> FeeEstimate {
        let relay = self
            .inner
            .peer_fees
            .lock()
            .expect("fees lock")
            .values()
            .copied()
            .max()
            .unwrap_or(DEFAULT_RELAY_FEE)
            .max(1);
        let mut rates: Vec<u64> = self
            .inner
            .recent
            .lock()
            .expect("recent lock")
            .fee_rates
            .iter()
            .copied()
            .collect();
        rates.extend(
            self.inner
                .mempool
                .read()
                .expect("mempool lock")
                .iter()
                .filter_map(|e| e.fee.map(|f| f * 1000 / e.tx.size().max(1) as u64)),
        );
        rates.sort_unstable();
        let median = rates.get(rates.len() / 2).copied().unwrap_or(relay);
        FeeEstimate {
            relay,
            estimate: median.max(relay),
        }
    }

    pub fn mempool_summary(&self) -> MempoolSummary {
        let mempool = self.inner.mempool.read().expect("mempool lock");
        MempoolSummary {
            tx_count: mempool.len(),
            bytes: mempool.bytes(),
            fee_rates: mempool
                .iter()
                .filter_map(|e| {
                    e.fee
                        .map(|f| (f as f64 / e.tx.size().max(1) as f64, e.tx.size()))
                })
                .collect(),
        }
    }

    /// Whether a transaction is in the mempool copy.
    pub fn in_mempool(&self, txid: &Txid) -> bool {
        self.inner
            .mempool
            .read()
            .expect("mempool lock")
            .contains(txid)
    }
}

impl Inner {
    fn fetcher_isolates(&self) -> bool {
        self.config
            .isolate_block_downloads
            .unwrap_or(self.config.proxy.is_some())
    }

    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }
}

/// The mempool transactions that pay a target or spend its outputs.
fn mempool_entries(state: &TargetState, mempool: &Mempool) -> Vec<MempoolEntry> {
    let mut owned: HashMap<OutPoint, (u64, Option<TokenData>)> = HashMap::new();
    let mut entries: HashMap<Txid, MempoolEntry> = HashMap::new();
    for entry in mempool.iter() {
        for (vout, output) in entry.tx.outputs.iter().enumerate() {
            if state.target.owns(output) {
                owned.insert(
                    OutPoint::new(entry.tx.txid(), vout as u32),
                    (output.value, output.token.clone()),
                );
                entries
                    .entry(entry.tx.txid())
                    .or_insert_with(|| new_entry(entry, mempool))
                    .received
                    .push(Received {
                        vout: vout as u32,
                        value: output.value,
                        token: output.token.clone(),
                        script: output.script.clone(),
                    });
            }
        }
    }
    for entry in mempool.iter() {
        for (vin, input) in entry.tx.inputs.iter().enumerate() {
            let coin = state
                .coins
                .get(&input.prevout)
                .map(|c: &Coin| (c.value, c.token.clone()));
            if let Some((value, token)) = coin.or_else(|| owned.get(&input.prevout).cloned()) {
                entries
                    .entry(entry.tx.txid())
                    .or_insert_with(|| new_entry(entry, mempool))
                    .spent
                    .push(Spent {
                        vin: vin as u32,
                        prevout: input.prevout,
                        value,
                        token,
                    });
            }
        }
    }
    let mut out: Vec<MempoolEntry> = entries.into_values().collect();
    out.sort_by_cached_key(|e| (e.unconfirmed_parent, e.txid.to_hex()));
    out
}

fn new_entry(entry: &crate::mempool::MempoolTx, mempool: &Mempool) -> MempoolEntry {
    MempoolEntry {
        txid: entry.tx.txid(),
        unconfirmed_parent: mempool.has_unconfirmed_parent(&entry.tx),
        fee: entry.fee,
        received: Vec::new(),
        spent: Vec::new(),
    }
}

// ---- background tasks

async fn event_loop(inner: Arc<Inner>, mut events: mpsc::Receiver<PeerEvent>) {
    let mut shutdown = inner.shutdown.subscribe();
    loop {
        let event = tokio::select! {
            e = events.recv() => match e { Some(e) => e, None => break },
            _ = shutdown.changed() => break,
        };
        let PeerEvent { peer, message } = event;
        match message.command.as_str() {
            "inv" => {
                let Ok(items) = decode_inv(&message.payload) else {
                    continue;
                };
                if items.iter().any(|i| i.kind == INV_BLOCK) {
                    inner.wake.notify_one();
                }
                let wanted: Vec<Inv> = {
                    let mempool = inner.mempool.read().expect("mempool lock");
                    let mut requested = inner.requested.lock().expect("requested lock");
                    if requested.len() > 100_000 {
                        requested.clear();
                    }
                    items
                        .iter()
                        .filter(|i| i.kind == INV_TX)
                        .filter(|i| {
                            !mempool.contains(&Txid(i.hash)) && requested.insert(Txid(i.hash))
                        })
                        .copied()
                        .collect()
                };
                // Every announced transaction is fetched: what is asked for says nothing.
                if !wanted.is_empty() {
                    if let Some(p) = inner.pool.peers().into_iter().find(|p| p.id == peer) {
                        p.send("getdata", encode_inv(&wanted));
                    }
                }
            }
            "headers" => inner.wake.notify_one(),
            "tx" => {
                if let Ok(tx) = Transaction::from_bytes(&message.payload) {
                    inner
                        .requested
                        .lock()
                        .expect("requested lock")
                        .remove(&tx.txid());
                    on_mempool_tx(&inner, tx);
                }
            }
            "feefilter" => {
                if let Ok(rate) = decode_feefilter(&message.payload) {
                    inner
                        .peer_fees
                        .lock()
                        .expect("fees lock")
                        .insert(peer, rate);
                }
            }
            _ => {}
        }
    }
}

/// Adds a relayed transaction to the mempool copy and tells which watched targets it touches.
fn on_mempool_tx(inner: &Inner, tx: Transaction) {
    let txid = tx.txid();
    let touched: Vec<Target> = {
        let states = inner.targets.lock().expect("targets lock");
        let recent = inner.recent.lock().expect("recent lock");
        let mut mempool = inner.mempool.write().expect("mempool lock");
        let known = |o: &OutPoint| {
            recent.outputs.get(o).copied().or_else(|| {
                states
                    .values()
                    .find_map(|s| s.coins.get(o).map(|c| c.value))
            })
        };
        if !mempool.insert(tx.clone(), known) {
            return;
        }
        let mut keys: HashSet<FilterKey> = HashSet::new();
        for output in &tx.outputs {
            keys.insert(FilterKey::script(&output.script));
            if let Some(token) = &output.token {
                keys.insert(FilterKey::category(&token.category));
            }
        }
        for input in &tx.inputs {
            if let Some(parent) = mempool.get(&input.prevout.txid) {
                if let Some(output) = parent.tx.outputs.get(input.prevout.vout as usize) {
                    keys.insert(FilterKey::script(&output.script));
                    if let Some(token) = &output.token {
                        keys.insert(FilterKey::category(&token.category));
                    }
                }
            }
        }
        states
            .values()
            .filter(|s| {
                keys.contains(&s.key) || tx.inputs.iter().any(|i| s.coins.contains_key(&i.prevout))
            })
            .map(|s| s.target.clone())
            .collect()
    };
    inner.emit(Event::MempoolTx { txid });
    for target in touched {
        inner.emit(Event::TargetChanged { target });
    }
}

async fn sync_loop(inner: Arc<Inner>) {
    let mut shutdown = inner.shutdown.subscribe();
    loop {
        if *shutdown.borrow() {
            break;
        }
        if let Err(e) = sync_once(&inner).await {
            warn!(error = %e, "sync round failed");
            inner.state.send_modify(|s| s.synced = false);
        }
        tokio::select! {
            _ = inner.wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = shutdown.changed() => {}
        }
    }
}

async fn sync_once(inner: &Arc<Inner>) -> Result<()> {
    let _guard = inner.sync_lock.lock().await;
    let peer = inner
        .pool
        .wait_peer(inner.config.request_timeout)
        .await
        .ok_or_else(|| Error::new(ErrorKind::Unavailable, "no peer connected"))?;
    sync_headers(inner, &peer).await?;
    sync_filters(inner).await?;
    follow_tip(inner).await?;
    let (header_tip, filter_tip) = {
        let chain = inner.chain.read().expect("chain lock");
        (
            chain.tip_height(),
            inner.filters.read().expect("filters lock").tip(),
        )
    };
    inner.state.send_modify(|s| {
        s.header_tip = header_tip;
        s.filter_tip = filter_tip;
        s.synced = filter_tip == Some(header_tip);
    });
    if let Some(height) = filter_tip {
        let hash = inner
            .chain
            .read()
            .expect("chain lock")
            .hash_at(height)
            .expect("filter tip has a header");
        let mut announced = inner.announced_tip.lock().expect("tip lock");
        if *announced != Some((height, hash)) {
            *announced = Some((height, hash));
            drop(announced);
            inner.emit(Event::Tip { height, hash });
        }
    }
    let watched = !inner.targets.lock().expect("targets lock").is_empty();
    if watched {
        let history = inner.clone();
        tokio::spawn(async move {
            if let Err(e) = catch_up(&history).await {
                warn!(error = %e, "history catch-up failed");
            }
        });
    }
    Ok(())
}

async fn sync_headers(inner: &Arc<Inner>, peer: &Peer) -> Result<()> {
    let timeout = inner.config.request_timeout;
    let mut branch: Vec<BlockHeader> = Vec::new();
    loop {
        let locator = match branch.last() {
            Some(last) => vec![last.hash()],
            None => inner.chain.read().expect("chain lock").locator(),
        };
        let reply = peer
            .request(
                "getheaders",
                encode_getheaders(&locator, BlockHash::ZERO),
                timeout,
                |m| {
                    if m.command == "headers" {
                        Step::Done
                    } else {
                        Step::Skip
                    }
                },
            )
            .await?;
        let headers = decode_headers(&reply[0].payload)
            .map_err(|e| Error::with_source(ErrorKind::InvalidData, "headers message", e))?;
        let full = headers.len() == MAX_HEADERS_PER_MSG;
        if headers.is_empty() {
            return Ok(());
        }
        branch.extend(headers.into_iter().map(|(_, h)| h));
        let accepted = {
            let mut chain = inner.chain.write().expect("chain lock");
            let result = chain.accept(&branch);
            if let Ok(Accepted::Extended { fork: Some(_), .. }) = result {
                inner.generation.fetch_add(1, Ordering::SeqCst);
            }
            result
        }
        .map_err(|e| Error::with_source(ErrorKind::InvalidData, "peer sent invalid headers", e))?;
        match accepted {
            Accepted::Extended { fork, tip } => {
                if let Some(fork) = fork {
                    on_reorg(inner, fork)?;
                }
                inner.state.send_modify(|s| s.header_tip = tip);
                debug!(tip, "headers extended");
                branch.clear();
                if !full {
                    return Ok(());
                }
            }
            Accepted::Known => {
                branch.clear();
                if !full {
                    return Ok(());
                }
            }
            Accepted::LessWork { .. } if full && branch.len() < 100_000 => continue,
            Accepted::LessWork { .. } => return Ok(()),
        }
    }
}

fn on_reorg(inner: &Arc<Inner>, fork: u32) -> Result<()> {
    warn!(fork, "chain reorganization");
    inner
        .filters
        .write()
        .expect("filters lock")
        .truncate(fork + 1)
        .map_err(|e| storage_error("filters", e))?;
    let changed: Vec<Target> = {
        let mut states = inner.targets.lock().expect("targets lock");
        states
            .values_mut()
            .filter_map(|s| s.rollback(fork).then(|| s.target.clone()))
            .collect()
    };
    {
        let mut live = inner.live_tip.lock().expect("live lock");
        *live = live.map(|l| l.min(fork));
    }
    inner.state.send_modify(|s| {
        s.filter_tip = s.filter_tip.map(|t| t.min(fork));
        s.synced = false;
    });
    inner.emit(Event::Reorg { fork_height: fork });
    for target in changed {
        inner.emit(Event::TargetChanged { target });
    }
    Ok(())
}

struct FilterBatch {
    start: u32,
    hashes: Vec<BlockHash>,
    prev_header: [u8; 32],
    filter_hashes: Vec<[u8; 32]>,
    filters: Vec<Vec<u8>>,
}

async fn fetch_filter_batch(
    peer: Arc<Peer>,
    start: u32,
    hashes: Vec<BlockHash>,
    timeout: Duration,
) -> Result<FilterBatch> {
    let stop = *hashes.last().expect("non-empty batch");
    let reply = peer
        .request(
            "getcfheaders",
            encode_getcf(SCRIPT_FILTER_TYPE, start, stop),
            timeout,
            move |m| match decode_cfheaders(&m.payload) {
                Ok(h)
                    if m.command == "cfheaders"
                        && h.filter_type == SCRIPT_FILTER_TYPE
                        && h.stop == stop =>
                {
                    Step::Done
                }
                _ => Step::Skip,
            },
        )
        .await?;
    let cfheaders = decode_cfheaders(&reply[0].payload)
        .map_err(|e| Error::with_source(ErrorKind::InvalidData, "cfheaders", e))?;
    if cfheaders.filter_hashes.len() != hashes.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("cfheaders from {start} has the wrong count"),
        ));
    }
    let mut filters: Vec<Vec<u8>> = Vec::with_capacity(hashes.len());
    for (i, chunk) in hashes.chunks(MAX_CFILTERS_PER_MSG).enumerate() {
        let chunk_start = start + (i * MAX_CFILTERS_PER_MSG) as u32;
        let wanted: HashSet<BlockHash> = chunk.iter().copied().collect();
        let mut remaining = chunk.len();
        let reply = peer
            .request(
                "getcfilters",
                encode_getcf(
                    SCRIPT_FILTER_TYPE,
                    chunk_start,
                    *chunk.last().expect("non-empty"),
                ),
                timeout,
                move |m| {
                    if m.command != "cfilter" {
                        return Step::Skip;
                    }
                    match decode_cfilter(&m.payload) {
                        Ok(f)
                            if f.filter_type == SCRIPT_FILTER_TYPE && wanted.contains(&f.block) =>
                        {
                            remaining -= 1;
                            if remaining == 0 {
                                Step::Done
                            } else {
                                Step::More
                            }
                        }
                        _ => Step::Skip,
                    }
                },
            )
            .await?;
        for (j, message) in reply.iter().enumerate() {
            let f = decode_cfilter(&message.payload)
                .map_err(|e| Error::with_source(ErrorKind::InvalidData, "cfilter", e))?;
            let index = i * MAX_CFILTERS_PER_MSG + j;
            if f.block != hashes[index] || sha256d(&f.filter) != cfheaders.filter_hashes[index] {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "filter of block {} does not match its filter header",
                        f.block
                    ),
                ));
            }
            filters.push(f.filter);
        }
    }
    Ok(FilterBatch {
        start,
        hashes,
        prev_header: cfheaders.prev_header,
        filter_hashes: cfheaders.filter_hashes,
        filters,
    })
}

async fn checkpoints(inner: &Arc<Inner>, stop: BlockHash) -> Result<Vec<[u8; 32]>> {
    let mut agreed: Option<Vec<[u8; 32]>> = None;
    for peer in inner.pool.peers() {
        let reply = peer
            .request(
                "getcfcheckpt",
                encode_getcfcheckpt(SCRIPT_FILTER_TYPE, stop),
                inner.config.request_timeout,
                move |m| match decode_cfcheckpt(&m.payload) {
                    Ok(c)
                        if m.command == "cfcheckpt"
                            && c.filter_type == SCRIPT_FILTER_TYPE
                            && c.stop == stop =>
                    {
                        Step::Done
                    }
                    _ => Step::Skip,
                },
            )
            .await;
        let Ok(reply) = reply else { continue };
        let Ok(list) = decode_cfcheckpt(&reply[0].payload) else {
            continue;
        };
        match &agreed {
            None => agreed = Some(list.headers),
            Some(previous) => {
                let common = previous.len().min(list.headers.len());
                if previous[..common] != list.headers[..common] {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "peers disagree on the filter header checkpoints",
                    ));
                }
            }
        }
    }
    Ok(agreed.unwrap_or_default())
}

async fn sync_filters(inner: &Arc<Inner>) -> Result<()> {
    let (tip, tip_hash) = {
        let chain = inner.chain.read().expect("chain lock");
        (chain.tip_height(), chain.tip_hash())
    };
    let first = inner.filters.read().expect("filters lock").len() as u32;
    if first > tip {
        return Ok(());
    }
    let generation = inner.generation.load(Ordering::SeqCst);
    let checkpoints = if tip / CHECKPOINT_INTERVAL > first / CHECKPOINT_INTERVAL || first == 0 {
        checkpoints(inner, tip_hash).await?
    } else {
        Vec::new()
    };
    let timeout = inner.config.request_timeout;
    let mut pending: VecDeque<JoinHandle<Result<FilterBatch>>> = VecDeque::new();
    let mut next = first;
    let in_flight = inner.pool.peers().len().max(1) * 2;
    let started = std::time::Instant::now();
    loop {
        while pending.len() < in_flight && next <= tip {
            let end = (next + MAX_CFHEADERS_PER_MSG as u32 - 1).min(tip);
            let hashes: Vec<BlockHash> = {
                let chain = inner.chain.read().expect("chain lock");
                (next..=end)
                    .map(|h| chain.hash_at(h).expect("below tip"))
                    .collect()
            };
            let peer = inner
                .pool
                .next_peer()
                .ok_or_else(|| Error::new(ErrorKind::Unavailable, "no peer connected"))?;
            pending.push_back(tokio::spawn(fetch_filter_batch(
                peer, next, hashes, timeout,
            )));
            next = end + 1;
        }
        let Some(task) = pending.pop_front() else {
            break;
        };
        let batch = task
            .await
            .map_err(|e| Error::new(ErrorKind::Stopped, e.to_string()))??;
        if inner.generation.load(Ordering::SeqCst) != generation {
            return Ok(());
        }
        let mut store = inner.filters.write().expect("filters lock");
        if store.len() as u32 != batch.start {
            return Ok(());
        }
        let prev = store
            .tip()
            .and_then(|t| store.filter_header(t))
            .unwrap_or([0u8; 32]);
        if batch.prev_header != prev {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("filter headers from {} do not chain to ours", batch.start),
            ));
        }
        let chain = inner.chain.read().expect("chain lock");
        let mut header = prev;
        let mut items = Vec::with_capacity(batch.filters.len());
        for (i, filter) in batch.filters.into_iter().enumerate() {
            let height = batch.start + i as u32;
            if chain.hash_at(height) != Some(batch.hashes[i]) {
                return Ok(());
            }
            header = filter_header_from_hash(&batch.filter_hashes[i], &header);
            if height % CHECKPOINT_INTERVAL == 0 && height > 0 {
                if let Some(cp) = checkpoints.get((height / CHECKPOINT_INTERVAL - 1) as usize) {
                    if *cp != header {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("filter header at {height} differs from the checkpoint"),
                        ));
                    }
                }
            }
            items.push((batch.hashes[i], header, filter));
        }
        store
            .append(&items)
            .map_err(|e| storage_error("filters", e))?;
        let tip_now = store.tip();
        drop(chain);
        drop(store);
        inner.state.send_modify(|s| s.filter_tip = tip_now);
    }
    if next > first + 1 {
        info!(
            from = first,
            to = tip,
            seconds = started.elapsed().as_secs_f64(),
            "filters synced"
        );
    }
    Ok(())
}

/// Downloads every new block at the tip (all of them, so that peers learn
/// nothing from which), checks it against its filter, and updates the
/// mempool copy, the fee samples and the known transaction-key support.
async fn follow_tip(inner: &Arc<Inner>) -> Result<()> {
    let Some(tip) = inner.filters.read().expect("filters lock").tip() else {
        return Ok(());
    };
    let live = *inner.live_tip.lock().expect("live lock");
    let start = match live {
        Some(l) if l >= tip => return Ok(()),
        Some(l) if tip - l <= LIVE_WINDOW => l + 1,
        Some(_) => {
            // Too many blocks went by to read them all: start the mempool copy over.
            *inner.mempool.write().expect("mempool lock") =
                Mempool::new(inner.config.mempool_max_bytes);
            for peer in inner.pool.peers() {
                peer.send("mempool", Vec::new());
            }
            tip
        }
        None => tip,
    };
    for height in start..=tip {
        let block = block_at(inner, height).await?;
        let txids: Vec<Txid> = block.txids();
        let removed = inner
            .mempool
            .write()
            .expect("mempool lock")
            .remove_for_block(&block.txs);
        {
            let mut recent = inner.recent.lock().expect("recent lock");
            let mut created = Vec::new();
            for tx in &block.txs {
                for (vout, output) in tx.outputs.iter().enumerate() {
                    let outpoint = OutPoint::new(tx.txid(), vout as u32);
                    recent.outputs.insert(outpoint, output.value);
                    created.push(outpoint);
                }
            }
            for tx in block.txs.iter().skip(1) {
                let inputs: Option<u64> = tx
                    .inputs
                    .iter()
                    .map(|i| recent.outputs.get(&i.prevout).copied())
                    .sum();
                let outputs: u64 = tx.outputs.iter().map(|o| o.value).sum();
                if let Some(fee) = inputs.and_then(|i| i.checked_sub(outputs)) {
                    recent
                        .fee_rates
                        .push_back(fee * 1000 / tx.size().max(1) as u64);
                }
            }
            while recent.fee_rates.len() > 2000 {
                recent.fee_rates.pop_front();
            }
            recent.blocks.push_back(created);
            while recent.blocks.len() > RECENT_BLOCKS {
                if let Some(old) = recent.blocks.pop_front() {
                    for o in old {
                        recent.outputs.remove(&o);
                    }
                }
            }
        }
        *inner.live_tip.lock().expect("live lock") = Some(height);
        if !removed.is_empty() {
            debug!(
                height,
                removed = removed.len(),
                "mempool transactions confirmed or replaced"
            );
        }
        inner.emit(Event::Block {
            height,
            hash: block.hash(),
            txids: txids.into(),
        });
    }
    Ok(())
}

/// The block at `height`, downloaded or cached, checked against its header and its filter.
async fn block_at(inner: &Arc<Inner>, height: u32) -> Result<Arc<Block>> {
    let hash = inner
        .chain
        .read()
        .expect("chain lock")
        .hash_at(height)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no block at height {height}")))?;
    let block = inner.fetcher.get(hash).await?;
    let filter = inner
        .filters
        .read()
        .expect("filters lock")
        .read_checked(height);
    if let Ok(filter) = filter {
        if inner
            .filters
            .read()
            .expect("filters lock")
            .block_hash(height)
            == Some(hash)
        {
            let check = check_block(&block, &filter).map_err(|e| {
                Error::with_source(ErrorKind::InvalidData, format!("block {height}"), e)
            })?;
            let mut known = inner.txid_keys.lock().expect("lock");
            if *known != Some(check.has_txid_keys) {
                info!(
                    supported = check.has_txid_keys,
                    "filters with transaction keys"
                );
                *known = Some(check.has_txid_keys);
            }
        }
    }
    Ok(block)
}

/// Heights from `from` on whose filters match `key`.
async fn matching_heights(inner: &Arc<Inner>, key: FilterKey, from: u32) -> Result<Vec<u32>> {
    let (path, spans) = {
        let store = inner.filters.read().expect("filters lock");
        (store.data_path().to_path_buf(), store.spans(from, u32::MAX))
    };
    let threads = scan_threads(&inner.config);
    let hits =
        tokio::task::spawn_blocking(move || scan(&path, &spans, &[ScanKey { key, from }], threads))
            .await
            .map_err(|e| Error::new(ErrorKind::Stopped, e.to_string()))?
            .map_err(|e| storage_error("scan", e))?;
    Ok(hits.into_iter().map(|(h, _)| h).collect())
}

fn scan_threads(config: &Config) -> usize {
    if config.scan_threads > 0 {
        config.scan_threads
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}

/// Finds the block that confirms `txid`.
async fn locate(
    inner: &Arc<Inner>,
    txid: Txid,
    height_hint: Option<u32>,
) -> Result<(Arc<Block>, u32)> {
    let mut candidates: Vec<u32> = Vec::new();
    if let Some(h) = height_hint {
        candidates.push(h);
    }
    {
        let states = inner.targets.lock().expect("targets lock");
        if let Some(h) = states
            .values()
            .find_map(|s| s.txs.iter().find(|t| t.txid == txid).map(|t| t.height))
        {
            candidates.push(h);
        }
    }
    for &height in &candidates {
        let block = block_at(inner, height).await?;
        if block.txs.iter().any(|t| t.txid() == txid) {
            return Ok((block, height));
        }
    }
    match *inner.txid_keys.lock().expect("lock") {
        Some(true) => {}
        Some(false) => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "the peers' script filters have no transaction keys yet, so a transaction is found by ID \
                 only in the mempool, in a watched history, or with its block height",
            ))
        }
        None => return Err(Error::new(ErrorKind::Unavailable, "not known yet whether the filters have transaction keys")),
    }
    let mut heights = matching_heights(inner, FilterKey::txid(&txid), 0).await?;
    heights.reverse();
    for height in heights {
        let block = block_at(inner, height).await?;
        if block.txs.iter().any(|t| t.txid() == txid) {
            return Ok((block, height));
        }
    }
    Err(Error::new(
        ErrorKind::NotFound,
        format!("transaction {txid} is not on the chain"),
    ))
}

/// Brings every watched target's history up to the filter tip: one scan for
/// all of them, then the blocks the filters point to, in height order.
async fn catch_up(inner: &Arc<Inner>) -> Result<()> {
    let _guard = inner.history_lock.lock().await;
    loop {
        let generation = inner.generation.load(Ordering::SeqCst);
        let Some(tip) = inner.filters.read().expect("filters lock").tip() else {
            return Ok(());
        };
        let keys: Vec<ScanKey> = {
            let states = inner.targets.lock().expect("targets lock");
            states
                .values()
                .filter(|s| s.next_height() <= tip)
                .map(|s| ScanKey {
                    key: s.key,
                    from: s.next_height(),
                })
                .collect()
        };
        if keys.is_empty() {
            return Ok(());
        }
        let from = keys.iter().map(|k| k.from).min().expect("non-empty");
        let (path, spans) = {
            let store = inner.filters.read().expect("filters lock");
            (store.data_path().to_path_buf(), store.spans(from, tip + 1))
        };
        let threads = scan_threads(&inner.config);
        let scan_keys = keys.clone();
        let started = std::time::Instant::now();
        let hits = tokio::task::spawn_blocking(move || scan(&path, &spans, &scan_keys, threads))
            .await
            .map_err(|e| Error::new(ErrorKind::Stopped, e.to_string()))?
            .map_err(|e| storage_error("scan", e))?;
        debug!(
            keys = keys.len(),
            from,
            tip,
            matches = hits.len(),
            ms = started.elapsed().as_millis() as u64,
            "scan"
        );
        if inner.generation.load(Ordering::SeqCst) != generation {
            continue;
        }
        // Which keys each height must be applied to.
        let mut work: Vec<(u32, Vec<FilterKey>)> = if inner.config.download_all_blocks {
            (from..=tip)
                .map(|h| {
                    (
                        h,
                        keys.iter().filter(|k| k.from <= h).map(|k| k.key).collect(),
                    )
                })
                .collect()
        } else {
            hits.into_iter()
                .map(|(h, ks)| (h, ks.into_iter().map(|i| keys[i].key).collect()))
                .collect()
        };
        let mut fetch: BTreeSet<u32> = work.iter().map(|(h, _)| *h).collect();
        if inner.config.decoy_blocks > 0 && !inner.config.download_all_blocks {
            let mut rng = rand::thread_rng();
            for _ in 0..work.len() * inner.config.decoy_blocks {
                fetch.insert(rng.gen_range(0..=tip));
            }
        }
        work.sort_by_key(|(h, _)| *h);
        let mut applied: HashSet<FilterKey> = HashSet::new();
        let mut queue: VecDeque<(u32, JoinHandle<Result<Arc<Block>>>)> = VecDeque::new();
        let mut order = fetch.into_iter();
        let ahead = inner.config.parallel_downloads.max(1) * 2;
        let mut work_iter = work.into_iter().peekable();
        let mut aborted = false;
        loop {
            while queue.len() < ahead {
                let Some(height) = order.next() else { break };
                let task_inner = inner.clone();
                queue.push_back((
                    height,
                    tokio::spawn(async move { block_at(&task_inner, height).await }),
                ));
            }
            let Some((height, task)) = queue.pop_front() else {
                break;
            };
            let block = task
                .await
                .map_err(|e| Error::new(ErrorKind::Stopped, e.to_string()))??;
            let Some((_, keys_here)) = work_iter.next_if(|(h, _)| *h == height) else {
                continue;
            };
            let mut states = inner.targets.lock().expect("targets lock");
            if inner.generation.load(Ordering::SeqCst) != generation {
                aborted = true;
                break;
            }
            let block_hash = block.hash();
            for key in keys_here {
                if let Some(state) = states.get_mut(&key) {
                    if state.next_height() <= height
                        && state.apply_block(height, block_hash, &block.txs)
                    {
                        applied.insert(key);
                    }
                }
            }
        }
        if aborted {
            continue;
        }
        let changed: Vec<Target> = {
            let mut states = inner.targets.lock().expect("targets lock");
            if inner.generation.load(Ordering::SeqCst) != generation {
                continue;
            }
            for k in &keys {
                if let Some(state) = states.get_mut(&k.key) {
                    if state.next_height() <= tip {
                        state.synced_to = Some(tip);
                    }
                }
            }
            applied
                .iter()
                .filter_map(|k| states.get(k).map(|s| s.target.clone()))
                .collect()
        };
        for target in changed {
            inner.emit(Event::TargetChanged { target });
        }
    }
}
