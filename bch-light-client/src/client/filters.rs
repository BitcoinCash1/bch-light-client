//! Keeping the filter stores (type 1 script filters and type 2 input prefix
//! filters) in step with the header chain: from the store's start height,
//! filter headers checked as a chain, against checkpoints and against a
//! second peer, and filters checked against their headers. When two peers'
//! filter headers disagree, the block settles it: a type 2 filter is rebuilt
//! from the block, a type 1 filter's tree is compared leaf by leaf.

use super::*;
use crate::dispute::{
    decode_cfproof, decode_cfrange, encode_getcfproof, encode_getcfrange, gcs_of_leaves,
    is_true_leaf, prove_leaf, settle_trees, Leaf, ProvedLeaf, Verdict,
};
use crate::p2p::message::CfHeaders;
use crate::rpa;

/// Which filters a store holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterKind {
    Script,
    Rpa,
}

impl FilterKind {
    pub(crate) fn filter_type(self) -> u8 {
        match self {
            FilterKind::Script => SCRIPT_FILTER_TYPE,
            FilterKind::Rpa => rpa::RPA_FILTER_TYPE,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            FilterKind::Script => "script filters",
            FilterKind::Rpa => "input prefix filters",
        }
    }
}

/// The first height a store keeps for a wallet whose history starts at
/// `birthday`: just after the checkpoint at or below it, whose filter
/// header the peers give (BIP157 checkpoints are every 1000 blocks).
pub(crate) fn store_base(birthday: u32) -> u32 {
    let cp = birthday / CHECKPOINT_INTERVAL * CHECKPOINT_INTERVAL;
    if cp == 0 {
        0
    } else {
        cp + 1
    }
}

impl Inner {
    pub(crate) fn store(&self, kind: FilterKind) -> Option<&RwLock<FilterStore>> {
        match kind {
            FilterKind::Script => Some(&self.filters),
            FilterKind::Rpa => self.rpa_filters.as_ref(),
        }
    }
}

async fn request_cfheaders(
    peer: &Peer,
    kind: FilterKind,
    start: u32,
    stop: BlockHash,
    timeout: Duration,
) -> Result<CfHeaders> {
    let filter_type = kind.filter_type();
    let reply = peer
        .request(
            "getcfheaders",
            encode_getcf(filter_type, start, stop),
            timeout,
            move |m| match decode_cfheaders(&m.payload) {
                Ok(h)
                    if m.command == "cfheaders"
                        && h.filter_type == filter_type
                        && h.stop == stop =>
                {
                    Step::Done
                }
                _ => Step::Skip,
            },
        )
        .await?;
    decode_cfheaders(&reply[0].payload)
        .map_err(|e| Error::with_source(ErrorKind::InvalidData, "cfheaders", e))
}

/// The filters of consecutive blocks, checked against their block hashes.
async fn request_cfilters(
    peer: &Peer,
    kind: FilterKind,
    start: u32,
    hashes: &[BlockHash],
    timeout: Duration,
) -> Result<Vec<Vec<u8>>> {
    let filter_type = kind.filter_type();
    let mut filters = Vec::with_capacity(hashes.len());
    for (i, chunk) in hashes.chunks(MAX_CFILTERS_PER_MSG).enumerate() {
        let chunk_start = start + (i * MAX_CFILTERS_PER_MSG) as u32;
        let wanted: HashSet<BlockHash> = chunk.iter().copied().collect();
        let mut remaining = chunk.len();
        let reply = peer
            .request(
                "getcfilters",
                encode_getcf(filter_type, chunk_start, *chunk.last().expect("non-empty")),
                timeout,
                move |m| {
                    if m.command != "cfilter" {
                        return Step::Skip;
                    }
                    match decode_cfilter(&m.payload) {
                        Ok(f) if f.filter_type == filter_type && wanted.contains(&f.block) => {
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
            if f.block != chunk[j] {
                return Err(Error::new(ErrorKind::InvalidData, "filters out of order"));
            }
            filters.push(f.filter);
        }
    }
    Ok(filters)
}

async fn request_checkpoints(
    peer: &Peer,
    kind: FilterKind,
    stop: BlockHash,
    timeout: Duration,
) -> Result<Vec<[u8; 32]>> {
    let filter_type = kind.filter_type();
    let reply = peer
        .request(
            "getcfcheckpt",
            encode_getcfcheckpt(filter_type, stop),
            timeout,
            move |m| match decode_cfcheckpt(&m.payload) {
                Ok(c)
                    if m.command == "cfcheckpt"
                        && c.filter_type == filter_type
                        && c.stop == stop =>
                {
                    Step::Done
                }
                _ => Step::Skip,
            },
        )
        .await?;
    decode_cfcheckpt(&reply[0].payload)
        .map(|c| c.headers)
        .map_err(|e| Error::with_source(ErrorKind::InvalidData, "cfcheckpt", e))
}

/// Checkpoints all answering peers agree on, or None when they disagree
/// (the per-batch check against a second peer then finds where).
async fn agreed_checkpoints(
    inner: &Arc<Inner>,
    kind: FilterKind,
    stop: BlockHash,
    timeout: Duration,
) -> Option<Vec<[u8; 32]>> {
    let mut agreed: Option<Vec<[u8; 32]>> = None;
    for peer in inner.pool.filter_peers() {
        let Ok(list) = request_checkpoints(&peer, kind, stop, timeout).await else {
            continue;
        };
        match &agreed {
            None => agreed = Some(list),
            Some(previous) => {
                let common = previous.len().min(list.len());
                if previous[..common] != list[..common] {
                    warn!(
                        kind = kind.name(),
                        "peers disagree on filter header checkpoints"
                    );
                    return None;
                }
            }
        }
    }
    agreed
}

struct Batch {
    peer: Arc<Peer>,
    start: u32,
    hashes: Vec<BlockHash>,
    cfheaders: CfHeaders,
    filters: Vec<Vec<u8>>,
}

async fn fetch_batch(
    peer: Arc<Peer>,
    kind: FilterKind,
    start: u32,
    hashes: Vec<BlockHash>,
    timeout: Duration,
) -> Result<Batch> {
    let stop = *hashes.last().expect("non-empty batch");
    let cfheaders = request_cfheaders(&peer, kind, start, stop, timeout).await?;
    if cfheaders.filter_hashes.len() != hashes.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("cfheaders from {start} has the wrong count"),
        ));
    }
    let filters = request_cfilters(&peer, kind, start, &hashes, timeout).await?;
    for (i, filter) in filters.iter().enumerate() {
        if sha256d(filter) != cfheaders.filter_hashes[i] {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "{} of block {} does not match its filter header",
                    kind.name(),
                    hashes[i]
                ),
            ));
        }
    }
    Ok(Batch {
        peer,
        start,
        hashes,
        cfheaders,
        filters,
    })
}

/// Brings one filter store up to the header tip.
pub(crate) async fn sync(inner: &Arc<Inner>, kind: FilterKind) -> Result<()> {
    let Some(store_lock) = inner.store(kind) else {
        return Ok(());
    };
    let timeout = match kind {
        FilterKind::Script => inner.config.request_timeout,
        // Nodes that do not serve type 2 never answer; do not stall on them.
        FilterKind::Rpa => inner.config.request_timeout.min(Duration::from_secs(15)),
    };
    let (tip, tip_hash) = {
        let chain = inner.chain.read().expect("chain lock");
        (chain.tip_height(), chain.tip_hash())
    };
    let (base, anchored, first) = {
        let store = store_lock.read().expect("filters lock");
        (store.base(), store.anchored(), store.next_height())
    };
    if first > tip {
        return Ok(());
    }
    // Configured nodes without filters relay, but are never asked for filters.
    if inner.pool.wait_filter_peer(timeout).await.is_none() {
        return Err(Error::new(
            ErrorKind::Unavailable,
            "no peer that serves filters",
        ));
    }
    let generation = inner.generation.load(Ordering::SeqCst);
    let crosses = tip / CHECKPOINT_INTERVAL > first / CHECKPOINT_INTERVAL || first == base;
    let checkpoints = if crosses {
        agreed_checkpoints(inner, kind, tip_hash, timeout).await
    } else {
        None
    };
    if !anchored {
        // The filter header just below the start height, from the checkpoints.
        let at = (base - 1) / CHECKPOINT_INTERVAL;
        let anchor = checkpoints
            .as_ref()
            .and_then(|c| c.get(at as usize - 1))
            .copied()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unavailable,
                    format!("no agreed checkpoint at {} for {}", base - 1, kind.name()),
                )
            })?;
        store_lock
            .write()
            .expect("filters lock")
            .set_anchor(anchor)
            .map_err(|e| storage_error("filters", e))?;
    }
    let mut pending: VecDeque<JoinHandle<Result<Batch>>> = VecDeque::new();
    let mut next = first;
    let in_flight = inner.pool.filter_peers().len().max(1) * 2;
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
                .next_filter_peer()
                .ok_or_else(|| Error::new(ErrorKind::Unavailable, "no peer that serves filters"))?;
            pending.push_back(tokio::spawn(fetch_batch(peer, kind, next, hashes, timeout)));
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
        cross_check(inner, kind, &batch, timeout).await?;
        if kind == FilterKind::Rpa {
            if let Some(i) = batch.filters.iter().position(|f| rpa::decode(f).is_err()) {
                inner
                    .pool
                    .ban(&batch.peer.addr, "served a malformed input prefix filter");
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "malformed input prefix filter at {}",
                        batch.start + i as u32
                    ),
                ));
            }
        }
        let mut store = store_lock.write().expect("filters lock");
        if store.next_height() != batch.start {
            return Ok(());
        }
        let prev = store.prev_header(batch.start);
        if batch.cfheaders.prev_header != prev {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("{} from {} do not chain to ours", kind.name(), batch.start),
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
            header = filter_header_from_hash(&batch.cfheaders.filter_hashes[i], &header);
            if height % CHECKPOINT_INTERVAL == 0 && height > 0 {
                if let Some(cp) = checkpoints
                    .as_ref()
                    .and_then(|c| c.get((height / CHECKPOINT_INTERVAL - 1) as usize))
                {
                    if *cp != header {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "{} header at {height} differs from the checkpoint",
                                kind.name()
                            ),
                        ));
                    }
                }
            }
            items.push((batch.hashes[i], header, filter));
        }
        inner.stats.filter_bytes.fetch_add(
            items.iter().map(|(_, _, f)| f.len() as u64).sum(),
            Ordering::Relaxed,
        );
        store
            .append(&items)
            .map_err(|e| storage_error("filters", e))?;
        let tip_now = store.tip();
        drop(chain);
        drop(store);
        inner.state.send_modify(|s| match kind {
            FilterKind::Script => s.filter_tip = tip_now,
            FilterKind::Rpa => s.rpa_tip = tip_now,
        });
    }
    if next > first + 1 {
        info!(
            kind = kind.name(),
            from = first,
            to = tip,
            seconds = started.elapsed().as_secs_f64(),
            "filters synced"
        );
    }
    Ok(())
}

/// Asks a second peer for the same filter headers; where they differ,
/// settles which peer is wrong and drops it.
async fn cross_check(
    inner: &Arc<Inner>,
    kind: FilterKind,
    batch: &Batch,
    timeout: Duration,
) -> Result<()> {
    let Some(other) = inner
        .pool
        .filter_peers()
        .into_iter()
        .find(|p| p.id != batch.peer.id)
    else {
        return Ok(());
    };
    let stop = *batch.hashes.last().expect("non-empty batch");
    let Ok(theirs) = request_cfheaders(&other, kind, batch.start, stop, timeout).await else {
        // A peer that does not serve this filter type is no witness.
        return Ok(());
    };
    if theirs.prev_header == batch.cfheaders.prev_header
        && theirs.filter_hashes == batch.cfheaders.filter_hashes
    {
        return Ok(());
    }
    let height = if theirs.prev_header != batch.cfheaders.prev_header {
        // They differ below this batch: find the first height where they do.
        first_divergence(inner, kind, &other, batch.start, timeout).await?
    } else {
        let i = theirs
            .filter_hashes
            .iter()
            .zip(&batch.cfheaders.filter_hashes)
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        batch.start + i as u32
    };
    warn!(kind = kind.name(), height, a = %batch.peer.addr, b = %other.addr, "peers disagree on a filter; settling it");
    let verdict = settle(inner, kind, height, &batch.peer, &other, timeout).await?;
    let (bad, good) = match verdict {
        Verdict::First => (&batch.peer, &other),
        Verdict::Second => (&other, &batch.peer),
        Verdict::Same => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "peers disagree on filters and nothing settles it",
            ))
        }
    };
    inner.pool.ban(&bad.addr, "served a wrong filter");
    if bad.id == batch.peer.id {
        // What we kept from the wrong peer above `height` goes.
        let mut store = inner
            .store(kind)
            .expect("store")
            .write()
            .expect("filters lock");
        if height < store.next_height() {
            store
                .truncate_from(height)
                .map_err(|e| storage_error("filters", e))?;
        }
    }
    Err(Error::new(
        ErrorKind::InvalidData,
        format!(
            "{} served a wrong {} at height {height}; dropped, {} kept",
            bad.addr,
            kind.name(),
            good.addr
        ),
    ))
}

/// The lowest stored height whose filter header `peer` gives differently.
async fn first_divergence(
    inner: &Arc<Inner>,
    kind: FilterKind,
    peer: &Peer,
    below: u32,
    timeout: Duration,
) -> Result<u32> {
    let store_lock = inner.store(kind).expect("store");
    let base = store_lock.read().expect("filters lock").base();
    let (mut lo, mut hi) = (base, below);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (hash, ours) = {
            let store = store_lock.read().expect("filters lock");
            (store.block_hash(mid), store.filter_header(mid))
        };
        let (Some(hash), Some(ours)) = (hash, ours) else {
            return Ok(mid);
        };
        let theirs = request_cfheaders(peer, kind, mid, hash, timeout).await?;
        let header = theirs
            .filter_hashes
            .first()
            .map(|h| filter_header_from_hash(h, &theirs.prev_header));
        if header == Some(ours) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// Which of two peers serves a wrong filter for the block at `height`.
async fn settle(
    inner: &Arc<Inner>,
    kind: FilterKind,
    height: u32,
    a: &Arc<Peer>,
    b: &Arc<Peer>,
    timeout: Duration,
) -> Result<Verdict> {
    let hash = inner
        .chain
        .read()
        .expect("chain lock")
        .hash_at(height)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "no such block"))?;
    let fa = request_cfilters(a, kind, height, &[hash], timeout)
        .await
        .ok()
        .and_then(|f| f.into_iter().next());
    let fb = request_cfilters(b, kind, height, &[hash], timeout)
        .await
        .ok()
        .and_then(|f| f.into_iter().next());
    let (fa, fb) = match (fa, fb) {
        (None, _) => return Ok(Verdict::First),
        (_, None) => return Ok(Verdict::Second),
        (Some(fa), Some(fb)) => (fa, fb),
    };
    if fa == fb {
        return Ok(Verdict::Same);
    }
    match kind {
        FilterKind::Rpa => {
            let block = inner.fetcher.get(hash).await?;
            let built = rpa::build(&block);
            Ok(if built == fa {
                Verdict::Second
            } else if built == fb {
                Verdict::First
            } else {
                // Neither is the block's: drop the first and let the next round judge the other.
                Verdict::First
            })
        }
        FilterKind::Script => settle_script(inner, height, hash, (a, &fa), (b, &fb), timeout).await,
    }
}

async fn proof_at(
    peer: &Peer,
    block: BlockHash,
    root: [u8; 32],
    index: u32,
    timeout: Duration,
) -> Option<ProvedLeaf> {
    let reply = peer
        .request(
            "getcfproof",
            encode_getcfproof(block, index),
            timeout,
            move |m| match decode_cfproof(&m.payload) {
                Ok(p) if m.command == "cfproof" && p.block == block && p.leaf_index == index => {
                    Step::Done
                }
                _ => Step::Skip,
            },
        )
        .await
        .ok()?;
    let proof = decode_cfproof(&reply[0].payload).ok()?;
    prove_leaf(&root, block, index, proof)
}

/// A peer's leaf count: from the proof of leaf 0, or 0 for an empty tree.
async fn leaf_count(
    peer: &Peer,
    block: BlockHash,
    root: [u8; 32],
    timeout: Duration,
) -> Option<u32> {
    if root == [0u8; 32] {
        return Some(0);
    }
    proof_at(peer, block, root, 0, timeout)
        .await
        .map(|p| p.proof.leaf_count)
}

async fn settle_script(
    inner: &Arc<Inner>,
    height: u32,
    block: BlockHash,
    (a, fa): (&Arc<Peer>, &[u8]),
    (b, fb): (&Arc<Peer>, &[u8]),
    timeout: Duration,
) -> Result<Verdict> {
    if fa.len() < 33 {
        return Ok(Verdict::First);
    }
    if fb.len() < 33 {
        return Ok(Verdict::Second);
    }
    let root_a: [u8; 32] = fa[..32].try_into().expect("32 bytes");
    let root_b: [u8; 32] = fb[..32].try_into().expect("32 bytes");
    let header = inner
        .chain
        .read()
        .expect("chain lock")
        .header_at(height)
        .expect("block below the tip");
    let small_tx_until = inner.config.network.params().magnetic_anomaly_height;
    if root_a != root_b {
        let Some(count_a) = leaf_count(a, block, root_a, timeout).await else {
            return Ok(Verdict::First);
        };
        let Some(count_b) = leaf_count(b, block, root_b, timeout).await else {
            return Ok(Verdict::Second);
        };
        let is_true = |leaf: &ProvedLeaf| {
            let chain = inner.chain.read().expect("chain lock");
            is_true_leaf(
                leaf,
                &header,
                height,
                |hash| {
                    chain
                        .height_of(hash)
                        .and_then(|h| chain.header_at(h).map(|hd| (h, hd)))
                },
                small_tx_until,
            )
        };
        let verdict = settle_trees(
            count_a,
            count_b,
            |i| proof_at(a, block, root_a, i, timeout),
            |i| proof_at(b, block, root_b, i, timeout),
            is_true,
        )
        .await;
        if verdict != Verdict::Same {
            return Ok(verdict);
        }
    }
    // Same tree, different filters: rebuild the filter from all the leaves,
    // fetched by whole key ranges.
    let leaves = match all_leaves(a, block, root_a, timeout).await {
        Some(l) => l,
        None => return Ok(Verdict::First),
    };
    let mut want = root_a.to_vec();
    want.extend(gcs_of_leaves(&block, &leaves));
    // Unless the first peer's filter is the one its own leaves give, it is
    // wrong, whether or not the second peer's is right.
    Ok(if want == fa {
        Verdict::Second
    } else {
        Verdict::First
    })
}

/// Every leaf of a peer's tree, by key ranges sized to about 100,000 leaves.
async fn all_leaves(
    peer: &Peer,
    block: BlockHash,
    root: [u8; 32],
    timeout: Duration,
) -> Option<Vec<Leaf>> {
    let ask = |bits: u16, prefix: [u8; 32]| async move {
        let reply = peer
            .request(
                "getcfrange",
                encode_getcfrange(block, bits, &prefix),
                timeout,
                move |m| match decode_cfrange(&m.payload) {
                    Ok(r) if m.command == "cfrange" && r.block == block => Step::Done,
                    _ => Step::Skip,
                },
            )
            .await
            .ok()?;
        let range = decode_cfrange(&reply[0].payload).ok()?;
        crate::dispute::check_range(&root, &range, &prefix, bits).then_some(range)
    };
    let first = ask(256, [0u8; 32]).await?;
    let count = first.leaf_count;
    let mut bits = 0u16;
    while bits < 16 && u64::from(count) >> bits > 100_000 {
        bits += 1;
    }
    let mut leaves = Vec::with_capacity(count as usize);
    for i in 0u32..(1 << bits) {
        let mut prefix = [0u8; 32];
        if bits > 0 {
            let shifted = (i << (16 - bits)) as u16;
            prefix[..2].copy_from_slice(&shifted.to_be_bytes());
        }
        let range = ask(bits, prefix).await?;
        if range.leaf_count != count || range.first_index as usize != leaves.len() {
            return None;
        }
        leaves.extend(range.run);
    }
    (leaves.len() as u32 == count).then_some(leaves)
}
