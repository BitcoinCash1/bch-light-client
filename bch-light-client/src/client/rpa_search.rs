//! Finding transactions that may pay a reusable payment address: by default
//! every block of the searched range is downloaded and the first 30 inputs
//! of each transaction tested here, so which blocks are read names no
//! prefix. With `Config::rpa_whole_ranges` off, only the blocks whose input
//! prefix filters hold the prefix are read (with cover prefixes if
//! configured): fewer bytes, but the blocks read depend on the prefix. No
//! request names the prefix either way. The wallet then tests the
//! candidates with its scan key.

use super::*;
use crate::rpa::{decode as decode_rpa, matching_inputs, Prefix};

/// A transaction with an input that has the prefix.
#[derive(Debug, Clone)]
pub struct RpaMatch {
    pub tx: Transaction,
    /// None while in the mempool.
    pub confirmation: Option<Confirmation>,
    /// The indexes of the inputs, among the first 30, whose hash has the prefix.
    pub inputs: Vec<u32>,
    /// For a mempool transaction: its fee when known, and whether it spends
    /// an output of another mempool transaction.
    pub fee: Option<u64>,
    pub unconfirmed_parent: bool,
}

impl LightClient {
    /// The heights the input prefix filters cover, if they are kept.
    pub fn rpa_heights(&self) -> Option<(u32, Option<u32>)> {
        let store = self
            .inner
            .store(FilterKind::Rpa)?
            .read()
            .expect("filters lock");
        Some((store.base(), store.tip()))
    }

    /// Where RPA searches start: `Config::rpa_from_height`, else the
    /// network's usual RPA start height or the birthday, whichever is later.
    /// With `rpa_whole_ranges` off, where the input prefix filters start.
    pub fn rpa_start_height(&self) -> u32 {
        let config = &self.inner.config;
        if !config.rpa_whole_ranges {
            if let Some((base, _)) = self.rpa_heights() {
                return base;
            }
        }
        config.rpa_from_height.unwrap_or(
            config
                .network
                .params()
                .rpa_start_height
                .max(config.filters_from_height),
        )
    }

    /// Confirmed transactions in blocks [from, to) with an input whose hash
    /// has the prefix, in chain order. Heights past the chain's tip are not
    /// searched. By default every block of the range is downloaded. With
    /// `Config::rpa_whole_ranges` off the input prefix filters choose the
    /// blocks: heights before their start are not searched, and a range
    /// with blocks whose filters are not synced yet is an error
    /// (Unavailable), as answering nothing would say no payment is there.
    pub async fn rpa_history(&self, prefix: Prefix, from: u32, to: u32) -> Result<Vec<RpaMatch>> {
        let inner = &self.inner;
        if inner.config.rpa_whole_ranges {
            let tip = inner.chain.read().expect("chain lock").tip_height();
            let mut out = Vec::new();
            cover::download_in_order(
                inner,
                from..to.min(tip.saturating_add(1)),
                |height, block| {
                    out.extend(matches_in(&block, height, &prefix));
                    Ok(())
                },
            )
            .await?;
            return Ok(out);
        }
        let store_lock = inner.store(FilterKind::Rpa).ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "input prefix filters are not kept (Config::rpa_filters)",
            )
        })?;
        let chain_tip = inner.chain.read().expect("chain lock").tip_height();
        let (base, next) = {
            let store = store_lock.read().expect("filters lock");
            (store.base(), store.next_height())
        };
        let end = to.min(chain_tip.saturating_add(1));
        if from < end && end > next {
            return Err(Error::new(
                ErrorKind::Unavailable,
                match next.checked_sub(1) {
                    Some(last) if next > base => format!(
                        "input prefix filters reach height {last}, not yet {}",
                        end - 1
                    ),
                    _ => format!("no input prefix filters yet, from height {base}"),
                },
            ));
        }
        // Random other prefixes, as many as there are besides this one.
        let others = (1usize << prefix.bits) - 1;
        let mut covers: Vec<Prefix> = Vec::new();
        {
            let mut rng = rand::thread_rng();
            while covers.len() < inner.config.rpa_cover_prefixes.min(others) {
                let value = rng.gen_range(0..(1u32 << prefix.bits)) as u16;
                let cover = Prefix {
                    value,
                    bits: prefix.bits,
                };
                if cover != prefix && !covers.contains(&cover) {
                    covers.push(cover);
                }
            }
        }
        // Read and matched off the async threads, a thousand filters at a
        // time under the store's lock.
        let scan = inner.clone();
        let (lo, hi) = (from.max(base), end.min(next));
        let (wanted, fetch) = tokio::task::spawn_blocking(move || {
            let store_lock = scan.store(FilterKind::Rpa).expect("kept");
            let mut wanted = Vec::new();
            let mut fetch = BTreeSet::new();
            let mut at = lo;
            while at < hi {
                let until = at.saturating_add(1000).min(hi);
                let filters: Vec<(u32, Vec<u8>)> = {
                    let store = store_lock.read().expect("filters lock");
                    (at..until)
                        .map(|h| store.read_checked(h).map(|f| (h, f)))
                        .collect::<std::io::Result<_>>()?
                };
                for (height, filter) in &filters {
                    // A malformed filter cannot hide a payment: its block is read.
                    let values = decode_rpa(filter).ok();
                    let hit = |p: &Prefix| values.as_ref().map_or(true, |v| p.matches(v));
                    if hit(&prefix) {
                        wanted.push(*height);
                        fetch.insert(*height);
                    }
                    if covers.iter().any(hit) {
                        fetch.insert(*height);
                    }
                }
                at = until;
            }
            Ok::<_, std::io::Error>((wanted, fetch))
        })
        .await
        .map_err(|e| Error::new(ErrorKind::Stopped, e.to_string()))?
        .map_err(|e| storage_error("input prefix filters", e))?;
        let wanted: HashSet<u32> = wanted.into_iter().collect();
        let mut out = Vec::new();
        let mut queue: VecDeque<(u32, JoinHandle<Result<Arc<Block>>>)> = VecDeque::new();
        let mut order = fetch.into_iter();
        let ahead = inner.config.parallel_downloads.max(1) * 2;
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
            if wanted.contains(&height) {
                out.extend(matches_in(&block, height, &prefix));
            }
        }
        Ok(out)
    }

    /// Mempool transactions with an input whose hash has the prefix (no
    /// download, and no input prefix filters needed): those
    /// without unconfirmed parents first, then by transaction ID.
    pub fn rpa_mempool(&self, prefix: Prefix) -> Vec<RpaMatch> {
        let mempool = self.inner.mempool.read().expect("mempool lock");
        let mut out: Vec<RpaMatch> = mempool
            .iter()
            .filter_map(|entry| {
                let inputs = matching_inputs(&entry.tx, &prefix);
                (!inputs.is_empty()).then(|| RpaMatch {
                    tx: entry.tx.clone(),
                    confirmation: None,
                    inputs,
                    fee: entry.fee,
                    unconfirmed_parent: mempool.has_unconfirmed_parent(&entry.tx),
                })
            })
            .collect();
        out.sort_by_cached_key(|m| (m.unconfirmed_parent, m.tx.txid().to_hex()));
        out
    }
}

/// The transactions of `block` with an input, among their first 30, whose
/// hash has the prefix.
fn matches_in(block: &Block, height: u32, prefix: &Prefix) -> Vec<RpaMatch> {
    let block_hash = block.hash();
    block
        .txs
        .iter()
        .enumerate()
        .skip(1)
        .filter_map(|(position, tx)| {
            let inputs = matching_inputs(tx, prefix);
            (!inputs.is_empty()).then(|| RpaMatch {
                tx: tx.clone(),
                confirmation: Some(Confirmation {
                    height,
                    block_hash,
                    position: position as u32,
                }),
                inputs,
                fee: None,
                unconfirmed_parent: false,
            })
        })
        .collect()
}
