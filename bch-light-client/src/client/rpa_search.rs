//! Finding transactions that may pay a reusable payment address: blocks
//! whose input prefix filters hold the prefix, downloaded whole (spread over
//! peers, and with cover prefixes if configured), and the first 30 inputs of
//! each transaction tested here. No request names the prefix. The wallet
//! then tests the candidates with its scan key.

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

    /// Confirmed transactions in blocks [from, to) with an input whose hash
    /// has the prefix, in chain order. Heights without input prefix filters
    /// (before their start height, or not synced yet) are not searched.
    pub async fn rpa_history(&self, prefix: Prefix, from: u32, to: u32) -> Result<Vec<RpaMatch>> {
        let inner = &self.inner;
        let store_lock = inner.store(FilterKind::Rpa).ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "input prefix filters are not kept (Config::rpa_filters)",
            )
        })?;
        let mut covers: Vec<Prefix> = Vec::new();
        {
            let mut rng = rand::thread_rng();
            while covers.len() < inner.config.rpa_cover_prefixes {
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
        let filters: Vec<(u32, Vec<u8>)> = {
            let store = store_lock.read().expect("filters lock");
            (from.max(store.base())..to.min(store.next_height()))
                .map(|h| store.read_checked(h).map(|f| (h, f)))
                .collect::<std::io::Result<_>>()
                .map_err(|e| storage_error("input prefix filters", e))?
        };
        let (wanted, fetch) = tokio::task::spawn_blocking(move || {
            let mut wanted = Vec::new();
            let mut fetch = BTreeSet::new();
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
            (wanted, fetch)
        })
        .await
        .map_err(|e| Error::new(ErrorKind::Stopped, e.to_string()))?;
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
            if !wanted.contains(&height) {
                continue;
            }
            let block_hash = block.hash();
            for (position, tx) in block.txs.iter().enumerate().skip(1) {
                let inputs = matching_inputs(tx, &prefix);
                if !inputs.is_empty() {
                    out.push(RpaMatch {
                        tx: tx.clone(),
                        confirmation: Some(Confirmation {
                            height,
                            block_hash,
                            position: position as u32,
                        }),
                        inputs,
                        fee: None,
                        unconfirmed_parent: false,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Mempool transactions with an input whose hash has the prefix: those
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
