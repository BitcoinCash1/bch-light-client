//! Double-spend proofs from relay: every announced proof is fetched (what is
//! asked for says nothing), checked against the mempool transaction that
//! spends the same output and the output itself, kept while that output is
//! unspent on the chain, and announced to subscribers.

use super::*;
use crate::dsproof::{DsProof, INV_DSPROOF};

/// A checked double-spend proof and the mempool transactions it concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsProofInfo {
    /// The proof ID, internal byte order (display reversed, like a txid).
    pub id: [u8; 32],
    pub outpoint: OutPoint,
    /// The mempool transaction that spends the output.
    pub txid: Txid,
    /// That transaction and every mempool transaction that spends its
    /// outputs, directly or not: all of them may be undone.
    pub descendants: Vec<Txid>,
    /// The serialized proof.
    pub raw: Vec<u8>,
}

struct Stored {
    proof: DsProof,
    raw: Vec<u8>,
    txid: Txid,
}

#[derive(Default)]
pub(crate) struct DsProofs {
    valid: HashMap<[u8; 32], Stored>,
    /// Proofs that wait for their spending transaction or output.
    pending: HashMap<[u8; 32], (DsProof, Vec<u8>)>,
    asked: HashSet<[u8; 32]>,
}

const MAX_PENDING: usize = 1000;

impl DsProofs {
    fn known(&self, id: &[u8; 32]) -> bool {
        self.valid.contains_key(id) || self.pending.contains_key(id) || self.asked.contains(id)
    }
}

/// The ids of announced proofs not seen yet, which are then asked for.
pub(crate) fn wanted(inner: &Inner, items: &[Inv]) -> Vec<Inv> {
    let mut proofs = inner.dsproofs.lock().expect("dsproof lock");
    if proofs.asked.len() > 10_000 {
        proofs.asked.clear();
    }
    items
        .iter()
        .filter(|i| i.kind == INV_DSPROOF)
        .filter(|i| !proofs.known(&i.hash) && proofs.asked.insert(i.hash))
        .copied()
        .collect()
}

/// The output a proof spends, from what the client holds: a mempool
/// transaction, a recent block, or a watched history.
fn coin(inner: &Inner, outpoint: &OutPoint) -> Option<TxOut> {
    if let Some(parent) = inner
        .mempool
        .read()
        .expect("mempool lock")
        .get(&outpoint.txid)
    {
        return parent.tx.outputs.get(outpoint.vout as usize).cloned();
    }
    if let Some(out) = inner
        .recent
        .lock()
        .expect("recent lock")
        .outputs
        .get(outpoint)
    {
        return Some(out.clone());
    }
    let states = inner.targets.lock().expect("targets lock");
    states.values().find_map(|s| {
        s.coins.get(outpoint).map(|c| TxOut {
            value: c.value,
            token: c.token.clone(),
            script: c.script.clone(),
        })
    })
}

/// A proof that arrived: checked now, or kept until what it needs arrives.
pub(crate) fn on_proof(inner: &Arc<Inner>, raw: Vec<u8>) {
    let Ok(proof) = DsProof::from_bytes(&raw) else {
        return;
    };
    if proof.check_sanity().is_err() {
        return;
    }
    let id = proof.id();
    let spender = {
        let mempool = inner.mempool.read().expect("mempool lock");
        mempool
            .spender(&proof.outpoint)
            .and_then(|txid| mempool.get(&txid))
    };
    let coin = coin(inner, &proof.outpoint);
    let (Some(spender), Some(coin)) = (spender, coin) else {
        let mut proofs = inner.dsproofs.lock().expect("dsproof lock");
        if proofs.pending.len() < MAX_PENDING {
            proofs.pending.insert(id, (proof.clone(), raw));
        }
        drop(proofs);
        fetch_coin_later(inner, proof.outpoint);
        return;
    };
    let Some(input) = spender
        .tx
        .inputs
        .iter()
        .find(|i| i.prevout == proof.outpoint)
    else {
        return;
    };
    match proof.validate(&coin, &input.script_sig) {
        Ok(()) => {
            let txid = spender.tx.txid();
            {
                let mut proofs = inner.dsproofs.lock().expect("dsproof lock");
                proofs.pending.remove(&id);
                // One proof per transaction is enough.
                if proofs.valid.values().any(|s| s.txid == txid) {
                    return;
                }
                proofs.valid.insert(id, Stored { proof, raw, txid });
            }
            info!(%txid, "double-spend proof");
            inner.emit(Event::DoubleSpendProof { txid, id });
        }
        Err(e) => {
            debug!(error = %e, "invalid double-spend proof");
            inner
                .dsproofs
                .lock()
                .expect("dsproof lock")
                .pending
                .remove(&id);
        }
    }
}

/// With transaction keys in the filters, the transaction that created the
/// output is found by its ID, and the waiting proofs are checked again.
fn fetch_coin_later(inner: &Arc<Inner>, outpoint: OutPoint) {
    if *inner.txid_keys.lock().expect("lock") != Some(true) {
        return;
    }
    let inner = inner.clone();
    tokio::spawn(async move {
        let Ok((block, _)) = locate(&inner, outpoint.txid, None).await else {
            return;
        };
        let Some(tx) = block.txs.iter().find(|t| t.txid() == outpoint.txid) else {
            return;
        };
        let Some(out) = tx.outputs.get(outpoint.vout as usize).cloned() else {
            return;
        };
        inner
            .recent
            .lock()
            .expect("recent lock")
            .outputs
            .insert(outpoint, out);
        retry_pending(&inner);
    });
}

/// Whether proofs wait for a transaction or an output.
pub(crate) fn has_pending(inner: &Inner) -> bool {
    !inner
        .dsproofs
        .lock()
        .expect("dsproof lock")
        .pending
        .is_empty()
}

/// Checks the waiting proofs again, after a transaction or an output arrived.
pub(crate) fn retry_pending(inner: &Arc<Inner>) {
    let waiting: Vec<Vec<u8>> = {
        let mut proofs = inner.dsproofs.lock().expect("dsproof lock");
        proofs.pending.drain().map(|(_, (_, raw))| raw).collect()
    };
    for raw in waiting {
        on_proof(inner, raw);
    }
}

/// Drops the proofs of outputs a block spends: the double spend is settled,
/// and the transactions they concerned are announced, as Fulcrum tells
/// their subscribers that the proof went.
pub(crate) fn on_block(inner: &Inner, block: &Block) {
    let spent: HashSet<OutPoint> = block
        .txs
        .iter()
        .flat_map(|t| t.inputs.iter().map(|i| i.prevout))
        .collect();
    let settled: Vec<([u8; 32], Txid)> = {
        let mut proofs = inner.dsproofs.lock().expect("dsproof lock");
        let gone: Vec<[u8; 32]> = proofs
            .valid
            .iter()
            .filter(|(_, s)| spent.contains(&s.proof.outpoint))
            .map(|(id, _)| *id)
            .collect();
        proofs
            .pending
            .retain(|_, (p, _)| !spent.contains(&p.outpoint));
        gone.into_iter()
            .filter_map(|id| proofs.valid.remove(&id).map(|s| (id, s.txid)))
            .collect()
    };
    for (id, txid) in settled {
        inner.emit(Event::DoubleSpendProof { txid, id });
    }
}

/// Announces a new mempool transaction that spends what a proved one
/// created: the proof concerns it too, as Fulcrum tells its subscribers.
pub(crate) fn on_descendant(inner: &Inner, tx: &Transaction) {
    let txid = tx.txid();
    let found = {
        let proofs = inner.dsproofs.lock().expect("dsproof lock");
        if proofs.valid.is_empty() {
            return;
        }
        let mempool = inner.mempool.read().expect("mempool lock");
        proofs
            .valid
            .iter()
            .find(|(_, s)| s.txid != txid && descendants(&mempool, s.txid).contains(&txid))
            .map(|(id, _)| *id)
    };
    if let Some(id) = found {
        inner.emit(Event::DoubleSpendProof { txid, id });
    }
}

fn descendants(mempool: &Mempool, txid: Txid) -> Vec<Txid> {
    let mut out = vec![txid];
    let mut seen: HashSet<Txid> = HashSet::from([txid]);
    let mut i = 0;
    while i < out.len() {
        if let Some(entry) = mempool.get(&out[i]) {
            for vout in 0..entry.tx.outputs.len() {
                if let Some(child) = mempool.spender(&OutPoint::new(out[i], vout as u32)) {
                    if seen.insert(child) {
                        out.push(child);
                    }
                }
            }
        }
        i += 1;
    }
    out
}

fn info_of(id: &[u8; 32], s: &Stored, mempool: &Mempool) -> DsProofInfo {
    DsProofInfo {
        id: *id,
        outpoint: s.proof.outpoint,
        txid: s.txid,
        descendants: descendants(mempool, s.txid),
        raw: s.raw.clone(),
    }
}

impl LightClient {
    /// The double-spend proof that concerns a transaction (the one that
    /// spends a double-spent output, or any of its mempool descendants),
    /// or the proof with this ID.
    pub fn ds_proof(&self, txid_or_id: [u8; 32]) -> Option<DsProofInfo> {
        let proofs = self.inner.dsproofs.lock().expect("dsproof lock");
        let mempool = self.inner.mempool.read().expect("mempool lock");
        if let Some(s) = proofs.valid.get(&txid_or_id) {
            return Some(info_of(&txid_or_id, s, &mempool));
        }
        let txid = Txid(txid_or_id);
        proofs
            .valid
            .iter()
            .map(|(id, s)| info_of(id, s, &mempool))
            .find(|info| info.descendants.contains(&txid))
    }

    /// The proof of a double-spent output.
    pub fn ds_proof_for_outpoint(&self, outpoint: &OutPoint) -> Option<DsProofInfo> {
        let proofs = self.inner.dsproofs.lock().expect("dsproof lock");
        let mempool = self.inner.mempool.read().expect("mempool lock");
        proofs
            .valid
            .iter()
            .find(|(_, s)| s.proof.outpoint == *outpoint)
            .map(|(id, s)| info_of(id, s, &mempool))
    }

    /// Every checked proof held.
    pub fn ds_proofs(&self) -> Vec<DsProofInfo> {
        let proofs = self.inner.dsproofs.lock().expect("dsproof lock");
        let mempool = self.inner.mempool.read().expect("mempool lock");
        proofs
            .valid
            .iter()
            .map(|(id, s)| info_of(id, s, &mempool))
            .collect()
    }
}
