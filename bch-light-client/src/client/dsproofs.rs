//! Double-spend proofs from relay. Every announced proof is fetched (what
//! is asked for says nothing), and a proof nobody asked for is dropped. A
//! proof is checked only against what the client holds: the mempool
//! transaction that spends the output, and the output itself as an output
//! of a mempool transaction, of the last blocks, or of a watched coin.
//! Nothing is fetched to check one: which proofs made the client fetch, and
//! which did not, would show a peer which coins are the wallet's. A proof
//! whose spending transaction has not arrived waits a while; checked proofs
//! are kept while their output is unspent on the chain. Each kind is bounded
//! in number, the oldest going first.

use super::*;
use crate::dsproof::{DsProof, INV_DSPROOF};
use std::time::Instant;

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
    outpoint: OutPoint,
    raw: Vec<u8>,
    txid: Txid,
    since: Instant,
}

struct Waiting {
    outpoint: OutPoint,
    raw: Vec<u8>,
    since: Instant,
}

#[derive(Default)]
pub(crate) struct DsProofs {
    valid: HashMap<[u8; 32], Stored>,
    /// Proofs that wait for the mempool transaction spending their output.
    waiting: HashMap<[u8; 32], Waiting>,
    /// Proofs asked for and not received yet, with when.
    asked: HashMap<[u8; 32], Instant>,
}

/// At most this many proofs are checked and kept, wait, or are asked for.
const MAX_VALID: usize = 1000;
const MAX_WAITING: usize = 1000;
const MAX_ASKED: usize = 10_000;
/// How long a proof asked for, or one waiting for its transaction, is kept.
const ASKED_FOR: Duration = Duration::from_secs(120);
const WAITING_FOR: Duration = Duration::from_secs(600);

impl DsProofs {
    fn known(&self, id: &[u8; 32]) -> bool {
        self.valid.contains_key(id) || self.waiting.contains_key(id) || self.asked.contains_key(id)
    }

    /// Notes a proof asked for; false when it is known, or too many asks wait.
    fn ask(&mut self, id: [u8; 32], now: Instant) -> bool {
        if self.known(&id) {
            return false;
        }
        if self.asked.len() >= MAX_ASKED {
            self.asked
                .retain(|_, at| now.saturating_duration_since(*at) < ASKED_FOR);
            if self.asked.len() >= MAX_ASKED {
                return false;
            }
        }
        self.asked.insert(id, now);
        true
    }

    /// Whether a proof that arrived was asked for: each ask lets one in.
    fn take_asked(&mut self, id: &[u8; 32]) -> bool {
        self.asked.remove(id).is_some()
    }

    /// Keeps a proof until a transaction spending its output arrives.
    fn wait(&mut self, id: [u8; 32], outpoint: OutPoint, raw: Vec<u8>, now: Instant) {
        self.waiting
            .retain(|_, w| now.saturating_duration_since(w.since) < WAITING_FOR);
        if self.waiting.len() >= MAX_WAITING {
            if let Some(oldest) = self
                .waiting
                .iter()
                .min_by_key(|(_, w)| w.since)
                .map(|(id, _)| *id)
            {
                self.waiting.remove(&oldest);
            }
        }
        self.waiting.insert(
            id,
            Waiting {
                outpoint,
                raw,
                since: now,
            },
        );
    }

    /// Takes out the waiting proofs of the outputs a transaction spends.
    fn waiting_for(&mut self, tx: &Transaction) -> Vec<Vec<u8>> {
        let spent: HashSet<OutPoint> = tx.inputs.iter().map(|i| i.prevout).collect();
        let ids: Vec<[u8; 32]> = self
            .waiting
            .iter()
            .filter(|(_, w)| spent.contains(&w.outpoint))
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter()
            .filter_map(|id| self.waiting.remove(&id).map(|w| w.raw))
            .collect()
    }

    /// Keeps a checked proof, one per transaction; past the bound the
    /// oldest goes. False when the transaction already has one.
    fn keep(&mut self, id: [u8; 32], stored: Stored) -> bool {
        self.waiting.remove(&id);
        if self.valid.values().any(|s| s.txid == stored.txid) {
            return false;
        }
        if self.valid.len() >= MAX_VALID {
            if let Some(oldest) = self
                .valid
                .iter()
                .min_by_key(|(_, s)| s.since)
                .map(|(id, _)| *id)
            {
                self.valid.remove(&oldest);
            }
        }
        self.valid.insert(id, stored);
        true
    }
}

/// The ids of announced proofs not seen yet, which are then asked for.
pub(crate) fn wanted(inner: &Inner, items: &[Inv]) -> Vec<Inv> {
    let mut proofs = inner.dsproofs.lock().expect("dsproof lock");
    let now = Instant::now();
    items
        .iter()
        .filter(|i| i.kind == INV_DSPROOF && proofs.ask(i.hash, now))
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

/// A proof a peer sent: dropped unless it was asked for.
pub(crate) fn on_relayed(inner: &Arc<Inner>, raw: Vec<u8>) {
    let asked = inner
        .dsproofs
        .lock()
        .expect("dsproof lock")
        .take_asked(&sha256d(&raw));
    if asked {
        on_proof(inner, raw);
    } else {
        debug!("a double-spend proof nobody asked for; dropped");
    }
}

/// A proof asked for: checked now against what the client holds, kept
/// waiting for its spending transaction, or dropped.
fn on_proof(inner: &Arc<Inner>, raw: Vec<u8>) {
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
    let Some(spender) = spender else {
        inner
            .dsproofs
            .lock()
            .expect("dsproof lock")
            .wait(id, proof.outpoint, raw, Instant::now());
        return;
    };
    // An output the client does not hold is never fetched: the proof goes.
    let Some(coin) = coin(inner, &proof.outpoint) else {
        debug!(outpoint = %proof.outpoint, "a double-spend proof of an output not held; dropped");
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
            let stored = Stored {
                outpoint: proof.outpoint,
                raw,
                txid,
                since: Instant::now(),
            };
            if inner
                .dsproofs
                .lock()
                .expect("dsproof lock")
                .keep(id, stored)
            {
                info!(%txid, "double-spend proof");
                inner.emit(Event::DoubleSpendProof { txid, id });
            }
        }
        Err(e) => debug!(error = %e, "invalid double-spend proof"),
    }
}

/// Checks the waiting proofs of the outputs a new mempool transaction spends.
pub(crate) fn on_mempool_tx(inner: &Arc<Inner>, tx: &Transaction) {
    let waiting = inner.dsproofs.lock().expect("dsproof lock").waiting_for(tx);
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
            .filter(|(_, s)| spent.contains(&s.outpoint))
            .map(|(id, _)| *id)
            .collect();
        proofs.waiting.retain(|_, w| !spent.contains(&w.outpoint));
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
        outpoint: s.outpoint,
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
            .find(|(_, s)| s.outpoint == *outpoint)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn outpoint(n: u32) -> OutPoint {
        OutPoint::new(Txid([n as u8; 32]), n)
    }

    #[test]
    fn only_proofs_asked_for_get_in_once_each() {
        let mut proofs = DsProofs::default();
        let now = Instant::now();
        assert!(!proofs.take_asked(&[1; 32]), "nobody asked for it");
        assert!(proofs.ask([1; 32], now));
        assert!(!proofs.ask([1; 32], now), "asked once");
        assert!(proofs.take_asked(&[1; 32]));
        assert!(!proofs.take_asked(&[1; 32]), "one ask lets one proof in");
    }

    #[test]
    fn asks_are_bounded_and_old_ones_expire() {
        let mut proofs = DsProofs::default();
        let start = Instant::now();
        for i in 0..MAX_ASKED as u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            assert!(proofs.ask(id, start));
        }
        assert!(
            !proofs.ask([0xff; 32], start),
            "no more while all are fresh"
        );
        assert!(
            proofs.ask([0xff; 32], start + ASKED_FOR),
            "the old ones expired"
        );
        assert_eq!(proofs.asked.len(), 1);
    }

    #[test]
    fn waiting_proofs_are_bounded_expire_and_go_to_their_spender() {
        let mut proofs = DsProofs::default();
        let start = Instant::now();
        for i in 0..MAX_WAITING as u32 + 5 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            let at = start + Duration::from_millis(u64::from(i));
            proofs.wait(id, outpoint(i), vec![i as u8], at);
        }
        assert_eq!(proofs.waiting.len(), MAX_WAITING, "the oldest went");
        assert!(!proofs.waiting.values().any(|w| w.outpoint == outpoint(0)));
        // A transaction spending one of the outputs takes its proof out.
        let tx = Transaction::from_bytes(&{
            let mut b = vec![1, 0, 0, 0, 1];
            b.extend_from_slice(&outpoint(7).txid.0);
            b.extend_from_slice(&7u32.to_le_bytes());
            b.extend_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 1]);
            b.extend_from_slice(&[0; 8]);
            b.extend_from_slice(&[1, 0x51, 0, 0, 0, 0]);
            b
        })
        .unwrap();
        assert_eq!(proofs.waiting_for(&tx), vec![vec![7u8]]);
        assert!(proofs.waiting_for(&tx).is_empty());
        // Ten minutes on, a new one finds the rest gone.
        proofs.wait([0xee; 32], outpoint(9999), vec![], start + WAITING_FOR * 2);
        assert_eq!(proofs.waiting.len(), 1);
    }

    #[test]
    fn checked_proofs_are_one_per_transaction_and_bounded() {
        let mut proofs = DsProofs::default();
        let start = Instant::now();
        let stored = |i: u32| Stored {
            outpoint: outpoint(i),
            raw: vec![],
            txid: Txid({
                let mut t = [0u8; 32];
                t[..4].copy_from_slice(&i.to_le_bytes());
                t
            }),
            since: start + Duration::from_millis(u64::from(i)),
        };
        assert!(proofs.keep([1; 32], stored(1)));
        assert!(
            !proofs.keep([2; 32], stored(1)),
            "one proof per transaction"
        );
        for i in 2..MAX_VALID as u32 + 3 {
            let mut id = [0u8; 32];
            id[4..8].copy_from_slice(&i.to_le_bytes());
            assert!(proofs.keep(id, stored(i)));
        }
        assert_eq!(proofs.valid.len(), MAX_VALID);
        assert!(!proofs.valid.contains_key(&[1; 32]), "the oldest went");
    }
}
