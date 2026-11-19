//! The client's own copy of the mempool, filled by ordinary transaction
//! relay: peers announce every transaction they accept, and the client
//! fetches all of them, so nothing it asks for says what it watches.

use crate::hash::Txid;
use crate::tx::{OutPoint, Transaction};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// A transaction in the mempool copy.
#[derive(Debug)]
pub struct MempoolTx {
    pub tx: Transaction,
    /// The fee, when the values of all spent outputs are known.
    pub fee: Option<u64>,
}

#[derive(Default)]
pub struct Mempool {
    txs: HashMap<Txid, Arc<MempoolTx>>,
    /// Which mempool transaction spends each outpoint.
    spends: HashMap<OutPoint, Txid>,
    order: VecDeque<Txid>,
    bytes: usize,
    max_bytes: usize,
}

impl Mempool {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            ..Default::default()
        }
    }

    pub fn contains(&self, txid: &Txid) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn get(&self, txid: &Txid) -> Option<Arc<MempoolTx>> {
        self.txs.get(txid).cloned()
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<MempoolTx>> {
        self.txs.values()
    }

    /// Records the fee of a transaction whose spent values were found after
    /// it came in.
    pub fn set_fee(&mut self, txid: &Txid, fee: u64) {
        if let Some(entry) = self.txs.get_mut(txid) {
            if entry.fee.is_none() {
                *entry = Arc::new(MempoolTx {
                    tx: entry.tx.clone(),
                    fee: Some(fee),
                });
            }
        }
    }

    /// The mempool transaction that spends `outpoint`.
    pub fn spender(&self, outpoint: &OutPoint) -> Option<Txid> {
        self.spends.get(outpoint).copied()
    }

    /// The value of an output of a mempool transaction.
    pub fn output_value(&self, outpoint: &OutPoint) -> Option<u64> {
        self.txs
            .get(&outpoint.txid)
            .and_then(|t| t.tx.outputs.get(outpoint.vout as usize))
            .map(|o| o.value)
    }

    /// Adds a transaction; `known_value` gives the value of confirmed
    /// outputs the client knows, for the fee. Returns false if it was there.
    pub fn insert(
        &mut self,
        tx: Transaction,
        known_value: impl Fn(&OutPoint) -> Option<u64>,
    ) -> bool {
        let txid = tx.txid();
        if self.txs.contains_key(&txid) || tx.is_coinbase() {
            return false;
        }
        let inputs: Option<u64> = tx
            .inputs
            .iter()
            .map(|i| {
                self.output_value(&i.prevout)
                    .or_else(|| known_value(&i.prevout))
            })
            .sum();
        let outputs: u64 = tx.outputs.iter().map(|o| o.value).sum();
        let fee = inputs.and_then(|i| i.checked_sub(outputs));
        for input in &tx.inputs {
            self.spends.insert(input.prevout, txid);
        }
        self.bytes += tx.size();
        self.order.push_back(txid);
        self.txs.insert(txid, Arc::new(MempoolTx { tx, fee }));
        while self.bytes > self.max_bytes {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.remove(&oldest);
        }
        true
    }

    fn remove(&mut self, txid: &Txid) -> Option<Arc<MempoolTx>> {
        let entry = self.txs.remove(txid)?;
        self.bytes -= entry.tx.size();
        for input in &entry.tx.inputs {
            if self.spends.get(&input.prevout) == Some(txid) {
                self.spends.remove(&input.prevout);
            }
        }
        Some(entry)
    }

    /// Removes the transactions a block confirms, those that conflict with
    /// it, and the descendants of conflicting ones. Returns what was removed.
    pub fn remove_for_block(&mut self, txs: &[Transaction]) -> Vec<Arc<MempoolTx>> {
        let mut removed = Vec::new();
        let mut doomed: Vec<Txid> = Vec::new();
        for tx in txs {
            if let Some(entry) = self.remove(&tx.txid()) {
                removed.push(entry);
            }
            for input in &tx.inputs {
                if let Some(conflict) = self.spends.get(&input.prevout).copied() {
                    doomed.push(conflict);
                }
            }
        }
        // Descendants of a conflicting transaction spend outputs that no longer exist.
        let mut seen: HashSet<Txid> = HashSet::new();
        while let Some(txid) = doomed.pop() {
            if !seen.insert(txid) {
                continue;
            }
            let Some(entry) = self.remove(&txid) else {
                continue;
            };
            for vout in 0..entry.tx.outputs.len() {
                if let Some(child) = self.spends.get(&OutPoint::new(txid, vout as u32)) {
                    doomed.push(*child);
                }
            }
            removed.push(entry);
        }
        if !removed.is_empty() {
            self.order.retain(|t| self.txs.contains_key(t));
        }
        removed
    }

    /// Whether a mempool transaction spends an output of another mempool transaction.
    pub fn has_unconfirmed_parent(&self, tx: &Transaction) -> bool {
        tx.inputs
            .iter()
            .any(|i| self.txs.contains_key(&i.prevout.txid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::WriteExt;

    fn tx(inputs: &[OutPoint], values: &[u64]) -> Transaction {
        let mut b = Vec::new();
        b.put_i32(2);
        b.put_compact_size(inputs.len() as u64);
        for i in inputs {
            b.put_bytes(&i.txid.0);
            b.put_u32(i.vout);
            b.put_var_bytes(&[0x51]);
            b.put_u32(0);
        }
        b.put_compact_size(values.len() as u64);
        for v in values {
            b.put_u64(*v);
            b.put_var_bytes(&[0x51]);
        }
        b.put_u32(0);
        Transaction::from_bytes(&b).unwrap()
    }

    #[test]
    fn fees_chains_and_block_removal() {
        let mut pool = Mempool::new(1 << 20);
        let funding = OutPoint::new(Txid([1; 32]), 0);
        let parent = tx(&[funding], &[1000]);
        let child = tx(&[OutPoint::new(parent.txid(), 0)], &[800]);
        assert!(pool.insert(parent.clone(), |o| (o == &funding).then_some(1500)));
        assert!(pool.insert(child.clone(), |_| None));
        assert_eq!(pool.get(&parent.txid()).unwrap().fee, Some(500));
        assert_eq!(pool.get(&child.txid()).unwrap().fee, Some(200));
        assert!(pool.has_unconfirmed_parent(&child));
        // A block with a conflicting spend of the funding output removes both.
        let conflict = tx(&[funding], &[1400]);
        let removed = pool.remove_for_block(&[conflict]);
        assert_eq!(removed.len(), 2);
        assert!(pool.is_empty());
        assert_eq!(pool.bytes(), 0);
    }
}
