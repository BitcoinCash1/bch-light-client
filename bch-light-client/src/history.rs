//! Histories built from whole blocks.
//!
//! A watched target is a locking script or a token category. Its history is
//! read from block 0 on: every output a block creates for the target, and
//! every input that spends one of the target's earlier outputs, found by
//! outpoint. Spending an output puts the spent script (and category) in the
//! block's filter, so the filters point to every block that matters.

use crate::filter::FilterKey;
use crate::hash::{BlockHash, Txid};
use crate::tx::{Category, OutPoint, TokenData, Transaction, TxOut};
use std::collections::HashMap;

/// What a wallet watches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Target {
    /// A locking script (bare, without token prefix): P2PKH, P2SH20, P2SH32,
    /// a bare pay-to-script output, anything a wallet derives.
    Script(Vec<u8>),
    /// Every output that carries a token category.
    Category(Category),
}

impl Target {
    /// The filter key of the target.
    pub fn key(&self) -> FilterKey {
        match self {
            Target::Script(script) => FilterKey::script(script),
            Target::Category(category) => FilterKey::category(category),
        }
    }

    /// Whether an output belongs to the target.
    pub fn owns(&self, output: &TxOut) -> bool {
        match self {
            Target::Script(script) => output.script == *script,
            Target::Category(category) => output.token.as_ref().is_some_and(|t| t.category == *category),
        }
    }

    /// The Electrum-style script hash of a script target: SHA-256 of the
    /// script, bytes reversed, as hex.
    pub fn script_hash_hex(&self) -> Option<String> {
        match self {
            Target::Script(script) => {
                let mut h = crate::hash::sha256(script);
                h.reverse();
                Some(hex::encode(h))
            }
            Target::Category(_) => None,
        }
    }
}

/// An output a target received.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Received {
    pub vout: u32,
    pub value: u64,
    pub token: Option<TokenData>,
    /// The locking script (for a category target, whose outputs go to many scripts).
    pub script: Vec<u8>,
}

/// An input that spent one of the target's outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Spent {
    pub vin: u32,
    pub prevout: OutPoint,
    pub value: u64,
    pub token: Option<TokenData>,
}

/// A confirmed transaction of a target's history.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConfirmedTx {
    pub txid: Txid,
    pub height: u32,
    pub block_hash: BlockHash,
    /// The transaction's index in its block.
    pub position: u32,
    pub received: Vec<Received>,
    pub spent: Vec<Spent>,
}

/// An output a target owns, with where it was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub value: u64,
    pub token: Option<TokenData>,
    pub script: Vec<u8>,
    pub height: u32,
}

/// The confirmed state of one target.
#[derive(Debug, Clone)]
pub struct TargetState {
    pub target: Target,
    pub key: FilterKey,
    /// Every block up to and including this height has been applied.
    pub synced_to: Option<u32>,
    pub txs: Vec<ConfirmedTx>,
    pub coins: HashMap<OutPoint, Coin>,
    /// The confirmed transaction (and height) that spent each spent coin.
    pub spent_by: HashMap<OutPoint, (Txid, u32)>,
}

impl TargetState {
    pub fn new(target: Target) -> Self {
        let key = target.key();
        Self { target, key, synced_to: None, txs: Vec::new(), coins: HashMap::new(), spent_by: HashMap::new() }
    }

    /// The first height not yet applied.
    pub fn next_height(&self) -> u32 {
        self.synced_to.map_or(0, |h| h + 1)
    }

    /// Applies a block at `height`; outputs first, since under canonical
    /// ordering a transaction may spend an output created later in the block.
    /// Returns whether the target's history changed.
    pub fn apply_block(&mut self, height: u32, block_hash: BlockHash, txs: &[Transaction]) -> bool {
        let mut entries: HashMap<usize, ConfirmedTx> = HashMap::new();
        let entry = |entries: &mut HashMap<usize, ConfirmedTx>, pos: usize, tx: &Transaction| {
            entries.entry(pos).or_insert_with(|| ConfirmedTx {
                txid: tx.txid(),
                height,
                block_hash,
                position: pos as u32,
                received: Vec::new(),
                spent: Vec::new(),
            });
        };
        for (pos, tx) in txs.iter().enumerate() {
            for (vout, output) in tx.outputs.iter().enumerate() {
                if self.target.owns(output) {
                    entry(&mut entries, pos, tx);
                    let outpoint = OutPoint::new(tx.txid(), vout as u32);
                    self.coins.insert(
                        outpoint,
                        Coin {
                            outpoint,
                            value: output.value,
                            token: output.token.clone(),
                            script: output.script.clone(),
                            height,
                        },
                    );
                    entries.get_mut(&pos).expect("just added").received.push(Received {
                        vout: vout as u32,
                        value: output.value,
                        token: output.token.clone(),
                        script: output.script.clone(),
                    });
                }
            }
        }
        for (pos, tx) in txs.iter().enumerate().skip(1) {
            for (vin, input) in tx.inputs.iter().enumerate() {
                if let Some(coin) = self.coins.get(&input.prevout) {
                    let spent =
                        Spent { vin: vin as u32, prevout: input.prevout, value: coin.value, token: coin.token.clone() };
                    self.spent_by.insert(input.prevout, (tx.txid(), height));
                    entry(&mut entries, pos, tx);
                    entries.get_mut(&pos).expect("just added").spent.push(spent);
                }
            }
        }
        let changed = !entries.is_empty();
        let mut new: Vec<ConfirmedTx> = entries.into_values().collect();
        new.sort_by_key(|e| e.position);
        self.txs.extend(new);
        changed
    }

    /// Forgets every block above `fork`. Returns whether the history changed.
    pub fn rollback(&mut self, fork: u32) -> bool {
        if self.synced_to.map_or(true, |h| h <= fork) {
            return false;
        }
        self.synced_to = Some(fork);
        let before = self.txs.len();
        self.txs.retain(|t| t.height <= fork);
        self.coins.retain(|_, c| c.height <= fork);
        self.spent_by.retain(|_, (_, h)| *h <= fork);
        before != self.txs.len()
    }

    /// Confirmed coins no confirmed transaction spent.
    pub fn unspent(&self) -> impl Iterator<Item = &Coin> {
        self.coins.values().filter(|c| !self.spent_by.contains_key(&c.outpoint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{Nft, NftCapability, TxIn};

    fn tx(inputs: &[OutPoint], outputs: &[(u64, &[u8], Option<TokenData>)], salt: u32) -> Transaction {
        let mut b = Vec::new();
        use crate::encode::WriteExt;
        b.put_i32(2);
        b.put_compact_size(inputs.len().max(1) as u64);
        if inputs.is_empty() {
            b.put_bytes(&[0u8; 32]);
            b.put_u32(u32::MAX);
            b.put_var_bytes(&salt.to_le_bytes());
            b.put_u32(0);
        }
        for i in inputs {
            b.put_bytes(&i.txid.0);
            b.put_u32(i.vout);
            b.put_var_bytes(&salt.to_le_bytes());
            b.put_u32(0);
        }
        b.put_compact_size(outputs.len() as u64);
        for (value, script, token) in outputs {
            b.put_u64(*value);
            let out = TxOut { value: *value, token: token.clone(), script: script.to_vec() };
            b.put_var_bytes(&out.script_field());
        }
        b.put_u32(0);
        Transaction::from_bytes(&b).unwrap()
    }

    #[test]
    fn outputs_and_spends_are_found_within_and_across_blocks_and_roll_back() {
        let script: &[u8] = &[0xaa, 0x20, 1, 2, 3, 0x87];
        let other: &[u8] = &[0x51];
        let mut state = TargetState::new(Target::Script(script.to_vec()));
        let coinbase = tx(&[], &[(5000, script, None)], 1);
        let b1 = [coinbase.clone()];
        assert!(state.apply_block(1, BlockHash([1; 32]), &b1));
        // In block 2 a transaction spends the coinbase output and pays the
        // script again, and a later one in the same block spends that.
        let spend = tx(&[OutPoint::new(coinbase.txid(), 0)], &[(4000, script, None), (900, other, None)], 2);
        let respend = tx(&[OutPoint::new(spend.txid(), 0)], &[(3900, other, None)], 3);
        let cb2 = tx(&[], &[(1, other, None)], 4);
        assert!(state.apply_block(2, BlockHash([2; 32]), &[cb2, respend.clone(), spend.clone()]));
        assert_eq!(state.txs.len(), 3);
        assert_eq!(state.unspent().count(), 0);
        let in_block2: Vec<&ConfirmedTx> = state.txs.iter().filter(|t| t.height == 2).collect();
        assert_eq!(in_block2.len(), 2);
        assert_eq!(in_block2[0].txid, respend.txid());
        assert_eq!(in_block2[0].spent[0].value, 4000);
        assert_eq!(in_block2[1].received[0].value, 4000);
        state.synced_to = Some(2);
        assert!(state.rollback(1));
        assert_eq!(state.txs.len(), 1);
        assert_eq!(state.unspent().count(), 1);
        assert!(state.spent_by.is_empty());
    }

    #[test]
    fn a_category_follows_its_tokens_across_scripts() {
        let category = Category([7; 32]);
        let nft = TokenData {
            category,
            amount: 0,
            nft: Some(Nft { capability: NftCapability::Mutable, commitment: vec![1] }),
        };
        let mut state = TargetState::new(Target::Category(category));
        let a: &[u8] = &[0xa9, 0x14, 9, 0x87];
        let b: &[u8] = &[0x76, 0xa9];
        let mint = tx(&[OutPoint::new(Txid([3; 32]), 0)], &[(1000, a, Some(nft.clone())), (500, a, None)], 1);
        let cb = tx(&[], &[(1, b, None)], 9);
        assert!(state.apply_block(5, BlockHash([5; 32]), &[cb, mint.clone()]));
        let moved = tx(&[OutPoint::new(mint.txid(), 0)], &[(900, b, Some(nft.clone()))], 2);
        let cb = tx(&[], &[(1, b, None)], 10);
        assert!(state.apply_block(6, BlockHash([6; 32]), &[cb, moved.clone()]));
        let unspent: Vec<&Coin> = state.unspent().collect();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].outpoint, OutPoint::new(moved.txid(), 0));
        assert_eq!(unspent[0].script, b);
        assert_eq!(unspent[0].token.as_ref(), Some(&nft));
        let _ = TxIn { prevout: OutPoint::new(Txid::ZERO, 0), script_sig: vec![], sequence: 0 };
    }
}
