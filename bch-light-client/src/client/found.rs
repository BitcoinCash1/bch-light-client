//! Transactions found by lookups, kept so that asking again downloads
//! nothing: a wallet that asks for the same transaction every few seconds
//! (a subscription, a Merkle proof, an output check) would otherwise show
//! a peer the same blocks each time. Kept until 10,000 are, then the
//! oldest go; checked against the header chain when read, so a
//! reorganization makes the lookup look again.

use super::*;

const MAX_KEPT: usize = 10_000;

/// A confirmed transaction and its Merkle branch.
pub(crate) struct FoundTx {
    pub tx: Transaction,
    pub confirmation: Confirmation,
    pub branch: Vec<[u8; 32]>,
}

impl FoundTx {
    pub fn proof(&self) -> MerkleProof {
        MerkleProof {
            txid: self.tx.txid(),
            height: self.confirmation.height,
            block_hash: self.confirmation.block_hash,
            position: self.confirmation.position,
            branch: self.branch.clone(),
        }
    }
}

#[derive(Default)]
pub(crate) struct Found {
    txs: HashMap<Txid, Arc<FoundTx>>,
    at: HashMap<(u32, u32), Txid>,
    order: VecDeque<Txid>,
    /// Outputs whose spender was looked for: the block the look went
    /// through (height and hash), and whether the output is spent there.
    spends: HashMap<OutPoint, (u32, BlockHash, bool)>,
    spend_order: VecDeque<OutPoint>,
}

impl Inner {
    /// Keeps the transaction at `position` of `block`, at `height`.
    pub(crate) fn keep_found(&self, block: &Block, height: u32, position: usize) -> Arc<FoundTx> {
        let leaves: Vec<[u8; 32]> = block.txs.iter().map(|t| t.txid().0).collect();
        let found = Arc::new(FoundTx {
            tx: block.txs[position].clone(),
            confirmation: Confirmation {
                height,
                block_hash: block.hash(),
                position: position as u32,
            },
            branch: merkle_branch(&leaves, position),
        });
        let txid = found.tx.txid();
        let mut kept = self.found.lock().expect("found lock");
        if kept.txs.insert(txid, found.clone()).is_none() {
            kept.order.push_back(txid);
        }
        kept.at.insert((height, position as u32), txid);
        while kept.order.len() > MAX_KEPT {
            if let Some(old) = kept.order.pop_front() {
                if let Some(gone) = kept.txs.remove(&old) {
                    let at = (gone.confirmation.height, gone.confirmation.position);
                    if kept.at.get(&at) == Some(&old) {
                        kept.at.remove(&at);
                    }
                }
            }
        }
        found
    }

    /// A kept transaction, while its block is still in the chain.
    pub(crate) fn found(&self, txid: &Txid) -> Option<Arc<FoundTx>> {
        let found = self
            .found
            .lock()
            .expect("found lock")
            .txs
            .get(txid)
            .cloned()?;
        self.in_chain(found.confirmation.height, found.confirmation.block_hash)
            .then_some(found)
    }

    /// The kept transaction at `position` of the block at `height`.
    pub(crate) fn found_at(&self, height: u32, position: u32) -> Option<Arc<FoundTx>> {
        let txid = *self
            .found
            .lock()
            .expect("found lock")
            .at
            .get(&(height, position))?;
        self.found(&txid)
    }

    /// Where the last look for a spender of `outpoint` went through, and
    /// whether it found one, while that block is still in the chain.
    pub(crate) fn spend_checked(&self, outpoint: &OutPoint) -> Option<(u32, bool)> {
        let (height, hash, spent) = *self
            .found
            .lock()
            .expect("found lock")
            .spends
            .get(outpoint)?;
        self.in_chain(height, hash).then_some((height, spent))
    }

    pub(crate) fn keep_spend_check(
        &self,
        outpoint: OutPoint,
        height: u32,
        hash: BlockHash,
        spent: bool,
    ) {
        let mut kept = self.found.lock().expect("found lock");
        if kept
            .spends
            .insert(outpoint, (height, hash, spent))
            .is_none()
        {
            kept.spend_order.push_back(outpoint);
        }
        while kept.spend_order.len() > MAX_KEPT {
            if let Some(old) = kept.spend_order.pop_front() {
                kept.spends.remove(&old);
            }
        }
    }

    fn in_chain(&self, height: u32, hash: BlockHash) -> bool {
        self.chain.read().expect("chain lock").hash_at(height) == Some(hash)
    }
}
