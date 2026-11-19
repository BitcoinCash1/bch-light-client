//! Block headers, blocks and Merkle trees of transaction IDs.

use crate::encode::{DecodeError, Reader, WriteExt};
use crate::hash::{sha256d, sha256d_pair, BlockHash, Txid};
use crate::tx::Transaction;

/// An 80-byte block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_hash: BlockHash,
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    pub const SIZE: usize = 80;

    pub fn from_bytes(raw: &[u8; 80]) -> Self {
        let word = |at: usize| [raw[at], raw[at + 1], raw[at + 2], raw[at + 3]];
        let mut prev = [0u8; 32];
        let mut merkle = [0u8; 32];
        prev.copy_from_slice(&raw[4..36]);
        merkle.copy_from_slice(&raw[36..68]);
        Self {
            version: i32::from_le_bytes(word(0)),
            prev_hash: BlockHash(prev),
            merkle_root: merkle,
            time: u32::from_le_bytes(word(68)),
            bits: u32::from_le_bytes(word(72)),
            nonce: u32::from_le_bytes(word(76)),
        }
    }

    pub fn to_bytes(&self) -> [u8; 80] {
        let mut out = Vec::with_capacity(80);
        out.put_i32(self.version);
        out.put_bytes(&self.prev_hash.0);
        out.put_bytes(&self.merkle_root);
        out.put_u32(self.time);
        out.put_u32(self.bits);
        out.put_u32(self.nonce);
        out.try_into().expect("80 bytes")
    }

    pub fn hash(&self) -> BlockHash {
        BlockHash(sha256d(&self.to_bytes()))
    }
}

/// A whole block.
#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
    /// Serialized size in bytes.
    pub size: usize,
}

impl Block {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let header = BlockHeader::from_bytes(&r.array::<80>()?);
        // A transaction takes at least 60 bytes.
        let n = r.count(60)?;
        let mut txs = Vec::with_capacity(n);
        for _ in 0..n {
            txs.push(Transaction::read(&mut r)?);
        }
        r.finish()?;
        Ok(Self {
            header,
            txs,
            size: bytes.len(),
        })
    }

    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    pub fn txids(&self) -> Vec<Txid> {
        self.txs.iter().map(Transaction::txid).collect()
    }
}

/// The Merkle root of transaction IDs, the last node of an odd level paired
/// with itself, and whether the tree is mutated: two equal siblings at any
/// level, which lets a block with repeated transactions share a valid block's
/// root (CVE-2012-2459).
pub fn merkle_root(txids: &[Txid]) -> ([u8; 32], bool) {
    if txids.is_empty() {
        return ([0u8; 32], false);
    }
    let mut level: Vec<[u8; 32]> = txids.iter().map(|t| t.0).collect();
    let mut mutated = false;
    while level.len() > 1 {
        mutated |= level.chunks_exact(2).any(|pair| pair[0] == pair[1]);
        level = level
            .chunks(2)
            .map(|pair| sha256d_pair(&pair[0], pair.get(1).unwrap_or(&pair[0])))
            .collect();
    }
    (level[0], mutated)
}

/// The Merkle branch of the item at `pos`: the sibling at each level from the
/// bottom, the last node of an odd level paired with itself.
pub fn merkle_branch(leaves: &[[u8; 32]], pos: usize) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    let mut level = leaves.to_vec();
    let mut index = pos;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty level"));
        }
        branch.push(level[index ^ 1]);
        level = level
            .chunks_exact(2)
            .map(|p| sha256d_pair(&p[0], &p[1]))
            .collect();
        index >>= 1;
    }
    branch
}

/// Folds a leaf with its branch to the root it proves; None for a position
/// that does not exist. The last node of an odd level is paired with itself,
/// so a node at an odd index whose left sibling equals it would be that
/// copy: a phantom position past the end of the level, which folds to the
/// true root (CVE-2012-2459). A true node never equals its left sibling.
pub fn merkle_fold(leaf: [u8; 32], pos: usize, branch: &[[u8; 32]]) -> Option<[u8; 32]> {
    let mut node = leaf;
    let mut index = pos;
    for sibling in branch {
        node = if index & 1 == 1 {
            if *sibling == node {
                return None;
            }
            sha256d_pair(sibling, &node)
        } else {
            sha256d_pair(&node, sibling)
        };
        index >>= 1;
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_genesis_header_hashes_to_its_known_hash() {
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
        )
        .unwrap();
        let header = BlockHeader::from_bytes(&raw.clone().try_into().unwrap());
        assert_eq!(header.to_bytes().to_vec(), raw);
        assert_eq!(
            header.hash().to_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn branches_fold_to_the_root_and_mutation_is_seen() {
        let txids: Vec<Txid> = (0u8..5).map(|i| Txid(sha256d(&[i]))).collect();
        let (root, mutated) = merkle_root(&txids);
        assert!(!mutated);
        let leaves: Vec<[u8; 32]> = txids.iter().map(|t| t.0).collect();
        for pos in 0..leaves.len() {
            let branch = merkle_branch(&leaves, pos);
            assert_eq!(merkle_fold(leaves[pos], pos, &branch), Some(root));
        }
        // Repeating the last two of six transactions keeps the root of the six.
        let six: Vec<Txid> = (0u8..6).map(|i| Txid(sha256d(&[i]))).collect();
        let mut eight = six.clone();
        eight.extend_from_slice(&six[4..6]);
        let (root6, _) = merkle_root(&six);
        let (root8, mutated8) = merkle_root(&eight);
        assert_eq!(root6, root8);
        assert!(mutated8);
    }

    #[test]
    fn a_phantom_position_past_an_odd_level_is_refused() {
        let ids: Vec<[u8; 32]> = (0u8..5).map(|i| sha256d(&[i])).collect();
        let txids: Vec<Txid> = ids.iter().map(|i| Txid(*i)).collect();
        // Three transactions: position 3 is the copy of position 2.
        let (root3, _) = merkle_root(&txids[..3]);
        let branch = merkle_branch(&ids[..3], 2);
        assert_eq!(merkle_fold(ids[2], 2, &branch), Some(root3));
        assert_eq!(merkle_fold(ids[2], 3, &branch), None);
        // Five: position 6 pairs the fifth with itself, as position 4 does,
        // and is caught a level up, where its node copies its left sibling.
        let (root5, _) = merkle_root(&txids);
        let branch = merkle_branch(&ids, 4);
        assert_eq!(merkle_fold(ids[4], 4, &branch), Some(root5));
        assert_eq!(merkle_fold(ids[4], 6, &branch), None);
        assert_eq!(merkle_fold(ids[4], 5, &branch), None);
    }
}
