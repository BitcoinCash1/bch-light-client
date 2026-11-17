//! Settling a disagreement over a block's script filter (filter type 1)
//! between peers, the way neutrino settles it: by leaf indexes and whole-key
//! ranges, never by a key the wallet watches.
//!
//! A served script filter starts with the root of a sorted tree of leaves
//! (key, transaction index, input or output index, kind). Two peers with
//! different roots are asked for the leaves at the same indexes
//! (`getcfproof`), each leaf proved against its own root, in a binary search
//! for the first index where their trees differ. There one peer holds a
//! leaf the other lacks; the proof carries the transaction (and, for a spent
//! output, the transaction that created it) with Merkle branches to the
//! block headers, so the client tells whether that leaf is true. When the
//! roots agree but the filters do not, all leaves are fetched by whole key
//! ranges (`getcfrange`) and the filter is rebuilt from them.

use crate::block::{merkle_fold, BlockHeader};
use crate::encode::{DecodeError, Reader, WriteExt};
use crate::filter::{script_is_filtered, FilterKey, SCRIPT_FILTER_TYPE};
use crate::gcs::filter_key;
use crate::hash::{sha256, BlockHash};
use crate::tx::{Transaction, TxOut};

pub const LEAF_SIZE: usize = 41;
/// A Merkle branch never has more than 32 levels.
const MAX_BRANCH: usize = 32;

/// What a leaf's key comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeafKind {
    Output = 0,
    Spent = 1,
    OutputCategory = 2,
    SpentCategory = 3,
    Transaction = 4,
}

/// One entry of a block's script filter tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Leaf {
    pub key: [u8; 32],
    pub tx_index: u32,
    pub index: u32,
    pub kind: LeafKind,
}

impl Leaf {
    pub fn parse(b: &[u8]) -> Result<Self, DecodeError> {
        if b.len() != LEAF_SIZE {
            return Err(DecodeError::Invalid("a script filter leaf is 41 bytes"));
        }
        let kind = match b[40] {
            0 => LeafKind::Output,
            1 => LeafKind::Spent,
            2 => LeafKind::OutputCategory,
            3 => LeafKind::SpentCategory,
            4 => LeafKind::Transaction,
            _ => {
                return Err(DecodeError::Invalid(
                    "a script filter leaf is of kind 0 to 4",
                ))
            }
        };
        Ok(Self {
            key: b[..32].try_into().expect("32 bytes"),
            tx_index: u32::from_le_bytes(b[32..36].try_into().expect("4 bytes")),
            index: u32::from_le_bytes(b[36..40].try_into().expect("4 bytes")),
            kind,
        })
    }

    pub fn bytes(&self) -> [u8; LEAF_SIZE] {
        let mut b = [0u8; LEAF_SIZE];
        b[..32].copy_from_slice(&self.key);
        b[32..36].copy_from_slice(&self.tx_index.to_le_bytes());
        b[36..40].copy_from_slice(&self.index.to_le_bytes());
        b[40] = self.kind as u8;
        b
    }

    fn spent(&self) -> bool {
        matches!(self.kind, LeafKind::Spent | LeafKind::SpentCategory)
    }

    fn category(&self) -> bool {
        matches!(
            self.kind,
            LeafKind::OutputCategory | LeafKind::SpentCategory
        )
    }
}

pub fn leaf_hash(leaf: &Leaf) -> [u8; 32] {
    let mut b = vec![0u8];
    b.extend_from_slice(&leaf.bytes());
    sha256(&b)
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut b = Vec::with_capacity(65);
    b.push(1u8);
    b.extend_from_slice(left);
    b.extend_from_slice(right);
    sha256(&b)
}

/// Pairs a level into the one above; a last node without a partner moves up unchanged.
fn next_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    level
        .chunks(2)
        .map(|p| {
            if p.len() == 2 {
                node_hash(&p[0], &p[1])
            } else {
                p[0]
            }
        })
        .collect()
}

/// The root over sorted leaves; the root of no leaves is 32 zero bytes.
pub fn leaves_root(leaves: &[Leaf]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// The edge hashes that prove the leaf at `index` (a branch, without the
/// levels where the node moves up alone).
pub fn leaf_branch(leaves: &[Leaf], index: usize) -> Vec<[u8; 32]> {
    let mut level: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    let mut at = index;
    let mut out = Vec::new();
    while level.len() > 1 {
        if at % 2 == 1 {
            out.push(level[at - 1]);
        } else if at + 1 < level.len() {
            out.push(level[at + 1]);
        }
        level = next_level(&level);
        at /= 2;
    }
    out
}

/// The root a run of consecutive leaves starting at `lo` rebuilds, in a
/// tree of `count` leaves, with the edge hashes listed level by level: the
/// node just left of the run, then the node just right of it, where the run
/// does not already reach them.
pub fn range_root(count: u32, lo: u32, run: &[Leaf], hashes: &[[u8; 32]]) -> Option<[u8; 32]> {
    if run.is_empty() || u64::from(lo) + run.len() as u64 > u64::from(count) {
        return None;
    }
    let mut nodes: Vec<[u8; 32]> = run.iter().map(leaf_hash).collect();
    let mut next = 0usize;
    let (mut a, mut b, mut width) = (
        u64::from(lo),
        u64::from(lo) + run.len() as u64 - 1,
        u64::from(count),
    );
    while width > 1 {
        if a % 2 == 1 {
            nodes.insert(0, *hashes.get(next)?);
            next += 1;
            a -= 1;
        }
        if b % 2 == 0 && b + 1 < width {
            nodes.push(*hashes.get(next)?);
            next += 1;
            b += 1;
        }
        nodes = next_level(&nodes);
        a /= 2;
        b /= 2;
        width = width.div_ceil(2);
    }
    (next == hashes.len()).then(|| nodes[0])
}

fn read_hashes(r: &mut Reader<'_>) -> Result<Vec<[u8; 32]>, DecodeError> {
    let n = r.count(32)?;
    if n > 2 * MAX_BRANCH {
        return Err(DecodeError::Invalid("branch too long"));
    }
    (0..n).map(|_| r.array()).collect()
}

/// A cfproof reply: a leaf with its branch, the transaction it names with its
/// Merkle branch, and for a spent output the transaction that created it.
#[derive(Debug, Clone)]
pub struct CfProof {
    pub block: BlockHash,
    pub leaf_count: u32,
    pub leaf_index: u32,
    pub leaf: Leaf,
    pub leaf_branch: Vec<[u8; 32]>,
    pub tx: Transaction,
    pub tx_branch: Vec<[u8; 32]>,
    pub origin: Option<Origin>,
}

/// The transaction that created a spent output, with where it is confirmed.
#[derive(Debug, Clone)]
pub struct Origin {
    pub block: BlockHash,
    pub tx_index: u32,
    pub tx: Transaction,
    pub branch: Vec<[u8; 32]>,
}

pub fn encode_getcfproof(block: BlockHash, leaf_index: u32) -> Vec<u8> {
    let mut out = vec![SCRIPT_FILTER_TYPE];
    out.put_bytes(&block.0);
    out.put_u32(leaf_index);
    out
}

pub fn decode_cfproof(payload: &[u8]) -> Result<CfProof, DecodeError> {
    let mut r = Reader::new(payload);
    if r.u8()? != SCRIPT_FILTER_TYPE {
        return Err(DecodeError::Invalid("cfproof of another filter type"));
    }
    let block = BlockHash(r.array()?);
    let leaf_count = r.u32()?;
    let leaf_index = r.u32()?;
    let leaf = Leaf::parse(r.bytes(LEAF_SIZE)?)?;
    let leaf_branch = read_hashes(&mut r)?;
    let tx = Transaction::read(&mut r)?;
    let tx_branch = read_hashes(&mut r)?;
    let origin = if leaf.spent() {
        let block = BlockHash(r.array()?);
        let tx_index = r.u32()?;
        let tx = Transaction::read(&mut r)?;
        let branch = read_hashes(&mut r)?;
        Some(Origin {
            block,
            tx_index,
            tx,
            branch,
        })
    } else {
        None
    };
    r.finish()?;
    Ok(CfProof {
        block,
        leaf_count,
        leaf_index,
        leaf,
        leaf_branch,
        tx,
        tx_branch,
        origin,
    })
}

/// A cfrange reply: the leaves whose keys have a prefix, their neighbours
/// and the edge hashes that tie them to the root.
#[derive(Debug, Clone)]
pub struct CfRange {
    pub block: BlockHash,
    pub leaf_count: u32,
    pub first_index: u32,
    pub run: Vec<Leaf>,
    pub before: Option<Leaf>,
    pub after: Option<Leaf>,
    pub hashes: Vec<[u8; 32]>,
}

pub fn encode_getcfrange(block: BlockHash, bits: u16, prefix: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![SCRIPT_FILTER_TYPE];
    out.put_bytes(&block.0);
    out.put_u16(bits);
    out.put_bytes(prefix);
    out
}

pub fn decode_cfrange(payload: &[u8]) -> Result<CfRange, DecodeError> {
    let mut r = Reader::new(payload);
    if r.u8()? != SCRIPT_FILTER_TYPE {
        return Err(DecodeError::Invalid("cfrange of another filter type"));
    }
    let block = BlockHash(r.array()?);
    let leaf_count = r.u32()?;
    let first_index = r.u32()?;
    let n = r.count(LEAF_SIZE)?;
    let run = (0..n)
        .map(|_| Leaf::parse(r.bytes(LEAF_SIZE)?))
        .collect::<Result<Vec<_>, _>>()?;
    let before = if first_index > 0 {
        Some(Leaf::parse(r.bytes(LEAF_SIZE)?)?)
    } else {
        None
    };
    let after = if u64::from(first_index) + (n as u64) < u64::from(leaf_count) {
        Some(Leaf::parse(r.bytes(LEAF_SIZE)?)?)
    } else {
        None
    };
    let hashes = read_hashes(&mut r)?;
    r.finish()?;
    Ok(CfRange {
        block,
        leaf_count,
        first_index,
        run,
        before,
        after,
        hashes,
    })
}

fn compare_prefix(key: &[u8; 32], prefix: &[u8; 32], bits: u16) -> std::cmp::Ordering {
    let full = usize::from(bits / 8);
    let c = key[..full].cmp(&prefix[..full]);
    if c.is_ne() || bits % 8 == 0 {
        return c;
    }
    let mask = 0xffu8 << (8 - bits % 8);
    (key[full] & mask).cmp(&(prefix[full] & mask))
}

/// Checks a cfrange reply against a root: every leaf with the prefix, in
/// order, bounded by neighbours without it, rebuilding the root.
pub fn check_range(root: &[u8; 32], reply: &CfRange, prefix: &[u8; 32], bits: u16) -> bool {
    let end = u64::from(reply.first_index) + reply.run.len() as u64;
    if end > u64::from(reply.leaf_count) {
        return false;
    }
    if reply.leaf_count == 0 {
        return reply.hashes.is_empty() && *root == [0u8; 32];
    }
    let mut span: Vec<Leaf> = Vec::new();
    span.extend(reply.before);
    span.extend(&reply.run);
    span.extend(reply.after);
    let lo = if reply.before.is_some() {
        reply.first_index - 1
    } else {
        reply.first_index
    };
    if range_root(reply.leaf_count, lo, &span, &reply.hashes) != Some(*root) {
        return false;
    }
    span.windows(2).all(|w| w[0] < w[1])
        && reply
            .run
            .iter()
            .all(|l| compare_prefix(&l.key, prefix, bits).is_eq())
        && reply
            .before
            .map_or(true, |l| compare_prefix(&l.key, prefix, bits).is_lt())
        && reply
            .after
            .map_or(true, |l| compare_prefix(&l.key, prefix, bits).is_gt())
}

/// A leaf proved against one peer's root, with the left siblings on its path.
#[derive(Debug, Clone)]
pub struct ProvedLeaf {
    pub proof: CfProof,
    pub lefts: Vec<[u8; 32]>,
}

/// Checks a cfproof against a peer's root and returns the leaf with its path.
pub fn prove_leaf(
    root: &[u8; 32],
    block: BlockHash,
    index: u32,
    proof: CfProof,
) -> Option<ProvedLeaf> {
    if proof.block != block || proof.leaf_index != index || index >= proof.leaf_count {
        return None;
    }
    if range_root(proof.leaf_count, index, &[proof.leaf], &proof.leaf_branch) != Some(*root) {
        return None;
    }
    let mut lefts = Vec::new();
    let mut branch = proof.leaf_branch.iter();
    let (mut at, mut width) = (u64::from(index), u64::from(proof.leaf_count));
    while width > 1 {
        if at % 2 == 1 {
            lefts.push(*branch.next()?);
        } else if at + 1 < width {
            branch.next()?;
        }
        at /= 2;
        width = width.div_ceil(2);
    }
    Some(ProvedLeaf { proof, lefts })
}

fn key_of(output: &TxOut, key: &[u8; 32], category: bool) -> bool {
    if category {
        output
            .token
            .as_ref()
            .is_some_and(|t| FilterKey::category(&t.category).0 == *key)
    } else {
        script_is_filtered(&output.script) && FilterKey::script(&output.script).0 == *key
    }
}

/// Whether a proved leaf is true of the block: its transaction under the
/// block's Merkle root, and the output (or spent output, or transaction ID)
/// it names giving its key. 64-byte transactions are refused above
/// `small_tx_until`, where they cannot be valid, so that a Merkle node cannot
/// pass for one.
pub fn is_true_leaf(
    leaf: &ProvedLeaf,
    header: &BlockHeader,
    height: u32,
    origin_header: impl Fn(&BlockHash) -> Option<(u32, BlockHeader)>,
    small_tx_until: u32,
) -> bool {
    let (l, p) = (&leaf.proof.leaf, &leaf.proof);
    let tx = &p.tx;
    if (height > small_tx_until && tx.size() == 64)
        || merkle_fold(tx.txid().0, l.tx_index as usize, &p.tx_branch) != Some(header.merkle_root)
        || p.tx_branch.len() > MAX_BRANCH
        || u64::from(l.tx_index) >> p.tx_branch.len() != 0
    {
        return false;
    }
    match l.kind {
        LeafKind::Transaction => l.index == 0 && FilterKey::txid(&tx.txid()).0 == l.key,
        LeafKind::Output | LeafKind::OutputCategory => tx
            .outputs
            .get(l.index as usize)
            .is_some_and(|o| key_of(o, &l.key, l.category())),
        LeafKind::Spent | LeafKind::SpentCategory => {
            let (Some(origin), Some(input)) = (&p.origin, tx.inputs.get(l.index as usize)) else {
                return false;
            };
            if l.tx_index == 0 || origin.tx.txid() != input.prevout.txid {
                return false;
            }
            let Some((origin_height, origin_header)) = origin_header(&origin.block) else {
                return false;
            };
            if origin_height > height
                || (origin_height > small_tx_until && origin.tx.size() == 64)
                || merkle_fold(origin.tx.txid().0, origin.tx_index as usize, &origin.branch)
                    != Some(origin_header.merkle_root)
            {
                return false;
            }
            origin
                .tx
                .outputs
                .get(input.prevout.vout as usize)
                .is_some_and(|o| key_of(o, &l.key, l.category()))
        }
    }
}

/// The verdict of comparing two peers' trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The trees do not differ in a way the proofs show.
    Same,
    /// The first peer serves a wrong tree.
    First,
    /// The second peer serves a wrong tree.
    Second,
}

/// The binary search over two trees, given each peer's leaf source (a
/// verified leaf at an index, or None when the peer gives no valid proof)
/// and leaf counts.
pub async fn settle_trees<A, B, FA, FB>(
    count_a: u32,
    count_b: u32,
    mut leaf_a: A,
    mut leaf_b: B,
    is_true: impl Fn(&ProvedLeaf) -> bool,
) -> Verdict
where
    A: FnMut(u32) -> FA,
    B: FnMut(u32) -> FB,
    FA: std::future::Future<Output = Option<ProvedLeaf>>,
    FB: std::future::Future<Output = Option<ProvedLeaf>>,
{
    let (mut lo, mut hi) = (0u32, count_a.min(count_b));
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let Some(a) = leaf_a(mid).await else {
            return Verdict::First;
        };
        let Some(b) = leaf_b(mid).await else {
            return Verdict::Second;
        };
        if a.proof.leaf == b.proof.leaf && a.lefts == b.lefts {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let first = lo;
    // The holder has, at `first`, a leaf the other lacks.
    let holder_is_a = if first == count_a && first == count_b {
        return Verdict::Same;
    } else if first == count_a {
        false
    } else if first < count_b {
        let Some(a) = leaf_a(first).await else {
            return Verdict::First;
        };
        let Some(b) = leaf_b(first).await else {
            return Verdict::Second;
        };
        match a.proof.leaf.cmp(&b.proof.leaf) {
            std::cmp::Ordering::Equal => return Verdict::Same,
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
        }
    } else {
        true
    };
    let (holder_bad, other_bad) = if holder_is_a {
        (Verdict::First, Verdict::Second)
    } else {
        (Verdict::Second, Verdict::First)
    };
    let held = if holder_is_a {
        leaf_a(first).await
    } else {
        leaf_b(first).await
    };
    let Some(held) = held else { return holder_bad };
    if first > 0 {
        let before = if holder_is_a {
            leaf_a(first - 1).await
        } else {
            leaf_b(first - 1).await
        };
        match before {
            Some(b) if b.proof.leaf < held.proof.leaf => {}
            _ => return holder_bad,
        }
    }
    if is_true(&held) {
        other_bad
    } else {
        holder_bad
    }
}

/// The GCS of a block's filter rebuilt from all its leaves, N-prefixed.
pub fn gcs_of_leaves(block: &BlockHash, leaves: &[Leaf]) -> Vec<u8> {
    let keys: Vec<&[u8]> = leaves.iter().map(|l| &l.key[..]).collect();
    crate::gcs::build(filter_key(&block.0), &keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/script-filter-vectors.json"
        ))
        .expect("vectors");
        serde_json::from_str(&text).expect("json")
    }

    #[test]
    fn tree_roots_follow_the_vectors() {
        let v = vectors();
        let leaves: Vec<Leaf> = v["tree"]["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| Leaf::parse(&hex::decode(l.as_str().unwrap()).unwrap()).unwrap())
            .collect();
        for n in 0..=leaves.len() {
            let want = v["tree"]["roots"][n.to_string()].as_str().unwrap();
            assert_eq!(hex::encode(leaves_root(&leaves[..n])), want, "{n} leaves");
            for i in 0..n {
                let branch = leaf_branch(&leaves[..n], i);
                assert_eq!(
                    hex::encode(range_root(n as u32, i as u32, &[leaves[i]], &branch).unwrap()),
                    want
                );
            }
        }
    }

    #[test]
    fn bchd_wire_cfproof_and_cfrange_decode() {
        let v = vectors();
        let w = &v["bchdWire"];
        for name in ["cfproof_output", "cfproof_spent", "cfproof_spent_category"] {
            let p = decode_cfproof(&hex::decode(w[name]["payload"].as_str().unwrap()).unwrap())
                .unwrap();
            assert_eq!(p.origin.is_some(), name != "cfproof_output", "{name}");
        }
        for name in [
            "cfrange_inner",
            "cfrange_none_at_start",
            "cfrange_all",
            "cfrange_empty_tree",
        ] {
            decode_cfrange(&hex::decode(w[name]["payload"].as_str().unwrap()).unwrap()).unwrap();
        }
        assert_eq!(
            hex::encode(encode_getcfproof(
                BlockHash::from(
                    <[u8; 32]>::try_from(
                        hex::decode(
                            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                        )
                        .unwrap()
                    )
                    .unwrap()
                ),
                3
            )),
            w["getcfproof"]["payload"].as_str().unwrap()
        );
    }

    /// One input, one output, both scripts OP_TRUE.
    const TINY_TX: &str = concat!(
        "01000000",
        "01",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff",
        "0151",
        "ffffffff",
        "01",
        "0000000000000000",
        "0151",
        "00000000"
    );

    /// TINY_TX with its lock time set to `n`, spending `prevout` when given.
    fn tiny_tx(n: u8, prevout: Option<[u8; 32]>) -> Transaction {
        let mut raw = hex::decode(TINY_TX).unwrap();
        if let Some(txid) = prevout {
            raw[5..37].copy_from_slice(&txid);
            raw[37..41].copy_from_slice(&0u32.to_le_bytes());
        }
        let len = raw.len();
        raw[len - 4] = n;
        Transaction::from_bytes(&raw).unwrap()
    }

    fn header_over(txs: &[&Transaction]) -> BlockHeader {
        let txids: Vec<crate::hash::Txid> = txs.iter().map(|t| t.txid()).collect();
        BlockHeader {
            version: 1,
            prev_hash: BlockHash::ZERO,
            merkle_root: crate::block::merkle_root(&txids).0,
            time: 0,
            bits: 0,
            nonce: 0,
        }
    }

    /// A block of three transactions: the last pairs with itself, so the
    /// branch of position 2 also folds to the root from position 3 (the
    /// duplicate pairing of CVE-2012-2459). A peer that claims a leaf there,
    /// or a spent output created there, lies and must lose the dispute.
    #[test]
    fn a_leaf_at_a_phantom_position_is_not_true() {
        let txs: Vec<Transaction> = (0u8..3).map(|i| tiny_tx(i, None)).collect();
        let header = header_over(&txs.iter().collect::<Vec<_>>());
        let ids: Vec<[u8; 32]> = txs.iter().map(|t| t.txid().0).collect();
        let branch = crate::block::merkle_branch(&ids, 2);
        let key = FilterKey::script(&[0x51]).0;
        let proved =
            |kind, tx_index, tx: &Transaction, tx_branch: Vec<[u8; 32]>, origin| ProvedLeaf {
                proof: CfProof {
                    block: BlockHash::ZERO,
                    leaf_count: 1,
                    leaf_index: 0,
                    leaf: Leaf {
                        key,
                        tx_index,
                        index: 0,
                        kind,
                    },
                    leaf_branch: vec![],
                    tx: tx.clone(),
                    tx_branch,
                    origin,
                },
                lefts: vec![],
            };
        let none = |_: &BlockHash| None;
        let output = |tx_index| proved(LeafKind::Output, tx_index, &txs[2], branch.clone(), None);
        assert!(is_true_leaf(&output(2), &header, 10, none, 0));
        assert!(!is_true_leaf(&output(3), &header, 10, none, 0));

        // A spend of the last transaction's output, in another block: its
        // origin at the true position, then at the phantom one.
        let spender = tiny_tx(9, Some(ids[2]));
        let spending = header_over(&[&txs[0], &spender]);
        let spender_branch = crate::block::merkle_branch(&[txs[0].txid().0, spender.txid().0], 1);
        let origin_block = header.hash();
        let origin_header = |b: &BlockHash| (*b == origin_block).then_some((5, header));
        let spent = |origin_index| {
            let origin = Origin {
                block: origin_block,
                tx_index: origin_index,
                tx: txs[2].clone(),
                branch: branch.clone(),
            };
            proved(
                LeafKind::Spent,
                1,
                &spender,
                spender_branch.clone(),
                Some(origin),
            )
        };
        assert!(is_true_leaf(&spent(2), &spending, 10, origin_header, 0));
        assert!(!is_true_leaf(&spent(3), &spending, 10, origin_header, 0));
    }

    fn leaf(key: u8, tx: u32, kind: LeafKind) -> Leaf {
        Leaf {
            key: [key; 32],
            tx_index: tx,
            index: 0,
            kind,
        }
    }

    /// Two trees that differ by one leaf: the search finds it and the truth
    /// of the held leaf decides.
    #[tokio::test]
    async fn the_binary_search_finds_the_extra_leaf() {
        let honest: Vec<Leaf> = (1u8..=9)
            .map(|k| leaf(k * 10, u32::from(k), LeafKind::Output))
            .collect();
        let mut lying = honest.clone();
        lying.remove(4);
        let block = BlockHash([1; 32]);
        let source = |leaves: Vec<Leaf>| {
            let root = leaves_root(&leaves);
            move |i: u32| {
                let leaves = leaves.clone();
                async move {
                    let l = *leaves.get(i as usize)?;
                    let proof = CfProof {
                        block,
                        leaf_count: leaves.len() as u32,
                        leaf_index: i,
                        leaf: l,
                        leaf_branch: leaf_branch(&leaves, i as usize),
                        tx: Transaction::from_bytes(&hex::decode(TINY_TX).unwrap()).ok()?,
                        tx_branch: vec![],
                        origin: None,
                    };
                    prove_leaf(&root, block, i, proof)
                }
            }
        };
        let missing = honest[4];
        let verdict = settle_trees(9, 8, source(honest.clone()), source(lying.clone()), |p| {
            p.proof.leaf == missing
        })
        .await;
        assert_eq!(verdict, Verdict::Second);
        // A peer that adds a false leaf loses.
        let mut padded = honest.clone();
        padded.insert(3, leaf(35, 99, LeafKind::Output));
        let verdict = settle_trees(10, 9, source(padded), source(honest.clone()), |p| {
            p.proof.leaf.key != [35; 32]
        })
        .await;
        assert_eq!(verdict, Verdict::First);
        let same = settle_trees(9, 9, source(honest.clone()), source(honest), |_| true).await;
        assert_eq!(same, Verdict::Same);
    }
}
