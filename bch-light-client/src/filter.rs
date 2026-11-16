//! Script filters (filter type 1).
//!
//! A block's script filter holds keys for the locking script of every output
//! it creates and of every output it spends (empty and OP_RETURN scripts
//! excepted), for the token category of each of those outputs, and, from
//! the transaction-leaf extension on, for the ID of every transaction. The
//! served bytes are the 32-byte root of the block's entry tree, then the
//! N-prefixed GCS of the distinct keys (P = 19, M = 784931, SipHash key =
//! first 16 bytes of the block hash). The filter header is
//! sha256d(sha256d(filter bytes) || previous filter header).

use crate::block::Block;
use crate::encode::DecodeError;
use crate::gcs::{filter_key, hash_to_range, Gcs};
use crate::hash::{sha256, sha256d, BlockHash, Txid};
use crate::tx::Category;

/// The filter type of script filters in BIP157 messages.
pub const SCRIPT_FILTER_TYPE: u8 = 1;

/// A 32-byte filter key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct FilterKey(pub [u8; 32]);

impl FilterKey {
    /// The key of a locking script (without token prefix): its SHA-256,
    /// which is the Electrum scripthash with its bytes in internal order.
    pub fn script(script: &[u8]) -> Self {
        Self(sha256(script))
    }

    /// The key of a token category: SHA-256 of 0x01 then the category.
    pub fn category(category: &Category) -> Self {
        let mut b = [0u8; 33];
        b[0] = 0x01;
        b[1..].copy_from_slice(&category.0);
        Self(sha256(&b))
    }

    /// The key of a transaction: SHA-256 of 0x02 then its ID in internal order.
    pub fn txid(txid: &Txid) -> Self {
        let mut b = [0u8; 33];
        b[0] = 0x02;
        b[1..].copy_from_slice(&txid.0);
        Self(sha256(&b))
    }
}

/// Whether a locking script gets a key: empty scripts and OP_RETURN outputs do not.
pub fn script_is_filtered(script: &[u8]) -> bool {
    script.first().is_some_and(|&op| op != 0x6a)
}

/// The GCS part of a served script filter, after the 32-byte root.
pub fn gcs_part(filter: &[u8]) -> Result<Gcs<'_>, DecodeError> {
    if filter.len() < 33 {
        return Err(DecodeError::Invalid("script filter shorter than its root and item count"));
    }
    Gcs::parse(&filter[32..])
}

/// The next filter header.
pub fn next_filter_header(filter: &[u8], prev: &[u8; 32]) -> [u8; 32] {
    filter_header_from_hash(&sha256d(filter), prev)
}

/// The next filter header from the filter's hash, as cfheaders lists it.
pub fn filter_header_from_hash(filter_hash: &[u8; 32], prev: &[u8; 32]) -> [u8; 32] {
    crate::hash::sha256d_pair(filter_hash, prev)
}

/// What checking a block against its filter found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockFilterCheck {
    /// Whether the filter has a key for every transaction ID of the block.
    pub has_txid_keys: bool,
}

/// A block's filter that leaves out a key the block must put in it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the filter of block {block} leaves out a key of an output the block creates")]
pub struct FilterMismatch {
    pub block: BlockHash,
}

/// Checks a block against its served filter: every key of an output the
/// block creates must be in it. Spent outputs' scripts sit in older blocks
/// and cannot be checked from the block alone. Also reports whether the
/// filter holds the block's transaction keys.
pub fn check_block(block: &Block, filter: &[u8]) -> Result<BlockFilterCheck, CheckBlockError> {
    let gcs = gcs_part(filter)?;
    let hash = block.hash();
    let key = filter_key(&hash.0);
    let mut created: Vec<FilterKey> = Vec::new();
    for tx in &block.txs {
        for output in &tx.outputs {
            if script_is_filtered(&output.script) {
                created.push(FilterKey::script(&output.script));
            }
            if let Some(token) = &output.token {
                created.push(FilterKey::category(&token.category));
            }
        }
    }
    created.sort_unstable();
    created.dedup();
    if created.len() as u64 > gcs.n {
        return Err(FilterMismatch { block: hash }.into());
    }
    let mut targets: Vec<(u64, usize)> =
        created.iter().enumerate().map(|(i, k)| (hash_to_range(key, gcs.n, &k.0), i)).collect();
    targets.sort_unstable();
    let mut found = 0usize;
    gcs.match_sorted(&targets, |_| found += 1)?;
    if found != created.len() {
        return Err(FilterMismatch { block: hash }.into());
    }
    let txid_keys: Vec<FilterKey> = block.txs.iter().map(|tx| FilterKey::txid(&tx.txid())).collect();
    let mut targets: Vec<(u64, usize)> =
        txid_keys.iter().enumerate().map(|(i, k)| (hash_to_range(key, gcs.n, &k.0), i)).collect();
    targets.sort_unstable();
    let mut found_txids = 0usize;
    gcs.match_sorted(&targets, |_| found_txids += 1)?;
    Ok(BlockFilterCheck { has_txid_keys: found_txids == txid_keys.len() })
}

/// Why a block does not fit its filter.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckBlockError {
    #[error(transparent)]
    Mismatch(#[from] FilterMismatch),
    #[error("malformed filter: {0}")]
    Decode(#[from] DecodeError),
}
