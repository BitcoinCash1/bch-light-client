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
        return Err(DecodeError::Invalid(
            "script filter shorter than its root and item count",
        ));
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
    let mut targets: Vec<(u64, usize)> = created
        .iter()
        .enumerate()
        .map(|(i, k)| (hash_to_range(key, gcs.n, &k.0), i))
        .collect();
    targets.sort_unstable();
    let mut found = 0usize;
    gcs.match_sorted(&targets, |_| found += 1)?;
    if found != created.len() {
        return Err(FilterMismatch { block: hash }.into());
    }
    let txid_keys: Vec<FilterKey> = block
        .txs
        .iter()
        .map(|tx| FilterKey::txid(&tx.txid()))
        .collect();
    let mut targets: Vec<(u64, usize)> = txid_keys
        .iter()
        .enumerate()
        .map(|(i, k)| (hash_to_range(key, gcs.n, &k.0), i))
        .collect();
    targets.sort_unstable();
    let mut found_txids = 0usize;
    gcs.match_sorted(&targets, |_| found_txids += 1)?;
    Ok(BlockFilterCheck {
        has_txid_keys: found_txids == txid_keys.len(),
    })
}

/// Why a block does not fit its filter.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckBlockError {
    #[error(transparent)]
    Mismatch(#[from] FilterMismatch),
    #[error("malformed filter: {0}")]
    Decode(#[from] DecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_keys_follow_the_spec_vectors() {
        // The genesis coinbase: SHA-256 of 0x02 and its ID in internal order.
        let txid =
            Txid::from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
                .unwrap();
        assert_eq!(
            hex::encode(FilterKey::txid(&txid).0),
            "025ed1aacae75dea93415773bb9a23b3942e03ef36aebc59acb67406902d03ce"
        );
    }

    /// bchd simnet block 127 with its served filter, with and without transaction keys.
    #[test]
    fn a_block_checks_against_its_served_filter() {
        let block = Block::from_bytes(&hex::decode("01000030faec54d16b2a5bdbc3371f5e1593a8166e95a55d0df4f8ee33b6d8281bee6d79816c95ada87beb3bac7be56331697aa815d04915e94c1d6570812f083e9669f791b0f66affff7f20000000000301000000010000000000000000000000000000000000000000000000000000000000000000ffffffff12017f086f88e3cf77f9ac8d062f626368642fffffffff01c621062a010000001976a914b2275cc60091cdde77bddb8c132f60494cb2ea6b88ac00000000010000000178618fd7cc15e6088f2b77cc5ac25dd92ad86619bbe91d693427a9cd965e8708000000006441dfea2c0f1c08e147bdf45182ca31e99745704f5caa7f348d3b9e55ff01a594141bf235e38ad141d4389033312c576917f0652c754bb452127a069a3dfab511d9412102be31cab636041636a1846f4358a241f608ca9d9f29177585280590f9d97e033fffffffff0300a3e1110000000017a91469d7ef8f42a25e8791bb37d5fb48456f102a3cb9870000000000000000176a157363726970742066696c74657220766563746f72734a462418010000001976a91438b726cdbeb1d7f311544519c3412a4ad67c26fb88ac0000000002000000013a90cdbcad008793ceca6cc7d7dd73c22e1d85dd0858760234cae2c1c79fdf2100000000020152ffffffff02f07be111000000001976a914040404040404040404040404040404040404040488ac0000000000000000176a157363726970742066696c74657220766563746f727300000000").unwrap()).unwrap();
        assert_eq!(
            block.hash().to_hex(),
            "0f5f466912edf56885b527866f8a3f12d8d620edef5ff3ebdf43ec00ab556868"
        );
        let served = hex::decode("0203471b91863237e77edce7baf8aece3399215b146501a2d5da70a0cc33819107e621fae1832906b2f0e54a00d93660c5896e").unwrap();
        let parent: [u8; 32] =
            hex::decode("3362679fcffacc8c327f41e9e79b3818bcca4f2359438ca3270350ea39b64ad1")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            hex::encode(next_filter_header(&served, &parent)),
            "e5058dd1d7d008d1391eec4ec1abc95748c837760f02c0157b4b6357d925839b"
        );
        assert_eq!(
            check_block(&block, &served).unwrap(),
            BlockFilterCheck {
                has_txid_keys: true
            }
        );
        let old = hex::decode("96abbd5fe8f576296a2f50b3ebe8f03d61e2dba7968309a18d6ceab2be7861db04bbbb62037514a1956b1740").unwrap();
        assert_eq!(
            check_block(&block, &old).unwrap(),
            BlockFilterCheck {
                has_txid_keys: false
            }
        );
        // A filter of another block leaves out this block's outputs.
        let genesis_filter = hex::decode(
            "c2da4de436a49fc717279422a4e6f7047bb384c006c1ac38bd54f7f95ed43f4502602548242a00",
        )
        .unwrap();
        assert!(matches!(
            check_block(&block, &genesis_filter),
            Err(CheckBlockError::Mismatch(_))
        ));
    }
}
