//! Bitcoin Cash Metadata Registries (CHIP-BCMR): what a light client checks
//! itself. An identity is its authbase transaction; its authchain is the
//! chain of transactions each spending output 0 (the identity output) of
//! the one before, and the last, the authhead, publishes the registry's
//! hash in its first output that starts with `OP_RETURN <'BCMR'>`. The
//! client never fetches a registry: the app downloads it from the
//! publication's URIs and checks the bytes with [`registry_matches`].

use crate::hash::{sha256, Txid};
use crate::script::read_op;
use crate::tx::Transaction;

/// The locking bytecode prefix of a publication output: `OP_RETURN <'BCMR'>`.
pub const PUBLICATION_PREFIX: [u8; 6] = [0x6a, 0x04, b'B', b'C', b'M', b'R'];

/// A metadata registry publication output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publication {
    /// The registry's SHA-256 (in `OP_SHA256` byte order, as hashed) and
    /// the URIs it may be downloaded from, in order. A URI that is not
    /// UTF-8 is left out.
    Registry { hash: [u8; 32], uris: Vec<String> },
    /// An output with the prefix that does not push a 32-byte hash next:
    /// it is still the transaction's publication output, and it publishes
    /// nothing.
    Malformed,
}

/// The publication of one output's locking bytecode, when it has the prefix.
pub fn publication(script: &[u8]) -> Option<Publication> {
    let rest = script.strip_prefix(&PUBLICATION_PREFIX[..])?;
    let mut pos = 0;
    let hash = match read_op(rest, &mut pos) {
        Some((op, data)) if op <= 0x4e && data.len() == 32 => data.try_into().expect("32 bytes"),
        _ => return Some(Publication::Malformed),
    };
    let mut uris = Vec::new();
    while pos < rest.len() {
        match read_op(rest, &mut pos) {
            Some((op, data)) if op <= 0x4e => {
                if let Ok(uri) = std::str::from_utf8(data) {
                    uris.push(uri.to_string());
                }
            }
            // A non-push, or a push past the end, ends the URIs.
            _ => break,
        }
    }
    Some(Publication::Registry { hash, uris })
}

/// A transaction's publication: its first output with the prefix (later
/// ones are ignored, even when the first is malformed).
pub fn tx_publication(tx: &Transaction) -> Option<Publication> {
    tx.outputs.iter().find_map(|o| publication(&o.script))
}

/// Whether downloaded registry bytes are those a publication commits to.
pub fn registry_matches(registry: &[u8], publication: &Publication) -> bool {
    matches!(publication, Publication::Registry { hash, .. } if sha256(registry) == *hash)
}

/// Whether an identity output burns the identity: it starts with OP_RETURN.
pub fn burns_identity(tx: &Transaction) -> bool {
    tx.outputs
        .first()
        .is_some_and(|o| o.script.first() == Some(&0x6a))
}

/// Why an `authchain` extension does not hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthchainError {
    #[error("the authchain extension is empty")]
    Empty,
    #[error("transaction {0} of the authchain extension does not decode")]
    Undecodable(usize),
    #[error("the first transaction of the authchain extension is not the authbase")]
    NotTheAuthbase,
    #[error("transaction {0} of the authchain extension does not spend the identity output of the one before")]
    Broken(usize),
}

/// Steps 1 and 2 of the `authchain` extension's validation: the first
/// transaction is the authbase (it hashes to it), and each next one spends
/// output 0 of the one before. Whether the last is on the chain, and its
/// identity output unspent, is the client's to find out (step 3).
pub fn verify_extension(
    authbase: Txid,
    raw: &[Vec<u8>],
) -> Result<Vec<Transaction>, AuthchainError> {
    if raw.is_empty() {
        return Err(AuthchainError::Empty);
    }
    let txs = raw
        .iter()
        .enumerate()
        .map(|(i, r)| Transaction::from_bytes(r).map_err(|_| AuthchainError::Undecodable(i)))
        .collect::<Result<Vec<_>, _>>()?;
    if txs[0].txid() != authbase {
        return Err(AuthchainError::NotTheAuthbase);
    }
    for (i, pair) in txs.windows(2).enumerate() {
        let identity = crate::tx::OutPoint::new(pair[0].txid(), 0);
        if !pair[1].inputs.iter().any(|input| input.prevout == identity) {
            return Err(AuthchainError::Broken(i + 1));
        }
    }
    Ok(txs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::WriteExt;

    /// The spec's example: a registry at example.com with the genesis block
    /// header's hash, in OP_SHA256 byte order.
    const EXAMPLE: &str = "6a0442434d52206fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000b6578616d706c652e636f6d";

    #[test]
    fn the_spec_example_publication_reads() {
        let script = hex::decode(EXAMPLE).unwrap();
        let Some(Publication::Registry { hash, uris }) = publication(&script) else {
            panic!("no publication");
        };
        assert_eq!(
            hex::encode(hash),
            "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
        );
        assert_eq!(uris, vec!["example.com".to_string()]);
        // The hash is SHA-256 in OP_SHA256 byte order: the genesis header's
        // OP_HASH256 is SHA-256 of its SHA-256.
        let header = hex::decode("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c").unwrap();
        let once = sha256(&header);
        let published = publication(&script).unwrap();
        assert!(registry_matches(&once, &published));
        assert!(!registry_matches(&header, &published));
    }

    #[test]
    fn malformed_and_other_outputs() {
        // The prefix without a hash still is the publication output.
        assert_eq!(
            publication(&PUBLICATION_PREFIX),
            Some(Publication::Malformed)
        );
        let mut short = PUBLICATION_PREFIX.to_vec();
        short.extend_from_slice(&[0x1f]);
        short.extend_from_slice(&[0u8; 31]);
        assert_eq!(publication(&short), Some(Publication::Malformed));
        // No URIs; a URI that is not UTF-8 is left out.
        let mut script = PUBLICATION_PREFIX.to_vec();
        script.push(0x20);
        script.extend_from_slice(&[7u8; 32]);
        assert_eq!(
            publication(&script),
            Some(Publication::Registry {
                hash: [7; 32],
                uris: vec![]
            })
        );
        script.extend_from_slice(&[2, 0xff, 0xfe, 4]);
        script.extend_from_slice(b"ipfs");
        let Some(Publication::Registry { uris, .. }) = publication(&script) else {
            panic!()
        };
        assert_eq!(uris, vec!["ipfs".to_string()]);
        assert_eq!(publication(&[0x6a, 0x04, b'B', b'C', b'M', b'X']), None);
        assert_eq!(publication(&[0x76, 0xa9]), None);
    }

    fn tx(spends: &[(Txid, u32)], first_output: &[u8], second_output: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.put_i32(2);
        b.put_compact_size(spends.len().max(1) as u64);
        if spends.is_empty() {
            b.put_bytes(&[9u8; 32]);
            b.put_u32(3);
            b.put_var_bytes(&[0x51]);
            b.put_u32(0xffff_ffff);
        }
        for (txid, vout) in spends {
            b.put_bytes(&txid.0);
            b.put_u32(*vout);
            b.put_var_bytes(&[0x51]);
            b.put_u32(0xffff_ffff);
        }
        b.put_compact_size(2);
        for script in [first_output, second_output] {
            b.put_u64(1000);
            b.put_var_bytes(script);
        }
        b.put_u32(0);
        b
    }

    #[test]
    fn the_first_publication_output_counts_and_burns_show() {
        let mut first = PUBLICATION_PREFIX.to_vec();
        first.push(0x20);
        first.extend_from_slice(&[1u8; 32]);
        let raw = tx(&[], &[0x6a], &first);
        let t = Transaction::from_bytes(&raw).unwrap();
        assert!(burns_identity(&t));
        assert!(
            matches!(tx_publication(&t), Some(Publication::Registry { hash, .. }) if hash == [1; 32])
        );
        // A malformed first publication output hides a later good one.
        let raw = tx(&[], &PUBLICATION_PREFIX, &first);
        let t = Transaction::from_bytes(&raw).unwrap();
        assert_eq!(tx_publication(&t), Some(Publication::Malformed));
        assert!(burns_identity(&t), "output 0 starts with OP_RETURN");
    }

    #[test]
    fn an_extension_must_start_at_the_authbase_and_follow_output_zero() {
        let base = tx(&[], &[0x51], &[0x52]);
        let base_id = Transaction::from_bytes(&base).unwrap().txid();
        let step = tx(&[(base_id, 0)], &[0x51], &[0x53]);
        let step_id = Transaction::from_bytes(&step).unwrap().txid();
        let head = tx(&[(Txid([5; 32]), 1), (step_id, 0)], &[0x51], &[0x54]);
        let chain = verify_extension(base_id, &[base.clone(), step.clone(), head]).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(verify_extension(base_id, &[]), Err(AuthchainError::Empty));
        assert_eq!(
            verify_extension(step_id, &[base.clone(), step.clone()]),
            Err(AuthchainError::NotTheAuthbase)
        );
        // Spending output 1 of the step is no authchain step.
        let off = tx(&[(step_id, 1)], &[0x51], &[0x55]);
        assert_eq!(
            verify_extension(base_id, &[base.clone(), step, off]),
            Err(AuthchainError::Broken(2))
        );
        assert_eq!(
            verify_extension(base_id, &[base, vec![1, 2]]),
            Err(AuthchainError::Undecodable(1))
        );
    }
}
