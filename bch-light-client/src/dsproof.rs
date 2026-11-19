//! Double-spend proofs (`dsproof-beta`): two signatures over the same
//! output, each with the parts of its signing serialization that are not
//! the output itself, so anyone holding one of the transactions and the
//! output can check that both spends were signed.
//!
//! Wire format: the outpoint (32-byte txid, 4-byte index), then two
//! spenders, each: version, sequence, lock time (4 bytes each), hashes of
//! previous outputs, sequences and outputs (32 bytes each), and the data the
//! input pushed (a count, then each push with its length): the signature.
//! The proof ID is the double SHA-256 of the whole message. Inventory type
//! 0x94a0.

use crate::encode::{DecodeError, Reader, WriteExt};
use crate::hash::{sha256, sha256d, Txid};
use crate::tx::{OutPoint, TxOut};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, FieldElement, ProjectivePoint, Scalar, U256};

/// The inventory type of double-spend proofs.
pub const INV_DSPROOF: u32 = 0x94a0;
/// The message command.
pub const COMMAND: &str = "dsproof-beta";

const MAX_PUSHES: u64 = 1000;
const SIGHASH_FORKID: u8 = 0x40;
const SIGHASH_UTXOS: u8 = 0x20;
const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// One of the two signed spends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spender {
    pub version: u32,
    pub sequence: u32,
    pub lock_time: u32,
    pub hash_prevouts: [u8; 32],
    pub hash_sequence: [u8; 32],
    pub hash_outputs: [u8; 32],
    pub push_data: Vec<Vec<u8>>,
}

/// A double-spend proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsProof {
    pub outpoint: OutPoint,
    pub first: Spender,
    pub second: Spender,
}

/// A proof that does not hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    #[error("malformed proof: {0}")]
    Malformed(&'static str),
    #[error("the spent output is not pay-to-pubkey-hash")]
    NotP2pkh,
    #[error("no public key in the spending transaction")]
    NoPublicKey,
    #[error("the public key does not match the output")]
    WrongKey,
    #[error("the {0} spender's signature does not verify")]
    BadSignature(&'static str),
}

fn read_spender(r: &mut Reader<'_>) -> Result<Spender, DecodeError> {
    let version = r.u32()?;
    let sequence = r.u32()?;
    let lock_time = r.u32()?;
    let hash_prevouts = r.array()?;
    let hash_sequence = r.array()?;
    let hash_outputs = r.array()?;
    let n = r.compact_size()?;
    if n > MAX_PUSHES {
        return Err(DecodeError::Invalid("too many pushes"));
    }
    let push_data = (0..n)
        .map(|_| r.var_bytes().map(<[u8]>::to_vec))
        .collect::<Result<_, _>>()?;
    Ok(Spender {
        version,
        sequence,
        lock_time,
        hash_prevouts,
        hash_sequence,
        hash_outputs,
        push_data,
    })
}

fn write_spender(out: &mut Vec<u8>, s: &Spender) {
    out.put_u32(s.version);
    out.put_u32(s.sequence);
    out.put_u32(s.lock_time);
    out.put_bytes(&s.hash_prevouts);
    out.put_bytes(&s.hash_sequence);
    out.put_bytes(&s.hash_outputs);
    out.put_compact_size(s.push_data.len() as u64);
    for p in &s.push_data {
        out.put_var_bytes(p);
    }
}

impl DsProof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let txid = Txid(r.array()?);
        let vout = r.u32()?;
        let first = read_spender(&mut r)?;
        let second = read_spender(&mut r)?;
        r.finish()?;
        Ok(Self {
            outpoint: OutPoint::new(txid, vout),
            first,
            second,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.put_bytes(&self.outpoint.txid.0);
        out.put_u32(self.outpoint.vout);
        write_spender(&mut out, &self.first);
        write_spender(&mut out, &self.second);
        out
    }

    /// The proof ID: the double SHA-256 of the serialized proof.
    pub fn id(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }

    /// The checks that need neither the output nor a transaction: one
    /// signature per spender with a valid encoding and hash type, the
    /// spenders different and in canonical order.
    pub fn check_sanity(&self) -> Result<(), ProofError> {
        if self.outpoint.vout > i32::MAX as u32 || self.outpoint.txid == Txid::ZERO {
            return Err(ProofError::Malformed("empty outpoint"));
        }
        for s in [&self.first, &self.second] {
            let [sig] = s.push_data.as_slice() else {
                return Err(ProofError::Malformed(
                    "a spender must push exactly one signature",
                ));
            };
            check_signature_encoding(sig)?;
        }
        if self.first == self.second {
            return Err(ProofError::Malformed("the spenders are the same"));
        }
        if compare_spenders(&self.first, &self.second) == std::cmp::Ordering::Greater {
            return Err(ProofError::Malformed(
                "the spenders are not in canonical order",
            ));
        }
        Ok(())
    }

    /// Checks both signatures against the spent output and the public key
    /// the known spending input pushed (its second push).
    pub fn validate(&self, coin: &TxOut, spending_script_sig: &[u8]) -> Result<(), ProofError> {
        self.check_sanity()?;
        let script = &coin.script;
        let p2pkh = script.len() == 25
            && script[0] == 0x76
            && script[1] == 0xa9
            && script[2] == 0x14
            && script[23] == 0x88
            && script[24] == 0xac;
        if !p2pkh {
            return Err(ProofError::NotP2pkh);
        }
        let pubkey = second_push(spending_script_sig).ok_or(ProofError::NoPublicKey)?;
        let hash160: [u8; 20] = {
            use ripemd::Digest;
            ripemd::Ripemd160::digest(sha256(&pubkey)).into()
        };
        if hash160[..] != script[3..23] {
            return Err(ProofError::WrongKey);
        }
        let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey)
            .map_err(|_| ProofError::WrongKey)?;
        for (s, which) in [(&self.first, "first"), (&self.second, "second")] {
            let sig = &s.push_data[0];
            let hash_type = sig[sig.len() - 1];
            let digest = self.sighash(s, coin, hash_type);
            if !verify(&key, &pubkey, &sig[..sig.len() - 1], &digest) {
                return Err(ProofError::BadSignature(which));
            }
        }
        Ok(())
    }

    /// The BIP143-style signing serialization hash of one spender.
    pub fn sighash(&self, s: &Spender, coin: &TxOut, hash_type: u8) -> [u8; 32] {
        let mut b = Vec::with_capacity(200);
        b.put_u32(s.version);
        b.put_bytes(&s.hash_prevouts);
        b.put_bytes(&s.hash_sequence);
        b.put_bytes(&self.outpoint.txid.0);
        b.put_u32(self.outpoint.vout);
        if let Some(token) = &coin.token {
            b.put_bytes(&token.prefix());
        }
        b.put_var_bytes(&coin.script);
        b.put_u64(coin.value);
        b.put_u32(s.sequence);
        b.put_bytes(&s.hash_outputs);
        b.put_u32(s.lock_time);
        b.put_u32(u32::from(hash_type));
        sha256d(&b)
    }
}

/// Orders spenders by their outputs hash, then their previous outputs hash,
/// each read as a little-endian 256-bit number.
pub fn compare_spenders(a: &Spender, b: &Spender) -> std::cmp::Ordering {
    let le = |h: &[u8; 32]| {
        let mut r = *h;
        r.reverse();
        r
    };
    le(&a.hash_outputs)
        .cmp(&le(&b.hash_outputs))
        .then_with(|| le(&a.hash_prevouts).cmp(&le(&b.hash_prevouts)))
}

fn check_signature_encoding(sig: &[u8]) -> Result<(), ProofError> {
    let Some((&hash_type, body)) = sig.split_last() else {
        return Err(ProofError::Malformed("empty signature"));
    };
    let base = hash_type & 0x1f;
    if !(1..=3).contains(&base)
        || hash_type & SIGHASH_FORKID == 0
        || hash_type & SIGHASH_UTXOS != 0
        || hash_type & !(0x1f | SIGHASH_FORKID | SIGHASH_ANYONECANPAY) != 0
    {
        return Err(ProofError::Malformed("signature hash type"));
    }
    if body.len() == 64 {
        return Ok(());
    }
    let sig = k256::ecdsa::Signature::from_der(body)
        .map_err(|_| ProofError::Malformed("signature encoding"))?;
    if sig.normalize_s().is_some() {
        return Err(ProofError::Malformed("signature has a high S"));
    }
    Ok(())
}

/// The data of the second push of a script (a P2PKH input's public key).
fn second_push(script: &[u8]) -> Option<Vec<u8>> {
    let mut pushes = Vec::new();
    let mut i = 0;
    while i < script.len() && pushes.len() < 2 {
        let op = script[i];
        i += 1;
        let len = match op {
            1..=75 => usize::from(op),
            76 => {
                let l = usize::from(*script.get(i)?);
                i += 1;
                l
            }
            77 => {
                let l = usize::from(u16::from_le_bytes([*script.get(i)?, *script.get(i + 1)?]));
                i += 2;
                l
            }
            _ => return None,
        };
        pushes.push(script.get(i..i + len)?.to_vec());
        i += len;
    }
    (pushes.len() == 2).then(|| pushes.pop().expect("two pushes"))
}

/// Verifies an ECDSA (DER) or Bitcoin Cash Schnorr (64-byte) signature.
fn verify(key: &k256::ecdsa::VerifyingKey, pubkey: &[u8], sig: &[u8], digest: &[u8; 32]) -> bool {
    if sig.len() == 64 {
        return verify_schnorr(key, pubkey, sig, digest);
    }
    let Ok(sig) = k256::ecdsa::Signature::from_der(sig) else {
        return false;
    };
    key.verify_prehash(digest, &sig).is_ok()
}

/// Bitcoin Cash Schnorr: e = SHA256(r || compressed key || message),
/// R = sG - eP must have a square y and x = r.
fn verify_schnorr(
    key: &k256::ecdsa::VerifyingKey,
    _pubkey: &[u8],
    sig: &[u8],
    digest: &[u8; 32],
) -> bool {
    let r_bytes: [u8; 32] = sig[..32].try_into().expect("32 bytes");
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("32 bytes");
    if bool::from(FieldElement::from_bytes(&FieldBytes::from(r_bytes)).is_none()) {
        return false;
    }
    let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(s_bytes))) else {
        return false;
    };
    let point = key.as_affine();
    let compressed = point.to_encoded_point(true);
    let mut e_input = Vec::with_capacity(97);
    e_input.extend_from_slice(&r_bytes);
    e_input.extend_from_slice(compressed.as_bytes());
    e_input.extend_from_slice(digest);
    let e = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(sha256(&e_input)));
    let big_r = (ProjectivePoint::GENERATOR * s - ProjectivePoint::from(*point) * e).to_affine();
    let encoded = big_r.to_encoded_point(false);
    let (Some(x), Some(y)) = (encoded.x(), encoded.y()) else {
        return false;
    };
    let y = FieldElement::from_bytes(y);
    let square = Option::<FieldElement>::from(y).is_some_and(|y| bool::from(y.sqrt().is_some()));
    square && x[..] == r_bytes[..]
}

use k256::elliptic_curve::PrimeField;

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;

    fn spender(outputs: u8, sig: Vec<u8>) -> Spender {
        Spender {
            version: 2,
            sequence: 0xffff_ffff,
            lock_time: 0,
            hash_prevouts: [1; 32],
            hash_sequence: [2; 32],
            hash_outputs: [outputs; 32],
            push_data: vec![sig],
        }
    }

    /// A proof signed by one key over two different outputs hashes.
    fn signed_proof() -> (DsProof, TxOut, Vec<u8>) {
        let sk = SigningKey::from_bytes(&[5u8; 32].into()).unwrap();
        let pubkey = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let pkh: [u8; 20] = {
            use ripemd::Digest;
            ripemd::Ripemd160::digest(sha256(&pubkey)).into()
        };
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&pkh);
        script.extend_from_slice(&[0x88, 0xac]);
        let coin = TxOut {
            value: 10_000,
            token: None,
            script,
        };
        let mut proof = DsProof {
            outpoint: OutPoint::new(Txid([9; 32]), 1),
            first: spender(3, vec![]),
            second: spender(4, vec![]),
        };
        for which in 0..2 {
            let s = if which == 0 {
                proof.first.clone()
            } else {
                proof.second.clone()
            };
            let digest = proof.sighash(&s, &coin, 0x41);
            let sig: k256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
            let sig = sig.normalize_s().unwrap_or(sig);
            let mut der = sig.to_der().as_bytes().to_vec();
            der.push(0x41);
            if which == 0 {
                proof.first.push_data = vec![der];
            } else {
                proof.second.push_data = vec![der];
            }
        }
        let mut script_sig = vec![proof.first.push_data[0].len() as u8];
        script_sig.extend_from_slice(&proof.first.push_data[0]);
        script_sig.push(pubkey.len() as u8);
        script_sig.extend_from_slice(&pubkey);
        (proof, coin, script_sig)
    }

    #[test]
    fn a_signed_proof_round_trips_and_validates() {
        let (proof, coin, script_sig) = signed_proof();
        let bytes = proof.serialize();
        assert_eq!(DsProof::from_bytes(&bytes).unwrap(), proof);
        assert_eq!(proof.id(), sha256d(&bytes));
        proof.validate(&coin, &script_sig).unwrap();
        // Another value is another signing serialization.
        let other = TxOut {
            value: 10_001,
            ..coin.clone()
        };
        assert_eq!(
            proof.validate(&other, &script_sig),
            Err(ProofError::BadSignature("first"))
        );
        // The spenders out of order.
        let swapped = DsProof {
            first: proof.second.clone(),
            second: proof.first.clone(),
            ..proof.clone()
        };
        assert!(matches!(
            swapped.check_sanity(),
            Err(ProofError::Malformed(_))
        ));
        // A pay-to-script-hash output is not supported.
        let p2sh = TxOut {
            script: vec![0xa9, 0x14, 0, 0x87],
            ..coin
        };
        assert_eq!(
            proof.validate(&p2sh, &script_sig),
            Err(ProofError::NotP2pkh)
        );
    }

    #[test]
    fn schnorr_signatures_verify() {
        // BCH Schnorr with the deterministic nonce k = 7 (test only).
        let sk_bytes = [3u8; 32];
        let x = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(sk_bytes));
        let key =
            k256::ecdsa::VerifyingKey::from_affine((ProjectivePoint::GENERATOR * x).to_affine())
                .unwrap();
        let pubkey = key.to_encoded_point(true).as_bytes().to_vec();
        let digest = sha256(b"message");
        let mut k = Scalar::from(7u64);
        let mut r_point = (ProjectivePoint::GENERATOR * k).to_affine();
        let y = FieldElement::from_bytes(r_point.to_encoded_point(false).y().unwrap()).unwrap();
        if bool::from(y.sqrt().is_none()) {
            k = -k;
            r_point = (ProjectivePoint::GENERATOR * k).to_affine();
        }
        let r_bytes: [u8; 32] = r_point.to_encoded_point(false).x().unwrap()[..]
            .try_into()
            .unwrap();
        let mut e_input = r_bytes.to_vec();
        e_input.extend_from_slice(&pubkey);
        e_input.extend_from_slice(&digest);
        let e = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(sha256(&e_input)));
        let s = k + e * x;
        let mut sig = r_bytes.to_vec();
        sig.extend_from_slice(&s.to_bytes());
        assert!(verify(&key, &pubkey, &sig, &digest));
        sig[40] ^= 1;
        assert!(!verify(&key, &pubkey, &sig, &digest));
    }
}
