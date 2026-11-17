//! CashAddr addresses: P2PKH, P2SH20 and P2SH32, plain or token-aware.

use std::fmt;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// What an address pays to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressKind {
    P2pkh,
    P2sh,
}

/// A decoded CashAddr address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    pub kind: AddressKind,
    /// 20 bytes, or 32 for P2SH32.
    pub hash: Vec<u8>,
    /// Whether the address says its owner accepts tokens.
    pub token_aware: bool,
}

/// A string that is not a valid CashAddr address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("invalid character in address")]
    Charset,
    #[error("address prefix is not {expected}")]
    Prefix { expected: String },
    #[error("bad address checksum")]
    Checksum,
    #[error("unsupported address version")]
    Version,
    #[error("address hash length does not match its version")]
    Length,
    #[error("mixed-case address")]
    MixedCase,
    #[error("script has no address")]
    NoAddress,
}

fn polymod(values: impl Iterator<Item = u8>) -> u64 {
    const GEN: [u64; 5] = [
        0x98f2bc8e61,
        0x79b76d99e2,
        0xf33e5fb3c4,
        0xae2eabe2a8,
        0x1e4f43e470,
    ];
    let mut c: u64 = 1;
    for d in values {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x07_ffff_ffff) << 5) ^ u64::from(d);
        for (i, g) in GEN.iter().enumerate() {
            if c0 >> i & 1 == 1 {
                c ^= g;
            }
        }
    }
    c ^ 1
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &v in data {
        if u32::from(v) >> from != 0 {
            return None;
        }
        acc = (acc << from) | u32::from(v);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || (acc << (to - bits)) & max != 0 {
        return None;
    }
    Some(out)
}

fn size_bits(len: usize) -> Option<u8> {
    match len {
        20 => Some(0),
        24 => Some(1),
        28 => Some(2),
        32 => Some(3),
        40 => Some(4),
        48 => Some(5),
        56 => Some(6),
        64 => Some(7),
        _ => None,
    }
}

fn checksum_input<'a>(prefix: &'a str, data: &'a [u8]) -> impl Iterator<Item = u8> + 'a {
    prefix
        .bytes()
        .map(|b| b & 0x1f)
        .chain([0])
        .chain(data.iter().copied())
}

/// Encodes a CashAddr string from its parts: the prefix, the type (the upper
/// bits of the version byte, 0 to 15, of which 0 to 3 are defined) and a
/// payload of 20, 24, 28, 32, 40, 48, 56 or 64 bytes.
pub fn encode(prefix: &str, kind: u8, payload: &[u8]) -> Result<String, AddressError> {
    if kind > 15 {
        return Err(AddressError::Version);
    }
    let size = size_bits(payload.len()).ok_or(AddressError::Length)?;
    let mut bytes = vec![(kind << 3) | size];
    bytes.extend_from_slice(payload);
    let mut data = convert_bits(&bytes, 8, 5, true).expect("8-bit input");
    let checksum = polymod(checksum_input(prefix, &data).chain([0u8; 8]));
    data.extend((0..8).map(|i| ((checksum >> (5 * (7 - i))) & 0x1f) as u8));
    let body: String = data.iter().map(|&d| CHARSET[d as usize] as char).collect();
    Ok(format!("{prefix}:{body}"))
}

/// Decodes a CashAddr string into its type and payload. The string may omit
/// the prefix; when it has one, it must be `prefix`.
pub fn decode(s: &str, prefix: &str) -> Result<(u8, Vec<u8>), AddressError> {
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(AddressError::MixedCase);
    }
    let s = s.to_ascii_lowercase();
    let body = match s.split_once(':') {
        Some((p, body)) if p == prefix => body,
        Some(_) => {
            return Err(AddressError::Prefix {
                expected: prefix.to_string(),
            })
        }
        None => s.as_str(),
    };
    let data: Vec<u8> = body
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<_>>()
        .ok_or(AddressError::Charset)?;
    if data.len() < 8 || polymod(checksum_input(prefix, &data)) != 0 {
        return Err(AddressError::Checksum);
    }
    let bytes = convert_bits(&data[..data.len() - 8], 5, 8, false).ok_or(AddressError::Checksum)?;
    let (&version, payload) = bytes.split_first().ok_or(AddressError::Length)?;
    if version & 0x80 != 0 {
        return Err(AddressError::Version);
    }
    if size_bits(payload.len()) != Some(version & 0x07) {
        return Err(AddressError::Length);
    }
    Ok((version >> 3, payload.to_vec()))
}

impl Address {
    /// The locking script the address pays to.
    pub fn script(&self) -> Vec<u8> {
        match (self.kind, self.hash.len()) {
            (AddressKind::P2pkh, _) => {
                let mut s = vec![0x76, 0xa9, 0x14];
                s.extend_from_slice(&self.hash);
                s.extend_from_slice(&[0x88, 0xac]);
                s
            }
            (AddressKind::P2sh, 32) => {
                let mut s = vec![0xaa, 0x20];
                s.extend_from_slice(&self.hash);
                s.push(0x87);
                s
            }
            (AddressKind::P2sh, _) => {
                let mut s = vec![0xa9, 0x14];
                s.extend_from_slice(&self.hash);
                s.push(0x87);
                s
            }
        }
    }

    /// The address of a standard P2PKH, P2SH20 or P2SH32 locking script.
    pub fn from_script(script: &[u8], token_aware: bool) -> Result<Self, AddressError> {
        let (kind, hash) = match script {
            [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
                (AddressKind::P2pkh, hash)
            }
            [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => (AddressKind::P2sh, hash),
            [0xaa, 0x20, hash @ .., 0x87] if hash.len() == 32 => (AddressKind::P2sh, hash),
            _ => return Err(AddressError::NoAddress),
        };
        Ok(Self {
            kind,
            hash: hash.to_vec(),
            token_aware,
        })
    }

    /// Encodes the address with `prefix` (e.g. "bitcoincash"); refused when
    /// the hash has no length CashAddr can encode.
    pub fn encode(&self, prefix: &str) -> Result<String, AddressError> {
        let kind = match (self.kind, self.token_aware) {
            (AddressKind::P2pkh, false) => 0u8,
            (AddressKind::P2sh, false) => 1,
            (AddressKind::P2pkh, true) => 2,
            (AddressKind::P2sh, true) => 3,
        };
        encode(prefix, kind, &self.hash)
    }

    /// Decodes an address of the network with `prefix`; the prefix may be
    /// omitted. Only addresses with a standard locking script decode: types
    /// 0 to 3, with a 20-byte hash, or a 32-byte one for P2SH.
    pub fn decode(s: &str, prefix: &str) -> Result<Self, AddressError> {
        let (kind, hash) = decode(s, prefix)?;
        let (kind, token_aware) = match kind {
            0 => (AddressKind::P2pkh, false),
            1 => (AddressKind::P2sh, false),
            2 => (AddressKind::P2pkh, true),
            3 => (AddressKind::P2sh, true),
            _ => return Err(AddressError::Version),
        };
        if !(hash.len() == 20 || (hash.len() == 32 && kind == AddressKind::P2sh)) {
            return Err(AddressError::Length);
        }
        Ok(Self {
            kind,
            hash,
            token_aware,
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode("bitcoincash").map_err(|_| fmt::Error)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_vectors_decode_and_encode() {
        // From the CashAddr specification's test vectors (20-byte hash
        // F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9).
        let hash = hex::decode("f5bf48b397dae70be82b3cca4793f8eb2b6cdac9").unwrap();
        let p2pkh = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        let p2sh = "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t";
        let a = Address::decode(p2pkh, "bitcoincash").unwrap();
        assert_eq!(
            (a.kind, a.hash.clone(), a.token_aware),
            (AddressKind::P2pkh, hash.clone(), false)
        );
        assert_eq!(a.encode("bitcoincash").unwrap(), p2pkh);
        let b = Address::decode(p2sh, "bchtest").unwrap();
        assert_eq!((b.kind, b.hash.clone()), (AddressKind::P2sh, hash));
        assert_eq!(b.encode("bchtest").unwrap(), p2sh);
        assert!(Address::decode(p2pkh, "bchtest").is_err());
        assert!(Address::decode(
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg3",
            "bitcoincash"
        )
        .is_err());
    }

    #[test]
    fn p2sh32_and_token_aware_round_trip_through_scripts() {
        let script = {
            let mut s = vec![0xaa, 0x20];
            s.extend_from_slice(&[0x11; 32]);
            s.push(0x87);
            s
        };
        let a = Address::from_script(&script, true).unwrap();
        let text = a.encode("bitcoincash").unwrap();
        let back = Address::decode(&text, "bitcoincash").unwrap();
        assert_eq!(back, a);
        assert_eq!(back.script(), script);
        // The regtest P2SH(OP_TRUE) mining address.
        let mine = Address::decode(
            "bchreg:prdpw30fk4ym6zl6rftfjuw806arpn26fveknc0qmt",
            "bchreg",
        )
        .unwrap();
        let redeem_hash = {
            use sha2::Digest;
            let sha = sha2::Sha256::digest([0x51u8]);
            ripemd::Ripemd160::digest(sha).to_vec()
        };
        assert_eq!(mine.hash, redeem_hash);
    }

    /// The CashAddr vectors of bitauth/libauth (MIT License, copyright Jason
    /// Dreyzehner; tests/data/libauth/LICENSE), src/lib/address/fixtures/
    /// cashaddr.json, as copied into mainnet-pat/libauth-rs at be3ed163:
    /// every type and payload size the format has, under five prefixes.
    #[test]
    fn libauth_vectors_encode_and_decode_exactly() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/libauth/cashaddr.json"
        ))
        .expect("vectors");
        let vectors: serde_json::Value = serde_json::from_str(&text).expect("json");
        let vectors = vectors.as_array().unwrap();
        assert_eq!(vectors.len(), 67);
        for v in vectors {
            let cashaddr = v["cashaddr"].as_str().unwrap();
            let kind = v["type"].as_u64().unwrap() as u8;
            let payload = hex::decode(v["payload"].as_str().unwrap()).unwrap();
            assert_eq!(payload.len() as u64, v["payloadSize"].as_u64().unwrap());
            let (prefix, body) = cashaddr.split_once(':').unwrap();
            assert_eq!(encode(prefix, kind, &payload).as_deref(), Ok(cashaddr));
            assert_eq!(
                decode(cashaddr, prefix),
                Ok((kind, payload.clone())),
                "{cashaddr}"
            );
            // Without the prefix, and in upper case, it is the same address.
            assert_eq!(
                decode(body, prefix),
                Ok((kind, payload.clone())),
                "{cashaddr}"
            );
            assert_eq!(
                decode(&cashaddr.to_ascii_uppercase(), prefix),
                Ok((kind, payload.clone())),
                "{cashaddr}"
            );
            // An address with a standard locking script decodes as one.
            let standard =
                kind <= 3 && (payload.len() == 20 || (payload.len() == 32 && kind % 2 == 1));
            match Address::decode(cashaddr, prefix) {
                Ok(a) => {
                    assert!(standard, "{cashaddr}");
                    assert_eq!(a.hash, payload);
                    assert_eq!(a.token_aware, kind >= 2);
                    assert_eq!(a.encode(prefix).as_deref(), Ok(cashaddr));
                }
                Err(e) => assert!(!standard, "{cashaddr}: {e}"),
            }
        }
    }

    #[test]
    fn malformed_strings_are_refused() {
        let good = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert_eq!(
            decode(
                "bitcoincash:Qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
                "bitcoincash"
            ),
            Err(AddressError::MixedCase)
        );
        assert_eq!(
            decode(
                "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg3",
                "bitcoincash"
            ),
            Err(AddressError::Checksum)
        );
        assert_eq!(
            decode(
                "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg1",
                "bitcoincash"
            ),
            Err(AddressError::Charset)
        );
        assert!(matches!(
            decode(good, "bchtest"),
            Err(AddressError::Prefix { .. })
        ));
        assert_eq!(
            encode("bitcoincash", 16, &[0; 20]),
            Err(AddressError::Version)
        );
        assert_eq!(
            encode("bitcoincash", 0, &[0; 21]),
            Err(AddressError::Length)
        );
    }
}
