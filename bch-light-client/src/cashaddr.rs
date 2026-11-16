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
    const GEN: [u64; 5] = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470];
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
            [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => (AddressKind::P2pkh, hash),
            [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => (AddressKind::P2sh, hash),
            [0xaa, 0x20, hash @ .., 0x87] if hash.len() == 32 => (AddressKind::P2sh, hash),
            _ => return Err(AddressError::NoAddress),
        };
        Ok(Self { kind, hash: hash.to_vec(), token_aware })
    }

    /// Encodes the address with `prefix` (e.g. "bitcoincash").
    pub fn encode(&self, prefix: &str) -> String {
        let kind = match (self.kind, self.token_aware) {
            (AddressKind::P2pkh, false) => 0u8,
            (AddressKind::P2sh, false) => 1,
            (AddressKind::P2pkh, true) => 2,
            (AddressKind::P2sh, true) => 3,
        };
        let version = (kind << 3) | size_bits(self.hash.len()).unwrap_or(0);
        let mut payload = vec![version];
        payload.extend_from_slice(&self.hash);
        let mut data = convert_bits(&payload, 8, 5, true).expect("8-bit input");
        let checksum = polymod(
            prefix.bytes().map(|b| b & 0x1f).chain([0]).chain(data.iter().copied()).chain([0u8; 8]),
        );
        data.extend((0..8).map(|i| ((checksum >> (5 * (7 - i))) & 0x1f) as u8));
        let body: String = data.iter().map(|&d| CHARSET[d as usize] as char).collect();
        format!("{prefix}:{body}")
    }

    /// Decodes an address of the network with `prefix`; the prefix may be omitted.
    pub fn decode(s: &str, prefix: &str) -> Result<Self, AddressError> {
        let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
        let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
        if has_lower && has_upper {
            return Err(AddressError::MixedCase);
        }
        let s = s.to_ascii_lowercase();
        let body = match s.split_once(':') {
            Some((p, body)) if p == prefix => body,
            Some(_) => return Err(AddressError::Prefix { expected: prefix.to_string() }),
            None => s.as_str(),
        };
        let data: Vec<u8> = body
            .bytes()
            .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
            .collect::<Option<_>>()
            .ok_or(AddressError::Charset)?;
        if data.len() < 8
            || polymod(prefix.bytes().map(|b| b & 0x1f).chain([0]).chain(data.iter().copied())) != 0
        {
            return Err(AddressError::Checksum);
        }
        let payload = convert_bits(&data[..data.len() - 8], 5, 8, false).ok_or(AddressError::Checksum)?;
        let (&version, hash) = payload.split_first().ok_or(AddressError::Length)?;
        if version & 0x80 != 0 {
            return Err(AddressError::Version);
        }
        let (kind, token_aware) = match version >> 3 {
            0 => (AddressKind::P2pkh, false),
            1 => (AddressKind::P2sh, false),
            2 => (AddressKind::P2pkh, true),
            3 => (AddressKind::P2sh, true),
            _ => return Err(AddressError::Version),
        };
        let size = version & 0x07;
        if size_bits(hash.len()) != Some(size) || !(hash.len() == 20 || (hash.len() == 32 && kind == AddressKind::P2sh))
        {
            return Err(AddressError::Length);
        }
        Ok(Self { kind, hash: hash.to_vec(), token_aware })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode("bitcoincash"))
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
        assert_eq!((a.kind, a.hash.clone(), a.token_aware), (AddressKind::P2pkh, hash.clone(), false));
        assert_eq!(a.encode("bitcoincash"), p2pkh);
        let b = Address::decode(p2sh, "bchtest").unwrap();
        assert_eq!((b.kind, b.hash.clone()), (AddressKind::P2sh, hash));
        assert_eq!(b.encode("bchtest"), p2sh);
        assert!(Address::decode(p2pkh, "bchtest").is_err());
        assert!(Address::decode("bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg3", "bitcoincash").is_err());
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
        let text = a.encode("bitcoincash");
        let back = Address::decode(&text, "bitcoincash").unwrap();
        assert_eq!(back, a);
        assert_eq!(back.script(), script);
        // The regtest P2SH(OP_TRUE) mining address.
        let mine = Address::decode("bchreg:prdpw30fk4ym6zl6rftfjuw806arpn26fveknc0qmt", "bchreg").unwrap();
        let redeem_hash = {
            use sha2::Digest;
            let sha = sha2::Sha256::digest([0x51u8]);
            ripemd::Ripemd160::digest(sha).to_vec()
        };
        assert_eq!(mine.hash, redeem_hash);
    }
}
