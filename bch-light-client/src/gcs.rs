//! BIP158 Golomb-coded sets as committed filters serve them: N as a compact
//! size, then the sorted values' Golomb-Rice coded differences, most
//! significant bit first. An item maps to [0, N*M) by SipHash-2-4 keyed with
//! the first 16 bytes of the block hash.

use crate::encode::{DecodeError, Reader};

/// Golomb-Rice parameter.
pub const P: u32 = 19;
/// Inverse false positive rate.
pub const M: u64 = 784_931;

#[inline(always)]
fn sip_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// SipHash-2-4 of `data` under the key (k0, k1).
pub fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let m = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
        v[3] ^= m;
        sip_round(&mut v);
        sip_round(&mut v);
        v[0] ^= m;
    }
    let rest = chunks.remainder();
    let mut last = [0u8; 8];
    last[..rest.len()].copy_from_slice(rest);
    last[7] = data.len() as u8;
    let m = u64::from_le_bytes(last);
    v[3] ^= m;
    sip_round(&mut v);
    sip_round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        sip_round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// The SipHash key of a block's filter: the first 16 bytes of its hash.
pub fn filter_key(block_hash: &[u8; 32]) -> (u64, u64) {
    (
        u64::from_le_bytes(block_hash[0..8].try_into().expect("8 bytes")),
        u64::from_le_bytes(block_hash[8..16].try_into().expect("8 bytes")),
    )
}

/// The value an item has in a filter of `n` items under `key`.
pub fn hash_to_range(key: (u64, u64), n: u64, item: &[u8]) -> u64 {
    let h = siphash24(key.0, key.1, item);
    ((u128::from(h) * u128::from(n * M)) >> 64) as u64
}

/// A filter: its item count and its Golomb-Rice coded bits.
#[derive(Debug, Clone, Copy)]
pub struct Gcs<'a> {
    pub n: u64,
    data: &'a [u8],
}

impl<'a> Gcs<'a> {
    /// Reads an N-prefixed filter.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let n = r.compact_size()?;
        // Every value takes at least P + 1 bits.
        if n.saturating_mul(u64::from(P) + 1) > r.remaining() as u64 * 8 {
            return Err(DecodeError::Invalid("filter shorter than its item count"));
        }
        let pos = r.position();
        Ok(Self {
            n,
            data: &bytes[pos..],
        })
    }

    /// Every value, in order.
    pub fn values(&self) -> Result<Vec<u64>, DecodeError> {
        let mut bits = BitReader::new(self.data);
        let mut last = 0u64;
        (0..self.n)
            .map(|_| {
                last += bits.golomb()?;
                Ok(last)
            })
            .collect()
    }

    /// Whether the filter may hold `item` (false positives at rate 1/M).
    pub fn matches(&self, key: (u64, u64), item: &[u8]) -> Result<bool, DecodeError> {
        if self.n == 0 {
            return Ok(false);
        }
        let target = hash_to_range(key, self.n, item);
        let mut bits = BitReader::new(self.data);
        let mut value = 0u64;
        for _ in 0..self.n {
            value += bits.golomb()?;
            if value >= target {
                return Ok(value == target);
            }
        }
        Ok(false)
    }

    /// Which of the sorted `targets` (values already mapped into this
    /// filter's range) the filter holds: one pass over the filter for any
    /// number of items. Calls `hit(i)` for each matching target index.
    pub fn match_sorted(
        &self,
        targets: &[(u64, usize)],
        mut hit: impl FnMut(usize),
    ) -> Result<(), DecodeError> {
        if self.n == 0 || targets.is_empty() {
            return Ok(());
        }
        let mut bits = BitReader::new(self.data);
        let mut value = bits.golomb()?;
        let mut read = 1u64;
        for &(target, index) in targets {
            while value < target {
                if read == self.n {
                    return Ok(());
                }
                value += bits.golomb()?;
                read += 1;
            }
            if value == target {
                hit(index);
            }
        }
        Ok(())
    }
}

/// Reads bits most significant first.
struct BitReader<'a> {
    data: &'a [u8],
    /// Next byte to load.
    pos: usize,
    /// Buffered bits, left aligned.
    buf: u64,
    /// How many bits of `buf` are valid.
    len: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buf: 0,
            len: 0,
        }
    }

    #[inline]
    fn refill(&mut self) {
        let take = (64 - self.len) / 8;
        if take == 0 {
            return;
        }
        if self.pos + 8 <= self.data.len() {
            let word = u64::from_be_bytes(
                self.data[self.pos..self.pos + 8]
                    .try_into()
                    .expect("8 bytes"),
            );
            // The first `take` bytes of the word, placed after the buffered bits.
            let bytes = if take == 8 {
                word
            } else {
                (word >> (64 - take * 8)) << (64 - take * 8)
            };
            self.buf |= bytes >> self.len;
            self.pos += take as usize;
            self.len += take * 8;
            return;
        }
        while self.len <= 56 && self.pos < self.data.len() {
            self.buf |= u64::from(self.data[self.pos]) << (56 - self.len);
            self.pos += 1;
            self.len += 8;
        }
    }

    /// One Golomb-Rice coded value: a unary quotient, then P remainder bits.
    #[inline]
    fn golomb(&mut self) -> Result<u64, DecodeError> {
        let mut quotient = 0u64;
        loop {
            if self.len == 0 {
                self.refill();
                if self.len == 0 {
                    return Err(DecodeError::Invalid("filter ends inside a value"));
                }
            }
            let ones = (!self.buf).leading_zeros().min(self.len);
            quotient += u64::from(ones);
            if ones < self.len {
                // Consume the ones and the terminating zero.
                self.consume(ones + 1);
                break;
            }
            self.consume(ones);
        }
        if self.len < P {
            self.refill();
            if self.len < P {
                return Err(DecodeError::Invalid("filter ends inside a remainder"));
            }
        }
        let remainder = self.buf >> (64 - P);
        self.consume(P);
        Ok((quotient << P) + remainder)
    }

    #[inline]
    fn consume(&mut self, n: u32) {
        self.buf = if n >= 64 { 0 } else { self.buf << n };
        self.len -= n;
    }
}

/// Builds an N-prefixed filter from items; used by tests to make filters.
pub fn build(key: (u64, u64), items: &[&[u8]]) -> Vec<u8> {
    use crate::encode::WriteExt;
    // The builders keep each distinct item once.
    let mut distinct: Vec<&[u8]> = items.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    let n = distinct.len() as u64;
    let mut values: Vec<u64> = distinct.iter().map(|i| hash_to_range(key, n, i)).collect();
    values.sort_unstable();
    let mut out = Vec::new();
    out.put_compact_size(values.len() as u64);
    let mut acc = 0u64;
    let mut used = 0u32;
    let mut bytes = Vec::new();
    let mut push = |bit: u64, bytes: &mut Vec<u8>| {
        acc = (acc << 1) | bit;
        used += 1;
        if used == 8 {
            bytes.push(acc as u8);
            acc = 0;
            used = 0;
        }
    };
    let mut last = 0u64;
    for v in values {
        let d = v - last;
        last = v;
        for _ in 0..(d >> P) {
            push(1, &mut bytes);
        }
        push(0, &mut bytes);
        for i in (0..P).rev() {
            push((d >> i) & 1, &mut bytes);
        }
    }
    if used > 0 {
        bytes.push((acc << (8 - used)) as u8);
    }
    out.extend_from_slice(&bytes);
    out
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
    fn siphash_matches_the_reference_vectors() {
        // The vectors use the key 00 01 .. 0f.
        let key: Vec<u8> = (0u8..16).collect();
        let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        for case in vectors()["siphash"].as_array().unwrap() {
            let data = hex::decode(case["data"].as_str().unwrap()).unwrap();
            let expected = hex::decode(case["hash"].as_str().unwrap()).unwrap();
            assert_eq!(siphash24(k0, k1, &data).to_be_bytes().to_vec(), expected);
        }
    }

    #[test]
    fn filter_values_and_matches_follow_the_vectors() {
        let v = vectors();
        let g = &v["gcs"];
        let mut block = [0u8; 32];
        hex::decode_to_slice(g["block"].as_str().unwrap(), &mut block).unwrap();
        let key = filter_key(&block);
        let items: Vec<Vec<u8>> = g["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| hex::decode(i.as_str().unwrap()).unwrap())
            .collect();
        let filter = hex::decode(g["filter"].as_str().unwrap()).unwrap();
        let expected: Vec<u64> = g["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        let gcs = Gcs::parse(&filter).unwrap();
        assert_eq!(gcs.values().unwrap(), expected);
        let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
        assert_eq!(build(key, &refs), filter);
        for item in &items {
            assert!(gcs.matches(key, item).unwrap());
        }
        assert!(!gcs.matches(key, &[0xffu8; 32]).unwrap());
        // One pass for many items finds every member and no stranger.
        let mut targets: Vec<(u64, usize)> = items
            .iter()
            .enumerate()
            .map(|(i, item)| (hash_to_range(key, gcs.n, item), i))
            .collect();
        targets.push((hash_to_range(key, gcs.n, &[0xffu8; 32]), items.len()));
        targets.sort_unstable();
        let mut hits = Vec::new();
        gcs.match_sorted(&targets, |i| hits.push(i)).unwrap();
        hits.sort_unstable();
        assert_eq!(hits, (0..items.len()).collect::<Vec<_>>());
    }

    #[test]
    fn bip158_testnet_genesis_vector() {
        let v = vectors();
        let g = &v["bip158Genesis"];
        let block = crate::hash::BlockHash::from_hex(g["blockHash"].as_str().unwrap()).unwrap();
        let script = hex::decode(g["script"].as_str().unwrap()).unwrap();
        let filter = hex::decode(g["filter"].as_str().unwrap()).unwrap();
        let gcs = Gcs::parse(&filter).unwrap();
        assert_eq!(
            gcs.values().unwrap(),
            vec![g["values"][0].as_u64().unwrap()]
        );
        assert!(gcs.matches(filter_key(&block.0), &script).unwrap());
    }
}
