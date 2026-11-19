//! Input prefix filters (filter type 2) for reusable payment addresses.
//!
//! A reusable payment address (RPA) payment is found by one of its inputs:
//! the sender grinds an input among the first 30 of the transaction until
//! the first bits of the double SHA-256 of the serialized input equal bits
//! of the receiver's scan key. A block's input prefix filter holds the first
//! two bytes (big-endian) of that hash for the first 30 inputs of every
//! transaction but the coinbase, as a sorted set of 16-bit values,
//! Rice-coded with a parameter the count fixes, so every set has exactly one
//! encoding. Filter headers chain as BIP157's, with filter type 2.

use crate::block::Block;
use crate::encode::{DecodeError, Reader, WriteExt};
use crate::hash::sha256d;
use crate::tx::{Transaction, TxIn};

/// The filter type of input prefix filters in BIP157 messages.
pub const RPA_FILTER_TYPE: u8 = 2;
/// Inputs of a transaction that count, from the first.
pub const RPA_INPUTS: usize = 30;
/// The most values a filter holds: every 16-bit value.
pub const RPA_MAX_VALUES: u64 = 65_536;
/// round(65536 * ln 2), which sets the Rice parameter.
const K_SCALE: u64 = 45_426;

/// A prefix of 1 to 16 bits of an input's hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    /// The prefix bits, right-aligned.
    pub value: u16,
    pub bits: u8,
}

/// A prefix that is not 1 to 16 bits, or has bits set past its length.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a prefix is 1 to 16 bits with no bits set past its length")]
pub struct BadPrefix;

impl Prefix {
    pub fn new(value: u16, bits: u8) -> Result<Self, BadPrefix> {
        if bits == 0 || bits > 16 || (bits < 16 && u32::from(value) >> bits != 0) {
            return Err(BadPrefix);
        }
        Ok(Self { value, bits })
    }

    /// A prefix written as 1 to 4 hex digits, 4 bits each, as wallets send it.
    pub fn from_hex(text: &str) -> Result<Self, BadPrefix> {
        let text = text.trim();
        if text.is_empty() || text.len() > 4 {
            return Err(BadPrefix);
        }
        let value = u16::from_str_radix(text, 16).map_err(|_| BadPrefix)?;
        Self::new(value, (text.len() * 4) as u8)
    }

    /// The prefix as hex digits, one per 4 bits (rounded up).
    pub fn to_hex(&self) -> String {
        let digits = usize::from(self.bits).div_ceil(4);
        let shifted = u32::from(self.value) << (digits * 4 - usize::from(self.bits));
        format!("{shifted:0digits$x}")
    }

    /// The 16-bit values with this prefix: [start, end).
    pub fn range(&self) -> (u32, u32) {
        let shift = 16 - u32::from(self.bits);
        (
            u32::from(self.value) << shift,
            (u32::from(self.value) + 1) << shift,
        )
    }

    pub fn contains(&self, value: u16) -> bool {
        let (lo, hi) = self.range();
        (lo..hi).contains(&u32::from(value))
    }

    /// Whether sorted filter values hold one with this prefix.
    pub fn matches(&self, values: &[u16]) -> bool {
        let (lo, hi) = self.range();
        let i = values.partition_point(|v| u32::from(*v) < lo);
        values.get(i).is_some_and(|v| u32::from(*v) < hi)
    }
}

/// The value of an input: the first two bytes, big-endian, of the double
/// SHA-256 of the input as serialized in its transaction.
pub fn input_value(input: &TxIn) -> u16 {
    let mut b = Vec::with_capacity(41 + input.script_sig.len());
    b.put_bytes(&input.prevout.txid.0);
    b.put_u32(input.prevout.vout);
    b.put_var_bytes(&input.script_sig);
    b.put_u32(input.sequence);
    let h = sha256d(&b);
    u16::from_be_bytes([h[0], h[1]])
}

/// The inputs of a transaction that count: the first 30, none of a coinbase.
pub fn counted_inputs(tx: &Transaction) -> &[TxIn] {
    if tx.is_coinbase() {
        &[]
    } else {
        &tx.inputs[..tx.inputs.len().min(RPA_INPUTS)]
    }
}

/// The sorted distinct values of transactions (none a coinbase).
pub fn values_of<'a>(txs: impl IntoIterator<Item = &'a Transaction>) -> Vec<u16> {
    let mut seen = vec![0u64; 1024];
    for tx in txs {
        for input in counted_inputs(tx) {
            let v = usize::from(input_value(input));
            seen[v / 64] |= 1 << (v % 64);
        }
    }
    let mut values = Vec::new();
    for (i, mut word) in seen.into_iter().enumerate() {
        while word != 0 {
            let bit = word.trailing_zeros() as usize;
            values.push((i * 64 + bit) as u16);
            word &= word - 1;
        }
    }
    values
}

/// The values of a block's filter: those of every transaction but the coinbase.
pub fn block_values(block: &Block) -> Vec<u16> {
    values_of(block.txs.iter().skip(1))
}

/// The Rice parameter of a filter of `n` values (n above 0).
pub fn rice_k(n: u64) -> u8 {
    let q = K_SCALE / n.max(1);
    if q == 0 {
        0
    } else {
        (63 - q.leading_zeros()) as u8
    }
}

/// The one encoding of sorted distinct values.
pub fn encode(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    out.put_compact_size(values.len() as u64);
    if values.is_empty() {
        return out;
    }
    let k = rice_k(values.len() as u64);
    out.push(k);
    let mut acc = 0u8;
    let mut used = 0u8;
    let mut bit = |one: bool, out: &mut Vec<u8>| {
        acc = (acc << 1) | u8::from(one);
        used += 1;
        if used == 8 {
            out.push(acc);
            acc = 0;
            used = 0;
        }
    };
    let mut prev = 0u32;
    for &v in values {
        let d = u32::from(v) - prev;
        prev = u32::from(v);
        for _ in 0..(d >> k) {
            bit(true, &mut out);
        }
        bit(false, &mut out);
        for j in (0..k).rev() {
            bit(d >> j & 1 == 1, &mut out);
        }
    }
    if used > 0 {
        out.push(acc << (8 - used));
    }
    out
}

/// A filter's values, refusing every encoding but the one `encode` gives.
pub fn decode(bytes: &[u8]) -> Result<Vec<u16>, DecodeError> {
    let mut r = Reader::new(bytes);
    let n = r.compact_size().map_err(|e| match e {
        DecodeError::NonCanonicalSize => {
            DecodeError::Invalid("filter count not in its shortest form")
        }
        other => other,
    })?;
    if n > RPA_MAX_VALUES {
        return Err(DecodeError::Invalid("filter count above 65,536"));
    }
    if n == 0 {
        r.finish()?;
        return Ok(Vec::new());
    }
    let k = r.u8()?;
    if k > 15 || k != rice_k(n) {
        return Err(DecodeError::Invalid(
            "Rice parameter is not the one the count gives",
        ));
    }
    let data = r.bytes(r.remaining())?;
    let mut bits = Bits { data, pos: 0 };
    let mut values = Vec::with_capacity(n as usize);
    let mut prev = 0u32;
    for i in 0..n {
        let mut q = 0u32;
        loop {
            match bits.next() {
                None => return Err(DecodeError::UnexpectedEnd),
                Some(false) => break,
                Some(true) => {
                    q += 1;
                    if q << k > 0xffff {
                        return Err(DecodeError::Invalid("filter value above 65,535"));
                    }
                }
            }
        }
        let mut d = q << k;
        for j in (0..k).rev() {
            if bits.next().ok_or(DecodeError::UnexpectedEnd)? {
                d |= 1 << j;
            }
        }
        if i > 0 && d == 0 {
            return Err(DecodeError::Invalid("filter repeats a value"));
        }
        let v = prev + d;
        if v > 0xffff {
            return Err(DecodeError::Invalid("filter value above 65,535"));
        }
        values.push(v as u16);
        prev = v;
    }
    let used = bits.pos.div_ceil(8);
    if used < data.len() {
        return Err(DecodeError::TrailingBytes(data.len() - used));
    }
    while bits.pos < used * 8 {
        if bits.next() == Some(true) {
            return Err(DecodeError::Invalid("filter padding is not zero"));
        }
    }
    Ok(values)
}

/// Reads bits most significant first.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn next(&mut self) -> Option<bool> {
        let byte = self.data.get(self.pos / 8)?;
        let one = byte >> (7 - self.pos % 8) & 1 == 1;
        self.pos += 1;
        Some(one)
    }
}

/// The served filter of a block, built from the block alone.
pub fn build(block: &Block) -> Vec<u8> {
    encode(&block_values(block))
}

/// The positions of the counted inputs of `tx` whose values have the prefix.
pub fn matching_inputs(tx: &Transaction, prefix: &Prefix) -> Vec<u32> {
    counted_inputs(tx)
        .iter()
        .enumerate()
        .filter(|(_, input)| prefix.contains(input_value(input)))
        .map(|(i, _)| i as u32)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::next_filter_header;
    use serde_json::Value;

    fn vectors() -> Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/rpa-filter-vectors.json"
        ))
        .expect("vectors");
        serde_json::from_str(&text).expect("json")
    }

    #[test]
    fn blocks_give_the_reference_values_filters_and_headers() {
        let v = vectors();
        let mut header = [0u8; 32];
        for case in v["blocks"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let block =
                Block::from_bytes(&hex::decode(case["block"].as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(
                hex::encode(block.hash().0),
                case["block_hash"].as_str().unwrap(),
                "{name}"
            );
            let values: Vec<String> = block_values(&block)
                .iter()
                .map(|v| format!("{v:04x}"))
                .collect();
            let expected: Vec<String> = case["values"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            assert_eq!(values, expected, "{name}");
            for (tx, inputs) in block
                .txs
                .iter()
                .skip(1)
                .zip(case["input_values"].as_array().unwrap())
            {
                let got: Vec<String> = tx
                    .inputs
                    .iter()
                    .map(|i| format!("{:04x}", input_value(i)))
                    .collect();
                let want: Vec<&str> = inputs
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect();
                assert_eq!(got, want, "{name}");
            }
            let filter = build(&block);
            assert_eq!(
                hex::encode(&filter),
                case["filter"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                hex::encode(sha256d(&filter)),
                case["filter_hash"].as_str().unwrap(),
                "{name}"
            );
            header = next_filter_header(&filter, &header);
            assert_eq!(
                hex::encode(header),
                case["header"].as_str().unwrap(),
                "{name}"
            );
            if let Some(k) = case["k"].as_u64() {
                assert_eq!(u64::from(filter[1]), k, "{name}");
            }
            assert_eq!(decode(&filter).unwrap(), block_values(&block), "{name}");
        }
    }

    #[test]
    fn the_large_filter_uses_k_zero() {
        let v = vectors();
        let large = &v["large"];
        let mut values = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for j in 1u32..=1000 {
            let mut txid = [0u8; 32];
            txid[..4].copy_from_slice(&j.to_le_bytes());
            for i in 0..30u32 {
                let input = TxIn {
                    prevout: crate::tx::OutPoint::new(crate::hash::Txid(txid), i),
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                };
                seen.insert(input_value(&input));
            }
        }
        values.extend(seen);
        assert_eq!(values.len() as u64, large["count"].as_u64().unwrap());
        let filter = encode(&values);
        assert_eq!(filter.len() as u64, large["bytes"].as_u64().unwrap());
        assert_eq!(hex::encode(&filter[..16]), large["head"].as_str().unwrap());
        assert_eq!(
            hex::encode(&filter[filter.len() - 8..]),
            large["tail"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(sha256d(&filter)),
            large["filter_hash"].as_str().unwrap()
        );
        assert_eq!(decode(&filter).unwrap(), values);
    }

    #[test]
    fn accepted_and_refused_encodings() {
        let v = vectors();
        for case in v["accepted"].as_array().unwrap() {
            let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
            let values = decode(&bytes).unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
            assert_eq!(values.len() as u64, case["count"].as_u64().unwrap());
            assert_eq!(encode(&values), bytes, "{}", case["name"]);
            assert_eq!(hex::encode(sha256d(&bytes)), case["hash"].as_str().unwrap());
        }
        for case in v["malformed"].as_array().unwrap() {
            let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
            assert!(
                decode(&bytes).is_err(),
                "took the malformed case {}",
                case["name"]
            );
        }
    }

    #[test]
    fn rice_parameters_where_they_change() {
        for (n, k) in [
            (1, 15),
            (2, 14),
            (3, 13),
            (5, 13),
            (6, 12),
            (30, 10),
            (45426, 0),
            (45427, 0),
            (65536, 0),
            (22713, 1),
            (22714, 0),
            (11356, 2),
            (11357, 1),
        ] {
            assert_eq!(rice_k(n), k, "{n} values");
        }
    }

    #[test]
    fn prefixes_match_at_the_edges_of_their_ranges() {
        let values = [0x0000u16, 0x12ff, 0x1300, 0xa5a5, 0xffff];
        let cases: [(u16, u8, bool); 21] = [
            (0x0, 4, true),
            (0x1, 4, true),
            (0x2, 4, false),
            (0xa, 4, true),
            (0xf, 4, true),
            (0x12, 8, true),
            (0x13, 8, true),
            (0x14, 8, false),
            (0xff, 8, true),
            (0xfe, 8, false),
            (0x12f, 12, true),
            (0x130, 12, true),
            (0x131, 12, false),
            (0xa5a, 12, true),
            (0x12ff, 16, true),
            (0x1300, 16, true),
            (0x1301, 16, false),
            (0xffff, 16, true),
            (0xfffe, 16, false),
            (0x0000, 16, true),
            (0x0001, 16, false),
        ];
        for (value, bits, want) in cases {
            assert_eq!(
                Prefix::new(value, bits).unwrap().matches(&values),
                want,
                "{value:x}/{bits}"
            );
        }
        assert!(Prefix::new(0, 0).is_err());
        assert!(Prefix::new(0x12ff, 17).is_err());
        assert!(Prefix::new(0x1ff, 8).is_err());
        assert!(!Prefix::new(0, 4).unwrap().matches(&[]));
        assert_eq!(
            Prefix::from_hex("a5").unwrap(),
            Prefix {
                value: 0xa5,
                bits: 8
            }
        );
        assert_eq!(Prefix::from_hex("A5a").unwrap().to_hex(), "a5a");
        assert!(Prefix::from_hex("12345").is_err());
        assert!(Prefix::from_hex("").is_err());
    }
}
