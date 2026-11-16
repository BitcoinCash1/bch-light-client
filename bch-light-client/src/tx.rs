//! Bitcoin Cash transactions, with CashTokens output prefixes.

use crate::encode::{DecodeError, Reader, WriteExt};
use crate::hash::{sha256d, Txid};
use std::fmt;

/// The output an input spends: a transaction ID and an output index.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: Txid, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// The previous output of a coinbase input.
    pub fn is_null(&self) -> bool {
        self.txid == Txid::ZERO && self.vout == u32::MAX
    }
}

impl fmt::Debug for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// What a non-fungible token may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum NftCapability {
    None,
    Mutable,
    Minting,
}

impl NftCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            NftCapability::None => "none",
            NftCapability::Mutable => "mutable",
            NftCapability::Minting => "minting",
        }
    }
}

/// A non-fungible token: its capability and commitment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Nft {
    pub capability: NftCapability,
    pub commitment: Vec<u8>,
}

/// A token category: the ID of the transaction whose first input created it,
/// in internal byte order as a token prefix holds it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Category(pub [u8; 32]);

impl Category {
    /// Display order hex, as explorers and node RPCs show categories.
    pub fn to_hex(&self) -> String {
        Txid(self.0).to_hex()
    }

    pub fn from_hex(s: &str) -> Result<Self, crate::hash::ParseHashError> {
        Txid::from_hex(s).map(|t| Category(t.0))
    }
}

impl fmt::Debug for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Category({})", self.to_hex())
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Category {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Category {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        Category::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// The CashTokens data an output carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenData {
    pub category: Category,
    /// Fungible amount; 0 when the output carries only an NFT.
    pub amount: u64,
    pub nft: Option<Nft>,
}

const PREFIX_TOKEN: u8 = 0xef;
const HAS_AMOUNT: u8 = 0x10;
const HAS_NFT: u8 = 0x20;
const HAS_COMMITMENT_LENGTH: u8 = 0x40;
const RESERVED_BIT: u8 = 0x80;
const MAX_COMMITMENT_LENGTH: u64 = 128;
const MAX_TOKEN_AMOUNT: u64 = i64::MAX as u64;

impl TokenData {
    /// Splits an output's script field into its token data, when it has a
    /// valid token prefix, and the locking bytecode. A field whose prefix does
    /// not parse is all locking bytecode, as nodes read it.
    pub fn split(field: &[u8]) -> (Option<TokenData>, &[u8]) {
        match Self::parse_prefix(field) {
            Some((token, rest)) => (Some(token), rest),
            None => (None, field),
        }
    }

    fn parse_prefix(field: &[u8]) -> Option<(TokenData, &[u8])> {
        if field.len() < 34 || field[0] != PREFIX_TOKEN {
            return None;
        }
        let mut r = Reader::new(&field[1..]);
        let category = Category(r.array().ok()?);
        let bits = r.u8().ok()?;
        let capability = bits & 0x0f;
        let has_nft = bits & HAS_NFT != 0;
        let has_amount = bits & HAS_AMOUNT != 0;
        let has_commitment = bits & HAS_COMMITMENT_LENGTH != 0;
        if bits & RESERVED_BIT != 0
            || bits & 0xf0 == 0
            || capability > 2
            || (!has_nft && (!has_amount || capability != 0 || has_commitment))
        {
            return None;
        }
        let commitment = if has_commitment {
            let len = r.compact_size().ok()?;
            if !(1..=MAX_COMMITMENT_LENGTH).contains(&len) {
                return None;
            }
            r.bytes(len as usize).ok()?.to_vec()
        } else {
            Vec::new()
        };
        let amount = if has_amount {
            let amount = r.compact_size().ok()?;
            if !(1..=MAX_TOKEN_AMOUNT).contains(&amount) {
                return None;
            }
            amount
        } else {
            0
        };
        let nft = has_nft.then_some(Nft {
            capability: match capability {
                1 => NftCapability::Mutable,
                2 => NftCapability::Minting,
                _ => NftCapability::None,
            },
            commitment,
        });
        let rest = &field[1 + r.position()..];
        Some((
            TokenData {
                category,
                amount,
                nft,
            },
            rest,
        ))
    }

    /// The serialized token prefix.
    pub fn prefix(&self) -> Vec<u8> {
        let mut out = vec![PREFIX_TOKEN];
        out.extend_from_slice(&self.category.0);
        let mut bits = 0u8;
        if let Some(nft) = &self.nft {
            bits |= HAS_NFT
                | match nft.capability {
                    NftCapability::None => 0,
                    NftCapability::Mutable => 1,
                    NftCapability::Minting => 2,
                };
            if !nft.commitment.is_empty() {
                bits |= HAS_COMMITMENT_LENGTH;
            }
        }
        if self.amount > 0 {
            bits |= HAS_AMOUNT;
        }
        out.push(bits);
        if let Some(nft) = self.nft.as_ref().filter(|n| !n.commitment.is_empty()) {
            out.put_var_bytes(&nft.commitment);
        }
        if self.amount > 0 {
            out.put_compact_size(self.amount);
        }
        out
    }
}

/// A transaction input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

/// A transaction output: value, optional token data and the bare locking bytecode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub token: Option<TokenData>,
    /// The locking bytecode, without any token prefix.
    pub script: Vec<u8>,
}

impl TxOut {
    /// The output's script field as serialized: token prefix, then locking bytecode.
    pub fn script_field(&self) -> Vec<u8> {
        match &self.token {
            Some(token) => {
                let mut field = token.prefix();
                field.extend_from_slice(&self.script);
                field
            }
            None => self.script.clone(),
        }
    }
}

/// A parsed transaction. Serializing it gives back the exact bytes it was
/// parsed from, so its ID is the hash of those bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
    txid: Txid,
    size: usize,
}

impl Transaction {
    /// Parses one transaction at the reader's position.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let start = r.position();
        let version = r.i32()?;
        // An input takes at least 41 bytes, an output at least 9.
        let n_in = r.count(41)?;
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let txid = Txid(r.array()?);
            let vout = r.u32()?;
            let script_sig = r.var_bytes()?.to_vec();
            let sequence = r.u32()?;
            inputs.push(TxIn {
                prevout: OutPoint { txid, vout },
                script_sig,
                sequence,
            });
        }
        let n_out = r.count(9)?;
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let value = r.u64()?;
            let (token, script) = TokenData::split(r.var_bytes()?);
            outputs.push(TxOut {
                value,
                token,
                script: script.to_vec(),
            });
        }
        let lock_time = r.u32()?;
        let raw = r.since(start);
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
            txid: Txid(sha256d(raw)),
            size: raw.len(),
        })
    }

    /// Parses a whole serialized transaction.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let tx = Self::read(&mut r)?;
        r.finish()?;
        Ok(tx)
    }

    pub fn txid(&self) -> Txid {
        self.txid
    }

    /// The serialized size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prevout.is_null()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size);
        out.put_i32(self.version);
        out.put_compact_size(self.inputs.len() as u64);
        for input in &self.inputs {
            out.put_bytes(&input.prevout.txid.0);
            out.put_u32(input.prevout.vout);
            out.put_var_bytes(&input.script_sig);
            out.put_u32(input.sequence);
        }
        out.put_compact_size(self.outputs.len() as u64);
        for output in &self.outputs {
            out.put_u64(output.value);
            out.put_var_bytes(&output.script_field());
        }
        out.put_u32(self.lock_time);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx_with_field(field: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.put_i32(2);
        b.put_compact_size(1);
        b.put_bytes(&[7u8; 32]);
        b.put_u32(0);
        b.put_var_bytes(&[0x51]);
        b.put_u32(0xffff_ffff);
        b.put_compact_size(1);
        b.put_u64(1000);
        b.put_var_bytes(field);
        b.put_u32(0);
        b
    }

    #[test]
    fn token_prefixes_parse_and_serialize_back() {
        let category = [0xabu8; 32];
        let script = [0xaa, 0x20, 1, 2, 3];
        let cases = [
            // fungible only
            TokenData {
                category: Category(category),
                amount: 1_000_000,
                nft: None,
            },
            // immutable NFT with a commitment
            TokenData {
                category: Category(category),
                amount: 0,
                nft: Some(Nft {
                    capability: NftCapability::None,
                    commitment: vec![1, 2, 3],
                }),
            },
            // minting NFT without commitment plus amount
            TokenData {
                category: Category(category),
                amount: 5,
                nft: Some(Nft {
                    capability: NftCapability::Minting,
                    commitment: vec![],
                }),
            },
        ];
        for token in cases {
            let mut field = token.prefix();
            field.extend_from_slice(&script);
            let raw = tx_with_field(&field);
            let tx = Transaction::from_bytes(&raw).unwrap();
            assert_eq!(tx.outputs[0].token.as_ref(), Some(&token));
            assert_eq!(tx.outputs[0].script, script);
            assert_eq!(tx.serialize(), raw);
            assert_eq!(tx.size(), raw.len());
        }
    }

    #[test]
    fn an_invalid_prefix_is_all_locking_bytecode() {
        // Capability 3 does not exist.
        let mut field = vec![PREFIX_TOKEN];
        field.extend_from_slice(&[1u8; 32]);
        field.push(HAS_NFT | 3);
        field.push(0x51);
        let raw = tx_with_field(&field);
        let tx = Transaction::from_bytes(&raw).unwrap();
        assert!(tx.outputs[0].token.is_none());
        assert_eq!(tx.outputs[0].script, field);
        assert_eq!(tx.serialize(), raw);
    }
}
