//! SHA-256 helpers and the 32-byte hash types of the chain.
//!
//! Hashes are kept in internal byte order, as they appear on the wire. Their
//! `Display` and hex forms are the reversed, display order block explorers
//! and node RPCs use.

use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 of the SHA-256 of `data`.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// SHA-256 of the SHA-256 of two 32-byte halves, as Merkle trees pair nodes.
pub fn sha256d_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256d(&buf)
}

/// A hex string that is not a 32-byte hash.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a 64-digit hex hash")]
pub struct ParseHashError;

macro_rules! hash_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// The all-zero hash.
            pub const ZERO: Self = Self([0u8; 32]);

            /// The hash in internal (wire) byte order.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// The hash in display order (reversed), as hex.
            pub fn to_hex(&self) -> String {
                let mut b = self.0;
                b.reverse();
                hex::encode(b)
            }

            /// Parses a display order hex hash.
            pub fn from_hex(s: &str) -> Result<Self, ParseHashError> {
                let mut b = [0u8; 32];
                hex::decode_to_slice(s.trim(), &mut b).map_err(|_| ParseHashError)?;
                b.reverse();
                Ok(Self(b))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = ParseHashError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::from_hex(s)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(b: [u8; 32]) -> Self {
                Self(b)
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = <String as serde::Deserialize>::deserialize(d)?;
                Self::from_hex(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

hash_newtype!(
    /// A transaction ID: the double SHA-256 of the serialized transaction.
    Txid
);
hash_newtype!(
    /// A block hash: the double SHA-256 of the 80-byte header.
    BlockHash
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_order_round_trips() {
        let h = BlockHash::from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .unwrap();
        assert_eq!(h.0[31], 0);
        assert_eq!(h.0[0], 0x6f);
        assert_eq!(h.to_string(), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        assert!(Txid::from_hex("00").is_err());
    }
}
