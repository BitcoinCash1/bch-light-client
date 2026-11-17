//! Network parameters: message start bytes, ports, genesis headers,
//! difficulty rules and checkpoints of each Bitcoin Cash network.

use crate::block::BlockHeader;
use crate::hash::BlockHash;
use crate::pow::{compact_to_target, U256};
use std::fmt;
use std::str::FromStr;

/// A Bitcoin Cash network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Chipnet,
    Regtest,
    Simnet,
}

impl Network {
    pub fn params(self) -> &'static Params {
        match self {
            Network::Mainnet => &MAINNET,
            Network::Testnet3 => &TESTNET3,
            Network::Testnet4 => &TESTNET4,
            Network::Chipnet => &CHIPNET,
            Network::Regtest => &REGTEST,
            Network::Simnet => &SIMNET,
        }
    }

    pub fn name(self) -> &'static str {
        self.params().name
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A network name that is not one of ours.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown network '{0}'")]
pub struct UnknownNetwork(pub String);

impl FromStr for Network {
    type Err = UnknownNetwork;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "mainnet" | "main" => Ok(Network::Mainnet),
            "testnet" | "testnet3" => Ok(Network::Testnet3),
            "testnet4" => Ok(Network::Testnet4),
            "chipnet" => Ok(Network::Chipnet),
            "regtest" => Ok(Network::Regtest),
            "simnet" => Ok(Network::Simnet),
            other => Err(UnknownNetwork(other.to_string())),
        }
    }
}

/// The constants of one network.
#[derive(Debug)]
pub struct Params {
    pub name: &'static str,
    /// Message start bytes, in wire order.
    pub magic: [u8; 4],
    pub default_port: u16,
    pub genesis_header: &'static str,
    pub pow_limit_bits: u32,
    pub uahf_height: u32,
    /// From this height on transactions under 100 bytes, and so 64-byte ones, are invalid.
    pub magnetic_anomaly_height: u32,
    /// Where wallets on reusable payment addresses start looking by default.
    pub rpa_start_height: u32,
    pub daa_height: u32,
    /// Blocks above this height use aserti3-2d.
    pub asert_activation_height: u32,
    pub asert_anchor_height: u32,
    pub asert_anchor_parent_time: i64,
    pub asert_anchor_bits: u32,
    pub asert_half_life: i64,
    pub reduce_min_difficulty: bool,
    pub no_difficulty_adjustment: bool,
    /// Block hashes at fixed heights, display order.
    pub checkpoints: &'static [(u32, &'static str)],
    pub cashaddr_prefix: &'static str,
    /// DNS seeds that list nodes of the network.
    pub dns_seeds: &'static [&'static str],
}

impl Params {
    pub fn genesis(&self) -> BlockHeader {
        let raw = hex::decode(self.genesis_header).expect("genesis header hex");
        BlockHeader::from_bytes(&raw.try_into().expect("80-byte genesis header"))
    }

    pub fn genesis_hash(&self) -> BlockHash {
        self.genesis().hash()
    }

    pub fn pow_limit(&self) -> U256 {
        compact_to_target(self.pow_limit_bits).0
    }

    /// The checkpoint hash at `height`, if there is one.
    pub fn checkpoint(&self, height: u32) -> Option<BlockHash> {
        self.checkpoints
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, hash)| BlockHash::from_hex(hash).expect("checkpoint hash"))
    }
}

// The genesis headers share version, previous hash and Merkle root; they
// differ in time, bits and nonce.
macro_rules! genesis {
    ($tail:literal) => {
        concat!(
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            $tail
        )
    };
}

const MAINNET_CHECKPOINTS: &[(u32, &str)] = &[
    (
        11111,
        "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
    ),
    (
        105000,
        "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",
    ),
    (
        210000,
        "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
    ),
    (
        295000,
        "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983",
    ),
    (
        400000,
        "000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f",
    ),
    (
        478559,
        "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec",
    ),
    (
        504032,
        "00000000000000000343e9875012f2062554c8752929892c82a0c0743ac7dcfd",
    ),
    (
        556767,
        "0000000000000000004626ff6e3b936941d341c5932ece4357eeccac44e6d56c",
    ),
    (
        582680,
        "000000000000000001b4b8e36aec7d4f9671a47872cb9a74dc16ca398c7dcc18",
    ),
    (
        609136,
        "000000000000000000b48bb207faac5ac655c313e41ac909322eaa694f5bc5b1",
    ),
    (
        635259,
        "00000000000000000033dfef1fc2d6a5d5520b078c55193a9bf498c5b27530f7",
    ),
];

const TESTNET4_CHECKPOINTS: &[(u32, &str)] = &[
    (
        5000,
        "000000009f092d074574a216faec682040a853c4f079c33dfd2c3ef1fd8108c4",
    ),
    (
        16845,
        "00000000fb325b8f34fe80c96a5f708a08699a68bbab82dba4474d86bd743077",
    ),
    (
        38000,
        "000000000015197537e59f339e3b1bbf81a66f691bd3d7aa08560fc7bf5113fb",
    ),
    (
        54700,
        "00000000009af4379d87f17d0f172ee4769b48839a5a3a3e81d69da4322518b8",
    ),
    (
        68117,
        "0000000000a2c2fc11a3b72adbd10a3f02a1f8745da55a85321523043639829a",
    ),
    (
        95465,
        "00000000a77206a2265cabc47cc2c34706ba1c5e5a5743ac6681b83d43c91a01",
    ),
];

pub static MAINNET: Params = Params {
    name: "mainnet",
    magic: [0xe3, 0xe1, 0xf3, 0xe8],
    default_port: 8333,
    genesis_header: genesis!("29ab5f49ffff001d1dac2b7c"),
    pow_limit_bits: 0x1d00ffff,
    uahf_height: 478558,
    magnetic_anomaly_height: 556766,
    rpa_start_height: 825000,
    daa_height: 504031,
    asert_activation_height: 661647,
    asert_anchor_height: 661647,
    asert_anchor_parent_time: 1605447844,
    asert_anchor_bits: 0x1804dafe,
    asert_half_life: 2 * 24 * 3600,
    reduce_min_difficulty: false,
    no_difficulty_adjustment: false,
    checkpoints: MAINNET_CHECKPOINTS,
    cashaddr_prefix: "bitcoincash",
    dns_seeds: &[
        "seed.flowee.cash",
        "seed-bch.bitcoinforks.org",
        "btccash-seeder.bitcoinunlimited.info",
        "seed.bchd.cash",
        "seed.bch.loping.net",
        "dnsseed.electroncash.de",
    ],
};

pub static TESTNET3: Params = Params {
    name: "testnet3",
    magic: [0xf4, 0xe5, 0xf3, 0xf4],
    default_port: 18333,
    genesis_header: genesis!("dae5494dffff001d1aa4ae18"),
    pow_limit_bits: 0x1d00ffff,
    uahf_height: 1155875,
    magnetic_anomaly_height: 1267996,
    rpa_start_height: 0,
    daa_height: 1188697,
    asert_activation_height: 1421481,
    asert_anchor_height: 1421481,
    asert_anchor_parent_time: 1605445400,
    asert_anchor_bits: 0x1d00ffff,
    asert_half_life: 3600,
    reduce_min_difficulty: true,
    no_difficulty_adjustment: false,
    checkpoints: &[],
    cashaddr_prefix: "bchtest",
    dns_seeds: &[
        "testnet-seed-bch.bitcoinforks.org",
        "testnet-seed.bchd.cash",
        "seed.tbch.loping.net",
    ],
};

pub static TESTNET4: Params = Params {
    name: "testnet4",
    magic: [0xe2, 0xb7, 0xda, 0xaf],
    default_port: 28333,
    genesis_header: genesis!("f1a93c5fffff001d01d3cd06"),
    pow_limit_bits: 0x1d00ffff,
    uahf_height: 6,
    magnetic_anomaly_height: 4000,
    rpa_start_height: 0,
    daa_height: 3000,
    asert_activation_height: 16844,
    asert_anchor_height: 16844,
    asert_anchor_parent_time: 1605451779,
    asert_anchor_bits: 0x1d00ffff,
    asert_half_life: 3600,
    reduce_min_difficulty: true,
    no_difficulty_adjustment: false,
    checkpoints: TESTNET4_CHECKPOINTS,
    cashaddr_prefix: "bchtest",
    dns_seeds: &[
        "testnet4-seed-bch.toom.im",
        "seed.tbch4.loping.net",
        "testnet4-seed.flowee.cash",
    ],
};

pub static CHIPNET: Params = Params {
    name: "chipnet",
    magic: [0xe2, 0xb7, 0xda, 0xaf],
    default_port: 48333,
    genesis_header: genesis!("f1a93c5fffff001d01d3cd06"),
    pow_limit_bits: 0x1d00ffff,
    uahf_height: 6,
    magnetic_anomaly_height: 4000,
    rpa_start_height: 0,
    daa_height: 3000,
    asert_activation_height: 16844,
    asert_anchor_height: 16844,
    asert_anchor_parent_time: 1605451779,
    asert_anchor_bits: 0x1d00ffff,
    asert_half_life: 3600,
    reduce_min_difficulty: true,
    no_difficulty_adjustment: false,
    checkpoints: TESTNET4_CHECKPOINTS,
    cashaddr_prefix: "bchtest",
    dns_seeds: &["chipnet.imaginary.cash", "chipnet.bitjson.com"],
};

pub static REGTEST: Params = Params {
    name: "regtest",
    magic: [0xda, 0xb5, 0xbf, 0xfa],
    default_port: 18444,
    genesis_header: genesis!("dae5494dffff7f2002000000"),
    pow_limit_bits: 0x207fffff,
    uahf_height: 0,
    magnetic_anomaly_height: 0,
    rpa_start_height: 0,
    daa_height: 0,
    asert_activation_height: 0,
    asert_anchor_height: 0,
    asert_anchor_parent_time: 1296688602,
    asert_anchor_bits: 0x207fffff,
    asert_half_life: 3600,
    reduce_min_difficulty: true,
    no_difficulty_adjustment: true,
    checkpoints: &[],
    cashaddr_prefix: "bchreg",
    dns_seeds: &[],
};

pub static SIMNET: Params = Params {
    name: "simnet",
    magic: [0x16, 0x1c, 0x14, 0x12],
    default_port: 18555,
    genesis_header: genesis!("45068653ffff7f2002000000"),
    pow_limit_bits: 0x207fffff,
    uahf_height: 0,
    magnetic_anomaly_height: 3000,
    rpa_start_height: 0,
    daa_height: 2000,
    asert_activation_height: 4000,
    asert_anchor_height: 0,
    asert_anchor_parent_time: 1401292357,
    asert_anchor_bits: 0x207fffff,
    asert_half_life: 3600,
    reduce_min_difficulty: true,
    no_difficulty_adjustment: true,
    checkpoints: &[],
    cashaddr_prefix: "bchsim",
    dns_seeds: &[],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hashes_are_the_known_ones() {
        let cases = [
            (
                Network::Mainnet,
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            ),
            (
                Network::Testnet3,
                "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            ),
            (
                Network::Testnet4,
                "000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b",
            ),
            (
                Network::Chipnet,
                "000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b",
            ),
            (
                Network::Regtest,
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            ),
            (
                Network::Simnet,
                "683e86bd5c6d110d91b94b97137ba6bfe02dbbdb8e3dff722a669b5d69d77af6",
            ),
        ];
        for (network, hash) in cases {
            assert_eq!(network.params().genesis_hash().to_hex(), hash, "{network}");
        }
    }
}
