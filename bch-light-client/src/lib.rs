//! A Bitcoin Cash light client for wallets, with no index anywhere.
//!
//! The client is a P2P peer of Bitcoin Cash nodes. It keeps every block
//! header (checked for proof of work and the difficulty rules), a copy of
//! every block's script filter (filter type 1), and a copy of the mempool
//! filled by ordinary transaction relay. To learn what a wallet's scripts
//! or token categories did, it matches them against its filters itself, on
//! every core, and downloads the whole blocks that match. It never sends a
//! peer anything that names what it watches.
//!
//! ```no_run
//! use bch_light_client::{Config, LightClient, Network, Target, TokenFilter};
//! # async fn demo() -> Result<(), bch_light_client::Error> {
//! let config = Config::new(Network::Mainnet, "/path/to/data", vec!["node.example:8333".into()]);
//! let client = LightClient::start(config).await?;
//! client.wait_synced(std::time::Duration::from_secs(600)).await?;
//! let script = hex::decode("76a914000102030405060708090a0b0c0d0e0f1011121388ac").unwrap();
//! let target = Target::Script(script);
//! client.watch([target.clone()]).await?;
//! let balance = client.balance(&target, TokenFilter::Include).await?;
//! let coins = client.unspent(&target, TokenFilter::Include).await?;
//! let mut events = client.subscribe();
//! # let _ = (balance, coins, events.recv().await);
//! # Ok(()) }
//! ```
//!
//! # What peers can learn, and the defaults that limit it
//!
//! The defaults protect: nothing has to be turned on.
//!
//! - **Service peers** (a few long-lived connections) serve headers and all
//!   filters, and relay every transaction they accept. They also see every
//!   new block at the tip fetched, since the client downloads all of them.
//!   None of that depends on what the wallet watches. A configured node
//!   that serves no filters (such as BCHN) is a service peer for headers,
//!   relay, its mempool and double-spend proofs, and is never asked for
//!   filters.
//! - **Block downloads for a lookup** are the one place interest shows: a
//!   peer that serves a block a wallet needed learns that someone wanted
//!   it. So by default:
//!   - Each block comes over a connection of its own
//!     ([`Config::isolate_block_downloads`]). The service peers do not see
//!     which blocks follow, and no peer sees two blocks asked for over one
//!     connection.
//!     - Through a SOCKS5 proxy such as Tor, each such connection has its
//!       own random credentials, which Tor puts on a circuit of its own,
//!       so peers cannot link downloads by address either.
//!     - Without a proxy, every peer still sees this host's IP address. Use
//!       a proxy, or several unrelated peers.
//!   - Each needed block brings three decoys ([`Config::decoy_blocks`])
//!     from its bucket of 144 heights. Decoy `draw` of the block at
//!     `height` is SHA-256(seed, height, draw) modulo 144, with a seed made
//!     once for the data folder (`decoys.seed`). The same block brings the
//!     same decoys in every session, so a peer that intersects what several
//!     sessions downloaded learns nothing new. A block in the bucket at the
//!     tip, which is not complete yet, brings that whole bucket.
//!   - Every lookup takes the same cover: histories, transactions by ID or
//!     by position, output spends, token geneses and the spenders of
//!     identity outputs.
//!   - A transaction found once is kept (10,000 at most), so asking again,
//!     as a subscription does, downloads nothing. The same goes for an
//!     output checked for a spender.
//!   - An RPA search downloads every block of its range
//!     ([`Config::rpa_whole_ranges`]), so which blocks it reads names no
//!     prefix, and it needs no input prefix filters.
//!   - [`Config::download_all_blocks`] goes further for histories, and
//!     reads every block of a scanned range.
//! - **A broadcast** goes over a connection of its own too, so the node
//!   that takes it in does not see it come from a connection that fetched
//!   the wallet's blocks. Without a proxy, the node sees this host's IP
//!   address.
//! - **The user agent** is Bitcoin Cash Node's current release
//!   ([`DEFAULT_USER_AGENT`]), the most common one on the network. A user
//!   agent of the client's own would mark every connection and link them
//!   together. The rest of the version message (no services, no address)
//!   still shows that a light client connected.
//! - Peer host names go to the proxy unresolved; the client makes no DNS
//!   lookups of its own through a proxy.
//!
//! # What the protections cost
//!
//! The `what_the_cover_costs` test measures this: bytes a bchd on regtest
//! sent for one operation on a fresh client, with blocks of about 300
//! bytes.
//!
//! | Operation | Defaults | Decoys and isolation off |
//! |---|---|---|
//! | A history needing 3 blocks: two in one bucket, one in the bucket at the tip | 23,141 bytes, 20 blocks | 882 bytes, 3 blocks |
//! | A transaction by ID | 4,750 bytes, 4 blocks | 294 bytes, 1 block |
//! | An RPA search of 60 blocks | 68,727 bytes, 60 blocks | 294 bytes, the one matching block |
//!
//! Regtest blocks are tiny, so these numbers are mostly handshakes: each
//! connection of its own costs about 900 bytes of version messages. On
//! mainnet the blocks dominate:
//! - Each needed block costs four blocks instead of one. A block in the
//!   bucket at the tip costs that whole bucket, up to 144 blocks.
//! - An RPA search costs every block of its range.
//!
//! With blocks of 300 KB, for example:
//! - A history that touches 100 blocks downloads about 120 MB instead of
//!   30 MB, once: histories are saved, and transactions found are kept.
//! - A 60-block RPA search (Fulcrum's limit) downloads about 18 MB,
//!   whatever the prefix.
//!
//! That is the price of a peer learning nothing.

// `is_multiple_of` and `as_chunks` are newer than the Rust some wallets
// that embed this library build with.
#![allow(
    unknown_lints,
    clippy::manual_is_multiple_of,
    clippy::chunks_exact_with_const_size
)]

pub mod bcmr;
pub mod block;
pub mod cashaddr;
pub mod chain;
mod client;
pub mod dispute;
pub mod dsproof;
pub mod encode;
mod error;
pub mod fetch;
pub mod filter;
pub mod filterstore;
pub mod gcs;
pub mod hash;
pub mod history;
pub mod mempool;
pub mod p2p;
pub mod params;
pub mod pow;
pub mod rpa;
pub mod scan;
pub mod script;
pub mod tx;

pub use client::{
    balances_of, supply_of, Authchain, Balance, CategoryBalance, Config, Confirmation, DsProofInfo,
    Event, FeeEstimate, History, LightClient, MempoolEntry, MempoolSummary, MerkleProof,
    OutputInfo, RpaMatch, Stats, Status, TokenFilter, TokenHolding, TokenSupply, TxInfo, Utxo,
    DEFAULT_USER_AGENT,
};
pub use error::{Error, ErrorKind, Result};
pub use hash::{BlockHash, Txid};
pub use history::{ConfirmedTx, Received, Spent, Target};
pub use params::Network;
pub use rpa::Prefix;
pub use tx::{Category, Nft, NftCapability, OutPoint, TokenData, Transaction, TxOut};
