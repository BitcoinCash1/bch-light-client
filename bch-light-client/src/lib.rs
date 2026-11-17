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
//! # What peers can learn
//!
//! - **Service peers** (a few long-lived connections) serve headers and all
//!   filters, relay every transaction they accept, and see every new block
//!   at the tip fetched, since the client downloads all of them. None of
//!   that depends on what the wallet watches. They see a broadcast
//!   transaction's origin unless it goes through a proxy.
//! - **Block downloads for a scan** are the one place interest shows: a peer
//!   that serves a block a wallet needed learns that the block is one of
//!   those the wallet's filters matched. A peer that sees the same client
//!   fetch two or three such blocks could intersect their scripts and find
//!   the address, so downloads are spread out:
//!   - *Direct connections:* blocks go round the peers, a different peer for
//!     each block in turn. Every peer still sees this host's IP address, so
//!     the blocks one peer serves are linkable to each other, and peers that
//!     share what they see can link all of them. Use several unrelated peers.
//!   - *Through a SOCKS5 proxy such as Tor* (the default once a proxy is
//!     set): each block is fetched over a new connection with its own
//!     random SOCKS credentials, which Tor puts on its own circuit, so peers
//!     cannot link one download to another by address. What is left is
//!     timing: downloads close together in time can be guessed to belong
//!     together.
//!   - [`Config::decoy_blocks`] adds random blocks to each scan, and
//!     [`Config::download_all_blocks`] fetches every block of a scanned
//!     range, so that which blocks are fetched says nothing at all.
//! - **Lookups by transaction ID** fetch the block the filters point to,
//!   which shows interest in that block in the same way.
//! - Peer host names go to the proxy unresolved; the client makes no DNS
//!   lookups of its own through a proxy.

// `is_multiple_of` and `as_chunks` are newer than the Rust some wallets
// that embed this library build with.
#![allow(
    unknown_lints,
    clippy::manual_is_multiple_of,
    clippy::chunks_exact_with_const_size
)]

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
pub mod tx;

pub use client::{
    Balance, Config, Confirmation, DsProofInfo, Event, FeeEstimate, History, LightClient,
    MempoolEntry, MempoolSummary, MerkleProof, OutputInfo, RpaMatch, Stats, Status, TokenFilter,
    TxInfo, Utxo,
};
pub use error::{Error, ErrorKind, Result};
pub use hash::{BlockHash, Txid};
pub use history::{ConfirmedTx, Received, Spent, Target};
pub use params::Network;
pub use rpa::Prefix;
pub use tx::{Category, Nft, NftCapability, OutPoint, TokenData, Transaction, TxOut};
