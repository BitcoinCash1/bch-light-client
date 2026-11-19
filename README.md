# bch-light-client

A private Bitcoin Cash light client in Rust, with no index anywhere, and an Electrum bridge for wallets that do not speak P2P.

The client is an ordinary P2P peer of Bitcoin Cash nodes. It keeps the block headers, a copy of every block's compact filters, and a copy of the mempool from ordinary relay. To learn what a wallet's addresses, tokens or reusable payment addresses did, it matches them against its own filters, on every core, and downloads the whole blocks that match. No node is ever told which addresses, scripts, token categories, transactions or prefixes the wallet watches. No server keeps an index of anyone's addresses.

[![CI](https://github.com/BitcoinCash1/bch-light-client/actions/workflows/ci.yml/badge.svg)](https://github.com/BitcoinCash1/bch-light-client/actions/workflows/ci.yml) ![License: MIT](https://img.shields.io/badge/license-MIT-blue)

## Why

Most Bitcoin Cash wallets ask an Electrum server such as Fulcrum about their addresses. The server learns every address, links them to one user, and must keep an index of every address in the chain, which grows with every transaction. This client replaces that with what the nodes already have: filters built from each block, and the blocks themselves.

| | Indexing server (Fulcrum) | bch-light-client |
|---|---|---|
| Who learns the wallet's addresses | the server, on every query | no one: the filters are matched on the wallet's own device |
| Answers checked | trusted as given | headers by proof of work, filters against their headers and other peers, blocks against their Merkle roots |
| Server-side storage | an address index that grows with the chain | none: nodes serve filters built from their blocks |
| Who can serve | servers that run the indexer | any node that serves compact filters |

Measured side by side on the same regtest chain (Fulcrum 2.1.4 on BCHN; the bridge on a Knuth node serving filters; [run 44618265629](https://github.com/BitcoinCash1/knuth-bch-startos/actions/runs/44618265629)):

| | Fulcrum | bch-light-client |
|---|---|---|
| Storage | 2,813,803 bytes | 603,734 bytes from genesis, 227,621 from a wallet birthday |
| Sync | 1.0 s | 0.5 s |
| Downloaded to answer | at least 829,102 bytes of block data | 316,256 bytes from genesis |
| Electrum answers | — | 174 of 187 calls equal to Fulcrum's; the other 13 differ on purpose (listed in the harness) |

## What it does

- **Histories, balances and unspent outputs** of scripts and addresses (P2PKH, P2SH20, P2SH32, bare scripts), with token data and a token filter.
- **CashTokens:** balances per category, supply (total, reserved, circulating) and genesis, all from the filters with no index.
- **BCMR:** authchains resolved and followed spend by spend, a registry's `authchain` extension checked, and a registry's bytes checked against its published hash. The client never fetches a registry: the wallet downloads it and asks the client to check it.
- **Reusable payment addresses (RPA):** input prefix filters (filter type 2) and lookups by prefix.
- **Lookups by transaction ID alone**, through the transaction keys in the script filters.
- **Unconfirmed transactions** from relay, and **double-spend proofs** checked against the coins the client holds.
- **Broadcast.**
- **Wallet birthday:** a restore downloads filters only from the wallet's own years.
- **Reorganizations:** filters and histories roll back to the fork.
- **Disputes between peers** settled by downloading the block, and the lying peer refused.
- **Tor:** with a SOCKS5 proxy, each block comes over a circuit of its own.

## Crates

| Crate | What it is |
|---|---|
| [`bch-light-client`](bch-light-client) | The library: headers, filters (types 1 and 2), scans, histories, tokens, BCMR, RPA, mempool, double-spend proofs, broadcast. Embed it in a wallet. |
| [`bch-electrum-bridge`](bch-electrum-bridge) | Only for wallets that do not speak P2P: answers the Electrum protocol on a loopback address, from the library in the same process. See its [README](bch-electrum-bridge/README.md). |

A wallet that can embed Rust should use the library directly and be a P2P light client itself. The bridge is a compatibility layer for wallets that cannot.

## Using the library

```rust
use bch_light_client::{Config, LightClient, Network, Target, TokenFilter};

let config = Config::new(Network::Mainnet, "/path/to/data", vec!["node.example:8333".into()]);
let client = LightClient::start(config).await?;
client.wait_synced(std::time::Duration::from_secs(600)).await?;

let target = Target::Script(hex::decode("76a914000102030405060708090a0b0c0d0e0f1011121388ac").unwrap());
client.watch([target.clone()]).await?;
let balance = client.balance(&target, TokenFilter::Include).await?;
let coins = client.unspent(&target, TokenFilter::Include).await?;
let mut events = client.subscribe(); // new blocks, payments, double-spend proofs
```

The crate documentation (`cargo doc --open`) explains what peers can and cannot learn, and the `Config` options that limit it: a proxy, isolated block downloads, decoy blocks, downloading every block of a range, and cover prefixes for RPA.

## Running the bridge

```bash
cargo run --release -p bch-electrum-bridge -- --network mainnet --datadir ~/.bch-bridge --peer node1.example:8333 --peer node2.example:8333 --listen 127.0.0.1:50001
```

Point the wallet at `127.0.0.1:50001`. The bridge refuses any address that is not loopback: it serves wallets on the same machine, never a network. More options (`--proxy`, `--birthday`, `--decoy-blocks`, `--download-all-blocks`, `--dns-seeds`, RPA settings) are in `--help` and in the [bridge README](bch-electrum-bridge/README.md).

## Which nodes serve the filters

The client needs at least one node that serves script filters (filter type 1, with transaction keys). Input prefix filters (type 2) are needed for RPA. Both formats are open pull requests, so today they come from the branches of those PRs:

- **Knuth:** k-nuth/kth#1002, #1003, #1004 (type 1) and #1013 (type 2).
- **BCHD:** gcash/bchd#776, #777, #778 (type 1) and #785 (type 2).

A node that serves no filters, such as BCHN, still serves headers, blocks, relay and double-spend proofs, and the client uses it for those.

## Building and testing

```bash
cargo build --release
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

The node tests start a BCHD built from the filter PRs above, found through `BCHD_BIN`. In CI they fail when no BCHD is available instead of being skipped. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) builds BCHD from those PRs, scans the repository and every dependency tree for a known malicious loader, then runs fmt, clippy and the tests. The comparison with Fulcrum and the CashTokens and BCMR checks against BCHN's blocks run in [BitcoinCash1/knuth-bch-startos](https://github.com/BitcoinCash1/knuth-bch-startos).

The crates are not on crates.io yet.

## Related

- **Knuth wallet support:** the same design inside the Knuth node, in C++, with answers from the node's own chain on a full node and from peers otherwise (k-nuth/kth#1040–#1049).
- **[BCH Explorer](https://github.com/BitcoinCash1/bitcoin-cash-explorer):** its P2P backend reads the same filters.

## License

[MIT](LICENSE)
