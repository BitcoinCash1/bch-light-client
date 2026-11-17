//! What the client must never do for what a wallet watches: download the
//! blocks of a watched payment's inputs to learn its fee, or fetch anything
//! to check a double-spend proof it cannot check from what it holds.
//! Against bchd on regtest, with filters that hold transaction keys (a
//! lookup by ID alone would work, so only the client's own rule stops it).

mod common;

use bch_light_client::{Config, LightClient, Network, Target, TokenFilter, Txid};
use common::*;
use std::time::{Duration, Instant};

async fn synced_client(node: &Bchd, name: &str) -> LightClient {
    let mut config = Config::new(Network::Regtest, node.dir.join(name), vec![node.peer()]);
    config.request_timeout = Duration::from_secs(20);
    let client = LightClient::start(config).await.expect("start client");
    let height = node.height().await;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = client.status();
        if status.synced && status.filter_height == Some(height) && status.txid_keys.is_some() {
            return client;
        }
        assert!(Instant::now() < deadline, "not synced: {status:?}");
        client.poke();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_mempool(client: &LightClient, txid: &Txid) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !client.in_mempool(txid) {
        assert!(Instant::now() < deadline, "{txid} not in the mempool copy");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A watched payment in the mempool that spends a coin older than the last
/// blocks: its fee stays unknown, and no block is downloaded to learn it.
/// Fetching the block of its input would tell the peer which payment the
/// wallet looks at.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_watched_payment_fee_is_never_looked_up() {
    let Some(bin) = bchd_txid_binary_or_skip() else {
        return;
    };
    let node = Bchd::start_with(&bin, "privacy-fee").await;
    node.generate(140).await;
    let client = synced_client(&node, "client").await;
    let key = Key::new(31);
    let target = Target::Script(key.script());
    client.watch([target.clone()]).await.unwrap();
    // A coin of block 1: well before the last 24 blocks the client keeps.
    let (coinbase, value) = node.coinbase(1).await;
    let pay = TxSpec {
        inputs: vec![(coinbase, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(value - 5000, key.script(), vec![])],
    }
    .build();
    let txid = Txid::from_hex(&node.send(&pay).await).unwrap();
    wait_mempool(&client, &txid).await;
    let before = client.stats().blocks_downloaded;
    let history = client.history(&target).await.unwrap();
    assert_eq!(history.mempool.len(), 1);
    assert_eq!(history.mempool[0].fee, None, "a fee not held is left out");
    let balance = client.balance(&target, TokenFilter::Include).await.unwrap();
    assert_eq!(balance.unconfirmed, (value - 5000) as i64);
    assert_eq!(
        client.stats().blocks_downloaded,
        before,
        "no block was downloaded for the fee"
    );
    client.shutdown();
}
