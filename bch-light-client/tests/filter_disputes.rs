//! Peers that serve wrong filters, made from an honest bchd by a man in the
//! middle that changes what it serves: each must be found out and dropped,
//! and filter sync must go on with the honest peer, never stall. Against
//! bchd on regtest; skipped when no bchd binary is found (set BCHD_BIN),
//! and failing instead in CI.

mod common;

use bch_light_client::{Config, LightClient, Network};
use common::*;
use std::time::{Duration, Instant};

/// Waits until the client has every filter of the node's chain and only
/// `peers` connections, the honest ones.
async fn settles_with(node: &Bchd, client: &LightClient, peers: usize, seconds: u64) {
    let height = node.height().await;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        let status = client.status();
        if status.synced && status.filter_height == Some(height) && status.peers == peers {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "filter sync did not settle at {height} with {peers} peer(s): {status:?}"
        );
        client.poke();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
}

async fn client_of(node: &Bchd, name: &str, peers: Vec<String>) -> LightClient {
    init_tracing();
    let mut config = Config::new(Network::Regtest, node.dir.join(name), peers);
    config.request_timeout = Duration::from_secs(10);
    config.learn_peers = false;
    LightClient::start(config).await.expect("start client")
}

/// A peer whose filter headers name, for the sixth block of each batch, a
/// filter hash that the filter it serves for that block does not have.
/// Asked as a witness, it disagreed with the honest peer, both served the
/// same filter, and the dispute ended in no verdict: an error every round,
/// no ban, and filters that never synced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_whose_filter_contradicts_its_own_header_is_dropped() {
    let Some(bin) = bchd_or_skip() else {
        return;
    };
    let node = Bchd::start_with(&bin, "dispute-self").await;
    node.generate(110).await;
    let liar = TamperProxy::start(node.p2p_port, |command, payload| {
        if command == "cfheaders" {
            let (at, count) = cfheaders_hashes(payload);
            if count > 5 {
                payload[at + 5 * 32] ^= 1;
            }
        }
    })
    .await;
    let client = client_of(&node, "client", vec![node.peer(), liar.peer()]).await;
    both_connected_then_twenty_blocks(&node, &client).await;
    settles_with(&node, &client, 1, 60).await;
    client.shutdown();
}

/// Waits for both connections, then mines twenty blocks: their filters
/// come in a batch from one peer, checked against the other.
async fn both_connected_then_twenty_blocks(node: &Bchd, client: &LightClient) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while client.status().peers < 2 {
        assert!(Instant::now() < deadline, "both peers did not connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    node.generate(20).await;
}

/// A peer whose filter headers for a batch chain from a previous filter
/// header that is not the one before them. Batch or witness, it disagreed
/// below the batch, served the same filters there, and the dispute ended in
/// no verdict every round, with no ban.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_whose_headers_do_not_chain_is_dropped() {
    let Some(bin) = bchd_or_skip() else {
        return;
    };
    let node = Bchd::start_with(&bin, "dispute-prev").await;
    node.generate(110).await;
    let liar = TamperProxy::start(node.p2p_port, |command, payload| {
        if command == "cfheaders" && cfheaders_hashes(payload).1 > 1 {
            payload[33] ^= 1;
        }
    })
    .await;
    let client = client_of(&node, "client", vec![node.peer(), liar.peer()]).await;
    both_connected_then_twenty_blocks(&node, &client).await;
    settles_with(&node, &client, 1, 60).await;
    client.shutdown();
}
