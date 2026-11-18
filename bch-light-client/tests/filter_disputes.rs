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

/// bchd that serves input prefix filters: $BCHD_RPA_BIN or .tools/bchd-rpa.
fn bchd_rpa_or_skip() -> Option<std::path::PathBuf> {
    let path = std::env::var("BCHD_RPA_BIN")
        .map(Into::into)
        .unwrap_or_else(|_| {
            let exe = if cfg!(windows) {
                "bchd-rpa.exe"
            } else {
                "bchd-rpa"
            };
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(".tools")
                .join(exe)
        });
    if path.exists() {
        return Some(path);
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "bchd with input prefix filters is missing (set BCHD_RPA_BIN)"
    );
    eprintln!("skipped: no bchd with input prefix filters (set BCHD_RPA_BIN)");
    None
}

/// The block whose input prefix filter the liar replaces, internal order.
static WRONG_RPA_BLOCK: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// Serves an empty input prefix filter (one byte, 0) for WRONG_RPA_BLOCK,
/// with filter headers that fit it, so the client keeps it unchallenged.
fn wrong_rpa_filter(command: &str, payload: &mut Vec<u8>) {
    let Some(block) = WRONG_RPA_BLOCK.get() else {
        return;
    };
    if payload.first() != Some(&2) || payload.get(1..33) != Some(&block[..]) {
        return;
    }
    match command {
        "cfilter" => {
            payload.truncate(33);
            payload.extend_from_slice(&[1, 0]);
        }
        "cfheaders" => {
            let (at, count) = cfheaders_hashes(payload);
            let last = at + (count - 1) * 32;
            payload[last..last + 32].copy_from_slice(&hash256(&[0]));
        }
        _ => {}
    }
}

/// A wrong input prefix filter (type 2), found when its block is read,
/// stopped the type 1 work that read the block: a watched payment in that
/// block could not be applied, and sync rounds failed. Now the wrong filter
/// and those above it go, the peer that served it is banned, and the block
/// is used.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_input_prefix_filter_does_not_stop_histories() {
    let Some(bin) = bchd_rpa_or_skip() else {
        return;
    };
    let node = Bchd::start_with(&bin, "dispute-rpa").await;
    node.generate(110).await;
    let key = Key::new(51);
    let (coinbase, value) = node.coinbase(1).await;
    let pay = TxSpec {
        inputs: vec![(coinbase, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(value - 3000, key.script(), vec![])],
    }
    .build();
    node.send(&pay).await;
    let block = node.generate(1).await.remove(0);
    let mut hash: [u8; 32] = hex::decode(&block).unwrap().try_into().unwrap();
    hash.reverse();
    WRONG_RPA_BLOCK.set(hash).unwrap();
    let liar = TamperProxy::start(node.p2p_port, wrong_rpa_filter).await;
    init_tracing();
    let mut config = Config::new(Network::Regtest, node.dir.join("client"), vec![liar.peer()]);
    config.request_timeout = Duration::from_secs(10);
    config.learn_peers = false;
    config.rpa_filters = true;
    let client = LightClient::start(config).await.expect("start client");
    let target = bch_light_client::Target::Script(key.script());
    let deadline = Instant::now() + Duration::from_secs(60);
    let history = loop {
        if client.status().filter_height == Some(111) {
            if let Ok(Ok(h)) =
                tokio::time::timeout(Duration::from_secs(10), client.history(&target)).await
            {
                break h;
            }
        }
        assert!(
            Instant::now() < deadline,
            "no history: {:?}",
            client.status()
        );
        client.poke();
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(history.confirmed.len(), 1, "the payment in block 111");
    assert_eq!(history.confirmed[0].height, 111);
    // The peer that served it is banned: no connection is left, and the
    // wrong filter is not fetched again.
    let deadline = Instant::now() + Duration::from_secs(20);
    while client.status().peers > 0 {
        assert!(
            Instant::now() < deadline,
            "the liar was not banned: {:?}",
            client.status()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (_, rpa_tip) = client.rpa_heights().unwrap();
    assert!(rpa_tip < Some(111), "the wrong filter went: {rpa_tip:?}");
    client.shutdown();
}

/// The block whose script filter the liar replaces, internal order.
static WRONG_SCRIPT_BLOCK: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// Serves an empty script filter (a zero root and no keys) for
/// WRONG_SCRIPT_BLOCK, with filter headers that fit it.
fn wrong_script_filter(command: &str, payload: &mut Vec<u8>) {
    let Some(block) = WRONG_SCRIPT_BLOCK.get() else {
        return;
    };
    if payload.first() != Some(&1) || payload.get(1..33) != Some(&block[..]) {
        return;
    }
    let empty = [0u8; 33];
    match command {
        "cfilter" => {
            payload.truncate(33);
            payload.push(33);
            payload.extend_from_slice(&empty);
        }
        "cfheaders" => {
            let (at, count) = cfheaders_hashes(payload);
            let last = at + (count - 1) * 32;
            payload[last..last + 32].copy_from_slice(&hash256(&empty));
        }
        _ => {}
    }
}

/// A script filter that its block contradicts, found when the block is
/// read, failed every read of the block and was never dropped. Now it goes
/// with those above it, histories from it are read again, and the peer
/// that served it is banned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_script_filter_is_dropped_with_its_peer() {
    let Some(bin) = bchd_or_skip() else {
        return;
    };
    let node = Bchd::start_with(&bin, "dispute-script").await;
    node.generate(110).await;
    let block = node.generate(1).await.remove(0);
    let mut hash: [u8; 32] = hex::decode(&block).unwrap().try_into().unwrap();
    hash.reverse();
    WRONG_SCRIPT_BLOCK.set(hash).unwrap();
    let liar = TamperProxy::start(node.p2p_port, wrong_script_filter).await;
    let client = client_of(&node, "client", vec![liar.peer()]).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = client.status();
        if status.peers == 0 && status.filter_height == Some(110) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the wrong filter stayed: {status:?}"
        );
        client.poke();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    client.shutdown();
}
