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

/// Waits until both peers had time to connect (the liar may already be
/// found out by then, in the first sync), then mines twenty blocks: their
/// filters come in a batch from one peer, checked against the other.
async fn both_connected_then_twenty_blocks(node: &Bchd, client: &LightClient) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while client.status().peers < 2 && Instant::now() < deadline {
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

/// Requests for filters of type 2 that reached the node without them.
static TYPE_2_ASKED_OF_PLAIN: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Two nodes that both say they serve committed filters, one with input
/// prefix filters (type 2) and one without, on the same chain. Batches of
/// type 2 went to both in turn: each one asked of the node without them
/// went unanswered, timed out, failed the round and closed the connection.
/// Now each node is asked once which filter types it serves (getcfcheckpt),
/// and batches go only to those that do: no getcfheaders or getcfilters of
/// type 2 reaches the node without them. (bchd also leaves type 1 requests
/// unanswered for a moment after a new block, while it does not count
/// itself current: such a batch now goes to the other peer.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_prefix_filters_come_only_from_nodes_that_serve_them() {
    let (Some(with), Some(without)) = (bchd_rpa_or_skip(), bchd_txid_binary_or_skip()) else {
        return;
    };
    let rpa = Bchd::start_with(&with, "types-rpa").await;
    let plain = Bchd::start_with(&without, "types-plain").await;
    plain
        .rpc("addnode", serde_json::json!([rpa.peer(), "add"]))
        .await;
    rpa.generate(110).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    while plain.height().await < 110 {
        assert!(Instant::now() < deadline, "the nodes did not connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    init_tracing();
    let watched = TamperProxy::observing(plain.p2p_port, |command, payload| {
        if matches!(command, "getcfheaders" | "getcfilters") && payload.first() == Some(&2) {
            TYPE_2_ASKED_OF_PLAIN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    })
    .await;
    let mut config = Config::new(
        Network::Regtest,
        rpa.dir.join("client"),
        vec![watched.peer(), rpa.peer()],
    );
    config.request_timeout = Duration::from_secs(30);
    config.learn_peers = false;
    config.rpa_filters = true;
    let client = LightClient::start(config).await.expect("start client");
    let deadline = Instant::now() + Duration::from_secs(30);
    while client.status().peers < 2 {
        assert!(Instant::now() < deadline, "both peers did not connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for round in 0..3 {
        rpa.generate(5).await;
        let tip = rpa.height().await;
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            let status = client.status();
            assert_eq!(
                TYPE_2_ASKED_OF_PLAIN.load(std::sync::atomic::Ordering::Relaxed),
                0,
                "round {round}: input prefix filters asked of the node without them"
            );
            if status.filter_height == Some(tip) && status.rpa_height == Some(tip) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "round {round}: not at {tip}: {status:?}"
            );
            client.poke();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    client.shutdown();
}

/// Only a node without input prefix filters: they never sync past their
/// start. A search of blocks the client has but whose input prefix filters
/// it lacks answered nothing found, as if no payment were there; it is now
/// an error that says how far the filters reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_rpa_search_past_the_input_prefix_filters_is_an_error() {
    let Some(without) = bchd_txid_binary_or_skip() else {
        return;
    };
    let node = Bchd::start_with(&without, "rpa-past").await;
    node.generate(30).await;
    init_tracing();
    let mut config = Config::new(Network::Regtest, node.dir.join("client"), vec![node.peer()]);
    config.request_timeout = Duration::from_secs(10);
    config.learn_peers = false;
    config.rpa_filters = true;
    let client = LightClient::start(config).await.expect("start client");
    client
        .wait_synced(Duration::from_secs(60))
        .await
        .expect("script filters sync");
    let prefix = bch_light_client::Prefix::new(0xbeef, 16).unwrap();
    let past = client.rpa_history(prefix, 0, 31).await;
    assert_eq!(
        past.as_ref().map_err(|e| e.kind()).err(),
        Some(bch_light_client::ErrorKind::Unavailable),
        "{past:?}"
    );
    // Blocks that do not exist yet are no error: there is nothing to find.
    assert!(client.rpa_history(prefix, 40, 50).await.unwrap().is_empty());
    client.shutdown();
}

/// More cover prefixes asked for than there are other prefixes of the
/// length: the search draws them all and goes on (it drew forever).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn more_cover_prefixes_than_exist_still_search() {
    let Some(with) = bchd_rpa_or_skip() else {
        return;
    };
    let node = Bchd::start_with(&with, "rpa-cover").await;
    node.generate(20).await;
    let mut config = Config::new(Network::Regtest, node.dir.join("client"), vec![node.peer()]);
    config.request_timeout = Duration::from_secs(10);
    config.learn_peers = false;
    config.rpa_filters = true;
    config.rpa_cover_prefixes = 1000;
    let client = LightClient::start(config).await.expect("start client");
    let deadline = Instant::now() + Duration::from_secs(60);
    while client.status().rpa_height != Some(20) {
        assert!(Instant::now() < deadline, "{:?}", client.status());
        client.poke();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let prefix = bch_light_client::Prefix::new(0x5a, 8).unwrap();
    let search = tokio::spawn({
        let client = client.clone();
        async move { client.rpa_history(prefix, 0, 21).await }
    });
    let found = tokio::time::timeout(Duration::from_secs(30), search)
        .await
        .expect("the search ended")
        .unwrap()
        .unwrap();
    assert!(found.is_empty());
    client.shutdown();
}
