//! A configured node that serves no filters, as BCHN, beside one that serves
//! them but offers no bloom filters, as kth: filters come only from the
//! first; the second's mempool (the mempool message, which the first would
//! disconnect for) and its relay reach the client. Against two bchd on
//! regtest; skipped when no bchd binary is found (set BCHD_BIN).

mod common;

use bch_light_client::{Config, LightClient, Network, OutPoint, Target, TokenFilter, Txid};
use common::*;
use serde_json::json;
use std::time::{Duration, Instant};

async fn wait_for<F: std::future::Future<Output = bool>>(what: &str, mut done: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done().await {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn in_mempool(node: &Bchd, txid: &str) -> bool {
    node.rpc("getrawmempool", json!([]))
        .await
        .as_array()
        .is_some_and(|ids| ids.iter().any(|id| id == txid))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_without_filters_relays_and_is_never_asked_for_filters() {
    let Some(bin) = bchd_binary() else {
        eprintln!("skipped: no bchd binary (set BCHD_BIN)");
        return;
    };
    let filters = Bchd::start_args(&bin, "relay-filters", &["--nopeerbloomfilters"]).await;
    let relay = Bchd::start_args(&bin, "relay-only", &["--nocfilters"]).await;
    relay.rpc("addnode", json!([filters.peer(), "add"])).await;
    filters.generate(110).await;
    wait_for("the relay node follows", || async {
        relay.height().await == 110
    })
    .await;

    // A payment in both mempools before the client starts.
    let key = Key::new(21);
    let (coinbase, value) = filters.coinbase(1).await;
    let early = TxSpec {
        inputs: vec![(coinbase, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(value - 3000, key.script(), vec![])],
    }
    .build();
    let early_id = filters.send(&early).await;
    wait_for("the payment reaches the relay node", || async {
        in_mempool(&relay, &early_id).await
    })
    .await;

    let dir = filters.dir.join("client");
    let mut config = Config::new(Network::Regtest, &dir, vec![filters.peer(), relay.peer()]);
    // A filter request to the relay node would go unanswered for this long.
    config.request_timeout = Duration::from_secs(30);
    let client = LightClient::start(config).await.expect("start client");
    wait_for("both nodes connected", || async {
        client.status().peers == 2
    })
    .await;
    // Each filter batch is checked against a second peer that serves
    // filters: asked of the relay node, it would wait out the timeout.
    let status = client
        .wait_synced(Duration::from_secs(20))
        .await
        .expect("filters from the node that serves them, without waiting on the other");
    assert_eq!(status.filter_height, Some(110));
    assert_eq!(status.peers, 2, "{status:?}");

    let early_txid = Txid::from_hex(&early_id).unwrap();
    wait_for("the payment from the relay node's mempool", || async {
        client.in_mempool(&early_txid)
    })
    .await;
    let target = Target::Script(key.script());
    client.watch([target.clone()]).await.unwrap();
    let balance = client.balance(&target, TokenFilter::Include).await.unwrap();
    assert_eq!(balance.unconfirmed, (value - 3000) as i64);

    // A broadcast reaches both nodes, whichever the client sends it to.
    let spend = TxSpec {
        inputs: vec![(
            OutPoint::new(early_txid, 0),
            Unlock::Sign(&key, value - 3000),
        )],
        outputs: vec![(value - 6000, mining_script(), vec![])],
    }
    .build();
    let sent = client.broadcast(&spend).await.expect("broadcast");
    assert_eq!(sent, txid_of(&spend));
    for node in [&filters, &relay] {
        wait_for("the broadcast reaches both nodes", || async {
            in_mempool(node, &sent.to_hex()).await
        })
        .await;
    }

    // New blocks, mined on the relay node as BCHN mines them for kth: it
    // announces each before the other node may have it. Headers and filters
    // come from the node that serves filters, blocks from either, each well
    // inside the timeout a filter request for a block the node does not have
    // would wait; both connections stay up.
    let synced_at = |height: u32| {
        let client = client.clone();
        async move {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                client.poke();
                let status = client.status();
                if status.synced && status.filter_height == Some(height) {
                    assert_eq!(status.peers, 2, "{status:?}");
                    return;
                }
                assert!(Instant::now() < deadline, "no block {height}: {status:?}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    for height in 111..=112 {
        relay.generate(1).await;
        synced_at(height).await;
    }
    assert!(!client.in_mempool(&sent));

    // The relay node alone mines two blocks: the client hears of them from
    // it, but takes headers only from the node that serves filters, so it
    // never asks that node for the filters of blocks it does not have.
    relay
        .rpc("addnode", json!([filters.peer(), "remove"]))
        .await;
    wait_for("the nodes part", || async {
        relay
            .rpc("getpeerinfo", json!([]))
            .await
            .as_array()
            .is_some_and(|peers| peers.len() == 1)
    })
    .await;
    let mined = relay.generate(2).await;
    let quiet = Instant::now() + Duration::from_secs(3);
    while Instant::now() < quiet {
        client.poke();
        let status = client.status();
        assert_eq!(
            (status.header_height, status.filter_height, status.peers),
            (112, Some(112), 2),
            "{status:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Once the other node has them, they come from it.
    for hash in &mined {
        let raw = relay.rpc("getblock", json!([hash, false])).await;
        filters.rpc("submitblock", json!([raw])).await;
    }
    synced_at(114).await;
    client.shutdown();
}

/// A node that takes a broadcast transaction but never gives it back when
/// asked, as BCHN serves only transactions it announced to the asker: the
/// broadcast is known to be taken in when another node announces it. Two
/// connections to one bchd, one through a man in the middle that answers
/// every transaction with notfound; broadcasts go to each in turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broadcast_is_taken_in_when_another_node_announces_it() {
    let Some(bin) = bchd_or_skip() else {
        return;
    };
    let node = Bchd::start_with(&bin, "relay-echo").await;
    node.generate(110).await;
    let silent = TamperProxy::rewriting(node.p2p_port, |command, payload| {
        if command == "tx" {
            let mut inv = vec![1u8];
            inv.extend_from_slice(&1u32.to_le_bytes());
            inv.extend_from_slice(&hash256(payload));
            *command = "notfound".to_string();
            *payload = inv;
        }
    })
    .await;
    let mut config = Config::new(
        Network::Regtest,
        node.dir.join("client"),
        vec![silent.peer(), node.peer()],
    );
    config.request_timeout = Duration::from_secs(30);
    config.learn_peers = false;
    let client = LightClient::start(config).await.expect("start client");
    wait_for("both connected", || async { client.status().peers == 2 }).await;
    client.wait_synced(Duration::from_secs(30)).await.unwrap();
    for height in 1..=2u32 {
        let (coinbase, value) = node.coinbase(height).await;
        let tx = TxSpec {
            inputs: vec![(coinbase, Unlock::Redeem(vec![0x51]))],
            outputs: vec![(value - 3000, mining_script(), vec![])],
        }
        .build();
        let started = Instant::now();
        let sent = client.broadcast(&tx).await.expect("taken in");
        assert_eq!(sent, txid_of(&tx));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert!(in_mempool(&node, &sent.to_hex()).await);
    }
    client.shutdown();
}
