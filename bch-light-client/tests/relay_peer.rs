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

    // New blocks: headers and blocks from either, filters from the first,
    // each well inside the timeout a filter request to the relay node would
    // wait; both connections stay up.
    for height in 111..=114 {
        filters.generate(1).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            client.poke();
            let status = client.status();
            if status.synced && status.filter_height == Some(height) {
                assert_eq!(status.peers, 2, "{status:?}");
                break;
            }
            assert!(Instant::now() < deadline, "no block {height}: {status:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert!(!client.in_mempool(&sent));
    client.shutdown();
}
