//! The download pattern the defaults give, as a peer sees it: which blocks
//! are asked for, and over which connections. Each needed block brings
//! three decoys from its bucket of 144 heights, derived from the data
//! folder's seed (the same after a restart). The bucket at the tip is
//! taken whole. Every block, and a broadcast, comes over a connection of
//! its own. A lookup asked again downloads nothing, and an RPA search
//! downloads its whole range. Against bchd on regtest through a proxy that
//! records what the client sends.

mod common;

use bch_light_client::rpa::input_value;
use bch_light_client::{Config, LightClient, Network, OutPoint, Prefix, Target, Transaction, Txid};
use common::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TIP: u32 = 300;

/// A chain of 300 blocks with three payments to `key`: at 150 and 200 (the
/// bucket 144..=287) and at 295 (the bucket at the tip, 288 on).
struct Chain {
    key: Key,
    payments: Vec<(Txid, u32, Vec<u8>)>,
    heights: HashMap<[u8; 32], u32>,
}

async fn chain(node: &Bchd) -> Chain {
    let key = Key::new(61);
    let mut payments = Vec::new();
    for (coinbase_height, at) in [(1, 150), (2, 200), (3, 295)] {
        let tip = node.height().await;
        node.generate(at - 1 - tip).await;
        let (coinbase, value) = node.coinbase(coinbase_height).await;
        let raw = TxSpec {
            inputs: vec![(coinbase, Unlock::Redeem(vec![0x51]))],
            outputs: vec![(value - 5000, key.script(), vec![])],
        }
        .build();
        let txid = Txid::from_hex(&node.send(&raw).await).unwrap();
        node.generate(1).await;
        let block = node.block(at).await;
        assert!(
            block["tx"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["txid"] == json!(txid.to_hex())),
            "payment at {at}"
        );
        payments.push((txid, at, raw));
    }
    node.generate(TIP - node.height().await).await;
    let mut heights = HashMap::new();
    for height in 0..=TIP {
        let hash = node.rpc("getblockhash", json!([height])).await;
        let mut bytes: [u8; 32] = hex::decode(hash.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        bytes.reverse();
        heights.insert(bytes, height);
    }
    Chain {
        key,
        payments,
        heights,
    }
}

async fn start(proxy: &TamperProxy, dir: &Path, change: impl FnOnce(&mut Config)) -> LightClient {
    let mut config = Config::new(Network::Regtest, dir, vec![proxy.peer()]);
    config.learn_peers = false;
    config.request_timeout = Duration::from_secs(20);
    change(&mut config);
    let client = LightClient::start(config).await.expect("start client");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = client.status();
        // Synced, and the block at the tip read (the client follows the tip).
        if status.synced
            && status.filter_height == Some(TIP)
            && status.txid_keys.is_some()
            && client.stats().blocks_downloaded >= 1
        {
            break;
        }
        assert!(Instant::now() < deadline, "not synced: {status:?}");
        client.poke();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    client
}

/// The blocks asked for in `sent` from entry `from` on: (connection, height).
fn blocks_asked(sent: &Mutex<Vec<Sent>>, from: usize, chain: &Chain) -> Vec<(usize, u32)> {
    sent.lock().unwrap()[from..]
        .iter()
        .filter(|s| s.command == "getdata")
        .flat_map(|s| {
            inv_blocks(&s.payload)
                .into_iter()
                .map(|h| (s.connection, chain.heights[&h]))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn heights(asked: &[(usize, u32)]) -> BTreeSet<u32> {
    asked.iter().map(|(_, h)| *h).collect()
}

/// The decoys the specification gives: SHA-256(seed, height, draw) within
/// the block's bucket of 144, three of them; the bucket at the tip whole.
fn expected_cover(seed: &[u8; 32], height: u32, tip: u32) -> BTreeSet<u32> {
    let start = height - height % 144;
    if start + 143 > tip {
        return (start..=tip).collect();
    }
    let mut out = BTreeSet::from([height]);
    let mut draw = 0u32;
    while out.len() < 4 {
        let digest = Sha256::new()
            .chain_update(seed)
            .chain_update(height.to_le_bytes())
            .chain_update(draw.to_le_bytes())
            .finalize();
        out.insert(start + (u64::from_le_bytes(digest[..8].try_into().unwrap()) % 144) as u32);
        draw += 1;
    }
    out
}

fn seed(dir: &Path) -> [u8; 32] {
    std::fs::read(dir.join("regtest").join("decoys.seed"))
        .expect("a decoy seed in the data folder")
        .try_into()
        .expect("32 bytes")
}

const SERVICE: [&str; 5] = [
    "getheaders",
    "getcfcheckpt",
    "getcfheaders",
    "getcfilters",
    "mempool",
];

/// The connections that carried anything but a single block or a broadcast.
fn connections(sent: &Mutex<Vec<Sent>>) -> BTreeMap<usize, Vec<String>> {
    let mut out: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for s in sent.lock().unwrap().iter() {
        let name = if s.command == "getdata" && !inv_blocks(&s.payload).is_empty() {
            "getdata block".to_string()
        } else {
            s.command.clone()
        };
        out.entry(s.connection).or_default().push(name);
    }
    out
}

async fn setup(name: &str) -> Option<(Bchd, Chain, TamperProxy, Arc<Mutex<Vec<Sent>>>)> {
    let bin = bchd_txid_binary_or_skip()?;
    let node = Bchd::start_with(&bin, name).await;
    let chain = chain(&node).await;
    let (proxy, sent) = TamperProxy::recording(node.p2p_port).await;
    Some((node, chain, proxy, sent))
}

/// A history needs blocks 150 and 200 of the bucket 144..=287, and 295 of
/// the bucket at the tip. It downloads exactly those, three decoys each
/// that the seed in the data folder gives, and the tip bucket whole; each
/// block over a connection that carries nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_history_downloads_its_blocks_with_derived_decoys_each_over_its_own_connection() {
    let Some((node, chain, proxy, sent)) = setup("cover-history").await else {
        return;
    };
    let dir = node.dir.join("client");
    let client = start(&proxy, &dir, |_| {}).await;
    let mark = sent.lock().unwrap().len();
    let before = heights(&blocks_asked(&sent, 0, &chain));
    let target = Target::Script(chain.key.script());
    client.watch([target.clone()]).await.unwrap();
    let history = client.history(&target).await.unwrap();
    assert_eq!(
        history
            .confirmed
            .iter()
            .map(|t| t.height)
            .collect::<Vec<_>>(),
        vec![150, 200, 295]
    );
    let asked = blocks_asked(&sent, mark, &chain);
    let seed = seed(&dir);
    let mut expected: BTreeSet<u32> = [150, 200, 295]
        .iter()
        .flat_map(|h| expected_cover(&seed, *h, TIP))
        .collect();
    // Blocks read before (the tip, as the client follows it) are not asked again.
    expected.retain(|h| !before.contains(h));
    assert_eq!(heights(&asked), expected, "the blocks asked for");
    assert_eq!(asked.len(), expected.len(), "each block asked once");
    let decoys = expected.range(144..=287).count();
    assert!(
        (5..=8).contains(&decoys),
        "{decoys} in the bucket of 150 and 200"
    );

    // One block per connection, and nothing else over it.
    let by_connection = connections(&sent);
    for (connection, _) in &asked {
        let carried = &by_connection[connection];
        assert_eq!(
            carried.iter().filter(|c| *c == "getdata block").count(),
            1,
            "connection {connection} carried {carried:?}"
        );
        assert!(
            !carried.iter().any(|c| SERVICE.contains(&c.as_str())),
            "connection {connection} carried {carried:?}"
        );
    }

    // A broadcast goes over a connection of its own too.
    let (coinbase, value) = node.coinbase(4).await;
    let raw = TxSpec {
        inputs: vec![(coinbase, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(value - 5000, chain.key.script(), vec![])],
    }
    .build();
    let mark = sent.lock().unwrap().len();
    client.broadcast(&raw).await.unwrap();
    let carrier = sent.lock().unwrap()[mark..]
        .iter()
        .find(|s| s.command == "tx")
        .map(|s| s.connection)
        .expect("the broadcast went through the proxy");
    let carried = &connections(&sent)[&carrier];
    assert!(
        sent.lock().unwrap()[..mark]
            .iter()
            .all(|s| s.connection != carrier),
        "the broadcast went over a connection that was already open: {carried:?}"
    );
    assert!(
        !carried
            .iter()
            .any(|c| SERVICE.contains(&c.as_str()) || c == "getdata block"),
        "the broadcast's connection carried {carried:?}"
    );
    client.stop().await;
}

/// A transaction found once is kept: asking for it again, for its Merkle
/// branch, for it by position, and for whether its output is spent
/// downloads nothing, even with no block cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_lookup_downloads_nothing() {
    let Some((node, chain, proxy, sent)) = setup("cover-repeat").await else {
        return;
    };
    let client = start(&proxy, &node.dir.join("client"), |c| {
        c.block_cache_bytes = 0
    })
    .await;
    let (a, a_height, _) = chain.payments[0];
    let (b, _, _) = chain.payments[1];
    let found = client.transaction(a, None).await.unwrap();
    let position = found.confirmation.unwrap().position;
    assert_eq!(found.confirmation.unwrap().height, a_height);
    client.transaction(b, None).await.unwrap();
    let outpoint = OutPoint::new(a, 0);
    assert!(client.output(outpoint, None).await.unwrap().is_some());

    let mark = sent.lock().unwrap().len();
    assert_eq!(client.transaction(a, None).await.unwrap().tx.txid(), a);
    let proof = client.merkle_proof(a, None).await.unwrap();
    assert_eq!(proof.height, a_height);
    let (at, _) = client.transaction_at(a_height, position).await.unwrap();
    assert_eq!(at.txid(), a);
    assert!(client.output(outpoint, None).await.unwrap().is_some());
    assert_eq!(client.transaction(b, None).await.unwrap().tx.txid(), b);
    assert_eq!(
        blocks_asked(&sent, mark, &chain),
        Vec::new(),
        "nothing downloaded again"
    );
    client.stop().await;
}

/// An RPA search downloads every block of its range, so which blocks it
/// reads names no prefix, and needs no input prefix filters.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_rpa_search_downloads_its_whole_range() {
    let Some((node, chain, proxy, sent)) = setup("cover-rpa").await else {
        return;
    };
    let client = start(&proxy, &node.dir.join("client"), |_| {}).await;
    let (a, a_height, raw) = &chain.payments[0];
    let tx = Transaction::from_bytes(raw).unwrap();
    let prefix = Prefix::new(input_value(&tx.inputs[0]), 16).unwrap();
    let before = heights(&blocks_asked(&sent, 0, &chain));
    let mark = sent.lock().unwrap().len();
    let found = client.rpa_history(prefix, 140, 200).await.unwrap();
    assert!(
        found
            .iter()
            .any(|m| m.tx.txid() == *a && m.confirmation.map(|c| c.height) == Some(*a_height)),
        "the payment at {a_height}"
    );
    let asked = heights(&blocks_asked(&sent, mark, &chain));
    let range: BTreeSet<u32> = (140..200).filter(|h| !before.contains(h)).collect();
    assert_eq!(asked, range, "every block of the range, and no other");
    client.stop().await;
}

/// The same block brings the same decoys after a restart, so that
/// intersecting what sessions downloaded shows nothing; another data
/// folder (another seed) brings others.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_block_brings_the_same_decoys_after_a_restart() {
    let Some((node, chain, proxy, sent)) = setup("cover-restart").await else {
        return;
    };
    let (a, a_height, _) = chain.payments[0];
    let lookup = |dir: PathBuf| {
        let (proxy, sent, chain) = (&proxy, &sent, &chain);
        async move {
            let client = start(proxy, &dir, |_| {}).await;
            let mark = sent.lock().unwrap().len();
            client.transaction(a, None).await.unwrap();
            let asked = heights(&blocks_asked(sent, mark, chain));
            client.stop().await;
            asked
        }
    };
    let first = lookup(node.dir.join("one")).await;
    assert_eq!(first.len(), 4, "the block and three decoys: {first:?}");
    assert!(first.contains(&a_height));
    assert_eq!(
        first,
        expected_cover(&seed(&node.dir.join("one")), a_height, TIP)
    );
    let again = lookup(node.dir.join("one")).await;
    assert_eq!(again, first, "the same decoys after a restart");
    let other = lookup(node.dir.join("two")).await;
    assert_ne!(other, first, "another seed, other decoys");
    assert!(other.contains(&a_height));
}

/// What the cover costs: bytes the node sent for a history, a lookup by
/// ID and an RPA search, each on a fresh client, with the defaults and
/// with decoys and isolation off. Printed for the docs (--nocapture).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_cover_costs() {
    let Some((node, chain, proxy, _sent)) = setup("cover-cost").await else {
        return;
    };
    let (a, _, raw) = &chain.payments[0];
    let tx = Transaction::from_bytes(raw).unwrap();
    let prefix = Prefix::new(input_value(&tx.inputs[0]), 16).unwrap();
    let target = Target::Script(chain.key.script());
    let mut costs: BTreeMap<(&str, &str), (u64, u64)> = BTreeMap::new();
    for (setting, protected) in [("defaults", true), ("decoys and isolation off", false)] {
        for operation in [
            "history of 3 blocks",
            "lookup by ID",
            "RPA search of 60 blocks",
        ] {
            let dir = node
                .dir
                .join(format!("{setting}-{operation}").replace(' ', "-"));
            let client = start(&proxy, &dir, |c| {
                if !protected {
                    c.decoy_blocks = 0;
                    c.isolate_block_downloads = false;
                }
            })
            .await;
            let bytes = || proxy.delivered.load(std::sync::atomic::Ordering::Relaxed);
            let (before, blocks) = (bytes(), client.stats().blocks_downloaded);
            match operation {
                "history of 3 blocks" => {
                    client.watch([target.clone()]).await.unwrap();
                    client.history(&target).await.unwrap();
                }
                "lookup by ID" => {
                    client.transaction(*a, None).await.unwrap();
                }
                _ if protected => {
                    client.rpa_history(prefix, 140, 200).await.unwrap();
                }
                // Without input prefix filters there is nothing else to
                // compare with: the search reads the matching block only.
                _ => {
                    client.transaction_at(150, 1).await.unwrap();
                }
            }
            costs.insert(
                (setting, operation),
                (bytes() - before, client.stats().blocks_downloaded - blocks),
            );
            client.stop().await;
        }
    }
    for ((setting, operation), (bytes, blocks)) in &costs {
        println!("cover cost: {operation}, {setting}: {bytes} bytes, {blocks} blocks");
    }
    for operation in [
        "history of 3 blocks",
        "lookup by ID",
        "RPA search of 60 blocks",
    ] {
        assert!(
            costs[&("defaults", operation)].0 > costs[&("decoys and isolation off", operation)].0,
            "{costs:?}"
        );
    }
}
