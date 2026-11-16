//! The light client against a bchd node on regtest: every watched script's
//! history, balance and unspent outputs (with token data) must equal what
//! bchd's own blocks and mempool say, before and after new blocks, with
//! unconfirmed payments, across a reorganization, and through isolated
//! block downloads. Skipped when no bchd binary is found (set BCHD_BIN or
//! build one into .tools/).

mod common;

use bch_light_client::{Category, Config, ErrorKind, Event, LightClient, Network, OutPoint, Target, TokenFilter, Txid};
use common::*;
use serde_json::json;
use std::collections::HashSet;
use std::time::{Duration, Instant};

const R_A: [u8; 3] = [0x52, 0x75, 0x51];
const R_B: [u8; 3] = [0x53, 0x75, 0x51];
const R_C: [u8; 3] = [0x54, 0x75, 0x51];
const BARE: [u8; 3] = [0x55, 0x75, 0x51];
const FEE: u64 = 3000;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_test_writer()
        .try_init();
}

async fn client(node: &Bchd, name: &str, isolate: bool) -> LightClient {
    let dir = node.dir.join(format!("client-{name}"));
    let mut config = Config::new(Network::Regtest, dir, vec![node.peer()]);
    config.isolate_block_downloads = Some(isolate);
    config.request_timeout = Duration::from_secs(20);
    LightClient::start(config).await.expect("start client")
}

/// Waits until the client's headers and filters reach bchd's tip.
async fn wait_tip(node: &Bchd, client: &LightClient) {
    let height = node.height().await;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let status = client.status();
        if status.synced && status.filter_height == Some(height) {
            return;
        }
        assert!(Instant::now() < deadline, "client did not reach height {height}: {status:?}");
        client.poke();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_mempool(client: &LightClient, txids: &[Txid]) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !txids.iter().all(|t| client.in_mempool(t)) {
        assert!(Instant::now() < deadline, "client did not see the mempool transactions");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The client's view of a target, in the shape of `Truth`.
async fn view(client: &LightClient, target: &Target) -> Truth {
    let history = client.history(target).await.expect("history");
    let mut t = Truth::default();
    for tx in &history.confirmed {
        t.confirmed.push((tx.txid.to_hex(), tx.height, tx.position));
        t.detail.insert(
            tx.txid.to_hex(),
            (
                tx.received.iter().map(|r| (r.vout, r.value, token_from_lib(&r.token))).collect(),
                tx.spent.iter().map(|s| (s.vin, s.prevout.to_string(), s.value)).collect(),
            ),
        );
    }
    let mut mempool: Vec<String> = history.mempool.iter().map(|e| e.txid.to_hex()).collect();
    mempool.sort();
    t.mempool = mempool;
    let unspent = client.unspent(target, TokenFilter::Include).await.expect("unspent");
    for u in unspent {
        match u.height {
            Some(h) => t.unspent_confirmed.push((u.outpoint.to_string(), u.value, token_from_lib(&u.token), h)),
            None => t.unspent_mempool.push((u.outpoint.to_string(), u.value, token_from_lib(&u.token))),
        }
    }
    t.unspent_confirmed.sort_by(|a, b| (a.3, &a.0).cmp(&(b.3, &b.0)));
    t.unspent_mempool.sort();
    let balance = client.balance(target, TokenFilter::Include).await.expect("balance");
    t.balance_confirmed = balance.confirmed;
    t.balance_unconfirmed = balance.unconfirmed;
    t
}

fn watch_of(target: &Target) -> Watch {
    match target {
        Target::Script(s) => Watch::Script(s.clone()),
        Target::Category(c) => Watch::Category(c.to_hex()),
    }
}

async fn compare(node: &Bchd, client: &LightClient, targets: &[(&str, Target)], step: &str) {
    wait_tip(node, client).await;
    let blocks = all_blocks(node).await;
    let mut summary = Vec::new();
    for (name, target) in targets {
        let mut expected = truth(node, &blocks, &watch_of(target)).await;
        expected.unspent_confirmed.sort_by(|a, b| (a.3, &a.0).cmp(&(b.3, &b.0)));
        let got = view(client, target).await;
        assert_eq!(got, expected, "{step}: {name} differs from bchd's blocks");
        summary.push(format!(
            "{name}: {} confirmed, {} mempool, {} unspent, balance {}/{}",
            got.confirmed.len(),
            got.mempool.len(),
            got.unspent_confirmed.len() + got.unspent_mempool.len(),
            got.balance_confirmed,
            got.balance_unconfirmed
        ));
    }
    eprintln!("[{step}] {}", summary.join("; "));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn histories_match_bchd_through_blocks_mempool_and_a_reorg() {
    init_tracing();
    if bchd_binary().is_none() {
        eprintln!("skipped: no bchd binary (set BCHD_BIN)");
        return;
    }
    let node = Bchd::start("histories").await;
    node.generate(110).await;
    let key = Key::new(7);
    let p2pkh = key.script();
    let a = p2sh20(&R_A);
    let b = p2sh32(&R_B);
    let c = p2sh32(&R_C);
    let mining = mining_script();
    let (cb2, _) = node.coinbase(2).await;
    let category = Category(cb2.txid.0);
    let targets: Vec<(&str, Target)> = vec![
        ("P2PKH", Target::Script(p2pkh.clone())),
        ("P2SH20", Target::Script(a.clone())),
        ("P2SH32", Target::Script(b.clone())),
        ("P2SH32 NFT holder", Target::Script(c.clone())),
        ("bare P2S", Target::Script(BARE.to_vec())),
        ("mining P2SH20", Target::Script(mining.clone())),
        ("NFT category", Target::Category(category)),
    ];
    let pooled = client(&node, "pooled", false).await;
    let started = Instant::now();
    pooled.wait_synced(Duration::from_secs(60)).await.expect("synced");
    eprintln!("headers and filters to height 110: {:?}", started.elapsed());
    let started = Instant::now();
    pooled.watch(targets.iter().map(|(_, t)| t.clone())).await.expect("watch");
    eprintln!("first scan of 7 targets (110 coinbase blocks to download): {:?}", started.elapsed());
    compare(&node, &pooled, &targets, "start").await;

    // Funding: P2PKH, P2SH20, P2SH32 and a bare script; an NFT minted to a P2SH32 output.
    let (cb1, v1) = node.coinbase(1).await;
    let (_, v2) = node.coinbase(2).await;
    let f1 = TxSpec {
        inputs: vec![(cb1, Unlock::Redeem(vec![0x51]))],
        outputs: vec![
            (1_000_000_000, p2pkh.clone(), vec![]),
            (500_000_000, a.clone(), vec![]),
            (300_000_000, b.clone(), vec![]),
            (200_000_000, BARE.to_vec(), vec![]),
            (v1 - 2_000_000_000 - FEE, mining.clone(), vec![]),
        ],
    }
    .build();
    let g = TxSpec {
        inputs: vec![(cb2, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(1000, c.clone(), nft_prefix(&category, b"qr")), (v2 - 1000 - FEE, mining.clone(), vec![])],
    }
    .build();
    node.send(&f1).await;
    node.send(&g).await;
    node.generate(1).await;
    compare(&node, &pooled, &targets, "funded").await;
    let f1id = txid_of(&f1);
    let gid = txid_of(&g);

    // Spends of each kind, and the NFT moved to another P2SH32 output.
    let (cb3, v3) = node.coinbase(3).await;
    let s1 = TxSpec {
        inputs: vec![(OutPoint::new(f1id, 0), Unlock::Sign(&key, 1_000_000_000))],
        outputs: vec![(100_000_000, a.clone(), vec![]), (900_000_000 - FEE, p2pkh.clone(), vec![])],
    }
    .build();
    let s2 = TxSpec {
        inputs: vec![(OutPoint::new(f1id, 1), Unlock::Redeem(R_A.to_vec())), (OutPoint::new(f1id, 3), Unlock::Empty)],
        outputs: vec![(700_000_000 - FEE, b.clone(), vec![])],
    }
    .build();
    let s3 = TxSpec {
        inputs: vec![(OutPoint::new(gid, 0), Unlock::Redeem(R_C.to_vec())), (cb3, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(1000, b.clone(), nft_prefix(&category, b"qr")), (v3 - FEE, mining.clone(), vec![])],
    }
    .build();
    for tx in [&s1, &s2, &s3] {
        node.send(tx).await;
    }
    node.generate(1).await;
    compare(&node, &pooled, &targets, "spent").await;
    // The comparisons above are not of empty sets: the NFT was minted and
    // moved, and now sits with its data at the P2SH32 output.
    let nft = view(&pooled, &Target::Category(category)).await;
    assert_eq!(nft.confirmed.len(), 2);
    let holder = view(&pooled, &Target::Script(b.clone())).await;
    assert!(holder
        .unspent_confirmed
        .iter()
        .any(|u| u.2 == Some((category.to_hex(), 0, Some(("none".to_string(), hex::encode(b"qr")))))));
    let spender = view(&pooled, &Target::Script(p2pkh.clone())).await;
    assert_eq!(spender.confirmed.len(), 2, "received in f1, spent and re-received in s1");

    // Unconfirmed: a payment to P2PKH, and a child spending it to P2SH32.
    let mut events = pooled.subscribe();
    let (cb4, v4) = node.coinbase(4).await;
    let m1 = TxSpec {
        inputs: vec![(cb4, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(50_000_000, p2pkh.clone(), vec![]), (v4 - 50_000_000 - FEE, mining.clone(), vec![])],
    }
    .build();
    let m2 = TxSpec {
        inputs: vec![(OutPoint::new(txid_of(&m1), 0), Unlock::Sign(&key, 50_000_000))],
        outputs: vec![(50_000_000 - FEE, b.clone(), vec![])],
    }
    .build();
    node.send(&m1).await;
    node.send(&m2).await;
    wait_mempool(&pooled, &[txid_of(&m1), txid_of(&m2)]).await;
    compare(&node, &pooled, &targets, "mempool").await;
    let p2pkh_target = Target::Script(p2pkh.clone());
    let mut notified = false;
    while let Ok(event) = events.try_recv() {
        notified |= matches!(event, Event::TargetChanged { target } if target == p2pkh_target);
    }
    assert!(notified, "no notice of the unconfirmed payment to the P2PKH script");
    let history = pooled.history(&p2pkh_target).await.unwrap();
    let child = history.mempool.iter().find(|e| e.txid == txid_of(&m2)).expect("child in mempool history");
    assert!(child.unconfirmed_parent);
    assert_eq!(child.fee, Some(FEE));
    node.generate(1).await;
    compare(&node, &pooled, &targets, "mempool confirmed").await;

    // A reorganization: two blocks replaced by three, with a new payment.
    let tip = node.height().await;
    let replaced = node.rpc("getblockhash", json!([tip - 1])).await;
    node.rpc("invalidateblock", json!([replaced])).await;
    let (cb5, v5) = node.coinbase(5).await;
    let n1 = TxSpec {
        inputs: vec![(cb5, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(200_000_000, a.clone(), vec![]), (v5 - 200_000_000 - FEE, mining.clone(), vec![])],
    }
    .build();
    node.send(&n1).await;
    node.generate(3).await;
    compare(&node, &pooled, &targets, "reorganized").await;

    // A broadcast through the client reaches bchd's mempool.
    let (cb6, v6) = node.coinbase(6).await;
    let bc = TxSpec {
        inputs: vec![(cb6, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(100_000_000, BARE.to_vec(), vec![]), (v6 - 100_000_000 - FEE, mining.clone(), vec![])],
    }
    .build();
    let sent = pooled.broadcast(&bc).await.expect("broadcast");
    assert_eq!(sent, txid_of(&bc));
    let pool = node.rpc("getrawmempool", json!([])).await;
    assert!(pool.as_array().unwrap().iter().any(|t| t.as_str() == Some(&sent.to_hex())));
    let refused = pooled.broadcast(&bc[..bc.len() - 1]).await;
    assert_eq!(refused.unwrap_err().kind(), ErrorKind::InvalidInput);
    let double_spend = TxSpec {
        inputs: vec![(cb6, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(v6 - 2 * FEE, a.clone(), vec![])],
    }
    .build();
    let rejected = pooled.broadcast(&double_spend).await;
    assert_eq!(rejected.unwrap_err().kind(), ErrorKind::Rejected);
    node.generate(1).await;
    compare(&node, &pooled, &targets, "broadcast confirmed").await;

    // Lookups by transaction ID, Merkle proofs, positions and outputs.
    let info = pooled.transaction(f1id, None).await.expect("watched transaction");
    let confirmation = info.confirmation.expect("confirmed");
    assert_eq!(info.tx.serialize(), f1);
    assert_eq!(confirmation.height, 111);
    let proof = pooled.merkle_proof(f1id, None).await.expect("proof");
    let header = pooled.header(proof.height).unwrap();
    assert_eq!(
        bch_light_client::block::merkle_fold(f1id.0, proof.position as usize, &proof.branch),
        header.merkle_root
    );
    let (at, at_proof) = pooled.transaction_at(111, proof.position).await.unwrap();
    assert_eq!(at.txid(), f1id);
    assert_eq!(at_proof, proof);
    let change = pooled.output(OutPoint::new(f1id, 4), None).await.unwrap().expect("unspent change");
    assert_eq!(change.script, mining);
    assert!(pooled.output(OutPoint::new(f1id, 0), None).await.unwrap().is_none(), "spent by s1");
    let tip = node.height().await;
    let (header_branch, root) = pooled.header_branch(5, tip).unwrap();
    assert_eq!(bch_light_client::block::merkle_fold(pooled.header(5).unwrap().hash().0, 5, &header_branch), root);
    let fees = pooled.fee_estimate();
    assert!(fees.relay >= 1000 && fees.estimate >= fees.relay, "{fees:?}");

    // A second client that downloads every block over a connection of its
    // own, and watches nothing until asked: same answers.
    let isolated = client(&node, "isolated", true).await;
    isolated.wait_synced(Duration::from_secs(60)).await.expect("synced");
    assert_eq!(isolated.status().txid_keys, Some(false), "bchd's filters have no transaction keys yet");
    let lookup = isolated.transaction(f1id, None).await;
    assert_eq!(lookup.unwrap_err().kind(), ErrorKind::Unsupported);
    let hinted = isolated.transaction(f1id, Some(111)).await.expect("lookup with a height");
    assert_eq!(hinted.tx.txid(), f1id);
    compare(&node, &isolated, &targets, "isolated").await;

    let seen: HashSet<String> = view(&isolated, &targets[0].1).await.confirmed.into_iter().map(|c| c.0).collect();
    assert!(seen.contains(&f1id.to_hex()));
    pooled.shutdown();
    isolated.shutdown();
}

/// Timings on a longer chain: header sync, filter sync, a first lookup of a
/// script with a few payments, and of one paid in every block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "takes minutes; run with --ignored"]
async fn measure_sync_and_lookups() {
    init_tracing();
    if bchd_binary().is_none() {
        eprintln!("skipped: no bchd binary (set BCHD_BIN)");
        return;
    }
    let blocks: u32 = std::env::var("MEASURE_BLOCKS").ok().and_then(|v| v.parse().ok()).unwrap_or(3000);
    let node = Bchd::start("measure").await;
    let started = Instant::now();
    let mut made = 0;
    while made < blocks {
        let n = (blocks - made).min(500);
        node.generate(n).await;
        made += n;
    }
    eprintln!("bchd mined {blocks} blocks in {:?}", started.elapsed());
    // A few payments to one P2PKH script spread over the chain.
    let key = Key::new(9);
    let p2pkh = key.script();
    for i in 0..5u32 {
        let (cb, v) = node.coinbase(1 + i).await;
        let tx = TxSpec {
            inputs: vec![(cb, Unlock::Redeem(vec![0x51]))],
            outputs: vec![(10_000_000, p2pkh.clone(), vec![]), (v - 10_000_000 - FEE, mining_script(), vec![])],
        }
        .build();
        node.send(&tx).await;
        node.generate(1).await;
    }
    let tip = node.height().await;
    let client = client(&node, "measure", false).await;
    let started = Instant::now();
    loop {
        let s = client.status();
        if s.header_height == tip {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let headers = started.elapsed();
    client.wait_synced(Duration::from_secs(600)).await.unwrap();
    let filters = started.elapsed();
    let t = Instant::now();
    let few = client.history(&Target::Script(p2pkh)).await.unwrap();
    let few_time = t.elapsed();
    let t = Instant::now();
    let every = client.history(&Target::Script(mining_script())).await.unwrap();
    let every_time = t.elapsed();
    let t = Instant::now();
    let again = client.balance(&Target::Script(mining_script()), TokenFilter::Include).await.unwrap();
    let again_time = t.elapsed();
    eprintln!(
        "MEASURE tip={tip} headers={headers:?} headers+filters={filters:?} \
         first lookup (5 txs)={few_time:?} [{}] first lookup (one per block, {} txs)={every_time:?} cached balance={again_time:?} [{}]",
        few.confirmed.len(),
        every.confirmed.len(),
        again.confirmed
    );
    client.shutdown();
}
