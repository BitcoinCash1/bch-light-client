//! Reusable payment address searches and double-spend proofs against a
//! bchd that serves input prefix filters (filter type 2) and relays proofs:
//! payments ground to a 16-bit and an 8-bit prefix are found in whole
//! blocks exactly where bchd's blocks have them, before confirmation from
//! the mempool copy, and an absent prefix finds nothing; a double spend
//! gives a proof the client checks and serves until a block settles it.
//! Skipped when no such bchd is found (set BCHD_RPA_BIN or build one into
//! .tools/bchd-rpa).

mod common;

use bch_light_client::{Config, Event, LightClient, Network, OutPoint, Prefix, Target, Txid};
use common::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub fn bchd_rpa_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("BCHD_RPA_BIN") {
        return Some(PathBuf::from(path));
    }
    let exe = if cfg!(windows) {
        "bchd-rpa.exe"
    } else {
        "bchd-rpa"
    };
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".tools")
        .join(exe);
    path.exists().then_some(path)
}

/// The value an input has in an input prefix filter, computed here from the
/// input's fields: the first two bytes of the double SHA-256 of the input.
fn input_value(txid_display: &str, vout: u32, script_sig: &[u8], sequence: u32) -> u16 {
    let mut b = Vec::new();
    let mut txid = hex::decode(txid_display).unwrap();
    txid.reverse();
    b.extend_from_slice(&txid);
    b.extend_from_slice(&vout.to_le_bytes());
    b.push(script_sig.len() as u8);
    b.extend_from_slice(script_sig);
    b.extend_from_slice(&sequence.to_le_bytes());
    let h = hash256(&b);
    u16::from_be_bytes([h[0], h[1]])
}

/// A sequence that gives the P2SH(OP_TRUE) spend of `outpoint` a value with the prefix.
fn grind(outpoint: OutPoint, prefix: Prefix) -> u32 {
    (0u32..)
        .find(|s| {
            prefix.contains(input_value(
                &outpoint.txid.to_hex(),
                outpoint.vout,
                &[0x01, 0x51],
                *s,
            ))
        })
        .unwrap()
}

/// A transaction spending a P2SH(OP_TRUE) output with the given sequence to
/// `script`; version 1, so that the sequence sets no relative lock time.
fn spend_with_sequence(outpoint: OutPoint, value: u64, sequence: u32, script: &[u8]) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&1i32.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&outpoint.txid.0);
    tx.extend_from_slice(&outpoint.vout.to_le_bytes());
    tx.extend_from_slice(&[0x02, 0x01, 0x51]);
    tx.extend_from_slice(&sequence.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&(value - 3000).to_le_bytes());
    tx.push(script.len() as u8);
    tx.extend_from_slice(script);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}

/// What bchd's blocks say: (txid, height) of every transaction with one of
/// its first 30 inputs having the prefix.
fn truth(blocks: &[Value], prefix: Prefix) -> BTreeSet<(String, u32)> {
    let mut out = BTreeSet::new();
    for (height, block) in blocks.iter().enumerate() {
        for tx in block["tx"].as_array().unwrap().iter().skip(1) {
            let hit = tx["vin"].as_array().unwrap().iter().take(30).any(|vin| {
                let script = hex::decode(vin["scriptSig"]["hex"].as_str().unwrap()).unwrap();
                prefix.contains(input_value(
                    vin["txid"].as_str().unwrap(),
                    vin["vout"].as_u64().unwrap() as u32,
                    &script,
                    vin["sequence"].as_u64().unwrap() as u32,
                ))
            });
            if hit {
                out.insert((tx["txid"].as_str().unwrap().to_string(), height as u32));
            }
        }
    }
    out
}

async fn wait_tip(node: &Bchd, client: &LightClient) {
    let height = node.height().await;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let s = client.status();
        if s.synced && s.filter_height == Some(height) && s.rpa_height == Some(height) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "client did not reach {height}: {s:?}"
        );
        client.poke();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_mempool(client: &LightClient, txids: &[Txid]) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !txids.iter().all(|t| client.in_mempool(t)) {
        assert!(
            Instant::now() < deadline,
            "client did not see the mempool transactions"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn found(client: &LightClient, prefix: Prefix, tip: u32) -> BTreeSet<(String, u32)> {
    client
        .rpa_history(prefix, 0, tip + 1)
        .await
        .unwrap()
        .iter()
        .map(|m| (m.tx.txid().to_hex(), m.confirmation.unwrap().height))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpa_payments_and_double_spend_proofs() {
    let Some(bin) = bchd_rpa_binary() else {
        eprintln!("skipped: no bchd with input prefix filters (set BCHD_RPA_BIN)");
        return;
    };
    let node = Bchd::start_with(&bin, "rpa").await;
    node.generate(110).await;
    let mining = mining_script();
    let key = Key::new(21);
    let p2pkh = key.script();
    // A P2PKH coin to double-spend later.
    let (cb1, v1) = node.coinbase(1).await;
    let fund = TxSpec {
        inputs: vec![(cb1, Unlock::Redeem(vec![0x51]))],
        outputs: vec![
            (1_000_000_000, p2pkh.clone(), vec![]),
            (v1 - 1_000_000_000 - 3000, mining.clone(), vec![]),
        ],
    }
    .build();
    node.send(&fund).await;
    node.generate(1).await;

    let dir = node.dir.join("client");
    let mut config = Config::new(Network::Regtest, dir, vec![node.peer()]);
    config.rpa_filters = true;
    config.request_timeout = Duration::from_secs(20);
    let client = LightClient::start(config).await.unwrap();
    client.wait_synced(Duration::from_secs(60)).await.unwrap();
    client.watch([Target::Script(p2pkh.clone())]).await.unwrap();
    let mut events = client.subscribe();
    wait_tip(&node, &client).await;
    assert_eq!(client.rpa_heights().map(|h| h.0), Some(0));

    // Payments ground to a 16-bit and an 8-bit prefix.
    let p16 = Prefix::new(0xbeef, 16).unwrap();
    let p8 = Prefix::new(0x5a, 8).unwrap();
    let (cb2, v2) = node.coinbase(2).await;
    let (cb3, v3) = node.coinbase(3).await;
    let r16 = spend_with_sequence(cb2, v2, grind(cb2, p16), &mining);
    let r8 = spend_with_sequence(cb3, v3, grind(cb3, p8), &mining);
    let (id16, id8) = (txid_of(&r16), txid_of(&r8));
    node.send(&r16).await;
    node.send(&r8).await;
    wait_mempool(&client, &[id16, id8]).await;
    let pending: Vec<Txid> = client
        .rpa_mempool(p16)
        .iter()
        .map(|m| m.tx.txid())
        .collect();
    assert_eq!(pending, vec![id16], "16-bit prefix in the mempool");
    assert!(client
        .rpa_mempool(p8)
        .iter()
        .any(|m| m.tx.txid() == id8 && m.inputs == vec![0]));
    node.generate(1).await;
    wait_tip(&node, &client).await;
    let blocks = all_blocks(&node).await;
    let tip = node.height().await;
    for prefix in [p16, p8] {
        let expected = truth(&blocks, prefix);
        assert!(!expected.is_empty());
        assert_eq!(
            found(&client, prefix, tip).await,
            expected,
            "prefix {}",
            prefix.to_hex()
        );
    }
    // A prefix no input has finds nothing.
    let absent = (0u16..)
        .map(|v| Prefix::new(v, 16).unwrap())
        .find(|p| truth(&blocks, *p).is_empty())
        .unwrap();
    assert!(found(&client, absent, tip).await.is_empty());
    // A range that ends before the payment does not have it.
    let before: Vec<_> = client.rpa_history(p16, 0, tip).await.unwrap();
    assert!(before.iter().all(|m| m.tx.txid() != id16));

    // A double spend of the P2PKH coin: bchd makes a proof and relays it.
    let fund_id = txid_of(&fund);
    let coin = OutPoint::new(fund_id, 0);
    let first = TxSpec {
        inputs: vec![(coin, Unlock::Sign(&key, 1_000_000_000))],
        outputs: vec![(999_990_000, p2sh20(&[0x52, 0x75, 0x51]), vec![])],
    }
    .build();
    let second = TxSpec {
        inputs: vec![(coin, Unlock::Sign(&key, 1_000_000_000))],
        outputs: vec![(999_980_000, p2sh32(&[0x53, 0x75, 0x51]), vec![])],
    }
    .build();
    let first_id = txid_of(&first);
    node.send(&first).await;
    wait_mempool(&client, &[first_id]).await;
    let refused = node
        .try_rpc("sendrawtransaction", json!([hex::encode(&second)]))
        .await;
    assert!(refused.is_err(), "bchd took a double spend");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut tried_p2p = false;
    let proof = loop {
        if let Some(p) = client.ds_proof(first_id.0) {
            break Some(p);
        }
        if Instant::now() > deadline {
            if tried_p2p {
                break None;
            }
            // bchd may make proofs only for double spends that arrive over P2P.
            assert!(client.broadcast(&second).await.is_err());
            tried_p2p = true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let proof = proof.expect("no double-spend proof reached the client");
    eprintln!(
        "double-spend proof {} for {} (via {})",
        hex::encode(proof.id),
        proof.txid,
        if tried_p2p { "P2P" } else { "RPC" }
    );
    assert_eq!(proof.outpoint, coin);
    assert_eq!(proof.txid, first_id);
    assert!(proof.descendants.contains(&first_id));
    assert_eq!(client.ds_proof_for_outpoint(&coin), Some(proof.clone()));
    assert_eq!(client.ds_proof(proof.id), Some(proof.clone()));
    let mut announced = false;
    while let Ok(e) = events.try_recv() {
        announced |= matches!(e, Event::DoubleSpendProof { txid, .. } if txid == first_id);
    }
    assert!(announced, "no event for the proof");
    // bchd's own view of the proof agrees.
    let theirs = node.rpc("getdsproof", json!([first_id.to_hex()])).await;
    let mut id = proof.id;
    id.reverse();
    assert_eq!(
        theirs["dspid"],
        json!(hex::encode(id)),
        "the proof ID, display order"
    );
    assert_eq!(theirs["descendants"], json!([first_id.to_hex()]));
    // A block settles the double spend and the proof goes.
    node.generate(1).await;
    wait_tip(&node, &client).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    while client.ds_proof(first_id.0).is_some() {
        assert!(Instant::now() < deadline, "the proof outlived the block");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    client.shutdown();
}
