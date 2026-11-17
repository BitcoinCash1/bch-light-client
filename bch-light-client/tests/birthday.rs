//! Filters from a wallet birthday, histories kept across a restart, and a
//! reorganization that puts a transaction back in the mempool copy, against
//! bchd on regtest. Skipped when no bchd binary is found (set BCHD_BIN).

mod common;

use bch_light_client::block::BlockHeader;
use bch_light_client::{BlockHash, Config, LightClient, Network, Target, TokenFilter};
use common::*;
use serde_json::json;
use std::time::{Duration, Instant};

async fn start(node: &Bchd, dir: &std::path::Path, birthday: u32) -> LightClient {
    let mut config = Config::new(Network::Regtest, dir, vec![node.peer()]);
    config.filters_from_height = birthday;
    config.request_timeout = Duration::from_secs(20);
    LightClient::start(config).await.expect("start client")
}

async fn wait_tip(node: &Bchd, client: &LightClient) -> Duration {
    let started = Instant::now();
    let height = node.height().await;
    loop {
        let status = client.status();
        if status.synced && status.filter_height == Some(height) {
            return started.elapsed();
        }
        assert!(started.elapsed() < Duration::from_secs(120), "client did not reach {height}: {status:?}");
        client.poke();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A block with only a coinbase (padded past 100 bytes), mined on `prev`.
fn empty_block(prev: &BlockHeader, height: u32) -> Vec<u8> {
    let mut script_sig = Vec::new();
    let h = height.to_le_bytes();
    let len = if height < 0x80 { 1 } else if height < 0x8000 { 2 } else { 3 };
    script_sig.push(len as u8);
    script_sig.extend_from_slice(&h[..len]);
    script_sig.push(40);
    script_sig.extend_from_slice(&[0x42; 40]);
    let mut tx = 1i32.to_le_bytes().to_vec();
    tx.push(1);
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&u32::MAX.to_le_bytes());
    tx.push(script_sig.len() as u8);
    tx.extend_from_slice(&script_sig);
    tx.extend_from_slice(&u32::MAX.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&0u64.to_le_bytes());
    tx.push(1);
    tx.push(0x51);
    tx.extend_from_slice(&0u32.to_le_bytes());
    let mut header = BlockHeader {
        version: 0x2000_0000,
        prev_hash: prev.hash(),
        merkle_root: hash256(&tx),
        time: prev.time + 1,
        bits: 0x207f_ffff,
        nonce: 0,
    };
    let limit = Network::Regtest.params().pow_limit();
    while !bch_light_client::pow::meets_target(&header.hash().0, header.bits, limit) {
        header.nonce += 1;
    }
    let mut block = header.to_bytes().to_vec();
    block.push(1);
    block.extend_from_slice(&tx);
    block
}

async fn header_of(node: &Bchd, height: u32) -> BlockHeader {
    let hash = node.rpc("getblockhash", json!([height])).await;
    let hex_header = node.rpc("getblockheader", json!([hash, false])).await;
    let raw: [u8; 80] = hex::decode(hex_header.as_str().unwrap()).unwrap().try_into().unwrap();
    BlockHeader::from_bytes(&raw)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn birthday_restart_and_reorg_mempool() {
    if bchd_binary().is_none() {
        eprintln!("skipped: no bchd binary (set BCHD_BIN)");
        return;
    }
    let node = Bchd::start("birthday").await;
    for _ in 0..5 {
        node.generate(500).await;
    }
    let key = Key::new(41);
    let p2pkh = key.script();
    let target = Target::Script(p2pkh.clone());
    let mining = mining_script();
    let (cb1, v1) = node.coinbase(1).await;
    let pay = TxSpec {
        inputs: vec![(cb1, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(100_000_000, p2pkh.clone(), vec![]), (v1 - 100_000_000 - 3000, mining.clone(), vec![])],
    }
    .build();
    node.send(&pay).await;
    node.generate(1).await;
    let tip = node.height().await;
    assert_eq!(tip, 2501);

    // Filters from the birthday 2400: the store starts after checkpoint 2000.
    let birthday_dir = node.dir.join("birthday");
    let client = start(&node, &birthday_dir, 2400).await;
    let birthday_sync = wait_tip(&node, &client).await;
    let history = client.history(&target).await.unwrap();
    assert_eq!(history.confirmed.len(), 1);
    assert_eq!(history.confirmed[0].txid, txid_of(&pay));
    assert_eq!(history.confirmed[0].height, 2501);
    let birthday_filters = client.stats().filters;
    let genesis_dir = node.dir.join("genesis");
    let from_genesis = start(&node, &genesis_dir, 0).await;
    let genesis_sync = wait_tip(&node, &from_genesis).await;
    let genesis_filters = from_genesis.stats().filters;
    from_genesis.shutdown();
    eprintln!(
        "MEASURE filter sync to {tip}: from birthday 2400 {birthday_sync:?} ({birthday_filters} bytes), \
         from genesis {genesis_sync:?} ({genesis_filters} bytes)"
    );
    assert!(birthday_filters * 4 < genesis_filters);

    // A restart reads the history from disk and downloads no block for it.
    client.shutdown();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let client = start(&node, &birthday_dir, 2400).await;
    wait_tip(&node, &client).await;
    let again = client.history(&target).await.unwrap();
    assert_eq!(again.confirmed, history.confirmed);
    assert!(client.stats().blocks_downloaded <= 1, "{:?}", client.stats());

    // A payment confirmed in a block that a reorganization removes goes back
    // to the mempool copy, as bchd puts it back in its mempool.
    let (cb2, v2) = node.coinbase(2).await;
    let moved = TxSpec {
        inputs: vec![(cb2, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(70_000_000, p2pkh.clone(), vec![]), (v2 - 70_000_000 - 3000, mining.clone(), vec![])],
    }
    .build();
    let moved_id = txid_of(&moved);
    node.send(&moved).await;
    node.generate(1).await;
    wait_tip(&node, &client).await;
    let confirmed = client.history(&target).await.unwrap();
    assert!(confirmed.confirmed.iter().any(|t| t.txid == moved_id && t.height == 2502));
    let replaced = node.rpc("getblockhash", json!([2502])).await;
    node.rpc("invalidateblock", json!([replaced])).await;
    let base = header_of(&node, 2501).await;
    let first = empty_block(&base, 2502);
    let first_header = BlockHeader::from_bytes(&first[..80].try_into().unwrap());
    let second = empty_block(&first_header, 2503);
    node.rpc("submitblock", json!([hex::encode(&first)])).await;
    node.rpc("submitblock", json!([hex::encode(&second)])).await;
    assert_eq!(BlockHash::from_hex(node.rpc("getbestblockhash", json!([])).await.as_str().unwrap()).unwrap(), BlockHeader::from_bytes(&second[..80].try_into().unwrap()).hash());
    wait_tip(&node, &client).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !client.in_mempool(&moved_id) {
        assert!(Instant::now() < deadline, "the reorganized payment is not back in the mempool copy");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let after = client.history(&target).await.unwrap();
    assert!(after.confirmed.iter().all(|t| t.txid != moved_id));
    assert!(after.mempool.iter().any(|e| e.txid == moved_id));
    let balance = client.balance(&target, TokenFilter::Include).await.unwrap();
    assert_eq!((balance.confirmed, balance.unconfirmed), (100_000_000, 70_000_000));
    client.shutdown();
}
