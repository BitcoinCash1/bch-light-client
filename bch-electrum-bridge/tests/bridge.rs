//! The bridge binary against bchd on regtest, spoken to as an Electrum
//! wallet would: every answer must equal what bchd's own blocks say.
//! Skipped when no bchd binary is found (set BCHD_BIN).

#[path = "../../bch-light-client/tests/common/mod.rs"]
mod common;

use bch_light_client::cashaddr::Address;
use bch_light_client::{Category, OutPoint};
use common::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

struct Bridge {
    child: Child,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An Electrum client: requests by id, notifications kept aside.
struct Wallet {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    next_id: u64,
    notifications: Vec<Value>,
}

impl Wallet {
    async fn connect(port: u16) -> Wallet {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
                let (r, w) = stream.into_split();
                return Wallet {
                    reader: BufReader::new(r),
                    writer: w,
                    next_id: 1,
                    notifications: Vec::new(),
                };
            }
            assert!(Instant::now() < deadline, "bridge did not listen");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn line(&mut self) -> Value {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(120), self.reader.read_line(&mut line))
            .await
            .expect("bridge answered in time")
            .expect("read");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line}"))
    }

    /// The full reply (result or error) of one request.
    async fn reply(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
            .to_string()
            + "\n";
        self.writer.write_all(request.as_bytes()).await.unwrap();
        loop {
            let message = self.line().await;
            if message["id"] == json!(id) {
                return message;
            }
            self.notifications.push(message);
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        let reply = self.reply(method, params.clone()).await;
        assert!(
            reply["error"].is_null(),
            "{method} {params}: {}",
            reply["error"]
        );
        reply["result"].clone()
    }

    async fn notification(&mut self, method: &str) -> Value {
        if let Some(i) = self
            .notifications
            .iter()
            .position(|n| n["method"] == method)
        {
            return self.notifications.remove(i);
        }
        loop {
            let message = self.line().await;
            if message["method"] == method {
                return message;
            }
            self.notifications.push(message);
        }
    }
}

fn scripthash(script: &[u8]) -> String {
    let mut h: [u8; 32] = Sha256::digest(script).into();
    h.reverse();
    hex::encode(h)
}

fn status_of(rows: &[(String, i64)]) -> Value {
    if rows.is_empty() {
        return Value::Null;
    }
    let text: String = rows.iter().map(|(t, h)| format!("{t}:{h}:")).collect();
    json!(hex::encode(Sha256::digest(text.as_bytes())))
}

async fn wait_bridge_tip(wallet: &mut Wallet, height: u32) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let tip = wallet.call("blockchain.headers.get_tip", json!([])).await;
        if tip["height"] == json!(height) {
            return;
        }
        assert!(Instant::now() < deadline, "bridge did not reach {height}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn electrum_answers_match_bchd() {
    if bchd_binary().is_none() {
        eprintln!("skipped: no bchd binary (set BCHD_BIN)");
        return;
    }
    let node = Bchd::start("bridge").await;
    node.generate(110).await;
    let key = Key::new(11);
    let p2pkh = key.script();
    let holder = p2sh32(&[0x56, 0x75, 0x51]);
    let mining = mining_script();
    let (cb1, v1) = node.coinbase(1).await;
    let (cb2, v2) = node.coinbase(2).await;
    let category = Category(cb2.txid.0);
    let pay = TxSpec {
        inputs: vec![(cb1, Unlock::Redeem(vec![0x51]))],
        outputs: vec![
            (700_000_000, p2pkh.clone(), vec![]),
            (v1 - 700_000_000 - 3000, mining.clone(), vec![]),
        ],
    }
    .build();
    let mint = TxSpec {
        inputs: vec![(cb2, Unlock::Redeem(vec![0x51]))],
        outputs: vec![
            (1000, holder.clone(), nft_prefix(&category, b"vault")),
            (v2 - 4000, mining.clone(), vec![]),
        ],
    }
    .build();
    node.send(&pay).await;
    node.send(&mint).await;
    node.generate(1).await;

    let port = free_port();
    let dir = node.dir.join("bridge-data");
    let log = std::fs::File::create(node.dir.join("bridge.log")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_bch-electrum-bridge"))
        .args([
            "--network",
            "regtest",
            "--peer",
            &node.peer(),
            "--listen",
            &format!("127.0.0.1:{port}"),
        ])
        .arg("--datadir")
        .arg(&dir)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("start bridge");
    let _bridge = Bridge { child };
    let mut w = Wallet::connect(port).await;

    let version = w
        .call("server.version", json!(["test-wallet", ["1.4", "1.6"]]))
        .await;
    assert_eq!(version[1], json!("1.6"));
    let features = w.call("server.features", json!([])).await;
    assert_eq!(
        features["genesis_hash"],
        node.rpc("getblockhash", json!([0])).await
    );
    let tip_height = node.height().await;
    wait_bridge_tip(&mut w, tip_height).await;
    let tip = w.call("blockchain.headers.subscribe", json!([])).await;
    let tip_hash = node.rpc("getblockhash", json!([tip_height])).await;
    assert_eq!(
        tip["hex"],
        node.rpc("getblockheader", json!([tip_hash, false])).await
    );

    // Headers, with a checkpoint proof.
    let h5 = w.call("blockchain.block.header", json!([5])).await;
    let hash5 = node.rpc("getblockhash", json!([5])).await;
    assert_eq!(h5, node.rpc("getblockheader", json!([hash5, false])).await);
    let proof = w
        .call("blockchain.block.header", json!([5, tip_height]))
        .await;
    let leaf = hash256(&hex::decode(proof["header"].as_str().unwrap()).unwrap());
    let branch: Vec<[u8; 32]> = proof["branch"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let mut h: [u8; 32] = hex::decode(b.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            h.reverse();
            h
        })
        .collect();
    let mut root = bch_light_client::block::merkle_fold(leaf, 5, &branch);
    root.reverse();
    assert_eq!(json!(hex::encode(root)), proof["root"]);
    let headers = w.call("blockchain.block.headers", json!([0, 10])).await;
    assert_eq!(headers["count"], json!(10));
    assert_eq!(headers["headers"].as_array().unwrap().len(), 10);

    // Histories, balances and unspent outputs equal bchd's blocks.
    let blocks = all_blocks(&node).await;
    for script in [&p2pkh, &holder, &mining] {
        let sh = scripthash(script);
        let truth = truth(&node, &blocks, &Watch::Script(script.clone())).await;
        let history = w
            .call("blockchain.scripthash.get_history", json!([sh]))
            .await;
        let rows: Vec<(String, i64)> = history
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["tx_hash"].as_str().unwrap().to_string(),
                    r["height"].as_i64().unwrap(),
                )
            })
            .collect();
        let expected: Vec<(String, i64)> = truth
            .confirmed
            .iter()
            .map(|(t, h, _)| (t.clone(), i64::from(*h)))
            .collect();
        assert_eq!(rows, expected);
        let balance = w
            .call("blockchain.scripthash.get_balance", json!([sh]))
            .await;
        assert_eq!(balance["confirmed"], json!(truth.balance_confirmed));
        let unspent = w
            .call("blockchain.scripthash.listunspent", json!([sh]))
            .await;
        assert_eq!(
            unspent.as_array().unwrap().len(),
            truth.unspent_confirmed.len()
        );
        let status = w
            .call("blockchain.scripthash.get_status", json!([sh]))
            .await;
        assert_eq!(status, status_of(&expected));
    }
    // The NFT at the P2SH32 output, by its token-aware CashAddr.
    let address = Address::from_script(&holder, true)
        .unwrap()
        .encode("bchreg");
    let unspent = w
        .call(
            "blockchain.address.listunspent",
            json!([address, "include_tokens"]),
        )
        .await;
    assert_eq!(
        unspent[0]["token_data"]["category"],
        json!(category.to_hex())
    );
    assert_eq!(
        unspent[0]["token_data"]["nft"]["commitment"],
        json!(hex::encode(b"vault"))
    );
    let excluded = w
        .call(
            "blockchain.address.listunspent",
            json!([address, "exclude_tokens"]),
        )
        .await;
    assert_eq!(excluded, json!([]));
    let first = w
        .call("blockchain.address.get_first_use", json!([address]))
        .await;
    assert_eq!(first["tx_hash"], json!(txid_of(&mint).to_hex()));

    // Transactions by ID (in a history the wallet asked for), proofs and positions.
    let pay_id = txid_of(&pay);
    let raw = w
        .call("blockchain.transaction.get", json!([pay_id.to_hex()]))
        .await;
    assert_eq!(raw, json!(hex::encode(&pay)));
    let verbose = w
        .call("blockchain.transaction.get", json!([pay_id.to_hex(), true]))
        .await;
    assert_eq!(
        verbose["blockhash"],
        node.rpc("getblockhash", json!([111])).await
    );
    assert_eq!(
        w.call(
            "blockchain.transaction.get_height",
            json!([pay_id.to_hex()])
        )
        .await,
        json!(111)
    );
    let merkle = w
        .call(
            "blockchain.transaction.get_merkle",
            json!([pay_id.to_hex(), 111]),
        )
        .await;
    let pos = merkle["pos"].as_u64().unwrap();
    let by_pos = w
        .call("blockchain.transaction.id_from_pos", json!([111, pos]))
        .await;
    assert_eq!(by_pos, json!(pay_id.to_hex()));
    let info = w
        .call("blockchain.utxo.get_info", json!([pay_id.to_hex(), 0]))
        .await;
    assert_eq!(info["value"], json!(700_000_000));
    assert_eq!(info["scripthash"], json!(scripthash(&p2pkh)));

    // A subscription follows an unconfirmed payment, then its confirmation.
    let sh = scripthash(&p2pkh);
    let before = w.call("blockchain.scripthash.subscribe", json!([sh])).await;
    assert_eq!(before, status_of(&[(pay_id.to_hex(), 111)]));
    let (cb3, v3) = node.coinbase(3).await;
    let incoming = TxSpec {
        inputs: vec![(cb3, Unlock::Redeem(vec![0x51]))],
        outputs: vec![
            (25_000_000, p2pkh.clone(), vec![]),
            (v3 - 25_000_000 - 3000, mining.clone(), vec![]),
        ],
    }
    .build();
    let incoming_id = node.send(&incoming).await;
    let note = w.notification("blockchain.scripthash.subscribe").await;
    assert_eq!(note["params"][0], json!(sh));
    assert_eq!(
        note["params"][1],
        status_of(&[(pay_id.to_hex(), 111), (incoming_id.clone(), 0)])
    );
    let mempool = w
        .call("blockchain.scripthash.get_mempool", json!([sh]))
        .await;
    assert_eq!(mempool[0]["tx_hash"], json!(incoming_id));
    assert_eq!(mempool[0]["height"], json!(0));
    let balance = w
        .call("blockchain.scripthash.get_balance", json!([sh]))
        .await;
    assert_eq!(balance["unconfirmed"], json!(25_000_000));
    node.generate(1).await;
    let header_note = w.notification("blockchain.headers.subscribe").await;
    assert_eq!(header_note["params"][0]["height"], json!(112));
    let confirmed = w.notification("blockchain.scripthash.subscribe").await;
    assert_eq!(
        confirmed["params"][1],
        status_of(&[(pay_id.to_hex(), 111), (incoming_id.clone(), 112)])
    );

    // A broadcast through the bridge reaches bchd.
    let (cb4, v4) = node.coinbase(4).await;
    let spend = TxSpec {
        inputs: vec![
            (OutPoint::new(pay_id, 0), Unlock::Sign(&key, 700_000_000)),
            (cb4, Unlock::Redeem(vec![0x51])),
        ],
        outputs: vec![(700_000_000 + v4 - 3000, mining.clone(), vec![])],
    }
    .build();
    let sent = w
        .call(
            "blockchain.transaction.broadcast",
            json!([hex::encode(&spend)]),
        )
        .await;
    assert_eq!(sent, json!(txid_of(&spend).to_hex()));
    assert!(node
        .rpc("getrawmempool", json!([]))
        .await
        .as_array()
        .unwrap()
        .contains(&sent));
    let bad = w
        .reply(
            "blockchain.transaction.broadcast",
            json!([hex::encode(&spend[..10])]),
        )
        .await;
    assert!(bad["error"]["message"]
        .as_str()
        .unwrap()
        .contains("rejected"));

    // Not yet: RPA and double-spend proofs; fees from what the client sees.
    let rpa = w
        .reply("blockchain.rpa.get_history", json!(["ab", 0]))
        .await;
    assert_eq!(rpa["error"]["code"], json!(-32601));
    let dsp = w
        .reply("blockchain.transaction.dsproof.get", json!([sent]))
        .await;
    assert_eq!(dsp["error"]["code"], json!(-32601));
    let fee = w.call("blockchain.estimatefee", json!([2])).await;
    assert!(fee.as_f64().unwrap() >= 0.00001);
    assert!(w
        .call("mempool.get_fee_histogram", json!([]))
        .await
        .is_array());
    assert_eq!(
        w.call("blockchain.relayfee", json!([])).await,
        json!(0.00001)
    );
}
