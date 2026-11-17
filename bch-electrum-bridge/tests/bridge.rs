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
        .encode("bchreg")
        .unwrap();
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
    // Scripts as BCHN's getrawtransaction shows them, which Fulcrum passes on.
    let pay_spk = &verbose["vout"][0]["scriptPubKey"];
    assert_eq!(
        pay_spk["asm"],
        json!(format!(
            "OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG",
            hex::encode(&p2pkh[3..23])
        ))
    );
    assert_eq!(pay_spk["type"], json!("pubkeyhash"));
    assert_eq!(pay_spk["reqSigs"], json!(1));
    let plain = Address::from_script(&p2pkh, false).unwrap();
    assert_eq!(
        pay_spk["addresses"],
        json!([plain.encode("bchreg").unwrap()])
    );
    // The redeem script OP_1, pushed as the byte 0x51: the number 81.
    assert_eq!(verbose["vin"][0]["scriptSig"]["asm"], json!("81"));
    // A token output's address is token-unaware, as BCHN writes it.
    let mint_verbose = w
        .call(
            "blockchain.transaction.get",
            json!([txid_of(&mint).to_hex(), true]),
        )
        .await;
    let holder_spk = &mint_verbose["vout"][0]["scriptPubKey"];
    assert_eq!(holder_spk["type"], json!("scripthash"));
    assert_eq!(
        holder_spk["addresses"],
        json!([Address::from_script(&holder, false)
            .unwrap()
            .encode("bchreg")
            .unwrap()])
    );
    assert!(mint_verbose["vout"][0]["tokenData"].is_object());
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
    // Its signature shows its hash type, as BCHN decodes it.
    let signed = w
        .call("blockchain.transaction.get", json!([sent, true]))
        .await;
    let asm = signed["vin"][0]["scriptSig"]["asm"].as_str().unwrap();
    assert!(
        asm.ends_with(&format!("[ALL|FORKID] {}", hex::encode(&key.pubkey))),
        "{asm}"
    );
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

    // This bchd serves no input prefix filters: an RPA search finds nothing
    // (rpa_and_dsproof_methods runs against one that does). No proof is
    // known for a transaction nobody double-spent. Fees from what the client sees.
    let rpa = w.call("blockchain.rpa.get_history", json!(["ab", 0])).await;
    assert_eq!(rpa, json!([]));
    let dsp = w
        .call("blockchain.transaction.dsproof.get", json!([sent]))
        .await;
    assert_eq!(dsp, Value::Null);
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

fn bchd_rpa_binary() -> Option<std::path::PathBuf> {
    if let Ok(path) = std::env::var("BCHD_RPA_BIN") {
        return Some(path.into());
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

fn rpa_value(outpoint: OutPoint, sequence: u32) -> u16 {
    let mut b = outpoint.txid.0.to_vec();
    b.extend_from_slice(&outpoint.vout.to_le_bytes());
    b.extend_from_slice(&[0x02, 0x01, 0x51]);
    b.extend_from_slice(&sequence.to_le_bytes());
    let h = hash256(&b);
    u16::from_be_bytes([h[0], h[1]])
}

/// A version 1 spend of a P2SH(OP_TRUE) coin whose input value is `prefix` (16 bits).
fn ground_spend(outpoint: OutPoint, value: u64, prefix: u16, script: &[u8]) -> Vec<u8> {
    let sequence = (0u32..)
        .find(|s| rpa_value(outpoint, *s) == prefix)
        .unwrap();
    let mut tx = 1i32.to_le_bytes().to_vec();
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

/// RPA searches and double-spend proofs through the bridge, with Fulcrum's
/// argument order, limits and result shapes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpa_and_dsproof_methods() {
    let Some(bin) = bchd_rpa_binary() else {
        eprintln!("skipped: no bchd with input prefix filters (set BCHD_RPA_BIN)");
        return;
    };
    let node = Bchd::start_with(&bin, "bridge-rpa").await;
    node.generate(110).await;
    let mining = mining_script();
    let key = Key::new(31);
    let (cb1, v1) = node.coinbase(1).await;
    let fund = TxSpec {
        inputs: vec![(cb1, Unlock::Redeem(vec![0x51]))],
        outputs: vec![
            (500_000_000, key.script(), vec![]),
            (v1 - 500_000_000 - 3000, mining.clone(), vec![]),
        ],
    }
    .build();
    node.send(&fund).await;
    node.generate(1).await;

    let port = free_port();
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
        .arg(node.dir.join("bridge-data"))
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("start bridge");
    let _bridge = Bridge { child };
    let mut w = Wallet::connect(port).await;
    w.call("server.version", json!(["test-wallet", "1.5"]))
        .await;
    let features = w.call("server.features", json!([])).await;
    assert_eq!(features["dsproof"], json!(true));
    assert_eq!(features["rpa"]["prefix_bits_min"], json!(8));
    assert_eq!(features["rpa"]["history_block_limit"], json!(60));
    wait_bridge_tip(&mut w, 111).await;

    // A payment ground to the prefix beef, seen first in the mempool.
    let (cb2, v2) = node.coinbase(2).await;
    let pay = ground_spend(cb2, v2, 0xbeef, &mining);
    let pay_id = node.send(&pay).await;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let pending = w.call("blockchain.rpa.get_mempool", json!(["beef"])).await;
        if pending
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["tx_hash"] == json!(pay_id))
        {
            assert_eq!(pending[0]["height"], json!(0));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the payment did not reach the mempool copy"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    node.generate(1).await;
    wait_bridge_tip(&mut w, 112).await;
    let rows = w
        .call("blockchain.rpa.get_history", json!(["beef", 100]))
        .await;
    assert_eq!(rows, json!([{"tx_hash": pay_id, "height": 112}]));
    // 8 bits of the same prefix find it too; another 16-bit prefix does not.
    let rows8 = w
        .call("blockchain.rpa.get_history", json!(["be", 100, 113]))
        .await;
    assert!(rows8
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["tx_hash"] == json!(pay_id)));
    assert_eq!(
        w.call("blockchain.rpa.get_history", json!(["beee", 100]))
            .await,
        json!([])
    );
    // At most 60 blocks per call, from `from`: from 0 never reaches 112.
    assert_eq!(
        w.call("blockchain.rpa.get_history", json!(["beef", 0]))
            .await,
        json!([])
    );
    // A to_height at or below from_height: nothing.
    assert_eq!(
        w.call("blockchain.rpa.get_history", json!(["beef", 112, 112]))
            .await,
        json!([])
    );
    // The older form: (from, count, prefix).
    let legacy = w
        .call("blockchain.reusable.get_history", json!([110, 5, "beef"]))
        .await;
    assert_eq!(legacy, json!([{"tx_hash": pay_id, "height": 112}]));
    // Fewer than 8 bits are refused.
    let short = w
        .reply("blockchain.rpa.get_history", json!(["b", 100]))
        .await;
    assert_eq!(short["error"]["code"], json!(-32602));

    // A double spend: the proof reaches the subscriber.
    let coin = OutPoint::new(txid_of(&fund), 0);
    let first = TxSpec {
        inputs: vec![(coin, Unlock::Sign(&key, 500_000_000))],
        outputs: vec![(499_990_000, mining.clone(), vec![])],
    }
    .build();
    let second = TxSpec {
        inputs: vec![(coin, Unlock::Sign(&key, 500_000_000))],
        outputs: vec![(499_980_000, p2sh32(&[0x57, 0x75, 0x51]), vec![])],
    }
    .build();
    let first_id = node.send(&first).await;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let height = w
            .call("blockchain.transaction.subscribe", json!([first_id]))
            .await;
        if height == json!(0) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the first spend did not reach the mempool copy"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        w.call(
            "blockchain.transaction.dsproof.subscribe",
            json!([first_id])
        )
        .await,
        Value::Null
    );
    assert!(node
        .try_rpc("sendrawtransaction", json!([hex::encode(&second)]))
        .await
        .is_err());
    let note = w
        .notification("blockchain.transaction.dsproof.subscribe")
        .await;
    assert_eq!(note["params"][0], json!(first_id));
    let proof = note["params"][1].clone();
    assert_eq!(proof["txid"], json!(first_id));
    assert_eq!(
        proof["outpoint"],
        json!({"txid": coin.txid.to_hex(), "vout": 0})
    );
    assert_eq!(proof["descendants"], json!([first_id]));
    let theirs = node.rpc("getdsproof", json!([first_id])).await;
    assert_eq!(proof["dspid"], theirs["dspid"]);
    assert_eq!(
        w.call("blockchain.transaction.dsproof.get", json!([first_id]))
            .await,
        proof
    );
    assert_eq!(
        w.call(
            "blockchain.transaction.dsproof.get",
            json!([proof["dspid"]])
        )
        .await,
        proof
    );
    assert_eq!(
        w.call("blockchain.transaction.dsproof.list", json!([]))
            .await,
        json!([first_id])
    );
    // A child of the proved transaction: the proof concerns it too, and its
    // subscriber hears so when it reaches the mempool, as from Fulcrum.
    let child = TxSpec {
        inputs: vec![(
            OutPoint::new(txid_of(&first), 0),
            Unlock::Redeem(vec![0x51]),
        )],
        outputs: vec![(499_980_000, mining.clone(), vec![])],
    }
    .build();
    let child_id = txid_of(&child).to_hex();
    assert_eq!(
        w.call(
            "blockchain.transaction.dsproof.subscribe",
            json!([child_id])
        )
        .await,
        Value::Null
    );
    node.send(&child).await;
    let note = loop {
        let note = w
            .notification("blockchain.transaction.dsproof.subscribe")
            .await;
        if note["params"][0] == json!(child_id) {
            break note;
        }
    };
    assert_eq!(note["params"][1]["dspid"], proof["dspid"]);
    assert_eq!(
        note["params"][1]["descendants"],
        json!([first_id, child_id])
    );
    // A block settles the double spend: both subscribers hear the proof went.
    w.notifications.clear();
    node.generate(1).await;
    let mut gone = std::collections::BTreeSet::new();
    while gone.len() < 2 {
        let note = w
            .notification("blockchain.transaction.dsproof.subscribe")
            .await;
        if note["params"][1].is_null() {
            gone.insert(note["params"][0].as_str().unwrap().to_string());
        }
    }
    assert_eq!(
        gone,
        [first_id.clone(), child_id.clone()].into_iter().collect()
    );
    assert_eq!(
        w.call("blockchain.transaction.dsproof.list", json!([]))
            .await,
        json!([])
    );
    let stats = w.call("light_client.stats", json!([])).await;
    assert!(stats["block_bytes"].as_u64().unwrap() > 0);
    let passthrough = w.reply("daemon.passthrough", json!([])).await;
    assert_eq!(passthrough["error"]["code"], json!(-32601));
    // Named, as Fulcrum takes them: still no node RPC, the code Fulcrum
    // gives when passthrough is off. Elsewhere an object is a bad parameter.
    let named = w
        .reply(
            "daemon.passthrough",
            json!({"method": "getblockcount", "params": []}),
        )
        .await;
    assert_eq!(named["error"]["code"], json!(-32601));
    let object = w
        .reply("blockchain.transaction.get", json!({"tx_hash": first_id}))
        .await;
    assert_eq!(object["error"]["code"], json!(-32602));
    // What Fulcrum keeps of BCHN's getmempoolinfo.
    let info = w.call("mempool.get_info", json!([])).await;
    assert_eq!(
        info,
        json!({"mempoolminfee": 0.00001, "minrelaytxfee": 0.00001})
    );
}
