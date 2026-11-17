//! A bchd node on regtest for the integration tests: process, RPC, a small
//! transaction builder, and the truth about scripts read from bchd's own
//! blocks (getblock with verbosity 2) and mempool.

#![allow(dead_code)]

use bch_light_client::{Category, OutPoint, Txid};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The bchd binary: $BCHD_BIN, or the one built into the repository's .tools folder.
pub fn bchd_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("BCHD_BIN") {
        return Some(PathBuf::from(path));
    }
    let exe = if cfg!(windows) { "bchd.exe" } else { "bchd" };
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".tools")
        .join(exe);
    path.exists().then_some(path)
}

/// A bchd whose script filters hold transaction keys (kind 4):
/// $BCHD_TXID_BIN, or .tools/bchd-txid(.exe).
pub fn bchd_txid_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("BCHD_TXID_BIN") {
        return Some(PathBuf::from(path));
    }
    let exe = if cfg!(windows) {
        "bchd-txid.exe"
    } else {
        "bchd-txid"
    };
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".tools")
        .join(exe);
    path.exists().then_some(path)
}

/// A binary a test needs: found, or the test is skipped with a note. In CI
/// (the CI variable is set) a missing binary fails the test instead.
fn required(found: Option<PathBuf>, what: &str) -> Option<PathBuf> {
    if found.is_some() {
        return found;
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "{what} is missing, and CI must run this test"
    );
    eprintln!("skipped: no {what}");
    None
}

/// bchd for a test, or None (skipped) outside CI.
pub fn bchd_or_skip() -> Option<PathBuf> {
    required(bchd_binary(), "bchd binary (set BCHD_BIN)")
}

/// A bchd whose filters hold transaction keys, or None (skipped) outside CI.
pub fn bchd_txid_binary_or_skip() -> Option<PathBuf> {
    required(
        bchd_txid_binary(),
        "bchd with transaction keys in its filters (set BCHD_TXID_BIN)",
    )
}

/// A port the OS gives out now; bchd binds it right after.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn hash160(b: &[u8]) -> [u8; 20] {
    ripemd::Ripemd160::digest(Sha256::digest(b)).into()
}

pub fn hash256(b: &[u8]) -> [u8; 32] {
    sha256(&sha256(b))
}

pub fn push(data: &[u8]) -> Vec<u8> {
    assert!(data.len() < 76);
    let mut out = vec![data.len() as u8];
    out.extend_from_slice(data);
    out
}

pub fn p2pkh(pkh: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(pkh);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

pub fn p2sh20(redeem: &[u8]) -> Vec<u8> {
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&hash160(redeem));
    s.push(0x87);
    s
}

pub fn p2sh32(redeem: &[u8]) -> Vec<u8> {
    let mut s = vec![0xaa, 0x20];
    s.extend_from_slice(&hash256(redeem));
    s.push(0x87);
    s
}

/// The regtest mining address's script: P2SH20 of OP_TRUE.
pub fn mining_script() -> Vec<u8> {
    p2sh20(&[0x51])
}

pub const MINING_ADDRESS: &str = "bchreg:prdpw30fk4ym6zl6rftfjuw806arpn26fveknc0qmt";

pub struct Bchd {
    child: Child,
    pub p2p_port: u16,
    rpc_port: u16,
    pub dir: PathBuf,
}

impl Drop for Bchd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Bchd {
    /// Starts bchd on regtest with OS-assigned ports and waits until its RPC answers.
    pub async fn start(name: &str) -> Bchd {
        Self::start_with(&bchd_binary().expect("bchd binary"), name).await
    }

    /// Starts the given bchd binary.
    pub async fn start_with(bin: &Path, name: &str) -> Bchd {
        Self::start_args(bin, name, &[]).await
    }

    /// Starts the given bchd binary with more options.
    pub async fn start_args(bin: &Path, name: &str, extra: &[&str]) -> Bchd {
        let dir =
            std::env::temp_dir().join(format!("bch-light-client-it-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p2p_port = free_port();
        let rpc_port = free_port();
        let log = std::fs::File::create(dir.join("stdout.log")).unwrap();
        let child = Command::new(bin)
            .arg("--regtest")
            .arg(format!("--datadir={}", dir.join("data").display()))
            .arg(format!("--logdir={}", dir.join("logs").display()))
            .arg(format!("--listen=127.0.0.1:{p2p_port}"))
            .arg(format!("--rpclisten=127.0.0.1:{rpc_port}"))
            .arg("--rpcuser=u")
            .arg("--rpcpass=p")
            .arg("--notls")
            .arg(format!("--miningaddr={MINING_ADDRESS}"))
            .arg(format!(
                "--debuglevel={}",
                std::env::var("BCHD_DEBUGLEVEL").unwrap_or_else(|_| "info".into())
            ))
            .args(extra)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start bchd");
        let node = Bchd {
            child,
            p2p_port,
            rpc_port,
            dir,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if node.rpc_raw("getblockcount", json!([])).await.is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "bchd did not start; see {}",
                node.dir.display()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        node
    }

    pub fn peer(&self) -> String {
        format!("127.0.0.1:{}", self.p2p_port)
    }

    async fn rpc_raw(&self, method: &str, params: Value) -> Result<Value, String> {
        let body =
            json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let mut stream = TcpStream::connect(("127.0.0.1", self.rpc_port))
            .await
            .map_err(|e| e.to_string())?;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic dTpw\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&response);
        let json_start = text.find("\r\n\r\n").ok_or("no body")? + 4;
        let value: Value =
            serde_json::from_str(&text[json_start..]).map_err(|e| format!("{e}: {text}"))?;
        if !value["error"].is_null() {
            return Err(value["error"].to_string());
        }
        Ok(value["result"].clone())
    }

    pub async fn rpc(&self, method: &str, params: Value) -> Value {
        match self.rpc_raw(method, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{method} {params}: {e}"),
        }
    }

    pub async fn try_rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        self.rpc_raw(method, params).await
    }

    pub async fn height(&self) -> u32 {
        self.rpc("getblockcount", json!([])).await.as_u64().unwrap() as u32
    }

    pub async fn generate(&self, n: u32) -> Vec<String> {
        // Right after start bchd may answer null while its miner gets ready.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let result = self.rpc("generate", json!([n])).await;
            if let Some(hashes) = result.as_array() {
                return hashes
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
            }
            assert!(Instant::now() < deadline, "generate answered {result}");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// The block at `height` with its transactions decoded, under "tx".
    pub async fn block(&self, height: u32) -> Value {
        let hash = self.rpc("getblockhash", json!([height])).await;
        let mut block = self.rpc("getblock", json!([hash, 2])).await;
        // bchd puts decoded transactions under "rawtx" and leaves "tx" to IDs.
        if block["rawtx"].is_array() {
            block["tx"] = block["rawtx"].take();
        }
        assert!(
            block["tx"][0]["txid"].is_string(),
            "getblock verbosity 2 gave {block}"
        );
        block
    }

    pub async fn send(&self, raw: &[u8]) -> String {
        self.rpc("sendrawtransaction", json!([hex::encode(raw)]))
            .await
            .as_str()
            .unwrap()
            .to_string()
    }

    /// The coinbase output of the block at `height`: outpoint and value.
    pub async fn coinbase(&self, height: u32) -> (OutPoint, u64) {
        let block = self.block(height).await;
        let tx = &block["tx"][0];
        (
            OutPoint::new(Txid::from_hex(tx["txid"].as_str().unwrap()).unwrap(), 0),
            sats(&tx["vout"][0]["value"]),
        )
    }
}

pub fn sats(v: &Value) -> u64 {
    (v.as_f64().unwrap() * 1e8).round() as u64
}

/// A key that signs P2PKH inputs.
pub struct Key {
    sk: SigningKey,
    pub pubkey: Vec<u8>,
}

impl Key {
    pub fn new(seed: u8) -> Self {
        let sk = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let pubkey = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        Self { sk, pubkey }
    }

    pub fn script(&self) -> Vec<u8> {
        p2pkh(&hash160(&self.pubkey))
    }
}

/// How an input unlocks the output it spends.
pub enum Unlock<'a> {
    /// P2SH (20 or 32) with this redeem script that needs no signature.
    Redeem(Vec<u8>),
    /// A bare script that needs nothing.
    Empty,
    /// P2PKH, signed with the key; the spent output's value.
    Sign(&'a Key, u64),
}

pub struct TxSpec<'a> {
    pub inputs: Vec<(OutPoint, Unlock<'a>)>,
    /// value, locking script, token prefix (already serialized) or empty.
    pub outputs: Vec<(u64, Vec<u8>, Vec<u8>)>,
}

fn put_varint(out: &mut Vec<u8>, n: usize) {
    if n < 0xfd {
        out.push(n as u8);
    } else {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    }
}

impl TxSpec<'_> {
    pub fn build(&self) -> Vec<u8> {
        let mut outputs = Vec::new();
        for (value, script, prefix) in &self.outputs {
            outputs.extend_from_slice(&value.to_le_bytes());
            put_varint(&mut outputs, prefix.len() + script.len());
            outputs.extend_from_slice(prefix);
            outputs.extend_from_slice(script);
        }
        let mut prevouts = Vec::new();
        let mut sequences = Vec::new();
        for (o, _) in &self.inputs {
            prevouts.extend_from_slice(&o.txid.0);
            prevouts.extend_from_slice(&o.vout.to_le_bytes());
            sequences.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        let mut tx = Vec::new();
        tx.extend_from_slice(&2i32.to_le_bytes());
        put_varint(&mut tx, self.inputs.len());
        for (outpoint, unlock) in &self.inputs {
            let script_sig = match unlock {
                Unlock::Redeem(redeem) => push(redeem),
                Unlock::Empty => Vec::new(),
                Unlock::Sign(key, value) => {
                    // BIP143-style signing serialization with SIGHASH_ALL | FORKID.
                    let mut pre = Vec::new();
                    pre.extend_from_slice(&2i32.to_le_bytes());
                    pre.extend_from_slice(&hash256(&prevouts));
                    pre.extend_from_slice(&hash256(&sequences));
                    pre.extend_from_slice(&outpoint.txid.0);
                    pre.extend_from_slice(&outpoint.vout.to_le_bytes());
                    let code = key.script();
                    put_varint(&mut pre, code.len());
                    pre.extend_from_slice(&code);
                    pre.extend_from_slice(&value.to_le_bytes());
                    pre.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
                    pre.extend_from_slice(&hash256(&outputs));
                    pre.extend_from_slice(&0u32.to_le_bytes());
                    pre.extend_from_slice(&0x41u32.to_le_bytes());
                    let digest = hash256(&pre);
                    let sig: Signature = key.sk.sign_prehash(&digest).unwrap();
                    let sig = sig.normalize_s().unwrap_or(sig);
                    let mut der = sig.to_der().as_bytes().to_vec();
                    der.push(0x41);
                    let mut s = push(&der);
                    s.extend(push(&key.pubkey));
                    s
                }
            };
            tx.extend_from_slice(&outpoint.txid.0);
            tx.extend_from_slice(&outpoint.vout.to_le_bytes());
            put_varint(&mut tx, script_sig.len());
            tx.extend_from_slice(&script_sig);
            tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        put_varint(&mut tx, self.outputs.len());
        tx.extend_from_slice(&outputs);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }
}

pub fn txid_of(raw: &[u8]) -> Txid {
    Txid(hash256(raw))
}

/// A token prefix for an immutable NFT with a commitment.
pub fn nft_prefix(category: &Category, commitment: &[u8]) -> Vec<u8> {
    let mut p = vec![0xef];
    p.extend_from_slice(&category.0);
    p.push(0x20 | 0x40);
    p.push(commitment.len() as u8);
    p.extend_from_slice(commitment);
    p
}

/// Token data in the shape both sides are compared in: category (display
/// hex), amount, and NFT capability and commitment.
pub type Token = Option<(String, u64, Option<(String, String)>)>;

/// Outputs a transaction gives a target: (vout, value, token).
pub type ReceivedRows = Vec<(u32, u64, Token)>;
/// Inputs that spend a target's outputs: (vin, prevout, value).
pub type SpentRows = Vec<(u32, String, u64)>;

pub fn token_from_json(v: &Value) -> Token {
    if v.is_null() {
        return None;
    }
    let nft = (!v["nft"].is_null()).then(|| {
        (
            v["nft"]["capability"].as_str().unwrap().to_string(),
            v["nft"]["commitment"].as_str().unwrap().to_string(),
        )
    });
    Some((
        v["category"].as_str().unwrap().to_string(),
        v["amount"].as_str().unwrap().parse().unwrap(),
        nft,
    ))
}

pub fn token_from_lib(t: &Option<bch_light_client::TokenData>) -> Token {
    t.as_ref().map(|t| {
        (
            t.category.to_hex(),
            t.amount,
            t.nft.as_ref().map(|n| {
                (
                    n.capability.as_str().to_string(),
                    hex::encode(&n.commitment),
                )
            }),
        )
    })
}

/// What a watched target should look like, from bchd's blocks and mempool.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Truth {
    /// (txid, height, position) in chain order.
    pub confirmed: Vec<(String, u32, u32)>,
    /// Per txid: received (vout, value, token) and spent (vin, prevout, value).
    pub detail: BTreeMap<String, (ReceivedRows, SpentRows)>,
    /// Unconfirmed txids.
    pub mempool: Vec<String>,
    /// Confirmed unspent: outpoint "txid:vout", value, token, height.
    pub unspent_confirmed: Vec<(String, u64, Token, u32)>,
    pub unspent_mempool: Vec<(String, u64, Token)>,
    pub balance_confirmed: u64,
    pub balance_unconfirmed: i64,
}

/// What a test watches, in bchd's JSON terms.
#[derive(Clone)]
pub enum Watch {
    Script(Vec<u8>),
    ScriptHash([u8; 32]),
    Category(String),
}

impl Watch {
    fn owns(&self, vout: &Value) -> bool {
        match self {
            Watch::Script(script) => {
                vout["scriptPubKey"]["hex"].as_str() == Some(&hex::encode(script))
            }
            Watch::ScriptHash(hash) => vout["scriptPubKey"]["hex"]
                .as_str()
                .is_some_and(|h| sha256(&hex::decode(h).unwrap()) == *hash),
            Watch::Category(cat) => vout["tokenData"]["category"].as_str() == Some(cat.as_str()),
        }
    }
}

/// Reads every block and the mempool and works out a target's history.
pub async fn truth(node: &Bchd, blocks: &[Value], watch: &Watch) -> Truth {
    let mut t = Truth::default();
    let mut coins: HashMap<String, (u64, Token, u32)> = HashMap::new();
    let mut spent: HashMap<String, ()> = HashMap::new();
    for (height, block) in blocks.iter().enumerate() {
        let txs = block["tx"].as_array().unwrap();
        // Outputs of the whole block first, then inputs.
        let mut per_tx: BTreeMap<u32, (String, ReceivedRows, SpentRows)> = BTreeMap::new();
        for (pos, tx) in txs.iter().enumerate() {
            let txid = tx["txid"].as_str().unwrap().to_string();
            for vout in tx["vout"].as_array().unwrap() {
                if watch.owns(vout) {
                    let n = vout["n"].as_u64().unwrap() as u32;
                    let token = token_from_json(&vout["tokenData"]);
                    coins.insert(
                        format!("{txid}:{n}"),
                        (sats(&vout["value"]), token.clone(), height as u32),
                    );
                    per_tx
                        .entry(pos as u32)
                        .or_insert_with(|| (txid.clone(), vec![], vec![]))
                        .1
                        .push((n, sats(&vout["value"]), token));
                }
            }
        }
        for (pos, tx) in txs.iter().enumerate().skip(1) {
            let txid = tx["txid"].as_str().unwrap().to_string();
            for (vin, input) in tx["vin"].as_array().unwrap().iter().enumerate() {
                let prev = format!(
                    "{}:{}",
                    input["txid"].as_str().unwrap(),
                    input["vout"].as_u64().unwrap()
                );
                if let Some((value, _, _)) = coins.get(&prev) {
                    spent.insert(prev.clone(), ());
                    per_tx
                        .entry(pos as u32)
                        .or_insert_with(|| (txid.clone(), vec![], vec![]))
                        .2
                        .push((vin as u32, prev, *value));
                }
            }
        }
        for (pos, (txid, received, spends)) in per_tx {
            t.confirmed.push((txid.clone(), height as u32, pos));
            t.detail.insert(txid, (received, spends));
        }
    }
    // The mempool.
    let pool = node.rpc("getrawmempool", json!([])).await;
    let mut pool_txs: Vec<Value> = Vec::new();
    for txid in pool.as_array().unwrap() {
        pool_txs.push(node.rpc("getrawtransaction", json!([txid, 1])).await);
    }
    let mut mempool_coins: HashMap<String, (u64, Token)> = HashMap::new();
    let mut touched: BTreeMap<String, ()> = BTreeMap::new();
    let mut mempool_spent: HashMap<String, ()> = HashMap::new();
    for tx in &pool_txs {
        let txid = tx["txid"].as_str().unwrap().to_string();
        for vout in tx["vout"].as_array().unwrap() {
            if watch.owns(vout) {
                let n = vout["n"].as_u64().unwrap();
                mempool_coins.insert(
                    format!("{txid}:{n}"),
                    (sats(&vout["value"]), token_from_json(&vout["tokenData"])),
                );
                touched.insert(txid.clone(), ());
                t.balance_unconfirmed += sats(&vout["value"]) as i64;
            }
        }
    }
    for tx in &pool_txs {
        let txid = tx["txid"].as_str().unwrap().to_string();
        for input in tx["vin"].as_array().unwrap() {
            let prev = format!(
                "{}:{}",
                input["txid"].as_str().unwrap(),
                input["vout"].as_u64().unwrap()
            );
            mempool_spent.insert(prev.clone(), ());
            let value = coins
                .get(&prev)
                .map(|c| c.0)
                .or_else(|| mempool_coins.get(&prev).map(|c| c.0));
            if let Some(value) = value {
                touched.insert(txid.clone(), ());
                t.balance_unconfirmed -= value as i64;
            }
        }
    }
    t.mempool = touched.into_keys().collect();
    let mut unspent: Vec<(String, u64, Token, u32)> = coins
        .iter()
        .filter(|(o, _)| !spent.contains_key(*o))
        .map(|(o, (v, tok, h))| (o.clone(), *v, tok.clone(), *h))
        .collect();
    t.balance_confirmed = unspent.iter().map(|u| u.1).sum();
    unspent.retain(|u| !mempool_spent.contains_key(&u.0));
    unspent.sort_by(|a, b| (a.3, &a.0).cmp(&(b.3, &b.0)));
    t.unspent_confirmed = unspent;
    let mut m: Vec<(String, u64, Token)> = mempool_coins
        .into_iter()
        .filter(|(o, _)| !mempool_spent.contains_key(o))
        .map(|(o, (v, tok))| (o, v, tok))
        .collect();
    m.sort();
    t.unspent_mempool = m;
    t
}

/// Every block of bchd's chain, verbosity 2.
pub async fn all_blocks(node: &Bchd) -> Vec<Value> {
    let tip = node.height().await;
    let mut out = Vec::with_capacity(tip as usize + 1);
    for h in 0..=tip {
        out.push(node.block(h).await);
    }
    out
}
