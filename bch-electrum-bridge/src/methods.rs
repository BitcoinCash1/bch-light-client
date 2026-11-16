//! The Electrum protocol methods, each answered through the light client.

use crate::session::{RpcError, ScriptSub, Session};
use bch_light_client::block::BlockHeader;
use bch_light_client::cashaddr::Address;
use bch_light_client::{
    BlockHash, ErrorKind, History, LightClient, OutPoint, Target, TokenData, TokenFilter,
    Transaction, Txid,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

const SERVER_VERSION: &str = concat!("bch-electrum-bridge ", env!("CARGO_PKG_VERSION"));
const PROTOCOL_MIN: (u32, u32, u32) = (1, 4, 0);
const PROTOCOL_MAX: (u32, u32, u32) = (1, 6, 0);
const TOKEN_AWARE: (u32, u32, u32) = (1, 5, 0);
const MAX_HEADERS: u32 = 2016;

type Result<T> = std::result::Result<T, RpcError>;

fn version_string(v: (u32, u32, u32)) -> String {
    if v.2 == 0 {
        format!("{}.{}", v.0, v.1)
    } else {
        format!("{}.{}.{}", v.0, v.1, v.2)
    }
}

fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.trim().split('.').map(|p| p.parse::<u32>().ok());
    let major = parts.next()??;
    let minor = parts.next().unwrap_or(Some(0))?;
    let patch = parts.next().unwrap_or(Some(0))?;
    Some((major, minor, patch))
}

fn arg(params: &[Value], i: usize) -> Option<&Value> {
    params.get(i).filter(|v| !v.is_null())
}

fn str_arg<'a>(params: &'a [Value], i: usize, what: &str) -> Result<&'a str> {
    arg(params, i)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::params(format!("missing or bad {what}")))
}

fn u32_arg(params: &[Value], i: usize, what: &str) -> Result<Option<u32>> {
    match arg(params, i) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| RpcError::params(format!("bad {what}"))),
    }
}

fn bool_arg(params: &[Value], i: usize) -> Result<bool> {
    match arg(params, i) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::Number(n)) => Ok(n.as_u64().unwrap_or(0) != 0),
        Some(Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(RpcError::params("expected a boolean")),
        },
        _ => Err(RpcError::params("expected a boolean")),
    }
}

fn txid_arg(params: &[Value], i: usize) -> Result<Txid> {
    Txid::from_hex(str_arg(params, i, "tx hash")?).map_err(|_| RpcError::params("Invalid tx hash"))
}

/// A script hash parameter: the reversed SHA-256 of a locking script.
fn scripthash_arg(params: &[Value]) -> Result<(Target, String)> {
    let text = str_arg(params, 0, "scripthash")?;
    let mut hash = [0u8; 32];
    hex::decode_to_slice(text, &mut hash).map_err(|_| RpcError::params("Invalid scripthash"))?;
    hash.reverse();
    Ok((Target::ScriptHash(hash), text.to_ascii_lowercase()))
}

fn address_arg(session: &Session, params: &[Value]) -> Result<(Target, String)> {
    let text = str_arg(params, 0, "address")?;
    let prefix = session.shared.network.params().cashaddr_prefix;
    let address = Address::decode(text, prefix)
        .map_err(|e| RpcError::params(format!("Invalid address: {text} ({e})")))?;
    Ok((Target::Script(address.script()), text.to_string()))
}

fn token_filter_arg(session: &Session, params: &[Value], i: usize) -> Result<TokenFilter> {
    match arg(params, i).and_then(Value::as_str) {
        None => {
            let version = session.state.lock().expect("session lock").version;
            Ok(if version >= TOKEN_AWARE { TokenFilter::Include } else { TokenFilter::Exclude })
        }
        Some(s) => match s.trim().to_ascii_lowercase().as_str() {
            "include_tokens" => Ok(TokenFilter::Include),
            "exclude_tokens" => Ok(TokenFilter::Exclude),
            "tokens_only" => Ok(TokenFilter::Only),
            _ => Err(RpcError::params(
                "Invalid token filtering option. Specify one of: \"exclude_tokens\", \"include_tokens\", \"tokens_only\"",
            )),
        },
    }
}

fn reversed_hex(b: &[u8; 32]) -> String {
    let mut r = *b;
    r.reverse();
    hex::encode(r)
}

fn token_json(token: &TokenData) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("category".into(), json!(token.category.to_hex()));
    m.insert("amount".into(), json!(token.amount.to_string()));
    if let Some(nft) = &token.nft {
        m.insert("nft".into(), json!({"capability": nft.capability.as_str(), "commitment": hex::encode(&nft.commitment)}));
    }
    Value::Object(m)
}

fn header_json(height: u32, header: &BlockHeader) -> Value {
    json!({"height": height, "hex": hex::encode(header.to_bytes())})
}

/// The history rows Electrum lists: confirmed in chain order, then the mempool.
fn history_rows(history: &History, from: u32, to: Option<u32>) -> Vec<Value> {
    let mut rows: Vec<Value> = history
        .confirmed
        .iter()
        .filter(|t| t.height >= from && !matches!(to, Some(to) if t.height >= to))
        .map(|t| json!({"tx_hash": t.txid.to_hex(), "height": t.height}))
        .collect();
    if to.is_none() {
        rows.extend(history.mempool.iter().map(|e| {
            let mut row = json!({"tx_hash": e.txid.to_hex(), "height": if e.unconfirmed_parent { -1 } else { 0 }});
            if let Some(fee) = e.fee {
                row["fee"] = json!(fee);
            }
            row
        }));
    }
    rows
}

/// The Electrum status of a history: SHA-256 of "txid:height:" for each
/// transaction, or null for none.
pub async fn status(
    client: &LightClient,
    target: &Target,
) -> std::result::Result<Option<String>, RpcError> {
    let history = client.history(target).await?;
    let mut text = String::new();
    for t in &history.confirmed {
        text.push_str(&format!("{}:{}:", t.txid.to_hex(), t.height));
    }
    for e in &history.mempool {
        text.push_str(&format!(
            "{}:{}:",
            e.txid.to_hex(),
            if e.unconfirmed_parent { -1 } else { 0 }
        ));
    }
    Ok((!text.is_empty()).then(|| hex::encode(Sha256::digest(text.as_bytes()))))
}

/// A transaction's subscription status: its height, 0 in the mempool, or null.
pub async fn tx_status(client: &LightClient, txid: Txid) -> Value {
    if client.in_mempool(&txid) {
        return json!(0);
    }
    match client.transaction(txid, None).await {
        Ok(info) => info.confirmation.map_or(json!(0), |c| json!(c.height)),
        Err(_) => Value::Null,
    }
}

fn script_type(script: &[u8]) -> &'static str {
    match script {
        [0x76, 0xa9, 0x14, .., 0x88, 0xac] if script.len() == 25 => "pubkeyhash",
        [0xa9, 0x14, .., 0x87] if script.len() == 23 => "scripthash",
        [0xaa, 0x20, .., 0x87] if script.len() == 35 => "scripthash32",
        [0x6a, ..] => "nulldata",
        _ => "nonstandard",
    }
}

fn verbose_tx(
    session: &Session,
    tx: &Transaction,
    confirmation: Option<(u32, BlockHash)>,
) -> Value {
    let prefix = session.shared.network.params().cashaddr_prefix;
    let vin: Vec<Value> = tx
        .inputs
        .iter()
        .map(|i| {
            if tx.is_coinbase() {
                json!({"coinbase": hex::encode(&i.script_sig), "sequence": i.sequence})
            } else {
                json!({
                    "txid": i.prevout.txid.to_hex(),
                    "vout": i.prevout.vout,
                    "scriptSig": {"asm": "", "hex": hex::encode(&i.script_sig)},
                    "sequence": i.sequence,
                })
            }
        })
        .collect();
    let vout: Vec<Value> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(n, o)| {
            let mut spk =
                json!({"asm": "", "hex": hex::encode(&o.script), "type": script_type(&o.script)});
            if let Ok(address) = Address::from_script(&o.script, o.token.is_some()) {
                spk["addresses"] = json!([address.encode(prefix)]);
            }
            let mut out = json!({"value": o.value as f64 / 1e8, "n": n, "scriptPubKey": spk});
            if let Some(token) = &o.token {
                out["tokenData"] = token_json(token);
            }
            out
        })
        .collect();
    let raw = tx.serialize();
    let mut v = json!({
        "txid": tx.txid().to_hex(),
        "hash": tx.txid().to_hex(),
        "version": tx.version,
        "size": raw.len(),
        "locktime": tx.lock_time,
        "vin": vin,
        "vout": vout,
        "hex": hex::encode(&raw),
    });
    if let Some((height, block)) = confirmation {
        let client = &session.shared.client;
        let time = client.header(height).map(|h| h.time).unwrap_or(0);
        let tip = client.tip().map(|t| t.0).unwrap_or(height);
        v["blockhash"] = json!(block.to_hex());
        v["confirmations"] = json!(tip.saturating_sub(height) + 1);
        v["time"] = json!(time);
        v["blocktime"] = json!(time);
    }
    v
}

fn lookup_error(e: bch_light_client::Error) -> RpcError {
    match e.kind() {
        ErrorKind::NotFound => {
            RpcError::bad_request("No transaction matching the requested hash was found")
        }
        _ => RpcError::bad_request(e.to_string()),
    }
}

/// The ElectrumX compact fee histogram: (fee rate, cumulative size) bins.
fn fee_histogram(rates: &[(f64, usize)]) -> Vec<Value> {
    let mut by_rate: BTreeMap<u64, usize> = BTreeMap::new();
    for (rate, size) in rates {
        *by_rate.entry(rate.floor() as u64).or_default() += size;
    }
    let mut bin_size = 100_000.0f64;
    let mut out = Vec::new();
    let mut cum = 0usize;
    let mut prev_rate = 0u64;
    for (&rate, &size) in by_rate.iter().rev() {
        if size as f64 > 2.0 * bin_size && prev_rate != 0 && cum > 0 {
            out.push(json!([prev_rate, cum]));
            cum = 0;
            bin_size *= 1.1;
        }
        cum += size;
        if cum as f64 > bin_size {
            out.push(json!([rate, cum]));
            cum = 0;
            bin_size *= 1.1;
        }
        prev_rate = rate;
    }
    out
}

async fn subscribe(
    session: &Arc<Session>,
    target: Target,
    method: &'static str,
    name: String,
) -> Result<Value> {
    let current = status(&session.shared.client, &target).await?;
    let mut state = session.state.lock().expect("session lock");
    let sub = state
        .scripts
        .entry(target.key())
        .or_insert_with(|| ScriptSub {
            target,
            aliases: Vec::new(),
            status: current.clone(),
        });
    if !sub.aliases.iter().any(|(m, n)| *m == method && *n == name) {
        sub.aliases.push((method, name));
    }
    sub.status = current.clone();
    Ok(json!(current))
}

fn unsubscribe(session: &Session, target: &Target, method: &'static str, name: &str) -> Value {
    let mut state = session.state.lock().expect("session lock");
    let key = target.key();
    let Some(sub) = state.scripts.get_mut(&key) else {
        return json!(false);
    };
    let before = sub.aliases.len();
    sub.aliases.retain(|(m, n)| !(*m == method && n == name));
    let removed = sub.aliases.len() != before;
    if sub.aliases.is_empty() {
        state.scripts.remove(&key);
    }
    json!(removed)
}

/// Dispatches one method.
pub async fn call(session: &Arc<Session>, method: &str, params: &[Value]) -> Result<Value> {
    let client = &session.shared.client;
    match method {
        "server.version" => {
            let mut state = session.state.lock().expect("session lock");
            if state.version_sent {
                return Err(RpcError::bad_request("server.version already sent"));
            }
            let negotiated = match arg(params, 1) {
                None => PROTOCOL_MIN,
                Some(Value::Array(range)) if range.len() == 2 => {
                    let lo = range[0].as_str().and_then(parse_version);
                    let hi = range[1].as_str().and_then(parse_version);
                    match (lo, hi) {
                        (Some(lo), Some(hi)) if lo <= hi && hi.min(PROTOCOL_MAX) >= lo.max(PROTOCOL_MIN) => hi.min(PROTOCOL_MAX),
                        _ => return Err(RpcError::bad_request("Unsupported protocol version")),
                    }
                }
                Some(v) => match v.as_str().and_then(parse_version) {
                    Some(p) if (PROTOCOL_MIN..=PROTOCOL_MAX).contains(&p) => p,
                    _ => return Err(RpcError::bad_request("Unsupported protocol version")),
                },
            };
            state.version = negotiated;
            state.version_sent = true;
            Ok(json!([SERVER_VERSION, version_string(negotiated)]))
        }
        "server.banner" => Ok(json!(session.shared.banner)),
        "server.donation_address" => Ok(json!(session.shared.donation_address)),
        "server.ping" => Ok(Value::Null),
        "server.peers.subscribe" => Ok(json!([])),
        "server.add_peer" => Ok(json!(false)),
        "server.features" => Ok(json!({
            "genesis_hash": session.shared.network.params().genesis_hash().to_hex(),
            "hosts": {},
            "protocol_min": version_string(PROTOCOL_MIN),
            "protocol_max": version_string(PROTOCOL_MAX),
            "server_version": SERVER_VERSION,
            "hash_function": "sha256",
            "pruning": null,
            "dsproof": false,
            "cashtokens": true,
        })),

        "blockchain.headers.subscribe" | "blockchain.headers.get_tip" => {
            if method == "blockchain.headers.subscribe" {
                session.state.lock().expect("session lock").headers = true;
            }
            let (height, header) = client.tip().ok_or_else(|| RpcError::bad_request("not synced yet"))?;
            Ok(header_json(height, &header))
        }
        "blockchain.headers.unsubscribe" => {
            let mut state = session.state.lock().expect("session lock");
            let was = state.headers;
            state.headers = false;
            Ok(json!(was))
        }
        "blockchain.header.get" => {
            let first = arg(params, 0).ok_or_else(|| RpcError::params("Invalid height or hash specified"))?;
            let (height, header) = match first.as_str() {
                Some(text) if text.len() == 64 => {
                    let hash = BlockHash::from_hex(text).map_err(|_| RpcError::params("Invalid block hash"))?;
                    client.header_by_hash(&hash).ok_or_else(|| RpcError::bad_request("Block not in active chain"))?
                }
                _ => {
                    let height = u32_arg(params, 0, "height")?.ok_or_else(|| RpcError::params("Invalid height"))?;
                    (height, client.header(height).ok_or_else(|| RpcError::bad_request("Invalid height"))?)
                }
            };
            Ok(header_json(height, &header))
        }
        "blockchain.block.header" => {
            let height = u32_arg(params, 0, "height")?.ok_or_else(|| RpcError::params("Invalid height"))?;
            let cp_height = u32_arg(params, 1, "cp_height")?.unwrap_or(0);
            let header = client.header(height).ok_or_else(|| RpcError::bad_request("Invalid height"))?;
            if cp_height == 0 {
                return Ok(json!(hex::encode(header.to_bytes())));
            }
            let (branch, root) = client.header_branch(height, cp_height).map_err(|e| RpcError::bad_request(e.to_string()))?;
            Ok(json!({
                "header": hex::encode(header.to_bytes()),
                "branch": branch.iter().map(reversed_hex).collect::<Vec<_>>(),
                "root": reversed_hex(&root),
            }))
        }
        "blockchain.block.headers" => {
            let start = u32_arg(params, 0, "height")?.ok_or_else(|| RpcError::params("Invalid height"))?;
            let count = u32_arg(params, 1, "count")?.ok_or_else(|| RpcError::params("Invalid count"))?.min(MAX_HEADERS);
            let cp_height = u32_arg(params, 2, "cp_height")?.unwrap_or(0);
            let headers = client.headers(start, count);
            let as_list = session.state.lock().expect("session lock").version >= (1, 6, 0);
            let mut out = json!({"count": headers.len(), "max": MAX_HEADERS});
            if as_list {
                out["headers"] = json!(headers.iter().map(|h| hex::encode(h.to_bytes())).collect::<Vec<_>>());
            } else {
                out["hex"] = json!(headers.iter().map(|h| hex::encode(h.to_bytes())).collect::<String>());
            }
            if cp_height > 0 && !headers.is_empty() {
                let last = start + headers.len() as u32 - 1;
                let (branch, root) = client.header_branch(last, cp_height).map_err(|e| RpcError::bad_request(e.to_string()))?;
                out["branch"] = json!(branch.iter().map(reversed_hex).collect::<Vec<_>>());
                out["root"] = json!(reversed_hex(&root));
            }
            Ok(out)
        }
        "blockchain.estimatefee" => {
            u32_arg(params, 0, "number of blocks")?;
            Ok(json!(client.fee_estimate().estimate as f64 / 1e8))
        }
        "blockchain.relayfee" => Ok(json!(client.fee_estimate().relay as f64 / 1e8)),

        "blockchain.scripthash.get_balance" | "blockchain.address.get_balance" => {
            let (target, _) = target_of(session, method, params)?;
            let tokens = token_filter_arg(session, params, 1)?;
            let balance = client.balance(&target, tokens).await?;
            Ok(json!({"confirmed": balance.confirmed, "unconfirmed": balance.unconfirmed}))
        }
        "blockchain.scripthash.get_history" | "blockchain.address.get_history" => {
            let (target, _) = target_of(session, method, params)?;
            let from = match arg(params, 1) {
                None => 0,
                Some(v) => v
                    .as_i64()
                    .filter(|n| *n >= 0)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| RpcError::params("Bad from_height argument"))?,
            };
            let to = match arg(params, 2).map(|v| v.as_i64()) {
                None | Some(Some(-1)) => None,
                Some(Some(n)) if n >= i64::from(from) => Some(u32::try_from(n).unwrap_or(u32::MAX)),
                _ => return Err(RpcError::params("Bad to_height argument")),
            };
            let history = client.history(&target).await?;
            Ok(json!(history_rows(&history, from, to)))
        }
        "blockchain.scripthash.get_mempool" | "blockchain.address.get_mempool" => {
            let (target, _) = target_of(session, method, params)?;
            let history = client.history(&target).await?;
            let rows = history_rows(&History { confirmed: vec![], ..history }, 0, None);
            Ok(json!(rows))
        }
        "blockchain.scripthash.listunspent" | "blockchain.address.listunspent" => {
            let (target, _) = target_of(session, method, params)?;
            let tokens = token_filter_arg(session, params, 1)?;
            let utxos = client.unspent(&target, tokens).await?;
            Ok(json!(utxos
                .iter()
                .map(|u| {
                    let mut row = json!({
                        "tx_hash": u.outpoint.txid.to_hex(),
                        "tx_pos": u.outpoint.vout,
                        "height": u.height.unwrap_or(0),
                        "value": u.value,
                    });
                    if let Some(token) = &u.token {
                        row["token_data"] = token_json(token);
                    }
                    row
                })
                .collect::<Vec<_>>()))
        }
        "blockchain.scripthash.get_first_use" | "blockchain.address.get_first_use" => {
            let (target, _) = target_of(session, method, params)?;
            Ok(match client.first_use(&target).await? {
                None => Value::Null,
                Some((txid, confirmation)) => {
                    let height = confirmation.map_or(0, |c| c.height);
                    let block = confirmation.map_or("0".repeat(64), |c| c.block_hash.to_hex());
                    json!({"block_hash": block, "height": height, "block_height": height, "tx_hash": txid.to_hex()})
                }
            })
        }
        "blockchain.scripthash.get_status" | "blockchain.address.get_status" => {
            let (target, _) = target_of(session, method, params)?;
            Ok(json!(status(client, &target).await?))
        }
        "blockchain.scripthash.subscribe" => {
            let (target, name) = scripthash_arg(params)?;
            subscribe(session, target, "blockchain.scripthash.subscribe", name).await
        }
        "blockchain.address.subscribe" => {
            let (target, name) = address_arg(session, params)?;
            subscribe(session, target, "blockchain.address.subscribe", name).await
        }
        "blockchain.scripthash.unsubscribe" => {
            let (target, name) = scripthash_arg(params)?;
            Ok(unsubscribe(session, &target, "blockchain.scripthash.subscribe", &name))
        }
        "blockchain.address.unsubscribe" => {
            let (target, name) = address_arg(session, params)?;
            Ok(unsubscribe(session, &target, "blockchain.address.subscribe", &name))
        }
        "blockchain.address.get_scripthash" => {
            let (target, _) = address_arg(session, params)?;
            Ok(json!(reversed_hex(&target.key().0)))
        }

        "blockchain.transaction.get" => {
            let txid = txid_arg(params, 0)?;
            let verbose = bool_arg(params, 1)?;
            let info = client.transaction(txid, None).await.map_err(lookup_error)?;
            if verbose {
                Ok(verbose_tx(session, &info.tx, info.confirmation.map(|c| (c.height, c.block_hash))))
            } else {
                Ok(json!(hex::encode(info.tx.serialize())))
            }
        }
        "blockchain.transaction.get_height" => {
            let txid = txid_arg(params, 0)?;
            let info = client.transaction(txid, None).await.map_err(lookup_error)?;
            Ok(json!(info.confirmation.map_or(0, |c| c.height)))
        }
        "blockchain.transaction.get_confirmed_blockhash" => {
            let txid = txid_arg(params, 0)?;
            let include_header = bool_arg(params, 1)?;
            let info = client.transaction(txid, None).await.map_err(lookup_error)?;
            let c = info
                .confirmation
                .ok_or_else(|| RpcError::bad_request("No confirmed transaction matching the requested hash was found"))?;
            let mut out = json!({"block_hash": c.block_hash.to_hex(), "block_height": c.height});
            if include_header {
                if let Some(h) = client.header(c.height) {
                    out["block_header"] = json!(hex::encode(h.to_bytes()));
                }
            }
            Ok(out)
        }
        "blockchain.transaction.get_merkle" => {
            let txid = txid_arg(params, 0)?;
            let height = u32_arg(params, 1, "height")?;
            let proof = client.merkle_proof(txid, height).await.map_err(lookup_error)?;
            Ok(json!({
                "block_height": proof.height,
                "pos": proof.position,
                "merkle": proof.branch.iter().map(reversed_hex).collect::<Vec<_>>(),
            }))
        }
        "blockchain.transaction.id_from_pos" => {
            let height = u32_arg(params, 0, "height")?.ok_or_else(|| RpcError::params("Invalid height argument"))?;
            let pos = u32_arg(params, 1, "tx_pos")?.ok_or_else(|| RpcError::params("Invalid tx_pos argument"))?;
            let merkle = bool_arg(params, 2)?;
            let (tx, proof) = client
                .transaction_at(height, pos)
                .await
                .map_err(|_| RpcError::bad_request(format!("No transaction at position {pos} for height {height}")))?;
            if merkle {
                Ok(json!({"tx_hash": tx.txid().to_hex(), "merkle": proof.branch.iter().map(reversed_hex).collect::<Vec<_>>()}))
            } else {
                Ok(json!(tx.txid().to_hex()))
            }
        }
        "blockchain.transaction.broadcast" => {
            let text = str_arg(params, 0, "raw transaction")?;
            let raw = hex::decode(text.trim()).map_err(|_| RpcError::bad_request("the transaction is not hex"))?;
            match client.broadcast(&raw).await {
                Ok(txid) => Ok(json!(txid.to_hex())),
                Err(e) => Err(RpcError::bad_request(format!(
                    "the transaction was rejected by network rules.\n\n{}\n",
                    e.message()
                ))),
            }
        }
        "blockchain.transaction.subscribe" => {
            let txid = txid_arg(params, 0)?;
            let current = tx_status(client, txid).await;
            session.state.lock().expect("session lock").txs.insert(txid, current.clone());
            Ok(current)
        }
        "blockchain.transaction.unsubscribe" => {
            let txid = txid_arg(params, 0)?;
            Ok(json!(session.state.lock().expect("session lock").txs.remove(&txid).is_some()))
        }
        "blockchain.utxo.get_info" => {
            let txid = txid_arg(params, 0)?;
            let vout = u32_arg(params, 1, "tx out number")?.ok_or_else(|| RpcError::params("Invalid tx out number"))?;
            match client.output(OutPoint::new(txid, vout), None).await {
                Ok(Some(info)) => {
                    let mut out = json!({
                        "value": info.value,
                        "scripthash": reversed_hex(&bch_light_client::hash::sha256(&info.script)),
                    });
                    if let Some(h) = info.height {
                        out["confirmed_height"] = json!(h);
                    }
                    if let Some(token) = &info.token {
                        out["token_data"] = token_json(token);
                    }
                    Ok(out)
                }
                Ok(None) => Ok(Value::Null),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(Value::Null),
                Err(e) => Err(RpcError::bad_request(e.to_string())),
            }
        }
        "mempool.get_fee_histogram" => Ok(json!(fee_histogram(&client.mempool_summary().fee_rates))),
        "mempool.get_info" => {
            let relay = client.fee_estimate().relay as f64 / 1e8;
            Ok(json!({"mempoolminfee": relay, "minrelaytxfee": relay, "incrementalrelayfee": relay}))
        }

        "blockchain.rpa.get_history" | "blockchain.rpa.get_mempool" | "blockchain.reusable.get_history"
        | "blockchain.reusable.get_mempool" => Err(RpcError::not_found(
            "RPA lookups are not available yet: they need input prefix filters (filter type 2), planned for phase 2",
        )),
        "blockchain.transaction.dsproof.get"
        | "blockchain.transaction.dsproof.list"
        | "blockchain.transaction.dsproof.subscribe"
        | "blockchain.transaction.dsproof.unsubscribe" => {
            Err(RpcError::not_found("This server lacks dsproof support (not available yet, planned for phase 2)"))
        }
        "blockchain.transaction.broadcast_package" => {
            Err(RpcError::not_found("blockchain.transaction.broadcast_package is not available on Bitcoin Cash"))
        }
        "daemon.passthrough" => Err(RpcError::not_found("there is no node RPC behind this server")),
        _ => Err(RpcError::not_found(format!("unknown method '{method}'"))),
    }
}

fn target_of(session: &Session, method: &str, params: &[Value]) -> Result<(Target, String)> {
    if method.starts_with("blockchain.address.") {
        address_arg(session, params)
    } else {
        scripthash_arg(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_print() {
        assert_eq!(parse_version("1.4"), Some((1, 4, 0)));
        assert_eq!(parse_version("1.5.3"), Some((1, 5, 3)));
        assert_eq!(version_string((1, 6, 0)), "1.6");
        assert_eq!(parse_version("x"), None);
    }

    #[test]
    fn fee_histogram_bins_like_electrumx() {
        // 100,000 bytes at each of the rates 1 to 5 sat/byte. The 5s alone
        // do not pass the first bin size, so the first bin closes at 4.
        let rates: Vec<(f64, usize)> = (0..1000).map(|i| (1.0 + (i % 5) as f64, 500)).collect();
        let bins = fee_histogram(&rates);
        assert_eq!(bins[0], json!([4, 200_000]));
        assert_eq!(bins[1], json!([2, 200_000]));
        assert_eq!(
            bins.len(),
            2,
            "the last 100,000 bytes stay under the grown bin size"
        );
    }
}
