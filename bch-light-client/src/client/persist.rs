//! The histories of watched targets, kept across restarts in one small file
//! (`watched.dat`): only what the wallet watches, nothing about the chain.
//! On start each history is checked against the header chain and rolled
//! back past any block that left it while the client was off.

use super::*;
use crate::encode::{Reader, WriteExt};
use crate::history::Coin;
use crate::tx::Category;

const MAGIC: &[u8; 4] = b"BCW1";
const NONE: u32 = u32::MAX;

fn put_token(out: &mut Vec<u8>, token: &Option<TokenData>) {
    out.put_var_bytes(&token.as_ref().map(TokenData::prefix).unwrap_or_default());
}

fn read_token(r: &mut Reader<'_>) -> Result<Option<TokenData>, crate::encode::DecodeError> {
    let prefix = r.var_bytes()?;
    if prefix.is_empty() {
        return Ok(None);
    }
    match TokenData::split(prefix) {
        (Some(token), rest) if rest.is_empty() => Ok(Some(token)),
        _ => Err(crate::encode::DecodeError::Invalid("bad token prefix")),
    }
}

fn serialize(states: &HashMap<FilterKey, TargetState>, chain: &HeaderChain) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.put_u32(states.len() as u32);
    for state in states.values() {
        match &state.target {
            Target::Script(s) => {
                out.put_u8(0);
                out.put_var_bytes(s);
            }
            Target::ScriptHash(h) => {
                out.put_u8(1);
                out.put_bytes(h);
            }
            Target::Category(c) => {
                out.put_u8(2);
                out.put_bytes(&c.0);
            }
        }
        out.put_u32(state.synced_to.unwrap_or(NONE));
        let hash = state
            .synced_to
            .and_then(|h| chain.hash_at(h))
            .unwrap_or(BlockHash::ZERO);
        out.put_bytes(&hash.0);
        out.put_u32(state.txs.len() as u32);
        for tx in &state.txs {
            out.put_bytes(&tx.txid.0);
            out.put_u32(tx.height);
            out.put_bytes(&tx.block_hash.0);
            out.put_u32(tx.position);
            out.put_u32(tx.received.len() as u32);
            for r in &tx.received {
                out.put_u32(r.vout);
                out.put_u64(r.value);
                put_token(&mut out, &r.token);
                out.put_var_bytes(&r.script);
            }
            out.put_u32(tx.spent.len() as u32);
            for s in &tx.spent {
                out.put_u32(s.vin);
                out.put_bytes(&s.prevout.txid.0);
                out.put_u32(s.prevout.vout);
                out.put_u64(s.value);
                put_token(&mut out, &s.token);
            }
        }
    }
    out
}

fn deserialize(bytes: &[u8]) -> Result<Vec<(TargetState, BlockHash)>, crate::encode::DecodeError> {
    let mut r = Reader::new(bytes);
    if r.bytes(4)? != MAGIC {
        return Err(crate::encode::DecodeError::Invalid("not a watched file"));
    }
    let n = r.u32()?;
    let mut out = Vec::new();
    for _ in 0..n {
        let target = match r.u8()? {
            0 => Target::Script(r.var_bytes()?.to_vec()),
            1 => Target::ScriptHash(r.array()?),
            2 => Target::Category(Category(r.array()?)),
            _ => return Err(crate::encode::DecodeError::Invalid("target kind")),
        };
        let synced = r.u32()?;
        let synced_hash = BlockHash(r.array()?);
        let mut state = TargetState::new(target);
        state.synced_to = (synced != NONE).then_some(synced);
        for _ in 0..r.u32()? {
            let txid = Txid(r.array()?);
            let height = r.u32()?;
            let block_hash = BlockHash(r.array()?);
            let position = r.u32()?;
            let mut received = Vec::new();
            for _ in 0..r.u32()? {
                let vout = r.u32()?;
                let value = r.u64()?;
                let token = read_token(&mut r)?;
                let script = r.var_bytes()?.to_vec();
                received.push(Received {
                    vout,
                    value,
                    token,
                    script,
                });
            }
            let mut spent = Vec::new();
            for _ in 0..r.u32()? {
                let vin = r.u32()?;
                let prevout = OutPoint::new(Txid(r.array()?), r.u32()?);
                let value = r.u64()?;
                let token = read_token(&mut r)?;
                spent.push(Spent {
                    vin,
                    prevout,
                    value,
                    token,
                });
            }
            for rec in &received {
                let outpoint = OutPoint::new(txid, rec.vout);
                state.coins.insert(
                    outpoint,
                    Coin {
                        outpoint,
                        value: rec.value,
                        token: rec.token.clone(),
                        script: rec.script.clone(),
                        height,
                    },
                );
            }
            for s in &spent {
                state.spent_by.insert(s.prevout, (txid, height));
            }
            state.txs.push(ConfirmedTx {
                txid,
                height,
                block_hash,
                position,
                received,
                spent,
            });
        }
        out.push((state, synced_hash));
    }
    r.finish()?;
    Ok(out)
}

/// Loads the watched histories, each checked against the chain.
pub(crate) fn load(dir: &std::path::Path, chain: &HeaderChain) -> HashMap<FilterKey, TargetState> {
    let Ok(bytes) = std::fs::read(dir.join("watched.dat")) else {
        return HashMap::new();
    };
    let Ok(states) = deserialize(&bytes) else {
        warn!("watched histories unreadable; they are scanned again");
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (mut state, synced_hash) in states {
        // The lowest height whose block is no longer the chain's.
        let mut fork = state.synced_to;
        if let Some(h) = state.synced_to {
            if chain.hash_at(h) != Some(synced_hash) {
                fork = h.checked_sub(1);
            }
        }
        if let Some(bad) = state
            .txs
            .iter()
            .filter(|t| chain.hash_at(t.height) != Some(t.block_hash))
            .map(|t| t.height)
            .min()
        {
            fork = fork.min(bad.checked_sub(1));
        }
        if fork != state.synced_to {
            // Back to the last tx height below the fork that still holds, then scan again.
            let keep = state
                .txs
                .iter()
                .map(|t| t.height)
                .filter(|h| Some(*h) <= fork)
                .max();
            match keep {
                Some(h) => {
                    state.rollback(h);
                }
                None => state = TargetState::new(state.target.clone()),
            }
        }
        out.insert(state.key, state);
    }
    out
}

/// Writes the watched histories, replacing the file at once.
pub(crate) fn save(inner: &Inner) {
    let bytes = {
        let states = inner.targets.lock().expect("targets lock");
        let chain = inner.chain.read().expect("chain lock");
        serialize(&states, &chain)
    };
    let path = inner.dir.join("watched.dat");
    let tmp = inner.dir.join("watched.dat.tmp");
    let result = std::fs::write(&tmp, &bytes).and_then(|()| std::fs::rename(&tmp, &path));
    if let Err(e) = result {
        warn!(error = %e, "could not save the watched histories");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histories_round_trip() {
        let mut state = TargetState::new(Target::Category(Category([4; 32])));
        state.synced_to = Some(7);
        let txid = Txid([1; 32]);
        state.txs.push(ConfirmedTx {
            txid,
            height: 3,
            block_hash: BlockHash([3; 32]),
            position: 1,
            received: vec![Received {
                vout: 0,
                value: 1000,
                token: Some(TokenData {
                    category: Category([4; 32]),
                    amount: 5,
                    nft: None,
                }),
                script: vec![0x51],
            }],
            spent: vec![Spent {
                vin: 0,
                prevout: OutPoint::new(Txid([2; 32]), 1),
                value: 9,
                token: None,
            }],
        });
        let dir = std::env::temp_dir().join(format!(
            "bch-light-client-test-{}-persist",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let chain = HeaderChain::open(
            &dir.join("headers.dat"),
            crate::params::Network::Regtest.params(),
        )
        .unwrap();
        let mut states = HashMap::new();
        states.insert(state.key, state.clone());
        let bytes = serialize(&states, &chain);
        let back = deserialize(&bytes).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].0.txs, state.txs);
        assert_eq!(back[0].0.synced_to, Some(7));
        assert!(back[0].0.coins.contains_key(&OutPoint::new(txid, 0)));
        // The chain here has only genesis: nothing of the history holds.
        std::fs::write(dir.join("watched.dat"), &bytes).unwrap();
        let loaded = load(&dir, &chain);
        assert_eq!(loaded.values().next().unwrap().synced_to, None);
    }
}
