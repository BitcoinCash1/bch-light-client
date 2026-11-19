//! Identities (CHIP-BCMR) against bchd on regtest: an authchain followed
//! from its authbase through two updates, each publishing a registry; an
//! update in the mempool seen live; the identity burned; a resolution
//! resumed from the client's records after a restart, and one sped up by a
//! registry's authchain extension. Tokens are not needed for identities;
//! the CashTokens checks run in the harness against kth, as bchd has no
//! CashTokens. Skipped when no bchd with transaction keys is found (set
//! BCHD_TXID_BIN), and failing instead in CI.

mod common;

use bch_light_client::bcmr::{registry_matches, Publication, PUBLICATION_PREFIX};
use bch_light_client::{Config, Event, LightClient, Network, OutPoint, Target, Txid};
use common::*;
use std::time::{Duration, Instant};

const IDENTITY: [u8; 3] = [0x56, 0x75, 0x51];

fn publication_script(registry: &[u8], uri: &str) -> Vec<u8> {
    let mut s = PUBLICATION_PREFIX.to_vec();
    s.push(0x20);
    s.extend_from_slice(&sha256(registry));
    s.push(uri.len() as u8);
    s.extend_from_slice(uri.as_bytes());
    s
}

/// Spends `identity` (output 0 of the previous step, `value` sats) to a new
/// identity output, with `extra` as output 1.
fn step(identity: OutPoint, value: u64, first: Vec<u8>, extra: Vec<u8>) -> Vec<u8> {
    TxSpec {
        inputs: vec![(identity, Unlock::Redeem(IDENTITY.to_vec()))],
        outputs: vec![(value - 2000, first, vec![]), (0, extra, vec![])],
    }
    .build()
}

async fn client_of(node: &Bchd, dir: &std::path::Path) -> LightClient {
    let mut config = Config::new(Network::Regtest, dir, vec![node.peer()]);
    config.request_timeout = Duration::from_secs(20);
    config.decoy_blocks = 1;
    let client = LightClient::start(config).await.expect("start client");
    let height = node.height().await;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = client.status();
        if status.synced && status.filter_height == Some(height) && status.txid_keys == Some(true) {
            return client;
        }
        assert!(Instant::now() < deadline, "not synced: {status:?}");
        client.poke();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_tip(node: &Bchd, client: &LightClient) {
    let height = node.height().await;
    let deadline = Instant::now() + Duration::from_secs(60);
    while client.status().filter_height != Some(height) || !client.status().synced {
        assert!(Instant::now() < deadline, "{:?}", client.status());
        client.poke();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authchains_are_followed_to_their_authhead_and_registry() {
    let Some(bin) = bchd_txid_binary_or_skip() else {
        return;
    };
    let node = Bchd::start_with(&bin, "bcmr").await;
    node.generate(110).await;
    let identity_script = p2sh20(&IDENTITY);
    let (coinbase, value) = node.coinbase(1).await;
    let authbase = TxSpec {
        inputs: vec![(coinbase, Unlock::Redeem(vec![0x51]))],
        outputs: vec![(value - 2000, identity_script.clone(), vec![])],
    }
    .build();
    let authbase_id = Txid::from_hex(&node.send(&authbase).await).unwrap();
    node.generate(1).await;
    let (r1, r2, r3) = (
        b"registry one".to_vec(),
        b"registry two".to_vec(),
        b"three".to_vec(),
    );
    let one = step(
        OutPoint::new(authbase_id, 0),
        value - 2000,
        identity_script.clone(),
        publication_script(&r1, "example.com"),
    );
    node.send(&one).await;
    node.generate(2).await;
    let two = step(
        OutPoint::new(txid_of(&one), 0),
        value - 4000,
        identity_script.clone(),
        publication_script(&r2, "ipfs://two"),
    );
    node.send(&two).await;
    node.generate(1).await;

    let dir = node.dir.join("client");
    let client = client_of(&node, &dir).await;
    let chain = client
        .resolve_authchain(authbase_id, None, true)
        .await
        .expect("resolved");
    assert_eq!(
        chain.steps,
        vec![(txid_of(&one), Some(112)), (txid_of(&two), Some(114))]
    );
    assert_eq!(chain.authhead.txid(), txid_of(&two));
    assert_eq!(chain.identity_output, OutPoint::new(txid_of(&two), 0));
    assert!(!chain.burned);
    let publication = chain.publication.clone().expect("a publication");
    assert!(matches!(&publication, Publication::Registry { uris, .. } if uris == &["ipfs://two"]));
    assert!(registry_matches(&r2, &publication));
    assert!(!registry_matches(&r1, &publication));

    // An update in the mempool: the tracked identity output's spend comes
    // as an event, and the authhead is the mempool transaction.
    let mut events = client.subscribe();
    let three = step(
        OutPoint::new(txid_of(&two), 0),
        value - 6000,
        identity_script.clone(),
        publication_script(&r3, "example.org"),
    );
    node.send(&three).await;
    let tracked = Target::Script(identity_script.clone());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
            Ok(Ok(Event::TargetChanged { target })) if target == tracked => break,
            _ => assert!(
                Instant::now() < deadline,
                "no event for the identity output"
            ),
        }
    }
    let chain = client
        .resolve_authchain(authbase_id, None, true)
        .await
        .unwrap();
    assert_eq!(chain.authhead.txid(), txid_of(&three));
    assert_eq!(chain.authhead_confirmation, None);
    assert!(registry_matches(&r3, chain.publication.as_ref().unwrap()));
    node.generate(1).await;
    wait_tip(&node, &client).await;

    // The identity burned: output 0 starts with OP_RETURN.
    let burn = TxSpec {
        inputs: vec![(
            OutPoint::new(txid_of(&three), 0),
            Unlock::Redeem(IDENTITY.to_vec()),
        )],
        outputs: vec![
            (0, vec![0x6a, 0x04, b'g', b'o', b'n', b'e'], vec![]),
            (value - 10000, mining_script(), vec![]),
        ],
    }
    .build();
    node.send(&burn).await;
    node.generate(1).await;
    wait_tip(&node, &client).await;
    let chain = client
        .resolve_authchain(authbase_id, None, false)
        .await
        .unwrap();
    assert!(chain.burned);
    assert_eq!(chain.authhead.txid(), txid_of(&burn));
    assert_eq!(chain.publication, None);
    // Resumed from the records (the last confirmed step found, the second
    // update): only the steps after it.
    assert_eq!(
        chain.steps,
        vec![(txid_of(&three), Some(115)), (txid_of(&burn), Some(116))]
    );
    client.stop().await;

    // After a restart, the records still resume it; a registry's authchain
    // extension (the authbase and the first update) gets there too.
    let again = client_of(&node, &dir).await;
    let resumed = again
        .resolve_authchain(authbase_id, None, false)
        .await
        .unwrap();
    assert!(resumed.steps.is_empty());
    assert_eq!(resumed.authhead.txid(), txid_of(&burn));
    let extended = again
        .resolve_authchain_from(authbase_id, &[authbase.clone(), one.clone()], false)
        .await
        .unwrap();
    assert_eq!(extended.authhead.txid(), txid_of(&burn));
    assert_eq!(extended.steps.len(), 3);
    // An extension that does not start at the authbase is refused.
    assert!(again
        .resolve_authchain_from(authbase_id, std::slice::from_ref(&one), false)
        .await
        .is_err());
    again.shutdown();
}
