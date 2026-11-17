//! The peers a client keeps: a few long-lived service connections for
//! headers, filters and transaction relay, and short-lived connections made
//! for one block download each when block downloads are isolated.
//!
//! Addresses come from the configuration, from the network's DNS seeds and
//! from the addresses connected peers announce. Learned addresses are kept
//! only when the node serves committed filters, until `want` such
//! connections are up. Every configured node is connected: one that serves
//! no filters is kept for headers, blocks, transaction relay, its mempool
//! and double-spend proofs, and is never asked for filters. Block downloads
//! may go to any node. A peer caught serving wrong data is banned for a day.

use super::message::{NODE_BLOOM, NODE_CF_BCH, NODE_COMPACT_FILTERS};
use super::peer::{Peer, PeerError, PeerEvent, PeerOptions};
use super::socks::PeerAddr;
use crate::encode::{DecodeError, Reader};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Notify};
use tracing::{debug, info, warn};

/// Where an address came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Config,
    Seed,
    Gossip,
}

#[derive(Debug, Clone)]
struct Known {
    addr: PeerAddr,
    services: Option<u64>,
    source: Source,
}

const MAX_KNOWN: usize = 2000;
const BAN: Duration = Duration::from_secs(24 * 3600);

/// Whether a node's service bits say it serves committed filters.
pub fn serves_filters(services: u64) -> bool {
    services & (NODE_CF_BCH | NODE_COMPACT_FILTERS) != 0
}

pub struct Pool {
    known: RwLock<Vec<Known>>,
    options: PeerOptions,
    want: usize,
    learn: bool,
    service: RwLock<Vec<Arc<Peer>>>,
    next: AtomicUsize,
    next_isolated: AtomicUsize,
    retry_at: Mutex<HashMap<PeerAddr, (Instant, Duration)>>,
    banned: Mutex<HashMap<PeerAddr, Instant>>,
    events: mpsc::Sender<PeerEvent>,
    connected: Notify,
}

impl Pool {
    /// A pool of the configured `addrs`, which keeps `want` connections to
    /// nodes that serve filters and learns more addresses when `learn`.
    pub fn new(
        addrs: Vec<PeerAddr>,
        options: PeerOptions,
        want: usize,
        learn: bool,
    ) -> (Arc<Pool>, mpsc::Receiver<PeerEvent>) {
        let (events, rx) = mpsc::channel(4096);
        let mut known: Vec<Known> = Vec::new();
        for addr in addrs {
            if !known.iter().any(|k| k.addr == addr) {
                known.push(Known {
                    addr,
                    services: None,
                    source: Source::Config,
                });
            }
        }
        let pool = Pool {
            known: RwLock::new(known),
            options,
            want: want.max(1),
            learn,
            service: RwLock::new(Vec::new()),
            next: AtomicUsize::new(0),
            next_isolated: AtomicUsize::new(rand::random::<usize>() % 1024),
            retry_at: Mutex::new(HashMap::new()),
            banned: Mutex::new(HashMap::new()),
            events,
            connected: Notify::new(),
        };
        (Arc::new(pool), rx)
    }

    pub fn options(&self) -> &PeerOptions {
        &self.options
    }

    /// Adds addresses learned from seeds or peers; returns how many were new.
    pub fn learn(
        &self,
        addrs: impl IntoIterator<Item = (PeerAddr, Option<u64>)>,
        source: Source,
    ) -> usize {
        let mut known = self.known.write().expect("pool lock");
        let mut added = 0;
        for (addr, services) in addrs {
            if let Some(k) = known.iter_mut().find(|k| k.addr == addr) {
                k.services = services.or(k.services);
                continue;
            }
            if known.len() >= MAX_KNOWN {
                break;
            }
            known.push(Known {
                addr,
                services,
                source,
            });
            added += 1;
        }
        added
    }

    /// Every known address, with what it is known to serve.
    pub fn known(&self) -> Vec<(PeerAddr, Option<u64>, Source)> {
        self.known
            .read()
            .expect("pool lock")
            .iter()
            .map(|k| (k.addr.clone(), k.services, k.source))
            .collect()
    }

    /// Looks the seeds up and learns their addresses.
    pub async fn seed(&self, seeds: &[&str], port: u16) -> usize {
        let mut found = Vec::new();
        for seed in seeds {
            match tokio::net::lookup_host((*seed, port)).await {
                Ok(addrs) => found.extend(addrs.map(|a| {
                    (
                        PeerAddr {
                            host: a.ip().to_string(),
                            port: a.port(),
                        },
                        None,
                    )
                })),
                Err(e) => debug!(seed, error = %e, "seed lookup failed"),
            }
        }
        let added = self.learn(found, Source::Seed);
        info!(added, "addresses from DNS seeds");
        added
    }

    /// Bans a peer for a day and closes its connection.
    pub fn ban(&self, addr: &PeerAddr, reason: &str) {
        warn!(peer = %addr, reason, "banned");
        self.banned
            .lock()
            .expect("ban lock")
            .insert(addr.clone(), Instant::now() + BAN);
        for peer in self
            .service
            .read()
            .expect("pool lock")
            .iter()
            .filter(|p| p.addr == *addr)
        {
            peer.close();
        }
    }

    fn is_banned(&self, addr: &PeerAddr) -> bool {
        let mut banned = self.banned.lock().expect("ban lock");
        match banned.get(addr) {
            Some(until) if *until > Instant::now() => true,
            Some(_) => {
                banned.remove(addr);
                false
            }
            None => false,
        }
    }

    /// Keeps the service connections up until `shutdown` turns true.
    pub fn spawn_maintainer(self: &Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                pool.maintain().await;
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                    _ = shutdown.changed() => break,
                }
                if *shutdown.borrow() {
                    break;
                }
            }
            for peer in pool.service.write().expect("pool lock").drain(..) {
                peer.close();
            }
        });
    }

    async fn maintain(&self) {
        let (connected, filter_peers): (Vec<PeerAddr>, usize) = {
            let mut service = self.service.write().expect("pool lock");
            service.retain(|p| p.is_alive());
            (
                service.iter().map(|p| p.addr.clone()).collect(),
                service
                    .iter()
                    .filter(|p| serves_filters(p.info.services))
                    .count(),
            )
        };
        let now = Instant::now();
        let candidate = {
            let retry = self.retry_at.lock().expect("retry lock");
            let known = self.known.read().expect("pool lock");
            let mut options: Vec<&Known> = known
                .iter()
                .filter(|k| !connected.contains(&k.addr))
                .filter(|k| k.source == Source::Config || k.services.map_or(true, serves_filters))
                // Every configured node; learned ones until enough serve filters.
                .filter(|k| k.source == Source::Config || filter_peers < self.want)
                .filter(|k| !matches!(retry.get(&k.addr), Some((at, _)) if *at > now))
                .collect();
            // Configured peers first, then those known to serve filters.
            options.sort_by_key(|k| {
                (
                    k.source != Source::Config,
                    !k.services.is_some_and(serves_filters),
                )
            });
            options
                .into_iter()
                .find(|k| !self.is_banned(&k.addr))
                .cloned()
        };
        let Some(candidate) = candidate else { return };
        let addr = candidate.addr.clone();
        match Peer::connect(addr.clone(), &self.options, Some(self.events.clone())).await {
            Ok(peer) => {
                self.learn([(addr.clone(), Some(peer.info.services))], candidate.source);
                let filters = serves_filters(peer.info.services);
                if candidate.source != Source::Config && !filters {
                    debug!(peer = %addr, "no committed filters; kept for block downloads only");
                    peer.close();
                    return;
                }
                info!(
                    peer = %addr,
                    agent = %peer.info.user_agent,
                    height = peer.info.start_height,
                    filters,
                    "connected"
                );
                // Every transaction the peer has, not those of interest: the mempool message.
                if self.options.relay && peer.info.services & NODE_BLOOM != 0 {
                    peer.send("mempool", Vec::new());
                }
                if self.learn {
                    peer.send("getaddr", Vec::new());
                }
                self.retry_at.lock().expect("retry lock").remove(&addr);
                self.service
                    .write()
                    .expect("pool lock")
                    .push(Arc::new(peer));
                self.connected.notify_waiters();
            }
            Err(e) => {
                debug!(peer = %addr, error = %e, "connect failed");
                let mut retry = self.retry_at.lock().expect("retry lock");
                let backoff = retry.get(&addr).map_or(Duration::from_secs(1), |(_, b)| {
                    (*b * 2).min(Duration::from_secs(60))
                });
                retry.insert(addr, (Instant::now() + backoff, backoff));
            }
        }
    }

    /// The live service connections.
    pub fn peers(&self) -> Vec<Arc<Peer>> {
        self.service
            .read()
            .expect("pool lock")
            .iter()
            .filter(|p| p.is_alive())
            .cloned()
            .collect()
    }

    /// The live service connections to nodes that serve committed filters.
    pub fn filter_peers(&self) -> Vec<Arc<Peer>> {
        self.service
            .read()
            .expect("pool lock")
            .iter()
            .filter(|p| p.is_alive() && serves_filters(p.info.services))
            .cloned()
            .collect()
    }

    fn take_turn(&self, peers: Vec<Arc<Peer>>) -> Option<Arc<Peer>> {
        if peers.is_empty() {
            return None;
        }
        let i = self.next.fetch_add(1, Ordering::Relaxed);
        Some(peers[i % peers.len()].clone())
    }

    /// The next service connection, in turn.
    pub fn next_peer(&self) -> Option<Arc<Peer>> {
        self.take_turn(self.peers())
    }

    /// The next service connection that serves filters, in turn.
    pub fn next_filter_peer(&self) -> Option<Arc<Peer>> {
        self.take_turn(self.filter_peers())
    }

    async fn wait_for(
        &self,
        timeout: Duration,
        pick: impl Fn(&Self) -> Option<Arc<Peer>>,
    ) -> Option<Arc<Peer>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.connected.notified();
            if let Some(peer) = pick(self) {
                return Some(peer);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return pick(self);
            }
        }
    }

    /// Waits up to `timeout` for a service connection.
    pub async fn wait_peer(&self, timeout: Duration) -> Option<Arc<Peer>> {
        self.wait_for(timeout, Self::next_peer).await
    }

    /// Waits up to `timeout` for a service connection that serves filters.
    pub async fn wait_filter_peer(&self, timeout: Duration) -> Option<Arc<Peer>> {
        self.wait_for(timeout, Self::next_filter_peer).await
    }

    /// A new connection of its own, to the next known peer in turn (any
    /// node: blocks need no filters), with no transaction relay and,
    /// through a proxy, its own circuit.
    pub async fn connect_isolated(&self) -> Result<Peer, PeerError> {
        let addrs: Vec<PeerAddr> = self
            .known
            .read()
            .expect("pool lock")
            .iter()
            .map(|k| k.addr.clone())
            .filter(|a| !self.is_banned(a))
            .collect();
        if addrs.is_empty() {
            return Err(PeerError::Disconnected);
        }
        let start = self.next_isolated.fetch_add(1, Ordering::Relaxed);
        let mut options = self.options.clone();
        options.relay = false;
        options.isolate = true;
        let mut last = PeerError::Disconnected;
        for i in 0..addrs.len().min(3) {
            let addr = addrs[(start + i) % addrs.len()].clone();
            match Peer::connect(addr, &options, None).await {
                Ok(peer) => return Ok(peer),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

/// The addresses of an addr message: (address, services).
pub fn decode_addr(payload: &[u8]) -> Result<Vec<(PeerAddr, u64)>, DecodeError> {
    let mut r = Reader::new(payload);
    let n = r.count(30)?;
    if n > 1000 {
        return Err(DecodeError::Invalid("too many addresses"));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        r.u32()?;
        let services = r.u64()?;
        let ip: [u8; 16] = r.array()?;
        let port = u16::from_be_bytes(r.array()?);
        let v6 = Ipv6Addr::from(ip);
        let host = match v6.to_ipv4_mapped() {
            Some(v4) if !v4.is_unspecified() => v4.to_string(),
            Some(_) => continue,
            // fd87:d87e:eb43::/48 is OnionCat (old Tor addresses): not reachable as an IP.
            None if ip[..6] == [0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43] => continue,
            None if v6.is_unspecified() => continue,
            None => v6.to_string(),
        };
        if port == 0 {
            continue;
        }
        out.push((PeerAddr { host, port }, services));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::WriteExt;

    #[test]
    fn addr_messages_decode() {
        let mut b = Vec::new();
        b.put_compact_size(2);
        b.put_u32(1);
        b.put_u64(1 | NODE_CF_BCH);
        b.put_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);
        b.put_bytes(&8333u16.to_be_bytes());
        b.put_u32(1);
        b.put_u64(1);
        b.put_bytes(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        b.put_bytes(&18333u16.to_be_bytes());
        let addrs = decode_addr(&b).unwrap();
        assert_eq!(
            addrs[0].0,
            PeerAddr {
                host: "10.0.0.1".into(),
                port: 8333
            }
        );
        assert!(serves_filters(addrs[0].1));
        assert_eq!(
            addrs[1].0,
            PeerAddr {
                host: "2001:db8::1".into(),
                port: 18333
            }
        );
    }
}
