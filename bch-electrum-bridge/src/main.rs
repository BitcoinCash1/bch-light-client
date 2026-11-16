//! bch-electrum-bridge: the Electrum protocol for wallets that do not
//! support the Bitcoin Cash P2P protocol, answered through the light client
//! library. A wallet that supports P2P should embed the library instead.

mod methods;
mod session;

use bch_light_client::{Config, LightClient, Network};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

const ABOUT: &str = "bch-electrum-bridge exists only for wallets that do not support the Bitcoin Cash P2P protocol. \
A wallet that does should be a P2P light client itself, through the bch-light-client library, and talk to nodes directly.";

const USAGE: &str = "\
Usage: bch-electrum-bridge --peer HOST:PORT [--peer HOST:PORT ...] [options]

Options:
  --network NAME          mainnet, chipnet, testnet4, testnet3, regtest or simnet (default mainnet)
  --datadir DIR           where headers and filters are kept (default ./bch-bridge-data)
  --peer HOST:PORT        a node that serves script filters (filter type 1); repeat for more
  --proxy HOST:PORT       a SOCKS5 proxy such as Tor; blocks then come over circuits of their own
  --isolate-blocks        fetch each block over a connection of its own even without a proxy
  --decoy-blocks N        fetch N random extra blocks with each block a scan needs
  --download-all-blocks   fetch every block of a scanned range: which blocks are fetched says nothing
  --listen ADDR:PORT      where wallets connect (default 127.0.0.1:50001)
  --banner TEXT           what server.banner answers
  --donation-address ADDR what server.donation_address answers
  -h, --help              this text";

pub struct Options {
    pub config: Config,
    pub listen: String,
    pub banner: String,
    pub donation_address: String,
}

fn parse_args(args: Vec<String>) -> Result<Options, String> {
    let mut network = Network::Mainnet;
    let mut datadir = "bch-bridge-data".to_string();
    let mut peers = Vec::new();
    let mut proxy = None;
    let mut isolate = None;
    let mut decoys = 0usize;
    let mut all_blocks = false;
    let mut listen = "127.0.0.1:50001".to_string();
    let mut banner = String::new();
    let mut donation_address = String::new();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--network" => network = value("--network")?.parse().map_err(|e| format!("{e}"))?,
            "--datadir" => datadir = value("--datadir")?,
            "--peer" => peers.push(value("--peer")?),
            "--proxy" => proxy = Some(value("--proxy")?),
            "--isolate-blocks" => isolate = Some(true),
            "--decoy-blocks" => {
                decoys = value("--decoy-blocks")?
                    .parse()
                    .map_err(|_| "--decoy-blocks needs a number")?
            }
            "--download-all-blocks" => all_blocks = true,
            "--listen" => listen = value("--listen")?,
            "--banner" => banner = value("--banner")?,
            "--donation-address" => donation_address = value("--donation-address")?,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown option {other}")),
        }
    }
    if peers.is_empty() {
        return Err("give at least one --peer".to_string());
    }
    let mut config = Config::new(network, datadir, peers);
    config.proxy = proxy;
    config.isolate_block_downloads = isolate.or(config.isolate_block_downloads);
    config.decoy_blocks = decoys;
    config.download_all_blocks = all_blocks;
    if banner.is_empty() {
        banner = format!("bch-electrum-bridge {}: {ABOUT}", env!("CARGO_PKG_VERSION"));
    }
    Ok(Options {
        config,
        listen,
        banner,
        donation_address,
    })
}

#[tokio::main]
async fn main() {
    let options = match parse_args(std::env::args().skip(1).collect()) {
        Ok(o) => o,
        Err(message) => {
            println!("{ABOUT}\n\n{USAGE}");
            if !message.is_empty() {
                eprintln!("\nerror: {message}");
                std::process::exit(2);
            }
            return;
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    info!("{ABOUT}");
    let network = options.config.network;
    let client = match LightClient::start(options.config.clone()).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "could not start the light client");
            std::process::exit(1);
        }
    };
    let listener = match TcpListener::bind(&options.listen).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, listen = %options.listen, "could not listen");
            std::process::exit(1);
        }
    };
    info!(listen = %options.listen, %network, "waiting for headers and filters before serving wallets");
    loop {
        match client.wait_synced(Duration::from_secs(60)).await {
            Ok(status) => {
                info!(height = status.header_height, "synced; serving wallets");
                break;
            }
            Err(e) => warn!(error = %e, status = ?client.status(), "still syncing"),
        }
    }
    let shared = Arc::new(session::Shared {
        client,
        network,
        banner: options.banner,
        donation_address: options.donation_address,
    });
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!(%addr, "wallet connected");
                tokio::spawn(session::run(shared.clone(), stream));
            }
            Err(e) => warn!(error = %e, "accept failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_parse_and_help_says_what_the_bridge_is_for() {
        let o = parse_args(
            [
                "--network",
                "regtest",
                "--peer",
                "127.0.0.1:1",
                "--proxy",
                "127.0.0.1:9050",
                "--decoy-blocks",
                "2",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        )
        .unwrap();
        assert_eq!(o.config.network, Network::Regtest);
        assert_eq!(o.config.proxy.as_deref(), Some("127.0.0.1:9050"));
        assert_eq!(o.config.decoy_blocks, 2);
        assert!(parse_args(vec![]).is_err());
        assert!(ABOUT.contains("do not support the Bitcoin Cash P2P protocol"));
    }
}
