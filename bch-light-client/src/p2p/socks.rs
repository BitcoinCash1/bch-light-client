//! Outgoing connections, direct or through a SOCKS5 proxy such as Tor.
//!
//! Through a proxy the peer's host name goes to the proxy unresolved, so no
//! local DNS lookup happens. When isolation is on, every connection sends
//! its own random user name and password; Tor then puts each connection on
//! its own circuit (IsolateSOCKSAuth, on by default), so peers cannot link
//! connections by exit address.

use rand::distributions::Alphanumeric;
use rand::Rng;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A peer's address: a host name or IP literal, and a port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerAddr {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// A string that is not `host:port`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{0}' is not host:port")]
pub struct BadPeerAddr(pub String);

impl PeerAddr {
    /// Parses `host:port` or `[ipv6]:port`; a missing port takes `default_port`.
    pub fn parse(s: &str, default_port: u16) -> Result<Self, BadPeerAddr> {
        let bad = || BadPeerAddr(s.to_string());
        let s = s.trim();
        if let Some(rest) = s.strip_prefix('[') {
            let (host, tail) = rest.split_once(']').ok_or_else(bad)?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| bad())?,
                None if tail.is_empty() => default_port,
                None => return Err(bad()),
            };
            return Ok(Self {
                host: host.to_string(),
                port,
            });
        }
        match s.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => Ok(Self {
                host: host.to_string(),
                port: port.parse().map_err(|_| bad())?,
            }),
            _ if !s.is_empty() => Ok(Self {
                host: s.to_string(),
                port: default_port,
            }),
            _ => Err(bad()),
        }
    }
}

impl FromStr for PeerAddr {
    type Err = BadPeerAddr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s, 0)
    }
}

/// How connections reach peers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Transport {
    /// Plain TCP from this host.
    #[default]
    Direct,
    /// Through a SOCKS5 proxy (Tor's is usually 127.0.0.1:9050).
    Socks5 { proxy: PeerAddr },
}

/// A connection that could not be made.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("connection: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection timed out")]
    Timeout,
    #[error("SOCKS5 proxy: {0}")]
    Proxy(String),
}

/// Opens a TCP connection to `peer`. With a proxy, `isolate` gives the
/// connection its own random credentials (its own Tor circuit).
pub async fn connect(
    peer: &PeerAddr,
    transport: &Transport,
    isolate: bool,
    timeout: Duration,
) -> Result<TcpStream, ConnectError> {
    let attempt = async {
        match transport {
            Transport::Direct => {
                Ok::<_, ConnectError>(TcpStream::connect((peer.host.as_str(), peer.port)).await?)
            }
            Transport::Socks5 { proxy } => {
                let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
                let credentials = isolate.then(random_credentials);
                socks5_handshake(&mut stream, peer, credentials.as_ref()).await?;
                Ok(stream)
            }
        }
    };
    let stream = tokio::time::timeout(timeout, attempt)
        .await
        .map_err(|_| ConnectError::Timeout)??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn random_credentials() -> (String, String) {
    let mut rng = rand::thread_rng();
    let mut word = || {
        (&mut rng)
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect::<String>()
    };
    (word(), word())
}

async fn socks5_handshake(
    stream: &mut TcpStream,
    peer: &PeerAddr,
    credentials: Option<&(String, String)>,
) -> Result<(), ConnectError> {
    let proxy_err = |m: &str| ConnectError::Proxy(m.to_string());
    let method = if credentials.is_some() { 0x02 } else { 0x00 };
    stream.write_all(&[0x05, 0x01, method]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != method {
        return Err(proxy_err("the proxy refused the authentication method"));
    }
    if let Some((user, pass)) = credentials {
        let mut auth = vec![0x01, user.len() as u8];
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass.as_bytes());
        stream.write_all(&auth).await?;
        stream.read_exact(&mut reply).await?;
        if reply[1] != 0x00 {
            return Err(proxy_err("the proxy refused the credentials"));
        }
    }
    if peer.host.len() > 255 {
        return Err(proxy_err("host name too long"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, peer.host.len() as u8];
    request.extend_from_slice(peer.host.as_bytes());
    request.extend_from_slice(&peer.port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(ConnectError::Proxy(format!(
            "connect to {peer} failed with code {}",
            head[1]
        )));
    }
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => usize::from(stream.read_u8().await?),
        _ => return Err(proxy_err("unknown address type in reply")),
    };
    let mut rest = vec![0u8; skip + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn peer_addresses_parse() {
        assert_eq!(
            PeerAddr::parse("127.0.0.1:8333", 1).unwrap(),
            PeerAddr {
                host: "127.0.0.1".into(),
                port: 8333
            }
        );
        assert_eq!(
            PeerAddr::parse("[::1]:18444", 1).unwrap(),
            PeerAddr {
                host: "::1".into(),
                port: 18444
            }
        );
        assert_eq!(PeerAddr::parse("abc.onion", 8333).unwrap().port, 8333);
        assert!(PeerAddr::parse("host:port", 1).is_err());
    }

    /// A minimal SOCKS5 server that records the credentials and target it is given.
    async fn fake_proxy(listener: TcpListener) -> (String, String) {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut greet = [0u8; 3];
        s.read_exact(&mut greet).await.unwrap();
        s.write_all(&[5, 2]).await.unwrap();
        let mut ver_ulen = [0u8; 2];
        s.read_exact(&mut ver_ulen).await.unwrap();
        let mut user = vec![0u8; ver_ulen[1] as usize];
        s.read_exact(&mut user).await.unwrap();
        let plen = s.read_u8().await.unwrap();
        let mut pass = vec![0u8; plen as usize];
        s.read_exact(&mut pass).await.unwrap();
        s.write_all(&[1, 0]).await.unwrap();
        let mut head = [0u8; 5];
        s.read_exact(&mut head).await.unwrap();
        let mut host = vec![0u8; head[4] as usize + 2];
        s.read_exact(&mut host).await.unwrap();
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        (
            String::from_utf8(user).unwrap(),
            String::from_utf8(host[..host.len() - 2].to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn isolated_connections_use_distinct_credentials_and_unresolved_names() {
        let mut users = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(fake_proxy(listener));
            let transport = Transport::Socks5 {
                proxy: PeerAddr {
                    host: "127.0.0.1".into(),
                    port,
                },
            };
            let peer = PeerAddr {
                host: "example.onion".into(),
                port: 8333,
            };
            connect(&peer, &transport, true, Duration::from_secs(5))
                .await
                .unwrap();
            let (user, host) = server.await.unwrap();
            assert_eq!(host, "example.onion");
            users.push(user);
        }
        assert_ne!(users[0], users[1]);
    }
}
