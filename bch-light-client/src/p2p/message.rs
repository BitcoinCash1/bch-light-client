//! P2P message framing and the payloads a light client sends and reads.

use crate::block::BlockHeader;
use crate::encode::{DecodeError, Reader, WriteExt};
use crate::hash::{sha256d, BlockHash, Txid};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const PROTOCOL_VERSION: i32 = 70016;
pub const HEADER_SIZE: usize = 24;
/// The largest payload accepted: a block, which ABLA lets grow over the years.
pub const MAX_PAYLOAD: usize = 512 * 1024 * 1024;
pub const MAX_HEADERS_PER_MSG: usize = 2000;
pub const MAX_CFHEADERS_PER_MSG: usize = 2000;
pub const MAX_CFILTERS_PER_MSG: usize = 1000;
pub const MAX_INV_PER_MSG: usize = 50_000;

pub const INV_TX: u32 = 1;
pub const INV_BLOCK: u32 = 2;

/// Service bit of nodes that serve BIP37 bloom filters and the mempool message.
pub const NODE_BLOOM: u64 = 1 << 2;
/// Service bit of nodes that serve committed filters.
pub const NODE_COMPACT_FILTERS: u64 = 1 << 6;
/// Bitcoin Cash nodes that serve committed filters set this bit too.
pub const NODE_CF_BCH: u64 = 1 << 8;

/// A framed message: its command and payload.
#[derive(Debug, Clone)]
pub struct RawMessage {
    pub command: String,
    pub payload: Vec<u8>,
}

/// A stream that broke the framing rules.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("wrong network magic")]
    Magic,
    #[error("message of {0} bytes is too large")]
    TooLarge(usize),
    #[error("bad message checksum")]
    Checksum,
    #[error("connection: {0}")]
    Io(#[from] std::io::Error),
}

pub fn encode_message(magic: [u8; 4], command: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.extend_from_slice(&magic);
    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command.as_bytes());
    out.extend_from_slice(&cmd);
    out.put_u32(payload.len() as u32);
    out.extend_from_slice(&sha256d(payload)[..4]);
    out.extend_from_slice(payload);
    out
}

/// Reads one message, checking magic, size and checksum. `progress` is
/// called as payload bytes arrive, so a caller can tell a slow large
/// message from a stalled connection.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    magic: [u8; 4],
    mut progress: impl FnMut(),
) -> Result<RawMessage, FrameError> {
    let mut head = [0u8; HEADER_SIZE];
    reader.read_exact(&mut head).await?;
    if head[..4] != magic {
        return Err(FrameError::Magic);
    }
    let len = u32::from_le_bytes(head[16..20].try_into().expect("4 bytes")) as usize;
    if len > MAX_PAYLOAD {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    let mut done = 0;
    while done < len {
        let end = (done + 256 * 1024).min(len);
        let n = reader.read(&mut payload[done..end]).await?;
        if n == 0 {
            return Err(FrameError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        done += n;
        progress();
    }
    if sha256d(&payload)[..4] != head[20..24] {
        return Err(FrameError::Checksum);
    }
    let end = head[4..16].iter().position(|&b| b == 0).unwrap_or(12);
    let command = String::from_utf8_lossy(&head[4..4 + end]).into_owned();
    Ok(RawMessage { command, payload })
}

/// What a peer said about itself in its version message.
#[derive(Debug, Clone, Default)]
pub struct VersionInfo {
    pub version: i32,
    pub services: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

fn network_address(out: &mut Vec<u8>) {
    // Services 0, IPv4-mapped 0.0.0.0, port 0: a light client gives no address.
    out.put_u64(0);
    out.extend_from_slice(&[0u8; 10]);
    out.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
    out.put_u16(0);
}

/// The version message of a light client: no services, no address.
pub fn encode_version(user_agent: &str, relay: bool) -> Vec<u8> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut out = Vec::new();
    out.put_i32(PROTOCOL_VERSION);
    out.put_u64(0);
    out.put_i64(now as i64);
    network_address(&mut out);
    network_address(&mut out);
    out.put_u64(rand::thread_rng().next_u64());
    out.put_var_bytes(user_agent.as_bytes());
    out.put_i32(0);
    out.put_u8(u8::from(relay));
    out
}

pub fn decode_version(payload: &[u8]) -> Result<VersionInfo, DecodeError> {
    let mut r = Reader::new(payload);
    let version = r.i32()?;
    let services = r.u64()?;
    r.bytes(8 + 26 + 26 + 8)?;
    let agent = r.var_bytes()?;
    let start_height = if r.remaining() >= 4 { r.i32()? } else { 0 };
    let relay = if r.remaining() >= 1 { r.u8()? != 0 } else { true };
    Ok(VersionInfo {
        version,
        services,
        user_agent: String::from_utf8_lossy(&agent[..agent.len().min(256)]).into_owned(),
        start_height,
        relay,
    })
}

pub fn encode_getheaders(locator: &[BlockHash], stop: BlockHash) -> Vec<u8> {
    let mut out = Vec::new();
    out.put_u32(PROTOCOL_VERSION as u32);
    out.put_compact_size(locator.len() as u64);
    for h in locator {
        out.put_bytes(&h.0);
    }
    out.put_bytes(&stop.0);
    out
}

pub fn decode_headers(payload: &[u8]) -> Result<Vec<([u8; 80], BlockHeader)>, DecodeError> {
    let mut r = Reader::new(payload);
    let n = r.count(81)?;
    if n > MAX_HEADERS_PER_MSG {
        return Err(DecodeError::Invalid("too many headers"));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let raw: [u8; 80] = r.array()?;
        // The transaction count, always 0 in a headers message.
        r.compact_size()?;
        out.push((raw, BlockHeader::from_bytes(&raw)));
    }
    r.finish()?;
    Ok(out)
}

pub fn encode_getcf(filter_type: u8, start_height: u32, stop: BlockHash) -> Vec<u8> {
    let mut out = Vec::new();
    out.put_u8(filter_type);
    out.put_u32(start_height);
    out.put_bytes(&stop.0);
    out
}

pub fn encode_getcfcheckpt(filter_type: u8, stop: BlockHash) -> Vec<u8> {
    let mut out = Vec::new();
    out.put_u8(filter_type);
    out.put_bytes(&stop.0);
    out
}

#[derive(Debug, Clone)]
pub struct CfHeaders {
    pub filter_type: u8,
    pub stop: BlockHash,
    pub prev_header: [u8; 32],
    pub filter_hashes: Vec<[u8; 32]>,
}

pub fn decode_cfheaders(payload: &[u8]) -> Result<CfHeaders, DecodeError> {
    let mut r = Reader::new(payload);
    let filter_type = r.u8()?;
    let stop = BlockHash(r.array()?);
    let prev_header = r.array()?;
    let n = r.count(32)?;
    if n > MAX_CFHEADERS_PER_MSG {
        return Err(DecodeError::Invalid("too many filter hashes"));
    }
    let filter_hashes = (0..n).map(|_| r.array()).collect::<Result<_, _>>()?;
    r.finish()?;
    Ok(CfHeaders { filter_type, stop, prev_header, filter_hashes })
}

#[derive(Debug, Clone)]
pub struct CfCheckpt {
    pub filter_type: u8,
    pub stop: BlockHash,
    pub headers: Vec<[u8; 32]>,
}

pub fn decode_cfcheckpt(payload: &[u8]) -> Result<CfCheckpt, DecodeError> {
    let mut r = Reader::new(payload);
    let filter_type = r.u8()?;
    let stop = BlockHash(r.array()?);
    let n = r.count(32)?;
    let headers = (0..n).map(|_| r.array()).collect::<Result<_, _>>()?;
    r.finish()?;
    Ok(CfCheckpt { filter_type, stop, headers })
}

#[derive(Debug, Clone)]
pub struct CFilter {
    pub filter_type: u8,
    pub block: BlockHash,
    pub filter: Vec<u8>,
}

pub fn decode_cfilter(payload: &[u8]) -> Result<CFilter, DecodeError> {
    let mut r = Reader::new(payload);
    let filter_type = r.u8()?;
    let block = BlockHash(r.array()?);
    let filter = r.var_bytes()?.to_vec();
    r.finish()?;
    Ok(CFilter { filter_type, block, filter })
}

/// An inventory item: type and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inv {
    pub kind: u32,
    pub hash: [u8; 32],
}

pub fn encode_inv(items: &[Inv]) -> Vec<u8> {
    let mut out = Vec::new();
    out.put_compact_size(items.len() as u64);
    for item in items {
        out.put_u32(item.kind);
        out.put_bytes(&item.hash);
    }
    out
}

/// Decodes inv, getdata and notfound payloads.
pub fn decode_inv(payload: &[u8]) -> Result<Vec<Inv>, DecodeError> {
    let mut r = Reader::new(payload);
    let n = r.count(36)?;
    if n > MAX_INV_PER_MSG {
        return Err(DecodeError::Invalid("too many inventory items"));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(Inv { kind: r.u32()?, hash: r.array()? });
    }
    r.finish()?;
    Ok(out)
}

pub fn decode_feefilter(payload: &[u8]) -> Result<u64, DecodeError> {
    let mut r = Reader::new(payload);
    let fee = r.u64()?;
    Ok(fee)
}

/// A reject message (BIP61): what was rejected and why.
#[derive(Debug, Clone)]
pub struct Reject {
    pub message: String,
    pub code: u8,
    pub reason: String,
    pub hash: Option<[u8; 32]>,
}

pub fn decode_reject(payload: &[u8]) -> Result<Reject, DecodeError> {
    let mut r = Reader::new(payload);
    let message = String::from_utf8_lossy(r.var_bytes()?).into_owned();
    let code = r.u8()?;
    let reason = String::from_utf8_lossy(r.var_bytes()?).into_owned();
    let hash = if r.remaining() >= 32 { Some(r.array()?) } else { None };
    Ok(Reject { message, code, reason, hash })
}

impl Inv {
    pub fn block(hash: BlockHash) -> Self {
        Self { kind: INV_BLOCK, hash: hash.0 }
    }

    pub fn tx(txid: Txid) -> Self {
        Self { kind: INV_TX, hash: txid.0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_bad_checksums_fail() {
        let magic = [1, 2, 3, 4];
        let bytes = encode_message(magic, "ping", &[9u8; 8]);
        let msg = read_message(&mut bytes.as_slice(), magic, || {}).await.unwrap();
        assert_eq!(msg.command, "ping");
        assert_eq!(msg.payload, vec![9u8; 8]);
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(read_message(&mut bad.as_slice(), magic, || {}).await, Err(FrameError::Checksum)));
        assert!(matches!(read_message(&mut bytes.as_slice(), [0; 4], || {}).await, Err(FrameError::Magic)));
    }

    #[test]
    fn version_round_trips() {
        let v = decode_version(&encode_version("/test:1/", true)).unwrap();
        assert_eq!(v.version, PROTOCOL_VERSION);
        assert_eq!(v.user_agent, "/test:1/");
        assert!(v.relay);
        assert_eq!(v.services, 0);
    }
}
