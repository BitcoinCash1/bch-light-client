//! The header chain: every block header from genesis, checked for proof of
//! work, the difficulty rules, timestamps and checkpoints, kept in memory
//! and in one flat file of 80-byte headers that only grows, except that a
//! reorganization truncates it at the fork.

use crate::block::BlockHeader;
use crate::hash::BlockHash;
use crate::params::Params;
use crate::pow::{meets_target, required_bits, work, ChainView};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// A header the rules refuse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("headers do not connect to the known chain")]
    Unconnected,
    #[error("headers do not form a chain at height {0}")]
    NotAChain(u32),
    #[error("header at height {0} does not meet its target")]
    ProofOfWork(u32),
    #[error(transparent)]
    Bits(#[from] crate::pow::BadBits),
    #[error("header at height {0} is not later than the median of the 11 before it")]
    TooOld(u32),
    #[error("header at height {0} is more than two hours in the future")]
    TooNew(u32),
    #[error("header at height {0} differs from the checkpoint")]
    Checkpoint(u32),
    #[error("the headers fork below a checkpoint at height {0}")]
    ForkBelowCheckpoint(u32),
}

/// What accepting headers did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// Every header was known already.
    Known,
    /// The chain grew; `fork` is set when blocks above it were replaced.
    Extended { fork: Option<u32>, tip: u32 },
    /// A valid branch with no more work than the current chain, not taken.
    LessWork { fork: u32, branch_tip: u32 },
}

pub struct HeaderChain {
    params: &'static Params,
    file: File,
    headers: Vec<BlockHeader>,
    hashes: Vec<BlockHash>,
    /// Total work up to each height.
    work: Vec<u128>,
}

impl ChainView for HeaderChain {
    fn time_at(&self, height: u32) -> u32 {
        self.headers[height as usize].time
    }
    fn bits_at(&self, height: u32) -> u32 {
        self.headers[height as usize].bits
    }
    fn chainwork_at(&self, height: u32) -> u128 {
        self.work[height as usize]
    }
}

/// The chain up to `fork`, then a candidate branch.
struct BranchView<'a> {
    chain: &'a HeaderChain,
    fork: u32,
    branch: &'a [BlockHeader],
    work: &'a [u128],
}

impl ChainView for BranchView<'_> {
    fn time_at(&self, height: u32) -> u32 {
        if height <= self.fork {
            self.chain.time_at(height)
        } else {
            self.branch[(height - self.fork - 1) as usize].time
        }
    }
    fn bits_at(&self, height: u32) -> u32 {
        if height <= self.fork {
            self.chain.bits_at(height)
        } else {
            self.branch[(height - self.fork - 1) as usize].bits
        }
    }
    fn chainwork_at(&self, height: u32) -> u128 {
        if height <= self.fork {
            self.chain.chainwork_at(height)
        } else {
            self.work[(height - self.fork - 1) as usize]
        }
    }
}

const MAX_FUTURE_SECONDS: u64 = 2 * 60 * 60;

impl HeaderChain {
    /// Opens the header file, keeping the longest prefix that chains from
    /// genesis and meets its targets.
    pub fn open(path: &Path, params: &'static Params) -> std::io::Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;
        let genesis = params.genesis();
        let mut chain = HeaderChain {
            params,
            file,
            headers: vec![genesis],
            hashes: vec![genesis.hash()],
            work: vec![work(genesis.bits)],
        };
        let pow_limit = params.pow_limit();
        let stored = raw.len() / 80;
        let mut good = 0usize;
        for (i, chunk) in raw.chunks_exact(80).enumerate() {
            let header = BlockHeader::from_bytes(chunk.try_into().expect("80 bytes"));
            if i == 0 {
                if header != genesis {
                    break;
                }
                good = 1;
                continue;
            }
            let hash = header.hash();
            if header.prev_hash != chain.hashes[i - 1] || !meets_target(&hash.0, header.bits, pow_limit) {
                break;
            }
            let total = chain.work[i - 1].saturating_add(work(header.bits));
            chain.headers.push(header);
            chain.hashes.push(hash);
            chain.work.push(total);
            good = i + 1;
        }
        if good != stored || stored == 0 {
            chain.file.set_len(0)?;
            chain.file.seek(SeekFrom::Start(0))?;
            let bytes: Vec<u8> = chain.headers.iter().flat_map(|h| h.to_bytes()).collect();
            chain.file.write_all(&bytes)?;
            chain.file.flush()?;
        }
        Ok(chain)
    }

    pub fn params(&self) -> &'static Params {
        self.params
    }

    pub fn tip_height(&self) -> u32 {
        (self.headers.len() - 1) as u32
    }

    pub fn tip_hash(&self) -> BlockHash {
        *self.hashes.last().expect("genesis is always there")
    }

    pub fn header_at(&self, height: u32) -> Option<BlockHeader> {
        self.headers.get(height as usize).copied()
    }

    pub fn hash_at(&self, height: u32) -> Option<BlockHash> {
        self.hashes.get(height as usize).copied()
    }

    pub fn chainwork(&self) -> u128 {
        *self.work.last().expect("genesis is always there")
    }

    /// The height of a block of the chain, searched from the tip down.
    pub fn height_of(&self, hash: &BlockHash) -> Option<u32> {
        self.hashes.iter().rposition(|h| h == hash).map(|i| i as u32)
    }

    /// Ten newest hashes, then exponentially sparser ones, then genesis.
    pub fn locator(&self) -> Vec<BlockHash> {
        let mut out = Vec::new();
        let mut step = 1u32;
        let mut height = self.tip_height();
        while height > 0 {
            out.push(self.hashes[height as usize]);
            if out.len() >= 10 {
                step = step.saturating_mul(2);
            }
            height = height.saturating_sub(step);
        }
        out.push(self.hashes[0]);
        out
    }

    /// Checks headers that follow a known block and takes them when they
    /// extend the chain or make a branch with more work.
    pub fn accept(&mut self, headers: &[BlockHeader]) -> Result<Accepted, HeaderError> {
        let Some(first) = headers.first() else { return Ok(Accepted::Known) };
        let parent = self.height_of(&first.prev_hash).ok_or(HeaderError::Unconnected)?;
        // Skip what the chain has already.
        let known = headers
            .iter()
            .enumerate()
            .take_while(|(i, h)| self.hash_at(parent + 1 + *i as u32) == Some(h.hash()))
            .count();
        let fork = parent + known as u32;
        let branch = &headers[known..];
        if branch.is_empty() {
            return Ok(Accepted::Known);
        }
        if let Some(cp) = self.params.checkpoints.iter().map(|(h, _)| *h).filter(|h| *h <= self.tip_height()).max() {
            if fork < cp {
                return Err(HeaderError::ForkBelowCheckpoint(cp));
            }
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let pow_limit = self.params.pow_limit();
        let mut branch_work: Vec<u128> = Vec::with_capacity(branch.len());
        let mut prev_hash = self.hashes[fork as usize];
        for (i, header) in branch.iter().enumerate() {
            let height = fork + 1 + i as u32;
            let view = BranchView { chain: self, fork, branch: &branch[..i], work: &branch_work };
            let hash = header.hash();
            if header.prev_hash != prev_hash {
                return Err(HeaderError::NotAChain(height));
            }
            if !meets_target(&hash.0, header.bits, pow_limit) {
                return Err(HeaderError::ProofOfWork(height));
            }
            let expected = required_bits(self.params, &view, height - 1, header.time);
            if header.bits != expected {
                return Err(crate::pow::BadBits { height, got: header.bits, expected }.into());
            }
            if header.time <= view.median_time_past(height - 1) {
                return Err(HeaderError::TooOld(height));
            }
            if u64::from(header.time) > now + MAX_FUTURE_SECONDS {
                return Err(HeaderError::TooNew(height));
            }
            if self.params.checkpoint(height).is_some_and(|cp| cp != hash) {
                return Err(HeaderError::Checkpoint(height));
            }
            branch_work.push(view.chainwork_at(height - 1).saturating_add(work(header.bits)));
            prev_hash = hash;
        }
        let branch_tip = fork + branch.len() as u32;
        let new_work = *branch_work.last().expect("non-empty branch");
        if fork < self.tip_height() && new_work <= self.chainwork() {
            return Ok(Accepted::LessWork { fork, branch_tip });
        }
        let replaced = fork < self.tip_height();
        self.truncate_to(fork).map_err(|_| HeaderError::Unconnected)?;
        for (header, total) in branch.iter().zip(branch_work) {
            self.hashes.push(header.hash());
            self.headers.push(*header);
            self.work.push(total);
        }
        self.persist_from(fork + 1).map_err(|_| HeaderError::Unconnected)?;
        Ok(Accepted::Extended { fork: replaced.then_some(fork), tip: self.tip_height() })
    }

    fn truncate_to(&mut self, height: u32) -> std::io::Result<()> {
        let keep = height as usize + 1;
        self.headers.truncate(keep);
        self.hashes.truncate(keep);
        self.work.truncate(keep);
        self.file.set_len((keep * 80) as u64)
    }

    fn persist_from(&mut self, height: u32) -> std::io::Result<()> {
        let start = height as usize;
        let bytes: Vec<u8> = self.headers[start..].iter().flat_map(|h| h.to_bytes()).collect();
        self.file.seek(SeekFrom::Start((start * 80) as u64))?;
        self.file.write_all(&bytes)?;
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Network;

    /// Mines a regtest header on top of `prev` (bits 0x207fffff: about one try in two).
    pub(crate) fn mine(prev: &BlockHeader, time: u32, salt: u32) -> BlockHeader {
        let mut header = BlockHeader {
            version: 4,
            prev_hash: prev.hash(),
            merkle_root: crate::hash::sha256d(&salt.to_le_bytes()),
            time,
            bits: 0x207fffff,
            nonce: 0,
        };
        let limit = Network::Regtest.params().pow_limit();
        while !meets_target(&header.hash().0, header.bits, limit) {
            header.nonce += 1;
        }
        header
    }

    fn temp_file(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bch-light-client-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("headers.dat");
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn extends_reorganizes_to_more_work_and_reloads() {
        let params = Network::Regtest.params();
        let path = temp_file("chain");
        let mut chain = HeaderChain::open(&path, params).unwrap();
        let genesis = params.genesis();
        let mut main = vec![genesis];
        for i in 0..5 {
            let next = mine(main.last().unwrap(), genesis.time + 600 * (i + 1), i);
            main.push(next);
        }
        assert_eq!(chain.accept(&main[1..]).unwrap(), Accepted::Extended { fork: None, tip: 5 });
        assert_eq!(chain.accept(&main[3..]).unwrap(), Accepted::Known);
        // A branch from height 3 of the same length has no more work.
        let mut side = vec![main[3]];
        for i in 0..2 {
            side.push(mine(side.last().unwrap(), genesis.time + 2000 + i, 100 + i));
        }
        assert_eq!(chain.accept(&side[1..]).unwrap(), Accepted::LessWork { fork: 3, branch_tip: 5 });
        side.push(mine(side.last().unwrap(), genesis.time + 3000, 200));
        assert_eq!(chain.accept(&side[1..]).unwrap(), Accepted::Extended { fork: Some(3), tip: 6 });
        assert_eq!(chain.hash_at(6), Some(side[3].hash()));
        drop(chain);
        let reopened = HeaderChain::open(&path, params).unwrap();
        assert_eq!(reopened.tip_height(), 6);
        assert_eq!(reopened.tip_hash(), side[3].hash());
    }

    #[test]
    fn refuses_bad_proof_of_work_bits_and_time() {
        let params = Network::Regtest.params();
        let mut chain = HeaderChain::open(&temp_file("bad"), params).unwrap();
        let genesis = params.genesis();
        let good = mine(&genesis, genesis.time + 600, 1);
        let mut bad_bits = good;
        bad_bits.bits = 0x2000ffff;
        assert!(chain.accept(&[bad_bits]).is_err());
        let old = mine(&genesis, genesis.time, 2);
        assert_eq!(chain.accept(&[old]), Err(HeaderError::TooOld(1)));
        let mut unconnected = good;
        unconnected.prev_hash = BlockHash([9; 32]);
        assert_eq!(chain.accept(&[unconnected]), Err(HeaderError::Unconnected));
        assert!(chain.accept(&[good]).is_ok());
    }
}
