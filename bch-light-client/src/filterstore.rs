//! The client's own copy of the script filters: for every block its hash,
//! filter header and filter, kept in two flat files that only grow, and are
//! truncated at the fork on a reorganization. filters.dat has the filters
//! back to back; filter-index.dat has a 68-byte record per height (block
//! hash, filter header, filter length). Nothing in them is per address or
//! per transaction, and a scan reads them in order.

use crate::filter::next_filter_header;
use crate::hash::BlockHash;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const RECORD: usize = 68;

pub struct FilterStore {
    data_path: PathBuf,
    data: File,
    index: File,
    block_hashes: Vec<BlockHash>,
    headers: Vec<[u8; 32]>,
    offsets: Vec<u64>,
    lengths: Vec<u32>,
}

/// Reads exactly `buf.len()` bytes at `offset`.
pub fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            let n = file.seek_read(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            done += n;
        }
        Ok(())
    }
}

impl FilterStore {
    /// Opens the store, keeping the records whose block hashes match the
    /// header chain (`hash_at`) and whose filters are whole and hash to their
    /// filter headers.
    pub fn open(dir: &Path, hash_at: impl Fn(u32) -> Option<BlockHash>) -> std::io::Result<Self> {
        let data_path = dir.join("filters.dat");
        let mut data = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&data_path)?;
        let mut index =
            OpenOptions::new().read(true).write(true).create(true).truncate(false).open(dir.join("filter-index.dat"))?;
        let mut records = Vec::new();
        index.read_to_end(&mut records)?;
        let data_len = data.seek(SeekFrom::End(0))?;
        let mut store = FilterStore {
            data_path,
            data,
            index,
            block_hashes: Vec::new(),
            headers: Vec::new(),
            offsets: Vec::new(),
            lengths: Vec::new(),
        };
        let mut offset = 0u64;
        for (height, record) in records.chunks_exact(RECORD).enumerate() {
            let hash = BlockHash(record[0..32].try_into().expect("32 bytes"));
            let header: [u8; 32] = record[32..64].try_into().expect("32 bytes");
            let length = u32::from_le_bytes(record[64..68].try_into().expect("4 bytes"));
            if hash_at(height as u32) != Some(hash) || offset + u64::from(length) > data_len {
                break;
            }
            store.block_hashes.push(hash);
            store.headers.push(header);
            store.offsets.push(offset);
            store.lengths.push(length);
            offset += u64::from(length);
        }
        // The newest filters are checked against their headers; a torn write lands there.
        let count = store.len();
        let mut keep = count;
        for height in count.saturating_sub(16)..count {
            let ok = store.read(height as u32).map(|f| {
                let prev = if height == 0 { [0u8; 32] } else { store.headers[height - 1] };
                next_filter_header(&f, &prev) == store.headers[height]
            });
            if !matches!(ok, Ok(true)) {
                keep = height;
                break;
            }
        }
        store.truncate(keep as u32)?;
        Ok(store)
    }

    /// The number of blocks with filters (heights 0 to len - 1).
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// The highest height with a filter.
    pub fn tip(&self) -> Option<u32> {
        self.len().checked_sub(1).map(|h| h as u32)
    }

    pub fn filter_header(&self, height: u32) -> Option<[u8; 32]> {
        self.headers.get(height as usize).copied()
    }

    pub fn block_hash(&self, height: u32) -> Option<BlockHash> {
        self.block_hashes.get(height as usize).copied()
    }

    /// The location of each filter of heights [from, to).
    pub fn spans(&self, from: u32, to: u32) -> Vec<(u32, BlockHash, u64, u32)> {
        let to = (to as usize).min(self.len());
        (from as usize..to).map(|h| (h as u32, self.block_hashes[h], self.offsets[h], self.lengths[h])).collect()
    }

    pub fn data_path(&self) -> &Path {
        &self.data_path
    }

    /// Appends filters for the heights after the tip, all checked by the caller.
    pub fn append(&mut self, items: &[(BlockHash, [u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        let mut offset = self.offsets.last().map_or(0, |o| o + u64::from(*self.lengths.last().expect("same length")));
        let blob: Vec<u8> = items.iter().flat_map(|(_, _, f)| f.iter().copied()).collect();
        let mut records = Vec::with_capacity(items.len() * RECORD);
        for (hash, header, filter) in items {
            records.extend_from_slice(&hash.0);
            records.extend_from_slice(header);
            records.extend_from_slice(&(filter.len() as u32).to_le_bytes());
        }
        self.data.seek(SeekFrom::Start(offset))?;
        self.data.write_all(&blob)?;
        self.data.flush()?;
        self.index.seek(SeekFrom::Start((self.len() * RECORD) as u64))?;
        self.index.write_all(&records)?;
        self.index.flush()?;
        for (hash, header, filter) in items {
            self.block_hashes.push(*hash);
            self.headers.push(*header);
            self.offsets.push(offset);
            self.lengths.push(filter.len() as u32);
            offset += filter.len() as u64;
        }
        Ok(())
    }

    /// Keeps heights [0, count).
    pub fn truncate(&mut self, count: u32) -> std::io::Result<()> {
        let count = (count as usize).min(self.len());
        let end = if count == 0 { 0 } else { self.offsets[count - 1] + u64::from(self.lengths[count - 1]) };
        self.block_hashes.truncate(count);
        self.headers.truncate(count);
        self.offsets.truncate(count);
        self.lengths.truncate(count);
        self.index.set_len((count * RECORD) as u64)?;
        self.data.set_len(end)
    }

    /// A stored filter.
    pub fn read(&self, height: u32) -> std::io::Result<Vec<u8>> {
        let h = height as usize;
        if h >= self.len() {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        let mut buf = vec![0u8; self.lengths[h] as usize];
        read_exact_at(&self.data, &mut buf, self.offsets[h])?;
        Ok(buf)
    }

    /// A stored filter, checked against its filter header.
    pub fn read_checked(&self, height: u32) -> std::io::Result<Vec<u8>> {
        let filter = self.read(height)?;
        let h = height as usize;
        let prev = if h == 0 { [0u8; 32] } else { self.headers[h - 1] };
        if next_filter_header(&filter, &prev) != self.headers[h] {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "stored filter does not match its header"));
        }
        Ok(filter)
    }
}

/// Opens a read handle of the filter data for a scanning thread.
pub fn open_reader(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::next_filter_header;

    #[test]
    fn appends_reloads_and_truncates() {
        let dir = std::env::temp_dir().join(format!("bch-light-client-test-{}-filters", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hashes: Vec<BlockHash> = (0u8..5).map(|i| BlockHash([i; 32])).collect();
        let mut store = FilterStore::open(&dir, |h| hashes.get(h as usize).copied()).unwrap();
        let mut prev = [0u8; 32];
        let mut items = Vec::new();
        for (i, hash) in hashes.iter().enumerate() {
            let filter = vec![i as u8; 40 + i];
            let header = next_filter_header(&filter, &prev);
            prev = header;
            items.push((*hash, header, filter));
        }
        store.append(&items[..3]).unwrap();
        store.append(&items[3..]).unwrap();
        assert_eq!(store.read_checked(4).unwrap(), items[4].2);
        drop(store);
        // A changed chain at height 3 keeps heights 0 to 2.
        let mut changed = hashes.clone();
        changed[3] = BlockHash([99; 32]);
        let store = FilterStore::open(&dir, |h| changed.get(h as usize).copied()).unwrap();
        assert_eq!(store.tip(), Some(2));
        assert_eq!(store.read_checked(2).unwrap(), items[2].2);
    }
}
