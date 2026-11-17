//! The client's own copy of a filter type: for every block from a start
//! height on, its hash, filter header and filter, kept in two flat files
//! that only grow and are truncated at the fork on a reorganization.
//! `<name>filters.dat` holds the filters back to back; `<name>filter-index.dat`
//! starts with the start height and the filter header before it, then has a
//! 68-byte record per height (block hash, filter header, filter length).
//! Nothing in them is per address or per transaction, and a scan reads them
//! in order.

use crate::filter::next_filter_header;
use crate::hash::BlockHash;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const RECORD: usize = 68;
const MAGIC: &[u8; 4] = b"BCF2";
const HEAD: usize = 4 + 4 + 32;

pub struct FilterStore {
    data_path: PathBuf,
    data: File,
    index: File,
    /// The first height kept.
    base: u32,
    /// The filter header of the block before `base` (zero for genesis).
    anchor: [u8; 32],
    /// Whether `anchor` is known; a store that starts above 0 learns it
    /// from the peers' checkpoints before taking filters.
    anchored: bool,
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
    /// Opens the store named `name` (a file name prefix) that starts at
    /// `base`, keeping the records whose block hashes match the header
    /// chain (`hash_at`) and whose filters are whole and hash to their
    /// filter headers. A store kept with another start height is begun anew.
    pub fn open(
        dir: &Path,
        name: &str,
        base: u32,
        hash_at: impl Fn(u32) -> Option<BlockHash>,
    ) -> std::io::Result<Self> {
        let data_path = dir.join(format!("{name}filters.dat"));
        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&data_path)?;
        let mut index = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(format!("{name}filter-index.dat")))?;
        let mut raw = Vec::new();
        index.read_to_end(&mut raw)?;
        let data_len = data.seek(SeekFrom::End(0))?;
        let mut store = FilterStore {
            data_path,
            data,
            index,
            base,
            anchor: [0u8; 32],
            anchored: base == 0,
            block_hashes: Vec::new(),
            headers: Vec::new(),
            offsets: Vec::new(),
            lengths: Vec::new(),
        };
        let same_base = raw.len() >= HEAD
            && &raw[..4] == MAGIC
            && u32::from_le_bytes(raw[4..8].try_into().expect("4 bytes")) == base;
        if !same_base {
            store.rewrite_head()?;
            store.index.set_len(HEAD as u64)?;
            store.data.set_len(0)?;
            return Ok(store);
        }
        store.anchor.copy_from_slice(&raw[8..40]);
        store.anchored = base == 0 || store.anchor != [0u8; 32];
        let mut offset = 0u64;
        for (i, record) in raw[HEAD..].chunks_exact(RECORD).enumerate() {
            let height = base + i as u32;
            let hash = BlockHash(record[0..32].try_into().expect("32 bytes"));
            let header: [u8; 32] = record[32..64].try_into().expect("32 bytes");
            let length = u32::from_le_bytes(record[64..68].try_into().expect("4 bytes"));
            if hash_at(height) != Some(hash) || offset + u64::from(length) > data_len {
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
        for i in count.saturating_sub(16)..count {
            let height = base + i as u32;
            let ok = store
                .read(height)
                .map(|f| next_filter_header(&f, &store.prev_header(height)) == store.headers[i]);
            if !matches!(ok, Ok(true)) {
                keep = i;
                break;
            }
        }
        store.truncate_from(base + keep as u32)?;
        Ok(store)
    }

    fn rewrite_head(&mut self) -> std::io::Result<()> {
        let mut head = Vec::with_capacity(HEAD);
        head.extend_from_slice(MAGIC);
        head.extend_from_slice(&self.base.to_le_bytes());
        head.extend_from_slice(&self.anchor);
        self.index.seek(SeekFrom::Start(0))?;
        self.index.write_all(&head)?;
        self.index.flush()
    }

    /// The first height kept.
    pub fn base(&self) -> u32 {
        self.base
    }

    /// Whether the filter header before `base` is known.
    pub fn anchored(&self) -> bool {
        self.anchored
    }

    /// Sets the filter header before `base`, learned from checkpoints.
    pub fn set_anchor(&mut self, anchor: [u8; 32]) -> std::io::Result<()> {
        self.anchor = anchor;
        self.anchored = true;
        self.rewrite_head()
    }

    /// The number of blocks with filters.
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// The next height to store.
    pub fn next_height(&self) -> u32 {
        self.base + self.len() as u32
    }

    /// The highest height with a filter.
    pub fn tip(&self) -> Option<u32> {
        (!self.is_empty()).then(|| self.next_height() - 1)
    }

    fn slot(&self, height: u32) -> Option<usize> {
        height
            .checked_sub(self.base)
            .map(|i| i as usize)
            .filter(|i| *i < self.len())
    }

    pub fn filter_header(&self, height: u32) -> Option<[u8; 32]> {
        self.slot(height).map(|i| self.headers[i])
    }

    /// The filter header before `height`: the anchor below the first stored height.
    pub fn prev_header(&self, height: u32) -> [u8; 32] {
        if height <= self.base {
            self.anchor
        } else {
            self.filter_header(height - 1).unwrap_or([0u8; 32])
        }
    }

    pub fn block_hash(&self, height: u32) -> Option<BlockHash> {
        self.slot(height).map(|i| self.block_hashes[i])
    }

    /// The location of each filter of heights [from, to) that is stored.
    pub fn spans(&self, from: u32, to: u32) -> Vec<(u32, BlockHash, u64, u32)> {
        let from = from.max(self.base);
        let to = to.min(self.next_height());
        (from..to)
            .map(|h| {
                let i = (h - self.base) as usize;
                (h, self.block_hashes[i], self.offsets[i], self.lengths[i])
            })
            .collect()
    }

    pub fn data_path(&self) -> &Path {
        &self.data_path
    }

    /// Appends filters for the heights after the tip, all checked by the caller.
    pub fn append(&mut self, items: &[(BlockHash, [u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        let mut offset = self.offsets.last().map_or(0, |o| {
            o + u64::from(*self.lengths.last().expect("same length"))
        });
        let blob: Vec<u8> = items
            .iter()
            .flat_map(|(_, _, f)| f.iter().copied())
            .collect();
        let mut records = Vec::with_capacity(items.len() * RECORD);
        for (hash, header, filter) in items {
            records.extend_from_slice(&hash.0);
            records.extend_from_slice(header);
            records.extend_from_slice(&(filter.len() as u32).to_le_bytes());
        }
        self.data.seek(SeekFrom::Start(offset))?;
        self.data.write_all(&blob)?;
        self.data.flush()?;
        self.index
            .seek(SeekFrom::Start((HEAD + self.len() * RECORD) as u64))?;
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

    /// Keeps the heights below `height`.
    pub fn truncate_from(&mut self, height: u32) -> std::io::Result<()> {
        let count = (height.saturating_sub(self.base) as usize).min(self.len());
        let end = if count == 0 {
            0
        } else {
            self.offsets[count - 1] + u64::from(self.lengths[count - 1])
        };
        self.block_hashes.truncate(count);
        self.headers.truncate(count);
        self.offsets.truncate(count);
        self.lengths.truncate(count);
        self.index.set_len((HEAD + count * RECORD) as u64)?;
        self.data.set_len(end)
    }

    /// A stored filter.
    pub fn read(&self, height: u32) -> std::io::Result<Vec<u8>> {
        let i = self.slot(height).ok_or(std::io::ErrorKind::NotFound)?;
        let mut buf = vec![0u8; self.lengths[i] as usize];
        read_exact_at(&self.data, &mut buf, self.offsets[i])?;
        Ok(buf)
    }

    /// A stored filter, checked against its filter header.
    pub fn read_checked(&self, height: u32) -> std::io::Result<Vec<u8>> {
        let filter = self.read(height)?;
        if Some(next_filter_header(&filter, &self.prev_header(height)))
            != self.filter_header(height)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stored filter does not match its header",
            ));
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

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bch-light-client-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn appends_reloads_and_truncates() {
        let dir = temp("filters");
        let hashes: Vec<BlockHash> = (0u8..5).map(|i| BlockHash([i; 32])).collect();
        let mut store =
            FilterStore::open(&dir, "", 0, |h| hashes.get(h as usize).copied()).unwrap();
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
        let store = FilterStore::open(&dir, "", 0, |h| changed.get(h as usize).copied()).unwrap();
        assert_eq!(store.tip(), Some(2));
        assert_eq!(store.read_checked(2).unwrap(), items[2].2);
    }

    #[test]
    fn a_store_from_a_later_height_chains_from_its_anchor() {
        let dir = temp("filters-base");
        let hashes: Vec<BlockHash> = (0u8..10).map(|i| BlockHash([i; 32])).collect();
        let anchor = [7u8; 32];
        let mut store =
            FilterStore::open(&dir, "rpa-", 5, |h| hashes.get(h as usize).copied()).unwrap();
        assert!(!store.anchored());
        store.set_anchor(anchor).unwrap();
        let filter = vec![1u8, 2, 3];
        let header = next_filter_header(&filter, &anchor);
        store
            .append(&[(hashes[5], header, filter.clone())])
            .unwrap();
        drop(store);
        let store =
            FilterStore::open(&dir, "rpa-", 5, |h| hashes.get(h as usize).copied()).unwrap();
        assert!(store.anchored());
        assert_eq!((store.base(), store.tip()), (5, Some(5)));
        assert_eq!(store.read_checked(5).unwrap(), filter);
        assert!(store.read(4).is_err());
        assert_eq!(store.spans(0, 100).len(), 1);
        drop(store);
        // Another start height begins the store anew.
        let store =
            FilterStore::open(&dir, "rpa-", 0, |h| hashes.get(h as usize).copied()).unwrap();
        assert_eq!(store.tip(), None);
    }
}
