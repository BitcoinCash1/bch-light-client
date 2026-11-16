//! Matching many keys against many stored filters at once, on every core.
//!
//! Each thread reads its share of the filter file in large sequential
//! chunks and tests all keys against each filter in one pass over the
//! filter's values.

use crate::filter::{gcs_part, FilterKey};
use crate::filterstore::{open_reader, read_exact_at};
use crate::gcs::{filter_key, hash_to_range};
use crate::hash::BlockHash;
use std::path::Path;

/// A key to test, from a height on.
#[derive(Debug, Clone, Copy)]
pub struct ScanKey {
    pub key: FilterKey,
    pub from: u32,
}

/// The heights whose filters match, each with the indexes of the keys it matches.
pub type ScanHits = Vec<(u32, Vec<usize>)>;

const CHUNK_BYTES: u64 = 16 * 1024 * 1024;

/// Tests `keys` against the filters at `spans` (height, block hash, offset,
/// length) of the file at `path`. A malformed filter counts as matching every
/// key, so that it can never hide a payment.
pub fn scan(path: &Path, spans: &[(u32, BlockHash, u64, u32)], keys: &[ScanKey], threads: usize) -> std::io::Result<ScanHits> {
    if spans.is_empty() || keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut keys_by_start: Vec<usize> = (0..keys.len()).collect();
    keys_by_start.sort_by_key(|&i| keys[i].from);
    let threads = threads.max(1).min(spans.len());
    let per_thread = spans.len().div_ceil(threads);
    let results: Vec<std::io::Result<ScanHits>> = std::thread::scope(|s| {
        let handles: Vec<_> = spans
            .chunks(per_thread)
            .map(|part| {
                let keys_by_start = &keys_by_start;
                s.spawn(move || scan_part(path, part, keys, keys_by_start))
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("scan thread panicked")).collect()
    });
    let mut hits = Vec::new();
    for part in results {
        hits.extend(part?);
    }
    Ok(hits)
}

fn scan_part(
    path: &Path,
    spans: &[(u32, BlockHash, u64, u32)],
    keys: &[ScanKey],
    keys_by_start: &[usize],
) -> std::io::Result<ScanHits> {
    let file = open_reader(path)?;
    let mut hits = Vec::new();
    let mut buf = Vec::new();
    let mut targets: Vec<(u64, usize)> = Vec::with_capacity(keys.len());
    let mut i = 0;
    while i < spans.len() {
        // A run of filters that fits one read.
        let base = spans[i].2;
        let mut j = i;
        while j + 1 < spans.len() && spans[j + 1].2 + u64::from(spans[j + 1].3) - base <= CHUNK_BYTES {
            j += 1;
        }
        let size = (spans[j].2 + u64::from(spans[j].3) - base) as usize;
        buf.resize(size, 0);
        read_exact_at(&file, &mut buf, base)?;
        for &(height, hash, offset, len) in &spans[i..=j] {
            let at = (offset - base) as usize;
            let filter = &buf[at..at + len as usize];
            let active = keys_by_start.partition_point(|&k| keys[k].from <= height);
            if active == 0 {
                continue;
            }
            let mut matched = Vec::new();
            match gcs_part(filter) {
                Ok(gcs) => {
                    let sip = filter_key(&hash.0);
                    targets.clear();
                    targets.extend(keys_by_start[..active].iter().map(|&k| (hash_to_range(sip, gcs.n, &keys[k].key.0), k)));
                    targets.sort_unstable();
                    if gcs.match_sorted(&targets, |k| matched.push(k)).is_err() {
                        matched = keys_by_start[..active].to_vec();
                    }
                }
                Err(_) => matched = keys_by_start[..active].to_vec(),
            }
            if !matched.is_empty() {
                matched.sort_unstable();
                matched.dedup();
                hits.push((height, matched));
            }
        }
        i = j + 1;
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcs::build;

    #[test]
    fn finds_each_key_in_its_blocks_from_its_start_height() {
        let dir = std::env::temp_dir().join(format!("bch-light-client-test-{}-scan", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("filters.dat");
        let keys: Vec<FilterKey> = (0u8..4).map(|i| FilterKey([i; 32])).collect();
        let mut data = Vec::new();
        let mut spans = Vec::new();
        for height in 0u32..200 {
            let hash = BlockHash(crate::hash::sha256d(&height.to_le_bytes()));
            // Key i is in the blocks whose height is a multiple of i + 2.
            let mut items: Vec<Vec<u8>> = (0..50u32).map(|j| crate::hash::sha256(&(height * 1000 + j).to_le_bytes()).to_vec()).collect();
            for (i, k) in keys.iter().enumerate() {
                if height % (i as u32 + 2) == 0 {
                    items.push(k.0.to_vec());
                }
            }
            let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
            let mut filter = vec![0u8; 32];
            filter.extend(build(filter_key(&hash.0), &refs));
            spans.push((height, hash, data.len() as u64, filter.len() as u32));
            data.extend(filter);
        }
        std::fs::write(&path, &data).unwrap();
        let scan_keys: Vec<ScanKey> = keys.iter().enumerate().map(|(i, k)| ScanKey { key: *k, from: i as u32 * 10 }).collect();
        for threads in [1, 3, 8] {
            let hits = scan(&path, &spans, &scan_keys, threads).unwrap();
            for (i, _) in keys.iter().enumerate() {
                let found: Vec<u32> = hits.iter().filter(|(_, ks)| ks.contains(&i)).map(|(h, _)| *h).collect();
                let expected: Vec<u32> = (i as u32 * 10..200).filter(|h| h % (i as u32 + 2) == 0).collect();
                assert_eq!(found, expected, "key {i} with {threads} threads");
            }
        }
    }
}
