//! Cover for the blocks a lookup downloads.
//!
//! A peer that serves a block learns that someone wanted it. So each block
//! a lookup needs comes with [`Config::decoy_blocks`] others from its bucket
//! of [`BUCKET`] heights. The decoys are derived, not random: decoy `draw`
//! of the block at `height` is SHA-256(seed, height, draw) modulo the
//! bucket, with a seed made once for the data folder. The same block
//! therefore brings the same decoys in every session, and a peer that
//! intersects what several sessions downloaded is left with the same four
//! blocks each time. Fresh random decoys would fall away under that
//! intersection, until only the needed block stayed.
//!
//! The bucket at the tip is not complete yet, so its decoys could not be
//! drawn from what it will hold. A block needed there brings the whole
//! bucket so far.

use super::*;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Heights per bucket: a day of blocks at ten minutes each.
pub(crate) const BUCKET: u32 = 144;

const SEED_FILE: &str = "decoys.seed";

/// The data folder's decoy seed, made the first time and kept.
pub(crate) fn load_seed(dir: &Path) -> std::io::Result<[u8; 32]> {
    let path = dir.join(SEED_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            return bytes.try_into().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} does not hold 32 bytes", path.display()),
                )
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut seed = [0u8; 32];
    rand::thread_rng().fill(&mut seed);
    let temporary = dir.join(format!("{SEED_FILE}.new"));
    std::fs::write(&temporary, seed)?;
    std::fs::rename(&temporary, &path)?;
    Ok(seed)
}

/// The heights downloaded when the block at `height` is needed: the block
/// and `count` decoys from its bucket, in height order. A bucket that
/// reaches past `tip` is downloaded whole, up to the tip.
pub(crate) fn covered(seed: &[u8; 32], height: u32, count: usize, tip: u32) -> Vec<u32> {
    if count == 0 || height > tip {
        return vec![height];
    }
    let start = height - height % BUCKET;
    let end = start.saturating_add(BUCKET - 1);
    if end > tip || count >= (BUCKET - 1) as usize {
        return (start..=end.min(tip)).collect();
    }
    let mut out = vec![height];
    let mut draw: u32 = 0;
    while out.len() <= count {
        let digest = Sha256::new()
            .chain_update(seed)
            .chain_update(height.to_le_bytes())
            .chain_update(draw.to_le_bytes())
            .finalize();
        let value = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
        let pick = start + (value % u64::from(BUCKET)) as u32;
        if !out.contains(&pick) {
            out.push(pick);
        }
        draw += 1;
    }
    out.sort_unstable();
    out
}

/// The heights to download for blocks needed at `needed`, with the cover of each.
pub(crate) fn cover_of(inner: &Inner, needed: impl IntoIterator<Item = u32>) -> BTreeSet<u32> {
    let tip = inner.chain.read().expect("chain lock").tip_height();
    needed
        .into_iter()
        .flat_map(|h| covered(&inner.seed, h, inner.config.decoy_blocks, tip))
        .collect()
}

/// Downloads the blocks at `heights` in height order, a few at a time, and
/// hands each to `each` in that order.
pub(crate) async fn download_in_order(
    inner: &Arc<Inner>,
    heights: impl IntoIterator<Item = u32>,
    mut each: impl FnMut(u32, Arc<Block>) -> Result<()>,
) -> Result<()> {
    let mut queue: VecDeque<(u32, JoinHandle<Result<Arc<Block>>>)> = VecDeque::new();
    let mut order = heights.into_iter();
    let ahead = inner.config.parallel_downloads.max(1) * 2;
    loop {
        while queue.len() < ahead {
            let Some(height) = order.next() else { break };
            let task_inner = inner.clone();
            queue.push_back((
                height,
                tokio::spawn(async move { block_at(&task_inner, height).await }),
            ));
        }
        let Some((height, task)) = queue.pop_front() else {
            return Ok(());
        };
        let block = task
            .await
            .map_err(|e| Error::new(ErrorKind::Stopped, e.to_string()))??;
        each(height, block)?;
    }
}

/// The blocks at `heights`, in height order, downloaded with their cover.
pub(crate) async fn blocks_with_cover(
    inner: &Arc<Inner>,
    heights: &[u32],
) -> Result<Vec<(u32, Arc<Block>)>> {
    let needed: HashSet<u32> = heights.iter().copied().collect();
    let mut out = Vec::with_capacity(needed.len());
    download_in_order(
        inner,
        cover_of(inner, heights.iter().copied()),
        |height, block| {
            if needed.contains(&height) {
                out.push((height, block));
            }
            Ok(())
        },
    )
    .await?;
    Ok(out)
}

/// The block at `height`, downloaded with its cover.
pub(crate) async fn block_with_cover(inner: &Arc<Inner>, height: u32) -> Result<Arc<Block>> {
    blocks_with_cover(inner, &[height])
        .await?
        .pop()
        .map(|(_, block)| block)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no block at height {height}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoys_are_derived_from_the_seed_within_the_bucket() {
        let seed = [7u8; 32];
        let tip = 10_000;
        let picked = covered(&seed, 1_000, 3, tip);
        assert_eq!(picked.len(), 4);
        assert!(picked.contains(&1_000));
        assert!(
            picked.iter().all(|h| (864..1_008).contains(h)),
            "{picked:?}"
        );
        // The same seed and block give the same decoys; another seed others.
        assert_eq!(covered(&seed, 1_000, 3, tip), picked);
        assert_ne!(covered(&[8u8; 32], 1_000, 3, tip), picked);
        // Another block of the same bucket has decoys of its own.
        assert_ne!(covered(&seed, 1_001, 3, tip), picked);
        // No decoys asked for: the block alone.
        assert_eq!(covered(&seed, 1_000, 0, tip), vec![1_000]);
    }

    #[test]
    fn the_bucket_at_the_tip_is_taken_whole() {
        let seed = [7u8; 32];
        // Bucket 9,936..=10,079 reaches past the tip.
        assert_eq!(
            covered(&seed, 9_950, 3, 10_000),
            (9_936..=10_000).collect::<Vec<u32>>()
        );
        // Complete once the tip reaches its last height.
        assert_eq!(covered(&seed, 9_950, 3, 10_079).len(), 4);
    }

    #[test]
    fn a_seed_is_made_once_and_kept() {
        let dir =
            std::env::temp_dir().join(format!("bch-light-client-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let first = load_seed(&dir).unwrap();
        assert_eq!(load_seed(&dir).unwrap(), first);
        std::fs::write(dir.join(SEED_FILE), [1u8; 5]).unwrap();
        assert!(load_seed(&dir).is_err(), "a damaged seed is not replaced");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
