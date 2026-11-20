//! CashTokens and identities (CHIP-BCMR) without an index. A category's
//! holders and supply come from its unspent outputs, which the category's
//! filter keys (created and spent) find like any watched target's. Its
//! genesis is the transaction that spends output 0 of the transaction whose
//! ID is the category, found in the first block whose filter has the
//! category. An identity's authchain is followed one identity output at a
//! time through the filter keys of that output's script, which every block
//! spending it holds. Blocks are downloaded with the configured decoys, as
//! for histories; nothing names a category or an identity to a peer.

use super::cover::blocks_with_cover;
use super::*;
use crate::bcmr::{self, Publication};
use crate::tx::{Category, Nft, NftCapability};

/// One script's tokens of a category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHolding {
    pub script: Vec<u8>,
    pub fungible: u64,
    pub nfts: Vec<(OutPoint, Nft)>,
}

/// A category's supply, from its unspent outputs (confirmed ones, and those
/// of the mempool copy, less what the mempool copy spends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSupply {
    pub category: Category,
    /// Fungible tokens in unspent outputs, those in provably unspendable
    /// (OP_RETURN) outputs left out.
    pub total: u64,
    /// The part of `total` held in outputs with a minting or mutable NFT.
    pub reserved: u64,
    /// `total` less `reserved`.
    pub circulating: u64,
    pub minting: usize,
    pub mutable: usize,
    pub immutable: usize,
    /// By script, in the order of their first unspent output.
    pub holders: Vec<TokenHolding>,
    /// Blocks up to this height are counted.
    pub height: Option<u32>,
}

/// One category's tokens in a target's unspent outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryBalance {
    pub category: Category,
    pub fungible: u64,
    pub nfts: Vec<(OutPoint, Nft)>,
}

/// An identity's authchain, followed to its authhead.
#[derive(Debug, Clone)]
pub struct Authchain {
    pub authbase: Txid,
    /// The transactions followed after the authbase (or after the point a
    /// resolution resumed from), oldest first, with their heights (None in
    /// the mempool).
    pub steps: Vec<(Txid, Option<u32>)>,
    pub authhead: Transaction,
    /// None while the authhead is in the mempool.
    pub authhead_confirmation: Option<Confirmation>,
    pub identity_output: OutPoint,
    /// Output 0 of the authhead starts with OP_RETURN.
    pub burned: bool,
    /// The authhead's metadata registry publication output.
    pub publication: Option<Publication>,
    /// The authhead's other data-carrier outputs: other identity claims.
    pub claims: Vec<Vec<u8>>,
}

/// A category's supply from its unspent outputs.
pub fn supply_of(category: Category, utxos: &[Utxo], height: Option<u32>) -> TokenSupply {
    let mut supply = TokenSupply {
        category,
        total: 0,
        reserved: 0,
        circulating: 0,
        minting: 0,
        mutable: 0,
        immutable: 0,
        holders: Vec::new(),
        height,
    };
    for utxo in utxos {
        let Some(token) = utxo.token.as_ref().filter(|t| t.category == category) else {
            continue;
        };
        if utxo.script.first() == Some(&0x6a) {
            continue;
        }
        supply.total = supply.total.saturating_add(token.amount);
        if let Some(nft) = &token.nft {
            match nft.capability {
                NftCapability::Minting => supply.minting += 1,
                NftCapability::Mutable => supply.mutable += 1,
                NftCapability::None => supply.immutable += 1,
            }
            if nft.capability != NftCapability::None {
                supply.reserved = supply.reserved.saturating_add(token.amount);
            }
        }
        let holder = match supply
            .holders
            .iter_mut()
            .position(|h| h.script == utxo.script)
        {
            Some(i) => &mut supply.holders[i],
            None => {
                supply.holders.push(TokenHolding {
                    script: utxo.script.clone(),
                    fungible: 0,
                    nfts: Vec::new(),
                });
                supply.holders.last_mut().expect("just pushed")
            }
        };
        holder.fungible = holder.fungible.saturating_add(token.amount);
        if let Some(nft) = &token.nft {
            holder.nfts.push((utxo.outpoint, nft.clone()));
        }
    }
    supply.circulating = supply.total - supply.reserved;
    supply
}

/// A target's tokens by category, in the order of each category's first
/// unspent output.
pub fn balances_of(utxos: &[Utxo]) -> Vec<CategoryBalance> {
    let mut out: Vec<CategoryBalance> = Vec::new();
    for utxo in utxos {
        let Some(token) = &utxo.token else { continue };
        let balance = match out.iter_mut().position(|b| b.category == token.category) {
            Some(i) => &mut out[i],
            None => {
                out.push(CategoryBalance {
                    category: token.category,
                    fungible: 0,
                    nfts: Vec::new(),
                });
                out.last_mut().expect("just pushed")
            }
        };
        balance.fungible = balance.fungible.saturating_add(token.amount);
        if let Some(nft) = &token.nft {
            balance.nfts.push((utxo.outpoint, nft.clone()));
        }
    }
    out
}

const IDENTITIES_FILE: &str = "identities.dat";

/// The latest identity transaction found for each authbase: the wallet's
/// own records, kept to resume resolutions, not an index of the chain.
pub(crate) fn load_identities(dir: &std::path::Path) -> HashMap<Txid, (Txid, u32)> {
    let Ok(text) = std::fs::read_to_string(dir.join(IDENTITIES_FILE)) else {
        return HashMap::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let authbase = Txid::from_hex(parts.next()?).ok()?;
            let latest = Txid::from_hex(parts.next()?).ok()?;
            let height = parts.next()?.parse().ok()?;
            Some((authbase, (latest, height)))
        })
        .collect()
}

fn save_identities(inner: &Inner) {
    let text: String = inner
        .identities
        .lock()
        .expect("identities lock")
        .iter()
        .map(|(base, (latest, height))| format!("{} {} {height}\n", base.to_hex(), latest.to_hex()))
        .collect();
    let path = inner.dir.join(IDENTITIES_FILE);
    let temp = path.with_extension("tmp");
    if std::fs::write(&temp, text)
        .and_then(|_| std::fs::rename(&temp, &path))
        .is_err()
    {
        warn!("identities not saved");
    }
}

impl LightClient {
    /// A target's tokens by category, from its unspent outputs.
    pub async fn token_balances(&self, target: &Target) -> Result<Vec<CategoryBalance>> {
        let utxos = self.unspent(target, TokenFilter::Only).await?;
        Ok(balances_of(&utxos))
    }

    /// A category's supply and holders. The category is watched from then
    /// on, like any target.
    pub async fn token_supply(&self, category: Category) -> Result<TokenSupply> {
        let target = Target::Category(category);
        let utxos = self.unspent(&target, TokenFilter::Include).await?;
        let height = self.history(&target).await?.synced_height;
        Ok(supply_of(category, &utxos, height))
    }

    /// A category's genesis transaction: the one that spends output 0 of
    /// the transaction whose ID is the category and creates its tokens. It
    /// is found in the mempool copy, or in the first block whose filter has
    /// the category, from the filters' start height on.
    pub async fn token_genesis(&self, category: Category) -> Result<TxInfo> {
        let parent = OutPoint::new(Txid(category.0), 0);
        let is_genesis = |tx: &Transaction| {
            tx.inputs.iter().any(|i| i.prevout == parent)
                && tx
                    .outputs
                    .iter()
                    .any(|o| o.token.as_ref().is_some_and(|t| t.category == category))
        };
        {
            let mempool = self.inner.mempool.read().expect("mempool lock");
            if let Some(entry) = mempool.spender(&parent).and_then(|t| mempool.get(&t)) {
                if is_genesis(&entry.tx) {
                    return Ok(TxInfo {
                        tx: entry.tx.clone(),
                        confirmation: None,
                    });
                }
            }
        }
        let base = self.inner.filters.read().expect("filters lock").base();
        let heights = matching_heights(&self.inner, FilterKey::category(&category), base).await?;
        for chunk in heights.chunks(1) {
            for (height, block) in blocks_with_cover(&self.inner, chunk).await? {
                if let Some((position, tx)) =
                    block.txs.iter().enumerate().find(|(_, t)| is_genesis(t))
                {
                    return Ok(TxInfo {
                        tx: tx.clone(),
                        confirmation: Some(Confirmation {
                            height,
                            block_hash: block.hash(),
                            position: position as u32,
                        }),
                    });
                }
            }
        }
        Err(Error::new(
            ErrorKind::NotFound,
            format!("no genesis of category {category} in the blocks from height {base}"),
        ))
    }

    /// Follows an identity's authchain to its authhead, from the last
    /// identity transaction found before for it, or from the authbase
    /// (looked up by ID: give its height when the filters hold no
    /// transaction keys). With `track`, the authhead's identity output is
    /// watched, so that its spend, an update, comes as an event.
    pub async fn resolve_authchain(
        &self,
        authbase: Txid,
        height_hint: Option<u32>,
        track: bool,
    ) -> Result<Authchain> {
        let known = self
            .inner
            .identities
            .lock()
            .expect("identities lock")
            .get(&authbase)
            .copied();
        if let Some((latest, height)) = known {
            if let Ok(info) = self.transaction(latest, Some(height)).await {
                return self.follow(authbase, info, track).await;
            }
        }
        let info = self.transaction(authbase, height_hint).await?;
        self.follow(authbase, info, track).await
    }

    /// Follows an authchain from a registry's `authchain` extension (the
    /// authbase and the transactions after it, serialized): the extension
    /// must start at the authbase and follow output 0, and its last
    /// transaction must be on the chain or in the mempool copy; the chain
    /// is then followed on from there.
    pub async fn resolve_authchain_from(
        &self,
        authbase: Txid,
        extension: &[Vec<u8>],
        track: bool,
    ) -> Result<Authchain> {
        let txs = bcmr::verify_extension(authbase, extension)
            .map_err(|e| Error::with_source(ErrorKind::InvalidData, "authchain extension", e))?;
        let last = txs.last().expect("verified non-empty").txid();
        let info = self.transaction(last, None).await.map_err(|e| {
            Error::with_source(
                ErrorKind::InvalidData,
                "the registry's authchain ends in a transaction this client does not find",
                e,
            )
        })?;
        self.follow(authbase, info, track).await
    }

    async fn follow(&self, authbase: Txid, start: TxInfo, track: bool) -> Result<Authchain> {
        let inner = &self.inner;
        let base = inner.filters.read().expect("filters lock").base();
        let mut current = start.tx;
        let mut confirmation = start.confirmation;
        let mut steps = Vec::new();
        loop {
            if bcmr::burns_identity(&current) {
                break;
            }
            let identity = OutPoint::new(current.txid(), 0);
            let unconfirmed = {
                let mempool = inner.mempool.read().expect("mempool lock");
                mempool
                    .spender(&identity)
                    .and_then(|t| mempool.get(&t))
                    .map(|e| e.tx.clone())
            };
            if let Some(next) = unconfirmed {
                steps.push((next.txid(), None));
                current = next;
                confirmation = None;
                continue;
            }
            let Some(at) = confirmation else { break };
            if at.height < base {
                return Err(Error::new(
                    ErrorKind::Unavailable,
                    format!(
                        "identity output {identity} is at height {}, before the filters start ({base})",
                        at.height
                    ),
                ));
            }
            let script = current.outputs[0].script.clone();
            if !script_is_filtered(&script) {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("identity output {identity} has no locking bytecode to follow"),
                ));
            }
            let heights = matching_heights(inner, FilterKey::script(&script), at.height).await?;
            let mut next = None;
            for (height, block) in blocks_with_cover(inner, &heights).await? {
                if let Some((position, tx)) = block
                    .txs
                    .iter()
                    .enumerate()
                    .find(|(_, t)| t.inputs.iter().any(|i| i.prevout == identity))
                {
                    next = Some((
                        tx.clone(),
                        Confirmation {
                            height,
                            block_hash: block.hash(),
                            position: position as u32,
                        },
                    ));
                    break;
                }
            }
            let Some((tx, at)) = next else { break };
            steps.push((tx.txid(), Some(at.height)));
            current = tx;
            confirmation = Some(at);
        }
        if let Some(at) = confirmation {
            inner
                .identities
                .lock()
                .expect("identities lock")
                .insert(authbase, (current.txid(), at.height));
            save_identities(inner);
        }
        let burned = bcmr::burns_identity(&current);
        if track && !burned {
            self.watch([Target::Script(current.outputs[0].script.clone())])
                .await?;
        }
        let publication = bcmr::tx_publication(&current);
        let claims = current
            .outputs
            .iter()
            .skip(1)
            .filter(|o| {
                o.script.first() == Some(&0x6a) && !o.script.starts_with(&bcmr::PUBLICATION_PREFIX)
            })
            .map(|o| o.script.clone())
            .collect();
        Ok(Authchain {
            authbase,
            steps,
            identity_output: OutPoint::new(current.txid(), 0),
            authhead: current,
            authhead_confirmation: confirmation,
            burned,
            publication,
            claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::TokenData;

    fn utxo(n: u8, script: &[u8], token: Option<TokenData>) -> Utxo {
        Utxo {
            outpoint: OutPoint::new(Txid([n; 32]), 0),
            value: 1000,
            token,
            script: script.to_vec(),
            height: Some(1),
        }
    }

    fn token(category: Category, amount: u64, nft: Option<NftCapability>) -> Option<TokenData> {
        Some(TokenData {
            category,
            amount,
            nft: nft.map(|capability| Nft {
                capability,
                commitment: vec![],
            }),
        })
    }

    #[test]
    fn supply_counts_reserved_and_leaves_out_unspendable_outputs() {
        let c = Category([1; 32]);
        let other = Category([2; 32]);
        let utxos = vec![
            utxo(1, &[0x51], token(c, 1000, Some(NftCapability::Minting))),
            utxo(2, &[0x52], token(c, 300, None)),
            utxo(3, &[0x52], token(c, 0, Some(NftCapability::None))),
            utxo(4, &[0x53], token(c, 50, Some(NftCapability::Mutable))),
            utxo(5, &[0x6a], token(c, 7, None)),
            utxo(6, &[0x52], token(other, 9, None)),
            utxo(7, &[0x52], None),
        ];
        let s = supply_of(c, &utxos, Some(9));
        assert_eq!((s.total, s.reserved, s.circulating), (1350, 1050, 300));
        assert_eq!((s.minting, s.mutable, s.immutable), (1, 1, 1));
        assert_eq!(s.holders.len(), 3);
        assert_eq!(s.holders[1].script, vec![0x52]);
        assert_eq!(s.holders[1].fungible, 300);
        assert_eq!(s.holders[1].nfts.len(), 1);
        let balances = balances_of(&utxos);
        assert_eq!(balances.len(), 2);
        assert_eq!(balances[0].fungible, 1357);
        assert_eq!(balances[1].category, other);
    }
}
