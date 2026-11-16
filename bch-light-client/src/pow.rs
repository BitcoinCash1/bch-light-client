//! Proof of work: 256-bit targets, work, and the Bitcoin Cash difficulty
//! rules: the original 2016-block retarget, the emergency adjustment of
//! 2017, the 144-block DAA of 2017-2020, and aserti3-2d since November 2020.

use crate::params::Params;
use std::cmp::Ordering;

/// An unsigned 256-bit integer, little-endian 64-bit limbs.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    pub const MAX: Self = Self([u64::MAX; 4]);

    pub fn from_u128(v: u128) -> Self {
        Self([v as u64, (v >> 64) as u64, 0, 0])
    }

    /// From 32 little-endian bytes, as a block hash is stored.
    pub fn from_le_bytes(b: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            *limb = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        }
        Self(limbs)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    /// The number of significant bits.
    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    /// The low 128 bits, or `u128::MAX` when the value does not fit.
    pub fn saturating_u128(&self) -> u128 {
        if self.0[2] != 0 || self.0[3] != 0 {
            return u128::MAX;
        }
        u128::from(self.0[0]) | (u128::from(self.0[1]) << 64)
    }

    pub fn low_u64(&self) -> u64 {
        self.0[0]
    }

    pub fn overflowing_add(self, other: Self) -> (Self, bool) {
        let mut out = [0u64; 4];
        let mut carry = false;
        for (i, limb) in out.iter_mut().enumerate() {
            let (s1, c1) = self.0[i].overflowing_add(other.0[i]);
            let (s2, c2) = s1.overflowing_add(u64::from(carry));
            *limb = s2;
            carry = c1 || c2;
        }
        (Self(out), carry)
    }

    pub fn wrapping_sub(self, other: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for (i, limb) in out.iter_mut().enumerate() {
            let (d1, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            *limb = d2;
            borrow = b1 || b2;
        }
        Self(out)
    }

    /// `self * m`, or `None` on overflow.
    pub fn checked_mul_u64(self, m: u64) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, limb) in out.iter_mut().enumerate() {
            let p = u128::from(self.0[i]) * u128::from(m) + carry;
            *limb = p as u64;
            carry = p >> 64;
        }
        (carry == 0).then_some(Self(out))
    }

    /// `self << n`, or `None` when bits are shifted out.
    pub fn checked_shl(self, n: u32) -> Option<Self> {
        if n == 0 {
            return Some(self);
        }
        if self.is_zero() {
            return Some(self);
        }
        if self.bits() + n > 256 {
            return None;
        }
        Some(self.shl(n))
    }

    fn shl(self, n: u32) -> Self {
        let mut out = [0u64; 4];
        let words = (n / 64) as usize;
        let rem = n % 64;
        for i in (words..4).rev() {
            let src = i - words;
            out[i] = self.0[src] << rem;
            if rem > 0 && src > 0 {
                out[i] |= self.0[src - 1] >> (64 - rem);
            }
        }
        Self(out)
    }

    pub fn shr(self, n: u32) -> Self {
        if n >= 256 {
            return Self::ZERO;
        }
        let mut out = [0u64; 4];
        let words = (n / 64) as usize;
        let rem = n % 64;
        for (i, limb) in out.iter_mut().enumerate().take(4 - words) {
            let src = i + words;
            *limb = self.0[src] >> rem;
            if rem > 0 && src + 1 < 4 {
                *limb |= self.0[src + 1] << (64 - rem);
            }
        }
        Self(out)
    }

    fn not(self) -> Self {
        Self([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    fn set_bit(&mut self, n: u32) {
        self.0[(n / 64) as usize] |= 1 << (n % 64);
    }

    /// Integer division; panics on division by zero, a caller's bug.
    pub fn div(self, divisor: Self) -> Self {
        assert!(!divisor.is_zero(), "U256 division by zero");
        if self < divisor {
            return Self::ZERO;
        }
        let shift = self.bits() - divisor.bits();
        let mut rem = self;
        let mut quotient = Self::ZERO;
        let mut d = divisor.shl(shift);
        for i in (0..=shift).rev() {
            if rem >= d {
                rem = rem.wrapping_sub(d);
                quotient.set_bit(i);
            }
            d = d.shr(1);
        }
        quotient
    }

    pub fn div_u64(self, divisor: u64) -> Self {
        self.div(Self([divisor, 0, 0, 0]))
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}

/// A compact target: its value, and whether it is negative or overflows.
pub fn compact_to_target(bits: u32) -> (U256, bool, bool) {
    let exponent = bits >> 24;
    let mut mantissa = bits & 0x007f_ffff;
    let value = if exponent <= 3 {
        mantissa >>= 8 * (3 - exponent);
        U256::from_u128(u128::from(mantissa))
    } else {
        U256::from_u128(u128::from(mantissa)).shl(8 * (exponent - 3).min(32))
    };
    let negative = mantissa != 0 && bits & 0x0080_0000 != 0;
    let overflow = mantissa != 0
        && (exponent > 34 || (mantissa > 0xff && exponent > 33) || (mantissa > 0xffff && exponent > 32));
    (value, negative, overflow)
}

/// The compact form of a non-negative target.
pub fn target_to_compact(target: U256) -> u32 {
    let mut size = target.bits().div_ceil(8);
    let mut compact = if size <= 3 {
        (target.low_u64() << (8 * (3 - size))) as u32
    } else {
        target.shr(8 * (size - 3)).low_u64() as u32
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact | (size << 24)
}

/// Whether a block hash meets the target its bits encode.
pub fn meets_target(hash: &[u8; 32], bits: u32, pow_limit: U256) -> bool {
    let (target, negative, overflow) = compact_to_target(bits);
    !negative && !overflow && !target.is_zero() && target <= pow_limit && U256::from_le_bytes(hash) <= target
}

/// The expected number of hashes for a block of these bits: 2^256 / (target + 1).
pub fn work(bits: u32) -> u128 {
    let (target, negative, overflow) = compact_to_target(bits);
    if negative || overflow || target.is_zero() {
        return 0;
    }
    // 2^256 / (t + 1) = ~t / (t + 1) + 1, which stays within 256 bits.
    let (plus_one, carry) = target.overflowing_add(U256::ONE);
    if carry {
        return 1;
    }
    target.not().div(plus_one).saturating_u128().saturating_add(1)
}

/// What the difficulty rules need from the chain a new header extends.
pub trait ChainView {
    /// Timestamp of the header at `height`.
    fn time_at(&self, height: u32) -> u32;
    /// Compact target of the header at `height`.
    fn bits_at(&self, height: u32) -> u32;
    /// Total work of the chain up to and including `height`.
    fn chainwork_at(&self, height: u32) -> u128;

    /// Median of the timestamps of the 11 headers ending at `height`.
    fn median_time_past(&self, height: u32) -> u32 {
        let start = height.saturating_sub(10);
        let mut times: Vec<u32> = (start..=height).map(|h| self.time_at(h)).collect();
        times.sort_unstable();
        times[times.len() / 2]
    }
}

/// A difficulty rule a header breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("header at height {height} has bits {got:08x}, the rules require {expected:08x}")]
pub struct BadBits {
    pub height: u32,
    pub got: u32,
    pub expected: u32,
}

const RETARGET_INTERVAL: u32 = 2016;
const TARGET_TIMESPAN: i64 = 14 * 24 * 60 * 60;
const TARGET_SPACING: i64 = 600;
const DAA_WINDOW: u32 = 144;
const RADIX: i64 = 65536;
const RBITS: u32 = 16;

/// The bits the header after `prev` (at `prev` height) must carry, given its time.
pub fn required_bits(params: &Params, chain: &impl ChainView, prev: u32, new_time: u32) -> u32 {
    if params.no_difficulty_adjustment {
        return chain.bits_at(prev);
    }
    let height = prev + 1;
    if height > params.asert_activation_height {
        asert_bits(params, chain, prev, new_time)
    } else if height > params.daa_height {
        daa_bits(params, chain, prev, new_time)
    } else {
        legacy_bits(params, chain, prev, new_time, height > params.uahf_height)
    }
}

fn min_difficulty_applies(params: &Params, chain: &impl ChainView, prev: u32, new_time: u32) -> bool {
    params.reduce_min_difficulty && i64::from(new_time) > i64::from(chain.time_at(prev)) + 2 * TARGET_SPACING
}

/// aserti3-2d: the target follows the anchor block's exponentially, by how far
/// the chain is ahead of or behind its ideal schedule.
pub fn asert_target(
    pow_limit: U256,
    anchor_bits: u32,
    anchor_height: i64,
    anchor_parent_time: i64,
    half_life: i64,
    prev_height: i64,
    prev_time: i64,
) -> U256 {
    let time_delta = prev_time - anchor_parent_time;
    let height_delta = prev_height - anchor_height;
    let exponent = ((time_delta - TARGET_SPACING * (height_delta + 1)) * RADIX) / half_life;
    let shifts = exponent >> RBITS;
    let frac = (exponent - shifts * RADIX) as u128;
    let factor = (195_766_423_245_049u128 * frac
        + 971_821_376u128 * frac * frac
        + 5127u128 * frac * frac * frac
        + (1u128 << 47))
        >> (RBITS * 3);
    let (anchor, _, _) = compact_to_target(anchor_bits);
    let scaled = anchor.checked_mul_u64(RADIX as u64 + factor as u64);
    let shifted = scaled.and_then(|t| {
        if shifts < 0 {
            Some(t.shr(u32::try_from(-shifts).unwrap_or(u32::MAX)))
        } else {
            t.checked_shl(u32::try_from(shifts).unwrap_or(u32::MAX))
        }
    });
    match shifted.map(|t| t.shr(RBITS)) {
        Some(t) if t.is_zero() => U256::ONE,
        Some(t) if t <= pow_limit => t,
        _ => pow_limit,
    }
}

fn asert_bits(params: &Params, chain: &impl ChainView, prev: u32, new_time: u32) -> u32 {
    if min_difficulty_applies(params, chain, prev, new_time) {
        return params.pow_limit_bits;
    }
    let target = asert_target(
        params.pow_limit(),
        params.asert_anchor_bits,
        i64::from(params.asert_anchor_height),
        params.asert_anchor_parent_time,
        params.asert_half_life,
        i64::from(prev),
        i64::from(chain.time_at(prev)),
    );
    target_to_compact(target)
}

/// The median-time block of the three ending at `height`.
fn suitable_block(chain: &impl ChainView, height: u32) -> u32 {
    let mut blocks = [height - 2, height - 1, height];
    blocks.sort_by_key(|&h| chain.time_at(h));
    blocks[1]
}

fn daa_bits(params: &Params, chain: &impl ChainView, prev: u32, new_time: u32) -> u32 {
    if min_difficulty_applies(params, chain, prev, new_time) {
        return params.pow_limit_bits;
    }
    let last = suitable_block(chain, prev);
    let first = suitable_block(chain, prev - DAA_WINDOW);
    let work = chain.chainwork_at(last) - chain.chainwork_at(first);
    let duration = (i64::from(chain.time_at(last)) - i64::from(chain.time_at(first)))
        .clamp(72 * TARGET_SPACING, 288 * TARGET_SPACING);
    let projected = work.saturating_mul(TARGET_SPACING as u128) / duration as u128;
    if projected == 0 {
        return params.pow_limit_bits;
    }
    let pw = U256::from_u128(projected);
    // (2^256 - pw) / pw
    let target = U256::ZERO.wrapping_sub(pw).div(pw);
    target_to_compact(target.min(params.pow_limit()))
}

fn legacy_bits(params: &Params, chain: &impl ChainView, prev: u32, new_time: u32, eda: bool) -> u32 {
    let height = prev + 1;
    if height % RETARGET_INTERVAL != 0 {
        if params.reduce_min_difficulty {
            if min_difficulty_applies(params, chain, prev, new_time) {
                return params.pow_limit_bits;
            }
            // The last block that did not use the minimum difficulty rule.
            let mut h = prev;
            while h > 0 && h % RETARGET_INTERVAL != 0 && chain.bits_at(h) == params.pow_limit_bits {
                h -= 1;
            }
            return chain.bits_at(h);
        }
        if eda {
            let (old, _, _) = compact_to_target(chain.bits_at(prev));
            if old == params.pow_limit() {
                return params.pow_limit_bits;
            }
            let mtp_span = i64::from(chain.median_time_past(prev))
                - i64::from(chain.median_time_past(prev.saturating_sub(6)));
            if mtp_span >= 12 * 3600 {
                let (raised, carry) = old.overflowing_add(old.shr(2));
                let limit = params.pow_limit();
                return if carry || raised > limit { params.pow_limit_bits } else { target_to_compact(raised) };
            }
        }
        return chain.bits_at(prev);
    }
    let first = prev + 1 - RETARGET_INTERVAL;
    let actual = i64::from(chain.time_at(prev)) - i64::from(chain.time_at(first));
    let adjusted = actual.clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4);
    let (old, _, _) = compact_to_target(chain.bits_at(prev));
    let target = old
        .checked_mul_u64(adjusted as u64)
        .map(|t| t.div_u64(TARGET_TIMESPAN as u64))
        .unwrap_or(U256::MAX);
    target_to_compact(target.min(params.pow_limit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_round_trips() {
        for bits in [0x1d00ffffu32, 0x1804dafe, 0x207fffff, 0x1a2b3c4d, 0x01010000, 0x13647d71] {
            let (t, neg, ovf) = compact_to_target(bits);
            assert!(!neg && !ovf);
            assert_eq!(target_to_compact(t), bits, "{bits:08x}");
        }
        // 0x01010000 is 1: re-encoding gives the canonical 0x01010000.
        assert_eq!(compact_to_target(0x0101_0000).0, U256::ONE);
    }

    #[test]
    fn work_of_known_targets() {
        // Mainnet's minimum difficulty: 2^256 / (0xffff * 2^208 + 1) = 4295032833.
        assert_eq!(work(0x1d00ffff), 4_295_032_833);
        // Regtest: (2^256) / (0x7fffff * 2^232 + 1) = 2.
        assert_eq!(work(0x207fffff), 2);
        assert_eq!(work(10_000_000), 0);
    }

    #[test]
    fn division_matches_u128() {
        let cases = [(u128::MAX, 3u128), (12345678901234567890123456789, 987654321), (5, 7), (1 << 100, 1 << 37)];
        for (a, b) in cases {
            assert_eq!(U256::from_u128(a).div(U256::from_u128(b)).saturating_u128(), a / b);
        }
    }

    #[test]
    fn asert_matches_the_reference_vectors() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/asert-vectors.txt"))
            .expect("asert vectors");
        let pow_limit = compact_to_target(0x1d00ffff).0;
        let mut anchor = (0i32, 0i64, 0u32);
        let mut checked = 0;
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let hex_bits = |s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
            // The reference keeps heights in 32-bit integers that wrap; only
            // the height difference matters, so it is taken the same way.
            let as_i32 = |s: &str| s.parse::<u64>().unwrap() as i32;
            if parts[0] == "run" {
                anchor = (as_i32(parts[2]), parts[3].parse().unwrap(), hex_bits(parts[4]));
                continue;
            }
            let height = as_i32(parts[0]);
            let time: i64 = parts[1].parse().unwrap();
            let expected = hex_bits(parts[2]);
            let delta = i64::from(height.wrapping_sub(anchor.0));
            let target = asert_target(pow_limit, anchor.2, 0, anchor.1, 2 * 24 * 3600, delta, time);
            assert_eq!(target_to_compact(target), expected, "height {height} time {time}");
            checked += 1;
        }
        assert!(checked > 10_000);
    }
}
