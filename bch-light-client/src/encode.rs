//! Byte readers and writers for the Bitcoin Cash serialization format.

/// A message or structure that does not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("data ends early")]
    UnexpectedEnd,
    #[error("{0} trailing bytes")]
    TrailingBytes(usize),
    #[error("count {count} exceeds what the data can hold")]
    CountTooLarge { count: u64 },
    #[error("non-canonical compact size")]
    NonCanonicalSize,
    #[error("{0}")]
    Invalid(&'static str),
}

/// Reads a byte slice front to back; every read past the end fails.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// The position of the next read.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The bytes from `start` up to the current position.
    pub fn since(&self, start: usize) -> &'a [u8] {
        &self.data[start..self.pos]
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::UnexpectedEnd);
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    /// A compact size (varint), refusing non-canonical encodings.
    pub fn compact_size(&mut self) -> Result<u64, DecodeError> {
        let first = self.u8()?;
        let (value, min) = match first {
            0xfd => (u64::from(self.u16()?), 0xfd),
            0xfe => (u64::from(self.u32()?), 0x1_0000),
            0xff => (self.u64()?, 0x1_0000_0000),
            n => return Ok(u64::from(n)),
        };
        if value < min {
            return Err(DecodeError::NonCanonicalSize);
        }
        Ok(value)
    }

    /// A count of items of at least `min_size` bytes each, refused when they cannot fit.
    pub fn count(&mut self, min_size: usize) -> Result<usize, DecodeError> {
        let count = self.compact_size()?;
        let fits = usize::try_from(count)
            .ok()
            .filter(|n| n.saturating_mul(min_size.max(1)) <= self.remaining());
        fits.ok_or(DecodeError::CountTooLarge { count })
    }

    /// A length-prefixed byte string.
    pub fn var_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.count(1)?;
        self.bytes(n)
    }

    /// Fails when bytes are left over.
    pub fn finish(&self) -> Result<(), DecodeError> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(DecodeError::TrailingBytes(n)),
        }
    }
}

/// Appends serialized values to a byte vector.
pub trait WriteExt {
    fn put_u8(&mut self, v: u8);
    fn put_u16(&mut self, v: u16);
    fn put_u32(&mut self, v: u32);
    fn put_i32(&mut self, v: i32);
    fn put_u64(&mut self, v: u64);
    fn put_i64(&mut self, v: i64);
    fn put_compact_size(&mut self, v: u64);
    fn put_bytes(&mut self, b: &[u8]);
    fn put_var_bytes(&mut self, b: &[u8]);
}

impl WriteExt for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v);
    }
    fn put_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_i32(&mut self, v: i32) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u64(&mut self, v: u64) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_i64(&mut self, v: i64) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_compact_size(&mut self, v: u64) {
        match v {
            0..=0xfc => self.push(v as u8),
            0xfd..=0xffff => {
                self.push(0xfd);
                self.put_u16(v as u16);
            }
            0x1_0000..=0xffff_ffff => {
                self.push(0xfe);
                self.put_u32(v as u32);
            }
            _ => {
                self.push(0xff);
                self.put_u64(v);
            }
        }
    }
    fn put_bytes(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
    }
    fn put_var_bytes(&mut self, b: &[u8]) {
        self.put_compact_size(b.len() as u64);
        self.extend_from_slice(b);
    }
}

/// The serialized size of a compact size.
pub fn compact_size_len(v: u64) -> usize {
    match v {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_sizes_round_trip_and_refuse_non_canonical() {
        for v in [0u64, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000] {
            let mut b = Vec::new();
            b.put_compact_size(v);
            assert_eq!(b.len(), compact_size_len(v));
            let mut r = Reader::new(&b);
            assert_eq!(r.compact_size().unwrap(), v);
            r.finish().unwrap();
        }
        assert_eq!(Reader::new(&[0xfd, 0x10, 0x00]).compact_size(), Err(DecodeError::NonCanonicalSize));
        assert!(Reader::new(&[0x05, 1, 2]).var_bytes().is_err());
    }
}
