//! Byte cursor types with QUIC varint support (RFC 9000 Section 16).

use crate::{Result, WireError, MAX_VARINT};

/// A read cursor over a borrowed byte slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader positioned at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }
    /// Bytes remaining.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    /// Returns the unread suffix without consuming it.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
    /// Reads `n` bytes as a borrowed slice.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(WireError::BufferTooShort);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    /// Reads one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    /// Peeks one byte without consuming it.
    pub fn peek_u8(&self) -> Result<u8> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or(WireError::BufferTooShort)
    }
    /// Reads a big-endian integer of `n` (<= 8) bytes.
    pub fn uint(&mut self, n: usize) -> Result<u64> {
        let b = self.bytes(n)?;
        Ok(b.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x)))
    }
    /// Reads a big-endian u32.
    pub fn u32(&mut self) -> Result<u32> {
        // A 4-byte read always fits in u32.
        Ok(self.uint(4)? as u32)
    }
    /// Reads a QUIC variable-length integer.
    pub fn varint(&mut self) -> Result<u64> {
        let first = self.peek_u8()?;
        let len = 1usize << (first >> 6);
        let b = self.bytes(len)?;
        let mut v = u64::from(b[0] & 0x3f);
        for &x in &b[1..] {
            v = (v << 8) | u64::from(x);
        }
        Ok(v)
    }
    /// Reads a varint length prefix followed by that many bytes.
    pub fn vbytes(&mut self) -> Result<&'a [u8]> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| WireError::BufferTooShort)?;
        self.bytes(n)
    }
}

/// A write cursor over a borrowed mutable byte slice.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Creates a writer positioned at the start of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    /// Bytes written so far.
    pub fn position(&self) -> usize {
        self.pos
    }
    /// Space left.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    /// Returns the written prefix.
    pub fn written(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
    /// Writes raw bytes.
    pub fn put(&mut self, data: &[u8]) -> Result<()> {
        if self.remaining() < data.len() {
            return Err(WireError::BufferFull);
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }
    /// Writes one byte.
    pub fn u8(&mut self, v: u8) -> Result<()> {
        self.put(&[v])
    }
    /// Writes the low `n` bytes of `v` big-endian.
    pub fn uint(&mut self, v: u64, n: usize) -> Result<()> {
        let be = v.to_be_bytes();
        self.put(&be[8 - n..])
    }
    /// Writes a varint using the shortest encoding.
    pub fn varint(&mut self, v: u64) -> Result<()> {
        let len = varint_len(v)?;
        self.varint_with_len(v, len)
    }
    /// Writes a varint using exactly `len` (1, 2, 4 or 8) bytes.
    pub fn varint_with_len(&mut self, v: u64, len: usize) -> Result<()> {
        if v > MAX_VARINT || varint_len(v)? > len {
            return Err(WireError::VarintRange);
        }
        let tag: u64 = match len {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => return Err(WireError::VarintRange),
        };
        self.uint(v | (tag << (len * 8 - 2)), len)
    }
    /// Writes a varint length prefix followed by `data`.
    pub fn vbytes(&mut self, data: &[u8]) -> Result<()> {
        self.varint(data.len() as u64)?;
        self.put(data)
    }
}

/// Number of bytes the shortest encoding of `v` takes.
pub fn varint_len(v: u64) -> Result<usize> {
    Ok(match v {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1_073_741_823 => 4,
        1_073_741_824..=MAX_VARINT => 8,
        _ => return Err(WireError::VarintRange),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rfc9000_appendix_a1_examples() {
        let cases: [(&[u8], u64); 4] = [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for (bytes, v) in cases {
            assert_eq!(Reader::new(bytes).varint().unwrap(), v);
            let mut out = [0u8; 8];
            let mut w = Writer::new(&mut out);
            w.varint(v).unwrap();
            assert_eq!(w.written(), bytes);
        }
        // Non-minimal two-byte encoding of 37.
        assert_eq!(Reader::new(&[0x40, 0x25]).varint().unwrap(), 37);
    }

    #[test]
    fn out_of_range_rejected() {
        let mut out = [0u8; 8];
        assert_eq!(
            Writer::new(&mut out).varint(MAX_VARINT + 1),
            Err(WireError::VarintRange)
        );
        assert_eq!(
            Reader::new(&[0x80, 0]).varint(),
            Err(WireError::BufferTooShort)
        );
    }

    proptest! {
        #[test]
        fn varint_roundtrip(v in 0..=MAX_VARINT) {
            let mut out = [0u8; 8];
            let mut w = Writer::new(&mut out);
            w.varint(v).unwrap();
            let n = w.position();
            prop_assert_eq!(n, varint_len(v).unwrap());
            let mut r = Reader::new(&out[..n]);
            prop_assert_eq!(r.varint().unwrap(), v);
            prop_assert_eq!(r.remaining(), 0);
        }

        #[test]
        fn varint_decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..10)) {
            let _ = Reader::new(&data).varint();
        }
    }
}
