//! Prefixed integers (RFC 7541 5.1) and string literals (RFC 7541 5.2,
//! with QPACK's variable prefix sizes, RFC 9204 4.1).

use super::huffman;

/// Why a primitive could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveError {
    /// More input is needed (only meaningful on the encoder and decoder
    /// streams, where instructions can be split across reads).
    Incomplete,
    /// The input is invalid.
    Invalid(&'static str),
}

/// Largest integer accepted (QUIC varint range, 2^62 - 1).
pub const MAX_INT: u64 = (1 << 62) - 1;

/// Decodes an integer whose first `prefix` (1..=8) bits are the low bits of
/// `buf[0]`; returns the value and the bytes consumed.
pub fn decode_int(buf: &[u8], prefix: u8) -> Result<(u64, usize), PrimitiveError> {
    if !(1..=8).contains(&prefix) {
        return Err(PrimitiveError::Invalid("prefix size"));
    }
    let first = *buf.first().ok_or(PrimitiveError::Incomplete)?;
    let max_prefix = (1u16 << prefix) - 1;
    let mut value = u64::from(first) & u64::from(max_prefix);
    if value < u64::from(max_prefix) {
        return Ok((value, 1));
    }
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate().skip(1) {
        let add = u64::from(b & 0x7f);
        if shift > 56 || (add << shift) >> shift != add {
            return Err(PrimitiveError::Invalid("integer overflow"));
        }
        value = value
            .checked_add(add << shift)
            .filter(|v| *v <= MAX_INT)
            .ok_or(PrimitiveError::Invalid("integer overflow"))?;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(PrimitiveError::Incomplete)
}

/// Appends `value` with a `prefix`-bit prefix (1..=8); `flags` supplies the
/// bits above the prefix in the first byte.
pub fn encode_int(out: &mut Vec<u8>, flags: u8, prefix: u8, value: u64) {
    let prefix = prefix.clamp(1, 8);
    let max_prefix = (1u16 << prefix) - 1;
    let flags = if prefix == 8 {
        0
    } else {
        flags & !(max_prefix as u8)
    };
    if value < u64::from(max_prefix) {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max_prefix as u8);
    let mut rest = value - u64::from(max_prefix);
    while rest >= 0x80 {
        out.push(0x80 | (rest & 0x7f) as u8);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// Decodes a string literal whose Huffman flag is the bit just above a
/// `prefix`-bit length (so `prefix` is 1..=7). Lengths above `max_len`
/// (before or after Huffman decoding) are invalid. Returns the string and
/// the bytes consumed.
pub fn decode_str(
    buf: &[u8],
    prefix: u8,
    max_len: usize,
) -> Result<(Vec<u8>, usize), PrimitiveError> {
    if !(1..=7).contains(&prefix) {
        return Err(PrimitiveError::Invalid("prefix size"));
    }
    let first = *buf.first().ok_or(PrimitiveError::Incomplete)?;
    let huff = first & (1 << prefix) != 0;
    let (len, n) = decode_int(buf, prefix)?;
    if len > max_len as u64 {
        return Err(PrimitiveError::Invalid("string literal too long"));
    }
    let end = n + len as usize;
    let raw = buf.get(n..end).ok_or(PrimitiveError::Incomplete)?;
    if !huff {
        return Ok((raw.to_vec(), end));
    }
    let mut s = Vec::with_capacity(raw.len() * 8 / 5);
    huffman::decode(raw, &mut s).map_err(PrimitiveError::Invalid)?;
    if s.len() > max_len {
        return Err(PrimitiveError::Invalid("string literal too long"));
    }
    Ok((s, end))
}

/// Appends a string literal with a `prefix`-bit length (1..=7) and the
/// Huffman flag just above it; `flags` supplies the bits above that.
/// Huffman coding is used when it is strictly shorter.
pub fn encode_str(out: &mut Vec<u8>, flags: u8, prefix: u8, s: &[u8]) {
    let prefix = prefix.clamp(1, 7);
    let h = 1u8 << prefix;
    let hlen = huffman::encoded_len(s);
    if hlen < s.len() {
        encode_int(out, (flags & !(h | (h - 1))) | h, prefix, hlen as u64);
        huffman::encode(s, out);
    } else {
        encode_int(out, flags & !(h | (h - 1)), prefix, s.len() as u64);
        out.extend_from_slice(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(flags: u8, prefix: u8, v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_int(&mut out, flags, prefix, v);
        out
    }

    /// RFC 7541 C.1.1 - C.1.3.
    #[test]
    fn rfc7541_integer_examples() {
        assert_eq!(int(0, 5, 10), [0x0a]);
        assert_eq!(decode_int(&[0x0a], 5), Ok((10, 1)));
        assert_eq!(int(0, 5, 1337), [0x1f, 0x9a, 0x0a]);
        assert_eq!(decode_int(&[0x1f, 0x9a, 0x0a], 5), Ok((1337, 3)));
        assert_eq!(int(0, 8, 42), [0x2a]);
        assert_eq!(decode_int(&[0x2a], 8), Ok((42, 1)));
        // Flag bits above the prefix are kept and ignored on decode.
        assert_eq!(int(0xe0, 5, 10), [0xea]);
        assert_eq!(decode_int(&[0xea], 5), Ok((10, 1)));
    }

    #[test]
    fn integer_edges() {
        assert_eq!(
            decode_int(&[0x1f, 0x9a], 5),
            Err(PrimitiveError::Incomplete)
        );
        assert_eq!(decode_int(&[], 5), Err(PrimitiveError::Incomplete));
        // Exactly the prefix maximum needs a zero continuation byte.
        assert_eq!(int(0, 5, 31), [0x1f, 0x00]);
        assert_eq!(decode_int(&[0x1f, 0x00], 5), Ok((31, 2)));
        assert_eq!(int(0, 3, MAX_INT).len(), 10);
        let big = int(0, 3, MAX_INT);
        assert_eq!(decode_int(&big, 3), Ok((MAX_INT, big.len())));
        let mut over = vec![0x07];
        over.extend([0xff; 9]);
        over.push(0x7f);
        assert!(matches!(
            decode_int(&over, 3),
            Err(PrimitiveError::Invalid(_))
        ));
        assert_eq!(
            decode_int(&int(0, 3, MAX_INT + 1), 3),
            Err(PrimitiveError::Invalid("integer overflow"))
        );
    }

    #[test]
    fn strings() {
        let mut out = Vec::new();
        encode_str(&mut out, 0, 7, b"www.example.com");
        // RFC 7541 C.4.1: Huffman, 12 bytes.
        assert_eq!(out[0], 0x8c);
        assert_eq!(
            decode_str(&out, 7, 100),
            Ok((b"www.example.com".to_vec(), 13))
        );
        assert!(matches!(
            decode_str(&out, 7, 14),
            Err(PrimitiveError::Invalid(_))
        ));
        assert_eq!(
            decode_str(&out[..5], 7, 100),
            Err(PrimitiveError::Incomplete)
        );
        // Not shorter with Huffman: raw.
        let mut out = Vec::new();
        encode_str(&mut out, 0x40, 3, b"\x00\x01");
        assert_eq!(out, [0x42, 0, 1]);
        assert_eq!(decode_str(&out, 3, 10), Ok((vec![0, 1], 3)));
    }
}
