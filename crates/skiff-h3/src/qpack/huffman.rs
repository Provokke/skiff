//! The static Huffman code of RFC 7541 Appendix B (shared by HPACK and
//! QPACK). Decoding walks a binary tree built at compile time from the code
//! table; the build doubles as a static check that the code is a complete
//! prefix code (exactly 256 internal nodes for 257 symbols).

pub use super::huffman_code::CODES;

/// Symbol number of end-of-string.
pub const EOS: usize = 256;

const LEAF: u16 = 0x8000;

/// `TREE[node][bit]` is a child node index, or `LEAF | symbol`.
static TREE: [[u16; 2]; 256] = build_tree();

const fn build_tree() -> [[u16; 2]; 256] {
    let mut t = [[0u16; 2]; 256];
    let mut next = 1usize;
    let mut sym = 0usize;
    while sym < CODES.len() {
        let (code, len) = CODES[sym];
        let mut node = 0usize;
        let mut i = len;
        while i > 0 {
            i -= 1;
            let bit = ((code >> i) & 1) as usize;
            if i == 0 {
                // A leaf may not replace an existing subtree.
                assert!(t[node][bit] == 0, "Huffman code is not prefix-free");
                t[node][bit] = LEAF | sym as u16;
            } else {
                if t[node][bit] == 0 {
                    t[node][bit] = next as u16;
                    next += 1;
                }
                assert!(t[node][bit] & LEAF == 0, "Huffman code is not prefix-free");
                node = t[node][bit] as usize;
            }
        }
        sym += 1;
    }
    assert!(next == 256, "Huffman code is not complete");
    t
}

/// Length in bytes of the Huffman encoding of `s` (padded to a byte).
pub fn encoded_len(s: &[u8]) -> usize {
    let bits: usize = s
        .iter()
        .map(|&b| CODES.get(usize::from(b)).map_or(0, |c| usize::from(c.1)))
        .sum();
    bits.div_ceil(8)
}

/// Appends the Huffman encoding of `s`, padded with the most significant
/// bits of EOS (all ones).
pub fn encode(s: &[u8], out: &mut Vec<u8>) {
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    for &b in s {
        let (code, len) = CODES.get(usize::from(b)).copied().unwrap_or((0, 0));
        acc = (acc << len) | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1u64 << bits) - 1;
    }
    if bits > 0 {
        let pad = 8 - bits;
        out.push(((acc << pad) | ((1u64 << pad) - 1)) as u8);
    }
}

/// Decodes `src`, appending to `out`. Rejects an EOS symbol, padding longer
/// than 7 bits and padding that is not all ones (RFC 7541 5.2).
pub fn decode(src: &[u8], out: &mut Vec<u8>) -> Result<(), &'static str> {
    let mut node = 0usize;
    // Bits consumed since the last complete symbol, and whether all were 1.
    let mut pending = 0u32;
    let mut ones = true;
    for &byte in src {
        for shift in (0..8).rev() {
            let bit = usize::from((byte >> shift) & 1);
            let next = TREE
                .get(node)
                .and_then(|n| n.get(bit))
                .copied()
                .ok_or("Huffman tree")?;
            pending += 1;
            ones &= bit == 1;
            if next & LEAF != 0 {
                let sym = usize::from(next & !LEAF);
                if sym == EOS {
                    return Err("EOS in Huffman string");
                }
                out.push(sym as u8);
                node = 0;
                pending = 0;
                ones = true;
            } else {
                node = usize::from(next);
            }
        }
    }
    if pending > 7 {
        return Err("Huffman padding longer than 7 bits");
    }
    if !ones {
        return Err("Huffman padding is not EOS");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Every Huffman-coded string literal of RFC 7541 C.4 (requests) and
    /// C.6 (responses), both directions.
    #[test]
    fn rfc7541_vectors() {
        let cases: &[(&str, &str)] = &[
            ("www.example.com", "f1e3 c2e5 f23a 6ba0 ab90 f4ff"),
            ("no-cache", "a8eb 1064 9cbf"),
            ("custom-key", "25a8 49e9 5ba9 7d7f"),
            ("custom-value", "25a8 49e9 5bb8 e8b4 bf"),
            ("302", "6402"),
            ("private", "aec3 771a 4b"),
            (
                "Mon, 21 Oct 2013 20:13:21 GMT",
                "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff",
            ),
            (
                "https://www.example.com",
                "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3",
            ),
            ("307", "640e ff"),
            (
                "Mon, 21 Oct 2013 20:13:22 GMT",
                "d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff",
            ),
            ("gzip", "9bd9 ab"),
            (
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
                "94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 \
                 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
            ),
        ];
        for (plain, enc) in cases {
            let enc = hex(enc);
            let mut out = Vec::new();
            encode(plain.as_bytes(), &mut out);
            assert_eq!(out, enc, "encode {plain}");
            assert_eq!(encoded_len(plain.as_bytes()), enc.len());
            let mut dec = Vec::new();
            decode(&enc, &mut dec).unwrap();
            assert_eq!(dec, plain.as_bytes(), "decode {plain}");
        }
    }

    #[test]
    fn every_symbol_roundtrips() {
        let all: Vec<u8> = (0..=255).collect();
        let mut enc = Vec::new();
        encode(&all, &mut enc);
        let mut dec = Vec::new();
        decode(&enc, &mut dec).unwrap();
        assert_eq!(dec, all);
    }

    #[test]
    fn invalid_padding_and_eos() {
        let mut out = Vec::new();
        // '0' is 00000 (5 bits): 3 bits of padding.
        assert_eq!(decode(&[0x07], &mut out), Ok(()));
        assert_eq!(out, b"0");
        assert!(decode(&[0x00], &mut out).is_err(), "padding not ones");
        // A whole byte of ones is padding longer than 7 bits.
        assert!(decode(&[0x07, 0xff], &mut out).is_err());
        assert!(decode(&[0xff], &mut out).is_err());
        // EOS (30 ones) inside the string.
        assert!(decode(&[0xff, 0xff, 0xff, 0xff], &mut out).is_err());
        assert_eq!(decode(&[], &mut out), Ok(()));
    }
}
