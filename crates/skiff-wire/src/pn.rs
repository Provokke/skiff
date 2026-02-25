//! Packet number truncation and recovery (RFC 9000 Section 17.1, Appendix A.2/A.3).

/// Number of bytes (1..=4) needed to encode `full_pn` given the largest
/// packet number acknowledged by the peer.
pub fn encoded_len(full_pn: u64, largest_acked: Option<u64>) -> usize {
    let num_unacked = match largest_acked {
        Some(la) => full_pn.saturating_sub(la),
        None => full_pn.saturating_add(1),
    };
    // Need enough bits to represent more than twice the unacked range.
    let min_bits = 64 - num_unacked.leading_zeros() + 1;
    (min_bits.div_ceil(8) as usize).clamp(1, 4)
}

/// Recovers a full packet number from its truncated encoding
/// (`truncated` with `len` bytes) given the largest packet number
/// successfully processed in the same space.
pub fn decode(largest_pn: Option<u64>, truncated: u64, len: usize) -> u64 {
    let expected = largest_pn.map_or(0, |l| l + 1);
    let pn_nbits = (len as u32) * 8;
    let win = 1u64 << pn_nbits;
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate.saturating_add(hwin) <= expected && candidate < (1u64 << 62) - win {
        candidate + win
    } else if candidate > expected.saturating_add(hwin) && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rfc9000_a3_example() {
        assert_eq!(decode(Some(0xa82f30ea), 0x9b32, 2), 0xa82f9b32);
    }

    #[test]
    fn rfc9000_a2_examples() {
        assert_eq!(encoded_len(0xac5c02, Some(0xabe8b3)), 2);
        assert_eq!(encoded_len(0xace8fe, Some(0xabe8b3)), 3);
        assert_eq!(encoded_len(0, None), 1);
    }

    proptest! {
        #[test]
        fn truncate_then_decode(largest in 0u64..(1 << 40), delta in 1u64..100_000) {
            let pn = largest + delta;
            let len = encoded_len(pn, Some(largest));
            let trunc = pn & ((1u64 << (len * 8)) - 1);
            prop_assert_eq!(decode(Some(largest), trunc, len), pn);
        }
    }
}
