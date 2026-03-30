//! Whole-packet protection: AEAD over the payload, then header protection
//! (RFC 9001 Sections 5.3 and 5.4), and the inverse operation in place.

use crate::crypto::{PacketProtection, SAMPLE_LEN, TAG_LEN};
use crate::{Error, Result};

fn first_byte_mask(first: u8) -> u8 {
    if first & 0x80 != 0 {
        0x0f
    } else {
        0x1f
    }
}

/// Protects a packet in place.
///
/// `buf[..pn_offset + pn_len]` is the plaintext header (ending with the
/// truncated packet number), `buf[pn_offset + pn_len..len]` the plaintext
/// payload, and `buf` must have `TAG_LEN` spare bytes after `len`.
/// Returns the protected packet length.
pub fn protect<K: PacketProtection + ?Sized>(
    keys: &K,
    buf: &mut [u8],
    pn_offset: usize,
    pn: u64,
    len: usize,
) -> Result<usize> {
    let pn_len = usize::from(buf.first().ok_or(Error::ShortPacket)? & 0x03) + 1;
    let hdr_len = pn_offset + pn_len;
    if buf.len() < len + TAG_LEN || len < hdr_len {
        return Err(Error::ShortPacket);
    }
    let (header, rest) = buf.split_at_mut(hdr_len);
    let tag = keys.seal(pn, header, &mut rest[..len - hdr_len])?;
    rest[len - hdr_len..len - hdr_len + TAG_LEN].copy_from_slice(&tag);
    let total = len + TAG_LEN;
    let sample_off = pn_offset + 4;
    if sample_off + SAMPLE_LEN > total {
        return Err(Error::ShortPacket);
    }
    let mask = keys.hp_mask(&buf[sample_off..sample_off + SAMPLE_LEN])?;
    buf[0] ^= mask[0] & first_byte_mask(buf[0]);
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
    }
    Ok(total)
}

/// Result of [`unprotect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    /// Recovered full packet number.
    pub pn: u64,
    /// Offset of the decrypted payload in the buffer.
    pub payload_offset: usize,
    /// Length of the decrypted payload.
    pub payload_len: usize,
}

/// Removes header and packet protection in place from `buf` (exactly one
/// packet), using `largest_pn` to expand the truncated packet number.
pub fn unprotect<K: PacketProtection + ?Sized>(
    keys: &K,
    buf: &mut [u8],
    pn_offset: usize,
    largest_pn: Option<u64>,
) -> Result<Opened> {
    let (pn, hdr_len) = remove_header_protection(keys, buf, pn_offset, largest_pn)?;
    open_payload(keys, buf, hdr_len, pn)
}

/// First half of [`unprotect`]: removes header protection in place and
/// returns `(packet number, header length)`. The first byte (key phase
/// bit included) is then readable, so the caller can pick the AEAD key for
/// [`open_payload`]. Only one key may be tried: a failed AEAD open leaves
/// the payload unspecified.
pub fn remove_header_protection<K: PacketProtection + ?Sized>(
    keys: &K,
    buf: &mut [u8],
    pn_offset: usize,
    largest_pn: Option<u64>,
) -> Result<(u64, usize)> {
    let sample_off = pn_offset + 4;
    if buf.len() < sample_off + SAMPLE_LEN {
        return Err(Error::ShortPacket);
    }
    let mask = keys.hp_mask(&buf[sample_off..sample_off + SAMPLE_LEN])?;
    buf[0] ^= mask[0] & first_byte_mask(buf[0]);
    let pn_len = usize::from(buf[0] & 0x03) + 1;
    let mut truncated = 0u64;
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
        truncated = (truncated << 8) | u64::from(buf[pn_offset + i]);
    }
    let pn = skiff_wire::pn::decode(largest_pn, truncated, pn_len);
    Ok((pn, pn_offset + pn_len))
}

/// Second half of [`unprotect`]: AEAD-opens the payload after
/// [`remove_header_protection`].
pub fn open_payload<K: PacketProtection + ?Sized>(
    keys: &K,
    buf: &mut [u8],
    hdr_len: usize,
    pn: u64,
) -> Result<Opened> {
    if hdr_len > buf.len() {
        return Err(Error::ShortPacket);
    }
    let (header, rest) = buf.split_at_mut(hdr_len);
    let payload_len = keys.open_in_place(pn, header, rest)?;
    Ok(Opened {
        pn,
        payload_offset: hdr_len,
        payload_len,
    })
}
