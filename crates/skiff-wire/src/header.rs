//! Packet headers (RFC 9000 Section 17). Parsing operates on *protected*
//! headers: it locates the packet number offset so the caller can remove
//! header protection in place.

use crate::{Reader, Result, WireError, Writer};

/// QUIC version 1.
pub const VERSION_1: u32 = 0x0000_0001;
/// Maximum connection ID length for QUIC v1.
pub const MAX_CID_LEN: usize = 20;

/// Packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Initial (long header type 0).
    Initial,
    /// 0-RTT (long header type 1).
    ZeroRtt,
    /// Handshake (long header type 2).
    Handshake,
    /// Retry (long header type 3).
    Retry,
    /// Version Negotiation (long header, version 0).
    VersionNegotiation,
    /// 1-RTT short header.
    Short,
}

/// A parsed protected header borrowing from the datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<'a> {
    /// Packet type.
    pub ty: PacketType,
    /// Version (0 for short headers).
    pub version: u32,
    /// Destination connection ID.
    pub dcid: &'a [u8],
    /// Source connection ID (empty for short headers).
    pub scid: &'a [u8],
    /// Token (Initial) or retry token (Retry); empty otherwise.
    pub token: &'a [u8],
    /// Offset of the (protected) packet number within the datagram.
    pub pn_offset: usize,
    /// Total length of this packet within the datagram (header + payload),
    /// allowing coalesced packets to be split.
    pub packet_len: usize,
}

fn cid<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let len = r.u8()? as usize;
    if len > MAX_CID_LEN {
        return Err(WireError::InvalidHeader);
    }
    r.bytes(len)
}

impl<'a> Header<'a> {
    /// Parses the protected header at the start of `buf`. `short_dcid_len`
    /// is the length of locally issued connection IDs (short headers do not
    /// carry a length).
    pub fn parse(buf: &'a [u8], short_dcid_len: usize) -> Result<Self> {
        let mut r = Reader::new(buf);
        let first = r.u8()?;
        if first & 0x80 == 0 {
            if first & 0x40 == 0 {
                return Err(WireError::InvalidHeader);
            }
            let dcid = r.bytes(short_dcid_len)?;
            return Ok(Header {
                ty: PacketType::Short,
                version: 0,
                dcid,
                scid: &[],
                token: &[],
                pn_offset: r.position(),
                packet_len: buf.len(),
            });
        }
        let version = r.u32()?;
        let dcid = cid(&mut r)?;
        let scid = cid(&mut r)?;
        if version == 0 {
            return Ok(Header {
                ty: PacketType::VersionNegotiation,
                version,
                dcid,
                scid,
                token: r.rest(),
                pn_offset: r.position(),
                packet_len: buf.len(),
            });
        }
        if version != VERSION_1 {
            // Unknown version: only the invariant fields are meaningful.
            return Err(WireError::InvalidHeader);
        }
        let ty = match (first >> 4) & 0x03 {
            0 => PacketType::Initial,
            1 => PacketType::ZeroRtt,
            2 => PacketType::Handshake,
            _ => PacketType::Retry,
        };
        let mut token: &[u8] = &[];
        if ty == PacketType::Retry {
            // Token runs until the 16-byte integrity tag.
            let rest = r
                .remaining()
                .checked_sub(16)
                .ok_or(WireError::InvalidHeader)?;
            token = r.bytes(rest)?;
            return Ok(Header {
                ty,
                version,
                dcid,
                scid,
                token,
                pn_offset: r.position(),
                packet_len: buf.len(),
            });
        }
        if ty == PacketType::Initial {
            token = r.vbytes()?;
        }
        let len = r.varint()?;
        let pn_offset = r.position();
        let len = usize::try_from(len).map_err(|_| WireError::InvalidHeader)?;
        if len > r.remaining() || len < 1 {
            return Err(WireError::InvalidHeader);
        }
        Ok(Header {
            ty,
            version,
            dcid,
            scid,
            token,
            pn_offset,
            packet_len: pn_offset + len,
        })
    }
}

/// Writes a long header up to and including a 2-byte Length field and the
/// truncated packet number. Returns the offset of the Length field so it
/// can be patched after the payload size is known.
#[allow(clippy::too_many_arguments)]
pub fn write_long(
    w: &mut Writer<'_>,
    ty: PacketType,
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    pn: u64,
    pn_len: usize,
) -> Result<usize> {
    let tbits = match ty {
        PacketType::Initial => 0,
        PacketType::ZeroRtt => 1,
        PacketType::Handshake => 2,
        _ => return Err(WireError::InvalidHeader),
    };
    let first = 0xc0 | (tbits << 4) | (pn_len as u8 - 1);
    w.u8(first)?;
    w.uint(u64::from(version), 4)?;
    w.u8(dcid.len() as u8)?;
    w.put(dcid)?;
    w.u8(scid.len() as u8)?;
    w.put(scid)?;
    if ty == PacketType::Initial {
        w.vbytes(token)?;
    }
    let len_off = w.position();
    w.varint_with_len(0, 2)?;
    w.uint(pn, pn_len)?;
    Ok(len_off)
}

/// Writes a short (1-RTT) header with the given truncated packet number.
pub fn write_short(
    w: &mut Writer<'_>,
    dcid: &[u8],
    key_phase: bool,
    pn: u64,
    pn_len: usize,
) -> Result<()> {
    w.u8(0x40 | (u8::from(key_phase) << 2) | (pn_len as u8 - 1))?;
    w.put(dcid)?;
    w.uint(pn, pn_len)
}

/// Writes a Version Negotiation packet listing `versions`.
pub fn write_version_negotiation(
    w: &mut Writer<'_>,
    dcid: &[u8],
    scid: &[u8],
    versions: &[u32],
) -> Result<()> {
    w.u8(0xc0)?;
    w.uint(0, 4)?;
    w.u8(dcid.len() as u8)?;
    w.put(dcid)?;
    w.u8(scid.len() as u8)?;
    w.put(scid)?;
    for v in versions {
        w.uint(u64::from(*v), 4)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn long_header_roundtrip(dcid in proptest::collection::vec(any::<u8>(), 0..=20),
                                 scid in proptest::collection::vec(any::<u8>(), 0..=20),
                                 token in proptest::collection::vec(any::<u8>(), 0..50),
                                 pn in 0u64..(1<<24), hs: bool, payload in 30usize..200) {
            let ty = if hs { PacketType::Handshake } else { PacketType::Initial };
            let mut buf = vec![0u8; 512];
            let mut w = Writer::new(&mut buf);
            let len_off = write_long(&mut w, ty, VERSION_1, &dcid, &scid, &token, pn, 3).unwrap();
            let pn_off = w.position() - 3;
            let total = w.position() + payload;
            let mut lw = Writer::new(&mut buf[len_off..]);
            lw.varint_with_len((3 + payload) as u64, 2).unwrap();
            let h = Header::parse(&buf[..total + 7], 0).unwrap();
            prop_assert_eq!(h.ty, ty);
            prop_assert_eq!(h.dcid, &dcid[..]);
            prop_assert_eq!(h.scid, &scid[..]);
            if !hs { prop_assert_eq!(h.token, &token[..]); }
            prop_assert_eq!(h.pn_offset, pn_off);
            prop_assert_eq!(h.packet_len, total);
        }

        #[test]
        fn short_header_roundtrip(dcid in proptest::collection::vec(any::<u8>(), 0..=20), pn in 0u64..256) {
            let mut buf = vec![0u8; 64];
            let mut w = Writer::new(&mut buf);
            write_short(&mut w, &dcid, false, pn, 1).unwrap();
            let n = w.position();
            let h = Header::parse(&buf[..n + 20], dcid.len()).unwrap();
            prop_assert_eq!(h.ty, PacketType::Short);
            prop_assert_eq!(h.dcid, &dcid[..]);
            prop_assert_eq!(h.pn_offset, n - 1);
        }

        #[test]
        fn parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..100), l in 0usize..21) {
            let _ = Header::parse(&data, l);
        }
    }

    #[test]
    fn version_negotiation_roundtrip() {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        write_version_negotiation(&mut w, b"abc", b"de", &[VERSION_1, 0x1a2a3a4a]).unwrap();
        let n = w.position();
        let h = Header::parse(&buf[..n], 0).unwrap();
        assert_eq!(h.ty, PacketType::VersionNegotiation);
        assert_eq!(h.token, &[0, 0, 0, 1, 0x1a, 0x2a, 0x3a, 0x4a]);
    }
}
