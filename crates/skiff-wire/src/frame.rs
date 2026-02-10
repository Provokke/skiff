//! QUIC frames (RFC 9000 Section 19). Decoding borrows payload bytes.

use crate::{Reader, Result, WireError, Writer};

/// Upper bound on ACK ranges accepted from a peer; bounds work per frame.
pub const MAX_ACK_RANGES: usize = 256;

/// ECN counts carried by ACK frames of type 0x03.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnCounts {
    /// ECT(0) count.
    pub ect0: u64,
    /// ECT(1) count.
    pub ect1: u64,
    /// ECN-CE count.
    pub ce: u64,
}

/// A decoded (or to-be-encoded) frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    /// PADDING (one byte per frame; runs are coalesced by the decoder).
    Padding {
        /// Number of padding bytes.
        len: usize,
    },
    /// PING.
    Ping,
    /// ACK. `ranges` are inclusive `(smallest, largest)` pairs, largest first.
    Ack {
        /// Encoded ACK delay (before exponent scaling).
        delay: u64,
        /// Acknowledged ranges, descending, non-overlapping.
        ranges: Vec<(u64, u64)>,
        /// Optional ECN counts.
        ecn: Option<EcnCounts>,
    },
    /// RESET_STREAM.
    ResetStream {
        /// Stream ID.
        id: u64,
        /// Application error code.
        error: u64,
        /// Final size of the stream.
        final_size: u64,
    },
    /// STOP_SENDING.
    StopSending {
        /// Stream ID.
        id: u64,
        /// Application error code.
        error: u64,
    },
    /// CRYPTO.
    Crypto {
        /// Offset in the crypto stream.
        offset: u64,
        /// Handshake bytes.
        data: &'a [u8],
    },
    /// NEW_TOKEN.
    NewToken {
        /// Opaque token.
        token: &'a [u8],
    },
    /// STREAM (types 0x08..=0x0f).
    Stream {
        /// Stream ID.
        id: u64,
        /// Offset of `data`.
        offset: u64,
        /// Payload.
        data: &'a [u8],
        /// FIN bit.
        fin: bool,
    },
    /// MAX_DATA.
    MaxData(u64),
    /// MAX_STREAM_DATA.
    MaxStreamData {
        /// Stream ID.
        id: u64,
        /// New limit.
        max: u64,
    },
    /// MAX_STREAMS.
    MaxStreams {
        /// Bidirectional (0x12) or unidirectional (0x13).
        bidi: bool,
        /// Cumulative stream count.
        max: u64,
    },
    /// DATA_BLOCKED.
    DataBlocked(u64),
    /// STREAM_DATA_BLOCKED.
    StreamDataBlocked {
        /// Stream ID.
        id: u64,
        /// Limit at which blocking occurred.
        limit: u64,
    },
    /// STREAMS_BLOCKED.
    StreamsBlocked {
        /// Bidirectional or unidirectional.
        bidi: bool,
        /// Limit at which blocking occurred.
        limit: u64,
    },
    /// NEW_CONNECTION_ID.
    NewConnectionId {
        /// Sequence number.
        seq: u64,
        /// Retire Prior To.
        retire_prior_to: u64,
        /// Connection ID (1..=20 bytes).
        cid: &'a [u8],
        /// Stateless reset token.
        reset_token: [u8; 16],
    },
    /// RETIRE_CONNECTION_ID.
    RetireConnectionId(u64),
    /// PATH_CHALLENGE.
    PathChallenge([u8; 8]),
    /// PATH_RESPONSE.
    PathResponse([u8; 8]),
    /// CONNECTION_CLOSE (0x1c transport with frame type, 0x1d application).
    ConnectionClose {
        /// Error code.
        error: u64,
        /// Triggering frame type (transport close only).
        frame_type: Option<u64>,
        /// Reason phrase.
        reason: &'a [u8],
    },
    /// HANDSHAKE_DONE.
    HandshakeDone,
}

fn rd8(r: &mut Reader<'_>) -> Result<[u8; 8]> {
    let mut a = [0u8; 8];
    a.copy_from_slice(r.bytes(8)?);
    Ok(a)
}

impl<'a> Frame<'a> {
    /// Decodes one frame from `r`.
    pub fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let ty = r.varint()?;
        let bad = |_: WireError| WireError::InvalidFrame(ty);
        Self::decode_body(ty, r).map_err(bad)
    }

    fn decode_body(ty: u64, r: &mut Reader<'a>) -> Result<Self> {
        Ok(match ty {
            0x00 => {
                let mut len = 1;
                while r.peek_u8().ok() == Some(0) {
                    r.u8()?;
                    len += 1;
                }
                Frame::Padding { len }
            }
            0x01 => Frame::Ping,
            0x02 | 0x03 => {
                let largest = r.varint()?;
                let delay = r.varint()?;
                let count = r.varint()?;
                let first = r.varint()?;
                let mut smallest = largest
                    .checked_sub(first)
                    .ok_or(WireError::InvalidFrame(ty))?;
                let mut ranges = vec![(smallest, largest)];
                if count as usize >= MAX_ACK_RANGES {
                    return Err(WireError::InvalidFrame(ty));
                }
                for _ in 0..count {
                    let gap = r.varint()?;
                    let len = r.varint()?;
                    let hi = smallest
                        .checked_sub(gap)
                        .and_then(|x| x.checked_sub(2))
                        .ok_or(WireError::InvalidFrame(ty))?;
                    let lo = hi.checked_sub(len).ok_or(WireError::InvalidFrame(ty))?;
                    ranges.push((lo, hi));
                    smallest = lo;
                }
                let ecn = if ty == 0x03 {
                    Some(EcnCounts {
                        ect0: r.varint()?,
                        ect1: r.varint()?,
                        ce: r.varint()?,
                    })
                } else {
                    None
                };
                Frame::Ack { delay, ranges, ecn }
            }
            0x04 => Frame::ResetStream {
                id: r.varint()?,
                error: r.varint()?,
                final_size: r.varint()?,
            },
            0x05 => Frame::StopSending {
                id: r.varint()?,
                error: r.varint()?,
            },
            0x06 => {
                let offset = r.varint()?;
                let data = r.vbytes()?;
                if offset + data.len() as u64 > crate::MAX_VARINT {
                    return Err(WireError::InvalidFrame(ty));
                }
                Frame::Crypto { offset, data }
            }
            0x07 => {
                let token = r.vbytes()?;
                if token.is_empty() {
                    return Err(WireError::InvalidFrame(ty));
                }
                Frame::NewToken { token }
            }
            0x08..=0x0f => {
                let id = r.varint()?;
                let offset = if ty & 0x04 != 0 { r.varint()? } else { 0 };
                let data = if ty & 0x02 != 0 {
                    r.vbytes()?
                } else {
                    r.bytes(r.remaining())?
                };
                if offset + data.len() as u64 > crate::MAX_VARINT {
                    return Err(WireError::InvalidFrame(ty));
                }
                Frame::Stream {
                    id,
                    offset,
                    data,
                    fin: ty & 0x01 != 0,
                }
            }
            0x10 => Frame::MaxData(r.varint()?),
            0x11 => Frame::MaxStreamData {
                id: r.varint()?,
                max: r.varint()?,
            },
            0x12 | 0x13 => {
                let max = r.varint()?;
                if max > 1 << 60 {
                    return Err(WireError::InvalidFrame(ty));
                }
                Frame::MaxStreams {
                    bidi: ty == 0x12,
                    max,
                }
            }
            0x14 => Frame::DataBlocked(r.varint()?),
            0x15 => Frame::StreamDataBlocked {
                id: r.varint()?,
                limit: r.varint()?,
            },
            0x16 | 0x17 => Frame::StreamsBlocked {
                bidi: ty == 0x16,
                limit: r.varint()?,
            },
            0x18 => {
                let seq = r.varint()?;
                let retire_prior_to = r.varint()?;
                let len = r.u8()? as usize;
                if !(1..=20).contains(&len) || retire_prior_to > seq {
                    return Err(WireError::InvalidFrame(ty));
                }
                let cid = r.bytes(len)?;
                let mut reset_token = [0u8; 16];
                reset_token.copy_from_slice(r.bytes(16)?);
                Frame::NewConnectionId {
                    seq,
                    retire_prior_to,
                    cid,
                    reset_token,
                }
            }
            0x19 => Frame::RetireConnectionId(r.varint()?),
            0x1a => Frame::PathChallenge(rd8(r)?),
            0x1b => Frame::PathResponse(rd8(r)?),
            0x1c | 0x1d => {
                let error = r.varint()?;
                let frame_type = if ty == 0x1c { Some(r.varint()?) } else { None };
                let reason = r.vbytes()?;
                Frame::ConnectionClose {
                    error,
                    frame_type,
                    reason,
                }
            }
            0x1e => Frame::HandshakeDone,
            _ => return Err(WireError::InvalidFrame(ty)),
        })
    }

    /// Whether receipt of this frame requires an acknowledgement.
    pub fn ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Frame::Padding { .. } | Frame::Ack { .. } | Frame::ConnectionClose { .. }
        )
    }

    /// Encodes this frame into `w`.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<()> {
        match self {
            Frame::Padding { len } => {
                for _ in 0..*len {
                    w.u8(0)?;
                }
            }
            Frame::Ping => w.varint(0x01)?,
            Frame::Ack { delay, ranges, ecn } => {
                let (first_lo, largest) = *ranges.first().ok_or(WireError::InvalidFrame(0x02))?;
                w.varint(if ecn.is_some() { 0x03 } else { 0x02 })?;
                w.varint(largest)?;
                w.varint(*delay)?;
                w.varint(ranges.len() as u64 - 1)?;
                w.varint(largest - first_lo)?;
                let mut smallest = first_lo;
                for &(lo, hi) in &ranges[1..] {
                    let gap = smallest
                        .checked_sub(hi)
                        .and_then(|g| g.checked_sub(2))
                        .ok_or(WireError::InvalidFrame(0x02))?;
                    w.varint(gap)?;
                    w.varint(hi.checked_sub(lo).ok_or(WireError::InvalidFrame(0x02))?)?;
                    smallest = lo;
                }
                if let Some(e) = ecn {
                    w.varint(e.ect0)?;
                    w.varint(e.ect1)?;
                    w.varint(e.ce)?;
                }
            }
            Frame::ResetStream {
                id,
                error,
                final_size,
            } => {
                w.varint(0x04)?;
                w.varint(*id)?;
                w.varint(*error)?;
                w.varint(*final_size)?;
            }
            Frame::StopSending { id, error } => {
                w.varint(0x05)?;
                w.varint(*id)?;
                w.varint(*error)?;
            }
            Frame::Crypto { offset, data } => {
                w.varint(0x06)?;
                w.varint(*offset)?;
                w.vbytes(data)?;
            }
            Frame::NewToken { token } => {
                w.varint(0x07)?;
                w.vbytes(token)?;
            }
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => {
                // Always include offset and length so frames can be coalesced.
                w.varint(0x08 | 0x04 | 0x02 | u64::from(*fin))?;
                w.varint(*id)?;
                w.varint(*offset)?;
                w.vbytes(data)?;
            }
            Frame::MaxData(v) => {
                w.varint(0x10)?;
                w.varint(*v)?;
            }
            Frame::MaxStreamData { id, max } => {
                w.varint(0x11)?;
                w.varint(*id)?;
                w.varint(*max)?;
            }
            Frame::MaxStreams { bidi, max } => {
                w.varint(if *bidi { 0x12 } else { 0x13 })?;
                w.varint(*max)?;
            }
            Frame::DataBlocked(v) => {
                w.varint(0x14)?;
                w.varint(*v)?;
            }
            Frame::StreamDataBlocked { id, limit } => {
                w.varint(0x15)?;
                w.varint(*id)?;
                w.varint(*limit)?;
            }
            Frame::StreamsBlocked { bidi, limit } => {
                w.varint(if *bidi { 0x16 } else { 0x17 })?;
                w.varint(*limit)?;
            }
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                reset_token,
            } => {
                w.varint(0x18)?;
                w.varint(*seq)?;
                w.varint(*retire_prior_to)?;
                w.u8(u8::try_from(cid.len()).map_err(|_| WireError::InvalidFrame(0x18))?)?;
                w.put(cid)?;
                w.put(reset_token)?;
            }
            Frame::RetireConnectionId(s) => {
                w.varint(0x19)?;
                w.varint(*s)?;
            }
            Frame::PathChallenge(d) => {
                w.varint(0x1a)?;
                w.put(d)?;
            }
            Frame::PathResponse(d) => {
                w.varint(0x1b)?;
                w.put(d)?;
            }
            Frame::ConnectionClose {
                error,
                frame_type,
                reason,
            } => {
                w.varint(if frame_type.is_some() { 0x1c } else { 0x1d })?;
                w.varint(*error)?;
                if let Some(ft) = frame_type {
                    w.varint(*ft)?;
                }
                w.vbytes(reason)?;
            }
            Frame::HandshakeDone => w.varint(0x1e)?,
        }
        Ok(())
    }
}

/// Iterator decoding all frames in a decrypted packet payload.
pub fn parse_all(payload: &[u8]) -> impl Iterator<Item = Result<Frame<'_>>> {
    let mut r = Reader::new(payload);
    let mut failed = false;
    core::iter::from_fn(move || {
        if failed || r.remaining() == 0 {
            return None;
        }
        let f = Frame::decode(&mut r);
        failed = f.is_err();
        Some(f)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn roundtrip(f: &Frame<'_>) {
        let mut buf = vec![0u8; 4096];
        let mut w = Writer::new(&mut buf);
        f.encode(&mut w).unwrap();
        let n = w.position();
        let mut r = Reader::new(&buf[..n]);
        assert_eq!(&Frame::decode(&mut r).unwrap(), f);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn ack_with_gaps() {
        roundtrip(&Frame::Ack {
            delay: 7,
            ranges: vec![(90, 100), (50, 60), (0, 3)],
            ecn: None,
        });
        roundtrip(&Frame::Ack {
            delay: 0,
            ranges: vec![(5, 5)],
            ecn: Some(EcnCounts {
                ect0: 1,
                ect1: 2,
                ce: 3,
            }),
        });
    }

    #[test]
    fn ack_underflow_rejected() {
        // largest=1, first range=5 -> negative smallest.
        assert!(Frame::decode(&mut Reader::new(&[0x02, 1, 0, 0, 5])).is_err());
    }

    #[test]
    fn stream_without_length_takes_rest() {
        let f = Frame::decode(&mut Reader::new(&[0x08, 4, b'h', b'i'])).unwrap();
        assert_eq!(
            f,
            Frame::Stream {
                id: 4,
                offset: 0,
                data: b"hi",
                fin: false
            }
        );
    }

    #[test]
    fn unknown_frame_type_rejected() {
        assert_eq!(
            Frame::decode(&mut Reader::new(&[0x1f])),
            Err(WireError::InvalidFrame(0x1f))
        );
    }

    fn v() -> impl Strategy<Value = u64> {
        prop_oneof![0u64..64, 0u64..16384, 0u64..(1 << 30), 0u64..(1 << 50)]
    }

    proptest! {
        #[test]
        fn simple_frames_roundtrip(a in v(), b in v(), c in v(), bidi: bool, fin: bool,
                                   data in proptest::collection::vec(any::<u8>(), 0..300),
                                   cid in proptest::collection::vec(any::<u8>(), 1..=20),
                                   tok: [u8; 16], d8: [u8; 8]) {
            let frames = [
                Frame::Ping, Frame::HandshakeDone, Frame::Padding { len: 3 },
                Frame::ResetStream { id: a, error: b, final_size: c },
                Frame::StopSending { id: a, error: b },
                Frame::Crypto { offset: a, data: &data },
                Frame::Stream { id: a, offset: b, data: &data, fin },
                Frame::MaxData(a), Frame::MaxStreamData { id: a, max: b },
                Frame::MaxStreams { bidi, max: a.min(1 << 60) },
                Frame::DataBlocked(a), Frame::StreamDataBlocked { id: a, limit: b },
                Frame::StreamsBlocked { bidi, limit: a },
                Frame::NewConnectionId { seq: a.max(b), retire_prior_to: b.min(a), cid: &cid, reset_token: tok },
                Frame::RetireConnectionId(c), Frame::PathChallenge(d8), Frame::PathResponse(d8),
                Frame::ConnectionClose { error: a, frame_type: Some(b), reason: &data },
                Frame::ConnectionClose { error: a, frame_type: None, reason: &data },
            ];
            if !data.is_empty() { roundtrip(&Frame::NewToken { token: &data }); }
            for f in &frames { roundtrip(f); }
        }

        #[test]
        fn ack_roundtrip(mut pns in proptest::collection::btree_set(0u64..100_000, 1..200), delay in v()) {
            // Build descending, non-adjacent ranges from a set.
            let mut ranges: Vec<(u64, u64)> = Vec::new();
            while let Some(hi) = pns.pop_last() {
                let mut lo = hi;
                while pns.remove(&(lo.wrapping_sub(1))) { lo -= 1; }
                ranges.push((lo, hi));
            }
            ranges.truncate(MAX_ACK_RANGES - 1);
            roundtrip(&Frame::Ack { delay, ranges, ecn: None });
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..200)) {
            for f in parse_all(&data) { let _ = f; }
        }
    }
}
