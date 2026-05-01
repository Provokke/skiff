//! HTTP/3 frames (RFC 9114 7), stream types (6.2), settings (7.2.4) and
//! error codes (8.1).

use skiff_wire::codec::Reader;

/// HTTP/3 frame types (RFC 9114 7.2).
pub mod frame_type {
    /// DATA.
    pub const DATA: u64 = 0x00;
    /// HEADERS.
    pub const HEADERS: u64 = 0x01;
    /// CANCEL_PUSH.
    pub const CANCEL_PUSH: u64 = 0x03;
    /// SETTINGS.
    pub const SETTINGS: u64 = 0x04;
    /// PUSH_PROMISE.
    pub const PUSH_PROMISE: u64 = 0x05;
    /// GOAWAY.
    pub const GOAWAY: u64 = 0x07;
    /// MAX_PUSH_ID.
    pub const MAX_PUSH_ID: u64 = 0x0d;

    /// HTTP/2 frame types reserved in HTTP/3 (7.2.8): receiving one is a
    /// connection error of type H3_FRAME_UNEXPECTED.
    pub fn is_reserved_h2(ty: u64) -> bool {
        matches!(ty, 0x02 | 0x06 | 0x08 | 0x09)
    }
}

/// Unidirectional stream types (RFC 9114 6.2, RFC 9204 4.2).
pub mod stream_type {
    /// Control stream.
    pub const CONTROL: u64 = 0x00;
    /// Push stream.
    pub const PUSH: u64 = 0x01;
    /// QPACK encoder stream.
    pub const QPACK_ENCODER: u64 = 0x02;
    /// QPACK decoder stream.
    pub const QPACK_DECODER: u64 = 0x03;
}

/// HTTP/3 error codes (RFC 9114 8.1).
pub mod error_code {
    /// No error.
    pub const H3_NO_ERROR: u64 = 0x100;
    /// General protocol error.
    pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
    /// Internal error.
    pub const H3_INTERNAL_ERROR: u64 = 0x102;
    /// Stream creation error.
    pub const H3_STREAM_CREATION_ERROR: u64 = 0x103;
    /// Critical stream was closed.
    pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
    /// Frame not permitted in the current state.
    pub const H3_FRAME_UNEXPECTED: u64 = 0x105;
    /// Frame violated layout or size rules.
    pub const H3_FRAME_ERROR: u64 = 0x106;
    /// Peer generating excessive load.
    pub const H3_EXCESSIVE_LOAD: u64 = 0x107;
    /// An identifier was used incorrectly.
    pub const H3_ID_ERROR: u64 = 0x108;
    /// SETTINGS frame contained invalid values.
    pub const H3_SETTINGS_ERROR: u64 = 0x109;
    /// No SETTINGS frame received.
    pub const H3_MISSING_SETTINGS: u64 = 0x10a;
    /// Request not processed.
    pub const H3_REQUEST_REJECTED: u64 = 0x10b;
    /// Data no longer needed.
    pub const H3_REQUEST_CANCELLED: u64 = 0x10c;
    /// Stream terminated early.
    pub const H3_REQUEST_INCOMPLETE: u64 = 0x10d;
    /// Malformed message.
    pub const H3_MESSAGE_ERROR: u64 = 0x10e;
    /// TCP reset or error on a CONNECT request.
    pub const H3_CONNECT_ERROR: u64 = 0x10f;
    /// Retry over HTTP/1.1.
    pub const H3_VERSION_FALLBACK: u64 = 0x110;
}

/// Setting identifiers (RFC 9114 7.2.4.1, RFC 9204 5).
pub mod setting_id {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    /// SETTINGS_MAX_FIELD_SECTION_SIZE.
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    /// SETTINGS_QPACK_BLOCKED_STREAMS.
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441 3, RFC 9220 3).
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

    /// HTTP/2 settings reserved in HTTP/3: receiving one is a connection
    /// error of type H3_SETTINGS_ERROR.
    pub fn is_reserved_h2(id: u64) -> bool {
        matches!(id, 0x00 | 0x02..=0x05)
    }
}

use error_code::{H3_FRAME_ERROR, H3_SETTINGS_ERROR};

/// A protocol violation found while decoding a frame: the HTTP/3 error
/// code and a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameError {
    /// HTTP/3 error code.
    pub code: u64,
    /// Diagnostic.
    pub reason: &'static str,
}

fn frame_err(code: u64, reason: &'static str) -> FrameError {
    FrameError { code, reason }
}

/// Appends a QUIC variable-length integer (values above 2^62 - 1 are
/// clamped; HTTP/3 never produces them).
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    let v = v.min(skiff_wire::MAX_VARINT);
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&(0xc000_0000_0000_0000 | v).to_be_bytes());
    }
}

/// A frame's type and payload length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Frame type.
    pub ty: u64,
    /// Payload length.
    pub len: u64,
}

impl FrameHeader {
    /// Parses a frame header at the start of `buf`; `None` if `buf` does
    /// not hold the whole header yet. Returns the header and its length.
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        let mut r = Reader::new(buf);
        let ty = r.varint().ok()?;
        let len = r.varint().ok()?;
        Some((Self { ty, len }, r.position()))
    }

    /// Appends a frame header.
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_varint(out, self.ty);
        put_varint(out, self.len);
    }
}

/// Appends a whole frame.
pub fn encode_frame(out: &mut Vec<u8>, ty: u64, payload: &[u8]) {
    FrameHeader {
        ty,
        len: payload.len() as u64,
    }
    .encode(out);
    out.extend_from_slice(payload);
}

/// Parses a payload that must be exactly one varint (GOAWAY, MAX_PUSH_ID,
/// CANCEL_PUSH).
pub fn parse_single_varint(payload: &[u8]) -> Result<u64, FrameError> {
    let mut r = Reader::new(payload);
    let v = r
        .varint()
        .map_err(|_| frame_err(H3_FRAME_ERROR, "truncated frame"))?;
    if r.remaining() != 0 {
        return Err(frame_err(H3_FRAME_ERROR, "excess bytes in frame"));
    }
    Ok(v)
}

/// The settings an endpoint sends in its SETTINGS frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (default 0).
    pub qpack_max_table_capacity: u64,
    /// SETTINGS_QPACK_BLOCKED_STREAMS (default 0).
    pub qpack_blocked_streams: u64,
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (default unlimited).
    pub max_field_section_size: Option<u64>,
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL = 1: the sender accepts extended
    /// CONNECT requests (`:protocol`, RFC 9220). Default off.
    pub enable_connect_protocol: bool,
}

impl Default for Settings {
    /// The values in force before a SETTINGS frame arrives.
    fn default() -> Self {
        Self {
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            max_field_section_size: None,
            enable_connect_protocol: false,
        }
    }
}

impl Settings {
    /// Decodes a SETTINGS payload: unknown identifiers are ignored;
    /// duplicates, reserved HTTP/2 identifiers and an
    /// ENABLE_CONNECT_PROTOCOL value other than 0 or 1 (RFC 8441 3) are
    /// H3_SETTINGS_ERROR; a truncated pair is H3_FRAME_ERROR.
    pub fn decode(payload: &[u8]) -> Result<Self, FrameError> {
        let mut s = Self::default();
        let mut seen = Vec::new();
        let mut r = Reader::new(payload);
        while r.remaining() > 0 {
            let (Ok(id), Ok(value)) = (r.varint(), r.varint()) else {
                return Err(frame_err(H3_FRAME_ERROR, "truncated setting"));
            };
            if setting_id::is_reserved_h2(id) {
                return Err(frame_err(H3_SETTINGS_ERROR, "reserved HTTP/2 setting"));
            }
            if seen.contains(&id) {
                return Err(frame_err(H3_SETTINGS_ERROR, "duplicate setting"));
            }
            seen.push(id);
            match id {
                setting_id::QPACK_MAX_TABLE_CAPACITY => s.qpack_max_table_capacity = value,
                setting_id::QPACK_BLOCKED_STREAMS => s.qpack_blocked_streams = value,
                setting_id::MAX_FIELD_SECTION_SIZE => s.max_field_section_size = Some(value),
                setting_id::ENABLE_CONNECT_PROTOCOL => {
                    s.enable_connect_protocol = match value {
                        0 => false,
                        1 => true,
                        _ => {
                            return Err(frame_err(
                                H3_SETTINGS_ERROR,
                                "ENABLE_CONNECT_PROTOCOL not 0 or 1",
                            ))
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(s)
    }

    /// Encodes the SETTINGS payload (default values are omitted), followed
    /// by one reserved "grease" setting (RFC 9114 7.2.4.1) so peers must
    /// ignore unknown identifiers.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.qpack_max_table_capacity > 0 {
            put_varint(&mut out, setting_id::QPACK_MAX_TABLE_CAPACITY);
            put_varint(&mut out, self.qpack_max_table_capacity);
        }
        if self.qpack_blocked_streams > 0 {
            put_varint(&mut out, setting_id::QPACK_BLOCKED_STREAMS);
            put_varint(&mut out, self.qpack_blocked_streams);
        }
        if let Some(m) = self.max_field_section_size {
            put_varint(&mut out, setting_id::MAX_FIELD_SECTION_SIZE);
            put_varint(&mut out, m);
        }
        if self.enable_connect_protocol {
            put_varint(&mut out, setting_id::ENABLE_CONNECT_PROTOCOL);
            put_varint(&mut out, 1);
        }
        // 0x1f * N + 0x21 is reserved for greasing; N = 1.
        put_varint(&mut out, 0x1f + 0x21);
        put_varint(&mut out, 0);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_and_headers() {
        for (v, len) in [
            (0u64, 1),
            (63, 1),
            (64, 2),
            (16383, 2),
            (16384, 4),
            (1 << 30, 8),
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(out.len(), len, "{v}");
            assert_eq!(Reader::new(&out).varint(), Ok(v));
        }
        let mut out = Vec::new();
        encode_frame(&mut out, frame_type::HEADERS, &[1, 2, 3]);
        assert_eq!(out, [0x01, 0x03, 1, 2, 3]);
        assert_eq!(
            FrameHeader::parse(&out),
            Some((FrameHeader { ty: 1, len: 3 }, 2))
        );
        assert_eq!(FrameHeader::parse(&[0x40]), None);
        assert_eq!(FrameHeader::parse(&[0x01]), None);
    }

    #[test]
    fn settings_roundtrip_and_errors() {
        let s = Settings {
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 16,
            max_field_section_size: Some(65536),
            enable_connect_protocol: false,
        };
        assert_eq!(Settings::decode(&s.encode()), Ok(s));
        let x = Settings {
            enable_connect_protocol: true,
            ..s
        };
        assert_eq!(Settings::decode(&x.encode()), Ok(x));
        assert_ne!(x.encode(), s.encode());
        assert_eq!(Settings::decode(&[]), Ok(Settings::default()));
        // ENABLE_CONNECT_PROTOCOL: 0 and 1 only (RFC 8441 3).
        let ecp = |v: u8| Settings::decode(&[0x08, v]).map(|s| s.enable_connect_protocol);
        assert_eq!(ecp(0), Ok(false));
        assert_eq!(ecp(1), Ok(true));
        assert_eq!(ecp(2).map_err(|e| e.code), Err(H3_SETTINGS_ERROR));
        // Unknown identifiers are ignored.
        assert_eq!(Settings::decode(&[0x21, 0x05]), Ok(Settings::default()));
        let code = |p: &[u8]| Settings::decode(p).map_err(|e| e.code);
        assert_eq!(code(&[0x01, 0x01, 0x01, 0x02]), Err(H3_SETTINGS_ERROR));
        for reserved in [0x00, 0x02, 0x03, 0x04, 0x05] {
            assert_eq!(code(&[reserved, 0x00]), Err(H3_SETTINGS_ERROR));
        }
        assert_eq!(code(&[0x01]), Err(H3_FRAME_ERROR));
        assert_eq!(parse_single_varint(&[0x04]), Ok(4));
        assert!(parse_single_varint(&[0x04, 0x00]).is_err());
        assert!(parse_single_varint(&[]).is_err());
    }
}
