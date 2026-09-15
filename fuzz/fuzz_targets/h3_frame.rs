#![no_main]
//! HTTP/3 frame parsing on arbitrary input: frame headers over the whole
//! buffer, SETTINGS payloads and single-varint payloads (GOAWAY,
//! MAX_PUSH_ID, CANCEL_PUSH). Must never panic; parsed headers and decoded
//! SETTINGS must re-encode and parse back to the same values.
use libfuzzer_sys::fuzz_target;
use skiff_h3::frame::{frame_type, parse_single_varint, put_varint, FrameHeader, Settings};

fuzz_target!(|data: &[u8]| {
    let mut pos = 0;
    while let Some((h, hl)) = data.get(pos..).and_then(FrameHeader::parse) {
        let mut enc = Vec::new();
        h.encode(&mut enc);
        assert_eq!(FrameHeader::parse(&enc), Some((h, enc.len())));
        let start = pos + hl;
        let end = usize::try_from(h.len)
            .ok()
            .and_then(|l| start.checked_add(l))
            .filter(|e| *e <= data.len())
            .unwrap_or(data.len());
        let payload = &data[start..end];
        match h.ty {
            frame_type::SETTINGS => {
                if let Ok(s) = Settings::decode(payload) {
                    assert_eq!(Settings::decode(&s.encode()).ok(), Some(s));
                }
            }
            frame_type::GOAWAY | frame_type::MAX_PUSH_ID | frame_type::CANCEL_PUSH => {
                if let Ok(v) = parse_single_varint(payload) {
                    let mut b = Vec::new();
                    put_varint(&mut b, v);
                    assert_eq!(parse_single_varint(&b).ok(), Some(v));
                }
            }
            _ => {}
        }
        if end == pos {
            break;
        }
        pos = end;
    }
});
