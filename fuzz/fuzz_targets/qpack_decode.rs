#![no_main]
//! QPACK decoder on arbitrary input: an interleaving of encoder-stream
//! chunks and field sections on a few streams. Must never panic; every
//! section that decodes must respect the size limit and survive a
//! re-encode (static table and literals) and decode unchanged; the dynamic
//! table never exceeds its capacity.
use libfuzzer_sys::fuzz_target;
use skiff_h3::qpack::{huffman, section_size, Decoded, Decoder, Encoder};

const MAX_SECTION: u64 = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    let mut dec = Decoder::new(4096, 4, MAX_SECTION);
    let mut rest = data;
    while let [op, len, tail @ ..] = rest {
        let n = (*len as usize).min(tail.len());
        let (chunk, next) = tail.split_at(n);
        rest = next;
        if op & 1 == 1 {
            // Encoder stream: an error closes the connection, so stop.
            if dec.on_encoder_stream(chunk).is_err() {
                break;
            }
        } else {
            let stream = u64::from(op >> 1) % 8 * 4;
            match dec.decode(stream, chunk) {
                Ok(Decoded::Fields(fields)) => {
                    assert!(section_size(&fields) <= MAX_SECTION);
                    // Round trip through a fresh encoder/decoder pair.
                    let mut enc = Encoder::new(0);
                    if let Ok(block) = enc.encode(0, &fields) {
                        let mut fresh = Decoder::new(0, 0, u64::MAX);
                        match fresh.decode(0, &block) {
                            Ok(Decoded::Fields(again)) => assert_eq!(again, fields),
                            other => panic!("re-encoded section failed: {other:?}"),
                        }
                    }
                }
                Ok(Decoded::Blocked {
                    required_insert_count,
                }) => {
                    assert!(required_insert_count > dec.insert_count());
                }
                Err(_) => {}
            }
        }
        let t = dec.table();
        assert!(t.size() <= t.capacity());
        let _ = dec.take_instructions();
    }
    // Huffman: whatever decodes must re-encode to bytes that decode back.
    let mut out = Vec::new();
    if huffman::decode(data, &mut out).is_ok() {
        let mut enc = Vec::new();
        huffman::encode(&out, &mut enc);
        assert_eq!(enc.len(), huffman::encoded_len(&out));
        let mut back = Vec::new();
        assert!(huffman::decode(&enc, &mut back).is_ok());
        assert_eq!(back, out);
    }
});
