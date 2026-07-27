//! QPACK property tests: encoder -> decoder round trips with a dynamic
//! table of random capacity and blocked-stream limit, where encoder- and
//! decoder-stream bytes are delivered late, in random-sized pieces; plus
//! never-panic properties for arbitrary input.

use proptest::prelude::*;
use skiff_h3::qpack::prefix::{decode_int, decode_str, encode_int, encode_str};
use skiff_h3::qpack::{huffman, Decoded, Decoder, Encoder, Field};
use std::collections::VecDeque;

fn field() -> impl Strategy<Value = Field> {
    let name = prop_oneof![
        Just(b":path".to_vec()),
        Just(b":method".to_vec()),
        Just(b"content-type".to_vec()),
        Just(b"x-trace".to_vec()),
        Just(b"cookie".to_vec()),
        proptest::collection::vec(b'a'..=b'z', 1..12),
    ];
    let value = prop_oneof![
        Just(b"GET".to_vec()),
        Just(b"/".to_vec()),
        Just(b"text/plain".to_vec()),
        proptest::collection::vec(any::<u8>(), 0..40),
        proptest::collection::vec(b'0'..=b'9', 1..3),
    ];
    (name, value, proptest::bool::weighted(0.1)).prop_map(|(name, value, never_index)| Field {
        name,
        value,
        never_index,
    })
}

/// One section to send and whether its stream is cancelled before decode.
type Plan = Vec<(Vec<Field>, bool)>;

fn plan() -> impl Strategy<Value = Plan> {
    proptest::collection::vec(
        (
            proptest::collection::vec(field(), 0..10),
            proptest::bool::weighted(0.1),
        ),
        1..25,
    )
}

/// Bytes in flight on one unidirectional instruction stream, delivered in
/// order in pieces whose sizes come from `cuts`.
struct Pipe {
    data: VecDeque<u8>,
}

impl Pipe {
    fn take(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.data.len());
        self.data.drain(..n).collect()
    }
}

fn names(f: &[Field]) -> Vec<(Vec<u8>, Vec<u8>)> {
    f.iter()
        .map(|f| (f.name.clone(), f.value.clone()))
        .collect()
}

fn roundtrip(
    capacity: u64,
    blocked: u64,
    plan: Plan,
    cuts: Vec<usize>,
) -> Result<(), TestCaseError> {
    let mut enc = Encoder::new(capacity);
    let mut dec = Decoder::new(capacity, blocked, u64::MAX);
    enc.apply_peer_settings(capacity, blocked, u64::MAX);
    let mut enc_pipe = Pipe {
        data: VecDeque::new(),
    };
    let mut dec_pipe = Pipe {
        data: VecDeque::new(),
    };
    let mut cut = cuts.iter().cycle();
    // Sections not yet decoded: (stream, bytes, expected).
    let mut waiting: Vec<(u64, Vec<u8>, Vec<Field>)> = Vec::new();
    let mut done = 0usize;
    let mut expected_done = 0usize;
    for (i, (fields, cancel)) in plan.into_iter().enumerate() {
        let id = 4 * i as u64;
        let section = enc
            .encode(id, &fields)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        enc_pipe.data.extend(enc.take_instructions());
        prop_assert!(enc.blocked_streams() as u64 <= blocked);
        if cancel {
            dec.cancel_stream(id);
        } else {
            waiting.push((id, section, fields));
            expected_done += 1;
        }
        // Deliver some encoder-stream bytes, then try every waiting section.
        let piece = enc_pipe.take(*cut.next().unwrap_or(&0));
        dec.on_encoder_stream(&piece)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        let mut still = Vec::new();
        for (id, bytes, want) in waiting.drain(..) {
            match dec
                .decode(id, &bytes)
                .map_err(|e| TestCaseError::fail(e.to_string()))?
            {
                Decoded::Fields(got) => {
                    prop_assert_eq!(names(&got), names(&want));
                    done += 1;
                }
                Decoded::Blocked { .. } => still.push((id, bytes, want)),
            }
        }
        waiting = still;
        prop_assert!(dec.blocked_streams() as u64 <= blocked);
        dec_pipe.data.extend(dec.take_instructions());
        let piece = dec_pipe.take(*cut.next().unwrap_or(&0));
        enc.on_decoder_stream(&piece)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
    }
    // Flush everything.
    let rest = enc_pipe.take(usize::MAX);
    dec.on_encoder_stream(&rest)
        .map_err(|e| TestCaseError::fail(e.to_string()))?;
    for (id, bytes, want) in waiting.drain(..) {
        match dec
            .decode(id, &bytes)
            .map_err(|e| TestCaseError::fail(e.to_string()))?
        {
            Decoded::Fields(got) => {
                prop_assert_eq!(names(&got), names(&want));
                done += 1;
            }
            Decoded::Blocked { .. } => prop_assert!(false, "still blocked after flush"),
        }
    }
    prop_assert_eq!(done, expected_done);
    dec_pipe.data.extend(dec.take_instructions());
    let rest = dec_pipe.take(usize::MAX);
    enc.on_decoder_stream(&rest)
        .map_err(|e| TestCaseError::fail(e.to_string()))?;
    prop_assert_eq!(enc.unacknowledged_sections(), 0);
    prop_assert_eq!(enc.blocked_streams(), 0);
    prop_assert_eq!(enc.known_received_count(), enc.table().insert_count());
    prop_assert_eq!(dec.insert_count(), enc.table().insert_count());
    prop_assert!(enc.table().size() <= enc.table().capacity());
    // Both tables hold the same entries.
    for abs in enc.table().first_index()..enc.table().insert_count() {
        prop_assert_eq!(enc.table().get(abs), dec.table().get(abs));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn encoder_decoder_roundtrip(
        capacity in prop_oneof![Just(0u64), Just(100), Just(220), Just(1000), Just(4096)],
        blocked in 0u64..4,
        plan in plan(),
        cuts in proptest::collection::vec(0usize..64, 1..8),
    ) {
        roundtrip(capacity, blocked, plan, cuts)?;
    }

    #[test]
    fn integer_roundtrip(v in 0u64..(1 << 62), prefix in 1u8..=8, flags in any::<u8>()) {
        let mut out = Vec::new();
        encode_int(&mut out, flags, prefix, v);
        prop_assert_eq!(decode_int(&out, prefix), Ok((v, out.len())));
        // Bits above the prefix are the caller's flags.
        if prefix < 8 {
            prop_assert_eq!(out[0] >> prefix, flags >> prefix);
        }
    }

    #[test]
    fn string_roundtrip(s in proptest::collection::vec(any::<u8>(), 0..300), prefix in 1u8..=7) {
        let mut out = Vec::new();
        encode_str(&mut out, 0, prefix, &s);
        prop_assert_eq!(decode_str(&out, prefix, 300), Ok((s.clone(), out.len())));
        let mut h = Vec::new();
        huffman::encode(&s, &mut h);
        prop_assert_eq!(h.len(), huffman::encoded_len(&s));
        let mut back = Vec::new();
        prop_assert_eq!(huffman::decode(&h, &mut back), Ok(()));
        prop_assert_eq!(back, s);
    }

    #[test]
    fn decoder_never_panics(
        enc_stream in proptest::collection::vec(any::<u8>(), 0..200),
        section in proptest::collection::vec(any::<u8>(), 0..200),
        cap in 0u64..5000,
    ) {
        let mut d = Decoder::new(cap, 4, 4096);
        let _ = d.on_encoder_stream(&enc_stream);
        let _ = d.decode(0, &section);
        let _ = d.take_instructions();
        let mut h = Vec::new();
        let _ = huffman::decode(&section, &mut h);
    }

    #[test]
    fn encoder_never_panics_on_decoder_stream(
        fields in proptest::collection::vec(field(), 0..10),
        dec_stream in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut e = Encoder::new(1000);
        e.apply_peer_settings(1000, 2, u64::MAX);
        let _ = e.encode(0, &fields);
        let _ = e.on_decoder_stream(&dec_stream);
        let _ = e.encode(4, &fields);
    }
}
