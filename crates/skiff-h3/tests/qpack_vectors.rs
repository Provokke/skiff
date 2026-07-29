//! QPACK against RFC 9204 Appendix B (the decoder side of every exchange,
//! byte for byte, including the decoder-stream instructions it must emit)
//! and against the error cases RFC 9204 requires.

use skiff_h3::qpack::{Decoded, Decoder, Encoder, Field, QpackError};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn fields(d: Decoded) -> Vec<(String, String)> {
    match d {
        Decoded::Fields(f) => f
            .into_iter()
            .map(|f| {
                (
                    String::from_utf8(f.name).unwrap(),
                    String::from_utf8(f.value).unwrap(),
                )
            })
            .collect(),
        Decoded::Blocked { .. } => panic!("unexpectedly blocked"),
    }
}

fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
    v.iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

/// The full Appendix B exchange, in order.
#[test]
fn rfc9204_appendix_b() {
    let mut d = Decoder::new(220, 16, 1 << 16);

    // B.1: Literal Field Line with Name Reference, static.
    let out = d
        .decode(0, &hex("0000 510b 2f69 6e64 6578 2e68 746d 6c"))
        .unwrap();
    assert_eq!(fields(out), pairs(&[(":path", "/index.html")]));
    assert!(d.take_instructions().is_empty());

    // B.2: Dynamic Table.
    d.on_encoder_stream(&hex(
        "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468",
    ))
    .unwrap();
    assert_eq!(d.table().capacity(), 220);
    assert_eq!(d.table().size(), 106);
    assert_eq!(d.insert_count(), 2);
    let out = d.decode(4, &hex("0381 10 11")).unwrap();
    assert_eq!(
        fields(out),
        pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")])
    );
    assert_eq!(
        d.take_instructions(),
        hex("84"),
        "Section Acknowledgment (stream=4)"
    );

    // B.3: Speculative Insert.
    d.on_encoder_stream(&hex(
        "4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565",
    ))
    .unwrap();
    assert_eq!(d.table().size(), 160);
    assert_eq!(
        d.take_instructions(),
        hex("01"),
        "Insert Count Increment (1)"
    );

    // B.4: the Duplicate is delayed, so the section on stream 8 blocks; the
    // stream is then cancelled.
    let section = hex("0500 80 c1 81");
    assert_eq!(
        d.decode(8, &section).unwrap(),
        Decoded::Blocked {
            required_insert_count: 4
        }
    );
    assert_eq!(d.blocked_streams(), 1);
    // What the section decodes to had the Duplicate arrived first:
    let mut late = d.clone();
    late.on_encoder_stream(&hex("02")).unwrap();
    assert_eq!(late.table().size(), 217);
    assert_eq!(
        fields(late.decode(8, &section).unwrap()),
        pairs(&[
            (":authority", "www.example.com"),
            (":path", "/"),
            ("custom-key", "custom-value")
        ])
    );
    assert_eq!(late.blocked_streams(), 0);
    d.cancel_stream(8);
    assert_eq!(d.blocked_streams(), 0);
    assert_eq!(
        d.take_instructions(),
        hex("48"),
        "Stream Cancellation (Stream=8)"
    );

    // The delayed Duplicate, then B.5: Insert With Name Reference (dynamic,
    // relative index 1) evicting the oldest entry.
    d.on_encoder_stream(&hex("02")).unwrap();
    assert_eq!(d.table().size(), 217);
    d.on_encoder_stream(&hex("810d 6375 7374 6f6d 2d76 616c 7565 32"))
        .unwrap();
    assert_eq!(d.table().size(), 215);
    assert_eq!(d.table().first_index(), 1);
    let e = d.table().get(4).unwrap();
    assert_eq!(
        (&e.name[..], &e.value[..]),
        (&b"custom-key"[..], &b"custom-value2"[..])
    );
    assert_eq!(
        d.take_instructions(),
        hex("02"),
        "Insert Count Increment (2)"
    );
}

/// Post-base references (the encoder never emits them, peers may): with
/// Base 0 every dynamic reference is post-base.
#[test]
fn post_base_references() {
    let mut d = Decoder::new(220, 0, 1 << 16);
    d.on_encoder_stream(&hex(
        "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468",
    ))
    .unwrap();
    // Required Insert Count 2 (encoded 3), Base = 2 - 1 - 1 = 0; post-base
    // indexed 0 and 1; post-base name reference 1 with the literal "x".
    let out = d.decode(0, &hex("0381 10 11 01 0178")).unwrap();
    assert_eq!(
        fields(out),
        pairs(&[
            (":authority", "www.example.com"),
            (":path", "/sample/path"),
            (":path", "x")
        ])
    );
    assert_eq!(d.take_instructions(), hex("80"));
}

#[test]
fn encoder_stream_split_at_every_byte() {
    let stream =
        hex("3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468");
    for cut in 0..=stream.len() {
        let mut d = Decoder::new(220, 0, 1 << 16);
        d.on_encoder_stream(&stream[..cut]).unwrap();
        d.on_encoder_stream(&stream[cut..]).unwrap();
        assert_eq!((d.insert_count(), d.table().size()), (2, 106), "cut {cut}");
    }
}

#[test]
fn decoder_errors() {
    let dec = |d: &mut Decoder, s: &str| d.decode(0, &hex(s));
    let mut d = Decoder::new(220, 1, 1 << 16);
    // Static index 99 does not exist.
    assert!(matches!(
        dec(&mut d, "0000 ff24"),
        Err(QpackError::DecompressionFailed(_))
    ));
    // Truncated literal.
    assert!(matches!(
        dec(&mut d, "0000 510b 2f69"),
        Err(QpackError::DecompressionFailed(_))
    ));
    // Required Insert Count with an empty table is fine (blocked); a second
    // blocked stream exceeds the limit of 1.
    assert!(matches!(dec(&mut d, "0200"), Ok(Decoded::Blocked { .. })));
    assert!(matches!(
        d.decode(4, &hex("0200")),
        Err(QpackError::DecompressionFailed("too many blocked streams"))
    ));
    // Encoded Required Insert Count beyond 2 * MaxEntries (2 * 6).
    assert!(matches!(
        dec(&mut d, "0d00"),
        Err(QpackError::DecompressionFailed(_))
    ));
    // Base below zero (sign set, delta >= RIC).
    let mut d = Decoder::new(220, 1, 1 << 16);
    d.on_encoder_stream(&hex("3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d"))
        .unwrap();
    assert!(matches!(
        d.decode(0, &hex("0281 80")),
        Err(QpackError::DecompressionFailed("invalid Base"))
    ));
    // Relative reference at or beyond the Required Insert Count.
    assert!(matches!(
        d.decode(0, &hex("0201 80")),
        Err(QpackError::DecompressionFailed(_))
    ));
    // Post-base reference >= RIC.
    assert!(matches!(
        d.decode(0, &hex("0200 10")),
        Err(QpackError::DecompressionFailed(_))
    ));
    // References to entries that exist but are at or above the declared
    // Required Insert Count (1) are invalid too (RFC 9204 2.2.3).
    let mut d = Decoder::new(220, 1, 1 << 16);
    d.on_encoder_stream(&hex(
        "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468",
    ))
    .unwrap();
    assert!(matches!(
        d.decode(0, &hex("0200 80")),
        Ok(Decoded::Fields(_))
    ));
    for bad in ["0201 80", "0200 10", "0200 0001 78"] {
        assert!(
            matches!(
                d.decode(0, &hex(bad)),
                Err(QpackError::DecompressionFailed(_))
            ),
            "{bad}"
        );
    }
    // No dynamic table: any Required Insert Count is invalid.
    let mut z = Decoder::new(0, 0, 1 << 16);
    assert!(matches!(
        z.decode(0, &hex("0100")),
        Err(QpackError::DecompressionFailed(_))
    ));
    // Section larger than the advertised limit.
    let mut small = Decoder::new(0, 0, 40);
    assert!(matches!(
        small.decode(0, &hex("0000 510b 2f69 6e64 6578 2e68 746d 6c")),
        Err(QpackError::FieldSectionTooLarge { .. })
    ));
}

#[test]
fn encoder_stream_errors() {
    let bad = |cap: u64, s: &str| {
        let mut d = Decoder::new(cap, 0, 1 << 16);
        d.on_encoder_stream(&hex(s))
    };
    // Capacity above the maximum we advertised.
    assert!(matches!(
        bad(100, "3f46"),
        Err(QpackError::EncoderStream(_))
    ));
    // Insert before any capacity was set (entry larger than capacity 0).
    assert!(matches!(
        bad(220, "c00f 7777 772e 6578 616d 706c 652e 636f 6d"),
        Err(QpackError::EncoderStream(_))
    ));
    // Invalid static name index (99).
    assert!(matches!(
        bad(220, "3fbd01 ff24 00"),
        Err(QpackError::EncoderStream(_))
    ));
    // Dynamic name reference / Duplicate with an empty table.
    assert!(matches!(
        bad(220, "3fbd01 8000"),
        Err(QpackError::EncoderStream(_))
    ));
    assert!(matches!(
        bad(220, "3fbd01 00"),
        Err(QpackError::EncoderStream(_))
    ));
    // A string longer than the maximum capacity is rejected before it is
    // buffered.
    // (Literal name of 286 bytes: 0x5f = 31, + 0xff 0x01 = 255.)
    assert!(matches!(
        bad(220, "3fbd01 5fff01"),
        Err(QpackError::EncoderStream(_))
    ));
}

#[test]
fn decoder_stream_errors() {
    let mut e = Encoder::new(4096);
    e.apply_peer_settings(4096, 10, u64::MAX);
    // Section Acknowledgment with nothing outstanding.
    assert!(matches!(
        e.on_decoder_stream(&hex("84")),
        Err(QpackError::DecoderStream(_))
    ));
    let mut e = Encoder::new(4096);
    e.apply_peer_settings(4096, 10, u64::MAX);
    // Insert Count Increment of zero, and beyond what was inserted.
    assert!(matches!(
        e.on_decoder_stream(&hex("00")),
        Err(QpackError::DecoderStream(_))
    ));
    let mut e = Encoder::new(4096);
    e.apply_peer_settings(4096, 10, u64::MAX);
    assert!(matches!(
        e.on_decoder_stream(&hex("01")),
        Err(QpackError::DecoderStream(_))
    ));
}

/// The encoder's dynamic-table bookkeeping through acknowledgments.
#[test]
fn encoder_acknowledgments_and_blocking() {
    let f = |n: &str, v: &str| Field::new(n.as_bytes(), v.as_bytes());
    let mut e = Encoder::new(4096);
    let mut d = Decoder::new(4096, 1, u64::MAX);
    // Before the peer's settings, nothing is inserted.
    let s = e.encode(0, &[f("x-a", "1")]).unwrap();
    assert!(e.take_instructions().is_empty());
    assert_eq!(fields(d.decode(0, &s).unwrap()), pairs(&[("x-a", "1")]));
    e.apply_peer_settings(4096, 1, u64::MAX);
    // Stream 4 inserts and references x-a: 1 (blocking, allowed: 1 stream).
    let s4 = e.encode(4, &[f("x-a", "1")]).unwrap();
    let ins = e.take_instructions();
    assert_eq!(e.blocked_streams(), 1);
    // Stream 8 may not block: the entry is unacknowledged, so a literal.
    let s8 = e.encode(8, &[f("x-a", "1")]).unwrap();
    assert_eq!(e.blocked_streams(), 1);
    assert_eq!(fields(d.decode(8, &s8).unwrap()), pairs(&[("x-a", "1")]));
    assert_eq!(
        d.decode(4, &s4).unwrap(),
        Decoded::Blocked {
            required_insert_count: 1
        }
    );
    d.on_encoder_stream(&ins).unwrap();
    assert_eq!(fields(d.decode(4, &s4).unwrap()), pairs(&[("x-a", "1")]));
    e.on_decoder_stream(&d.take_instructions()).unwrap();
    assert_eq!(e.known_received_count(), 1);
    assert_eq!((e.blocked_streams(), e.unacknowledged_sections()), (0, 0));
    // Now acknowledged: stream 12 references it without blocking.
    let s12 = e.encode(12, &[f("x-a", "1")]).unwrap();
    assert!(e.take_instructions().is_empty());
    assert_eq!(s12, [0x02, 0x00, 0x80]);
    assert_eq!(fields(d.decode(12, &s12).unwrap()), pairs(&[("x-a", "1")]));
    // Never-indexed fields are not inserted and keep the N bit.
    let s16 = e
        .encode(
            16,
            &[Field {
                name: b"authorization".to_vec(),
                value: b"secret".to_vec(),
                never_index: true,
            }],
        )
        .unwrap();
    assert!(e.take_instructions().is_empty());
    match d.decode(16, &s16).unwrap() {
        Decoded::Fields(v) => assert!(v[0].never_index),
        Decoded::Blocked { .. } => panic!("blocked"),
    }
    // ...even when the static table holds the whole field (RFC 9204 4.5.4:
    // always a literal). Found by the qpack_decode fuzz target's oracle.
    let f = Field {
        name: b":method".to_vec(),
        value: b"GET".to_vec(),
        never_index: true,
    };
    let s20 = e.encode(20, std::slice::from_ref(&f)).unwrap();
    // No dynamic references; then a literal with static name reference and
    // the N bit (01 N=1 T=1, index 17 = 15 + 2), then the value.
    assert_eq!(s20[..4], [0x00, 0x00, 0x7f, 0x02]);
    match d.decode(20, &s20).unwrap() {
        Decoded::Fields(v) => assert_eq!(v, [f]),
        Decoded::Blocked { .. } => panic!("blocked"),
    }
}

/// Entries referenced by unacknowledged sections are never evicted.
#[test]
fn encoder_never_evicts_referenced_entries() {
    let mut e = Encoder::new(200);
    e.apply_peer_settings(200, 100, u64::MAX);
    let mut d = Decoder::new(200, 100, u64::MAX);
    d.on_encoder_stream(&e.take_instructions()).unwrap();
    // Each entry is 32 + 4 + 60 = 96 bytes: two fit in 200.
    let field = |i: u32| Field::new(format!("x-{i:02}"), vec![b'a' + i as u8; 60]);
    let s0 = e.encode(0, &[field(0)]).unwrap();
    let s4 = e.encode(4, &[field(1)]).unwrap();
    assert_eq!(e.table().len(), 2);
    // A third insert would evict entry 0, which stream 0 still references.
    let s8 = e.encode(8, &[field(2)]).unwrap();
    assert_eq!(e.table().len(), 2);
    assert_eq!(e.table().first_index(), 0);
    d.on_encoder_stream(&e.take_instructions()).unwrap();
    for (id, s) in [(0, &s0), (4, &s4), (8, &s8)] {
        assert!(matches!(d.decode(id, s).unwrap(), Decoded::Fields(_)));
    }
    e.on_decoder_stream(&d.take_instructions()).unwrap();
    // Everything acknowledged: the next insert may evict.
    let s12 = e.encode(12, &[field(3)]).unwrap();
    assert_eq!(e.table().first_index(), 1);
    d.on_encoder_stream(&e.take_instructions()).unwrap();
    match d.decode(12, &s12).unwrap() {
        Decoded::Fields(v) => assert_eq!(v, vec![field(3)]),
        Decoded::Blocked { .. } => panic!("blocked"),
    }
}

/// An acknowledged insert stays while a section that references it is
/// unacknowledged (the decoder may not have decoded it yet).
#[test]
fn encoder_keeps_acknowledged_entries_still_referenced() {
    let mut e = Encoder::new(200);
    e.apply_peer_settings(200, 100, u64::MAX);
    let mut d = Decoder::new(200, 100, u64::MAX);
    let field = |i: u32| Field::new(format!("x-{i:02}"), vec![b'a' + i as u8; 60]);
    let s0 = e.encode(0, &[field(0)]).unwrap();
    // The decoder receives the insert (Insert Count Increment) but has not
    // read stream 0 yet.
    d.on_encoder_stream(&e.take_instructions()).unwrap();
    e.on_decoder_stream(&d.take_instructions()).unwrap();
    let s4 = e.encode(4, &[field(1)]).unwrap();
    d.on_encoder_stream(&e.take_instructions()).unwrap();
    e.on_decoder_stream(&d.take_instructions()).unwrap();
    assert_eq!(e.known_received_count(), 2);
    // Inserting a third entry would evict entry 0, still referenced by s0.
    let s8 = e.encode(8, &[field(2)]).unwrap();
    assert_eq!((e.table().first_index(), e.table().len()), (0, 2));
    assert!(e.take_instructions().is_empty());
    for (id, s, i) in [(0, &s0, 0), (4, &s4, 1), (8, &s8, 2)] {
        match d.decode(id, s).unwrap() {
            Decoded::Fields(v) => assert_eq!(v, vec![field(i)]),
            Decoded::Blocked { .. } => panic!("blocked"),
        }
    }
}

/// An unreferenced insert is still not evictable until the decoder has
/// acknowledged it (RFC 9204 2.1.1).
#[test]
fn encoder_never_evicts_unacknowledged_inserts() {
    let mut e = Encoder::new(200);
    // No blocked streams: inserts are made but never referenced until
    // acknowledged.
    e.apply_peer_settings(200, 0, u64::MAX);
    let mut d = Decoder::new(200, 0, u64::MAX);
    let field = |i: u32| Field::new(format!("x-{i:02}"), vec![b'a' + i as u8; 60]);
    let s0 = e.encode(0, &[field(0)]).unwrap();
    let s4 = e.encode(4, &[field(1)]).unwrap();
    let s8 = e.encode(8, &[field(2)]).unwrap();
    assert_eq!((e.table().first_index(), e.table().len()), (0, 2));
    assert_eq!(e.unacknowledged_sections(), 0);
    d.on_encoder_stream(&e.take_instructions()).unwrap();
    for (id, s) in [(0, &s0), (4, &s4), (8, &s8)] {
        assert!(matches!(d.decode(id, s).unwrap(), Decoded::Fields(_)));
    }
    e.on_decoder_stream(&d.take_instructions()).unwrap();
    assert_eq!(e.known_received_count(), 2);
    // Acknowledged and unreferenced: now entry 0 may be evicted.
    let s12 = e.encode(12, &[field(2)]).unwrap();
    assert_eq!((e.table().first_index(), e.table().len()), (1, 2));
    d.on_encoder_stream(&e.take_instructions()).unwrap();
    assert!(matches!(d.decode(12, &s12).unwrap(), Decoded::Fields(_)));
}
