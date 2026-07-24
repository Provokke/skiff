//! HTTP/3 over two in-memory skiff `Connection`s (instant, lossless
//! delivery on a virtual clock): requests and responses with bodies and
//! trailers, the QPACK dynamic table in both directions, GOAWAY, and the
//! stream and connection errors RFC 9114 requires, provoked with raw
//! frames from a peer that bypasses `H3Connection`.

mod common;

use common::*;
use skiff_h3::frame::{error_code::*, frame_type, put_varint, stream_type, Settings};
use skiff_h3::qpack::{Encoder, Field};
use skiff_h3::{H3Config, H3Connection, H3Event};
use skiff_quic::{ApiError, CloseReason, Connection, TransportConfig};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Client and server connections exchanging datagrams instantly.
struct Pair {
    client: Connection,
    server: Option<Connection>,
    now: Instant,
    buf: Vec<u8>,
}

impl Pair {
    fn new() -> Self {
        let (c, _) = tls();
        let now = Instant::now();
        let client = Connection::connect(c, "localhost", TransportConfig::default(), now).unwrap();
        Self {
            client,
            server: None,
            now,
            buf: vec![0; 65536],
        }
    }

    /// Delivers everything both sides want to send; advances the clock to
    /// the next timer when idle. Returns false when nothing can happen.
    /// With nothing in flight the next timer is the idle timeout, so loops
    /// that only wait for traffic to settle use [`Pair::exchange`].
    fn step(&mut self) -> bool {
        if self.exchange() {
            return true;
        }
        self.advance()
    }

    /// Delivers everything both sides want to send without moving the
    /// clock; returns whether any datagram moved.
    fn exchange(&mut self) -> bool {
        let mut moved = false;
        loop {
            let n = self.client.send(&mut self.buf, self.now);
            if n == 0 {
                break;
            }
            moved = true;
            let mut d = self.buf[..n].to_vec();
            if self.server.is_none() {
                let (_, s) = tls();
                self.server = Connection::accept(s, TransportConfig::default(), &d, self.now).ok();
            }
            if let Some(s) = self.server.as_mut() {
                s.recv(&mut d, self.now);
            }
        }
        if let Some(s) = self.server.as_mut() {
            loop {
                let n = s.send(&mut self.buf, self.now);
                if n == 0 {
                    break;
                }
                moved = true;
                let mut d = self.buf[..n].to_vec();
                self.client.recv(&mut d, self.now);
            }
        }
        moved
    }

    /// Moves the clock to the next timer and fires it; false if none.
    fn advance(&mut self) -> bool {
        let next = [
            self.client.timeout(),
            self.server.as_ref().and_then(Connection::timeout),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(t) = next else {
            return false;
        };
        self.now = t.max(self.now + Duration::from_micros(1));
        if self.client.timeout().is_some_and(|x| x <= self.now) {
            self.client.on_timeout(self.now);
        }
        if let Some(s) = self.server.as_mut() {
            if s.timeout().is_some_and(|x| x <= self.now) {
                s.on_timeout(self.now);
            }
        }
        true
    }
}

/// Runs client and server apps until `done` or a 10 s virtual budget.
fn run(
    p: &mut Pair,
    ch: &mut H3Connection,
    sh: &mut H3Connection,
    client: &mut Client,
    server: &mut Server,
    mut done: impl FnMut(&Client, &Server) -> bool,
) {
    let start = p.now;
    while !done(client, server) {
        assert!(p.now - start < Duration::from_secs(10), "budget exceeded");
        client.poll(ch, &mut p.client, p.now);
        if let Some(s) = p.server.as_mut() {
            server.poll(sh, s, p.now);
        }
        if !p.step() {
            break;
        }
    }
}

fn setup() -> (Pair, H3Connection, H3Connection, Client, Server) {
    (
        Pair::new(),
        H3Connection::new(H3Config::default()),
        H3Connection::new(H3Config::default()),
        Client::default(),
        Server::default(),
    )
}

#[test]
fn get_requests_and_settings() {
    let (mut p, mut ch, mut sh, mut client, mut server) = setup();
    for n in [0usize, 1, 1000, 70_000, 300_000] {
        client.get(&format!("/size/{n}"));
    }
    client.get("/missing");
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.finished() == 6,
    );
    let paths: BTreeMap<u64, String> = client.sent[..5]
        .iter()
        .zip([0usize, 1, 1000, 70_000, 300_000])
        .map(|(id, n)| (*id, format!("/size/{n}")))
        .collect();
    client.verify_sizes(&paths);
    let missing = &client.responses[&client.sent[5]];
    assert_eq!(value(&missing.headers, ":status"), Some(&b"404"[..]));
    assert_eq!(
        value(&client.responses[&client.sent[3]].headers, "content-length"),
        Some(&b"70000"[..])
    );
    let expect = Settings {
        qpack_max_table_capacity: 4096,
        qpack_blocked_streams: 16,
        max_field_section_size: Some(65536),
        enable_connect_protocol: false,
    };
    assert_eq!(ch.peer_settings(), Some(&expect));
    assert_eq!(sh.peer_settings(), Some(&expect));
    assert_eq!(server.served, 6);
}

/// Repeated non-static fields go through the dynamic table both ways and
/// every section is acknowledged. Requests sent before the server's
/// SETTINGS arrive must use the static table only (RFC 9114 7.2.4.2), so
/// the first request completes before the other 39 are queued.
#[test]
fn dynamic_table_in_both_directions() {
    let (mut p, mut ch, mut sh, mut client, mut server) = setup();
    client.get("/size/100");
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.finished() == 1,
    );
    assert!(ch.peer_settings().is_some());
    for i in 1..40 {
        client.get(&format!("/size/{}", 100 + i % 3));
    }
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.finished() == 40,
    );
    let paths: BTreeMap<u64, String> = client
        .sent
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, format!("/size/{}", 100 + i % 3)))
        .collect();
    client.verify_sizes(&paths);
    // Let the last acknowledgments arrive (without advancing the clock).
    for _ in 0..50 {
        ch.poll(&mut p.client, p.now).unwrap();
        sh.poll(p.server.as_mut().unwrap(), p.now).unwrap();
        if !p.exchange() {
            break;
        }
    }
    assert_eq!(p.client.close_reason(), None);
    for (name, h3) in [("client", &ch), ("server", &sh)] {
        let e = h3.qpack_encoder();
        assert!(e.table().insert_count() >= 2, "{name} encoder inserted");
        assert_eq!(e.unacknowledged_sections(), 0, "{name}");
        assert_eq!(e.known_received_count(), e.table().insert_count(), "{name}");
    }
    assert_eq!(
        ch.qpack_decoder().insert_count(),
        sh.qpack_encoder().table().insert_count()
    );
    assert_eq!(
        sh.qpack_decoder().insert_count(),
        ch.qpack_encoder().table().insert_count()
    );
}

#[test]
fn post_echo_with_trailers() {
    let (mut p, mut ch, mut sh, mut client, mut server) = setup();
    let big = body_for("upload", 1_500_000);
    client.post("/echo", big.clone(), Vec::new());
    client.post("/echo", b"short".to_vec(), vec![f("x-checksum", "abc123")]);
    client.post("/echo", Vec::new(), Vec::new());
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.finished() == 3,
    );
    let r = &client.responses[&client.sent[0]];
    assert!(r.done && r.body == big, "1.5 MB echo intact");
    assert_eq!(value(&r.headers, "content-length"), Some(&b"1500000"[..]));
    let r = &client.responses[&client.sent[1]];
    assert_eq!(r.body, b"short");
    assert_eq!(value(&r.trailers, "x-checksum"), Some(&b"abc123"[..]));
    let r = &client.responses[&client.sent[2]];
    assert!(r.done && r.body.is_empty());
}

#[test]
fn goaway_stops_new_requests() {
    let (mut p, mut ch, mut sh, mut client, mut server) = setup();
    client.get("/goaway");
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.finished() == 1 && c.going_away,
    );
    assert_eq!(ch.goaway_received(), Some(4), "first unseen request stream");
    client.get("/size/1");
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.queue.is_empty(),
    );
    assert_eq!(client.sent.len(), 1, "no request after GOAWAY");
    assert_eq!(server.served, 1);
}

/// A raw QUIC client (no `H3Connection`) talking to an HTTP/3 server.
struct Raw {
    p: Pair,
    sh: H3Connection,
    server: Server,
}

impl Raw {
    fn new() -> Self {
        let mut r = Self {
            p: Pair::new(),
            sh: H3Connection::new(H3Config::default()),
            server: Server::default(),
        };
        r.drive(|p| p.client.is_handshake_complete() && p.server.is_some());
        r
    }

    fn drive(&mut self, mut done: impl FnMut(&mut Pair) -> bool) {
        let start = self.p.now;
        while !done(&mut self.p) && self.p.now - start < Duration::from_secs(5) {
            while self.p.client.poll_event().is_some() {}
            if let Some(s) = self.p.server.as_mut() {
                self.server.poll(&mut self.sh, s, self.p.now);
            }
            if !self.p.step() {
                break;
            }
        }
    }

    /// Runs the server application and exchanges datagrams until no more
    /// move, without advancing the clock (so no idle timeout can fire).
    fn settle(&mut self) {
        for _ in 0..1000 {
            while self.p.client.poll_event().is_some() {}
            if let Some(s) = self.p.server.as_mut() {
                self.server.poll(&mut self.sh, s, self.p.now);
            }
            if !self.p.exchange() {
                break;
            }
        }
    }

    /// Asserts the client saw no close of any kind.
    fn assert_open(&self) {
        assert_eq!(self.p.client.close_reason(), None);
        assert!(!self.p.client.is_closing());
    }

    /// Opens a client stream and writes `bytes` (with FIN if asked).
    fn stream(&mut self, bidi: bool, bytes: &[u8], fin: bool) -> u64 {
        let id = self.p.client.open_stream(bidi).unwrap();
        assert_eq!(
            self.p.client.stream_write(id, bytes, fin).unwrap(),
            bytes.len()
        );
        id
    }

    /// The control stream preface with an empty SETTINGS frame.
    fn control(&mut self) -> u64 {
        let mut b = vec![stream_type::CONTROL as u8];
        skiff_h3::frame::encode_frame(&mut b, frame_type::SETTINGS, &Settings::default().encode());
        self.stream(false, &b, false)
    }

    fn closed_with(&mut self) -> Option<u64> {
        self.drive(|p| p.client.is_closing());
        match self.p.client.close_reason() {
            Some(CloseReason::PeerApplication { code, .. }) => Some(*code),
            _ => None,
        }
    }
}

fn headers_frame(fields: &[skiff_h3::qpack::Field]) -> Vec<u8> {
    let block = Encoder::new(0).encode(0, fields).unwrap();
    let mut b = Vec::new();
    skiff_h3::frame::encode_frame(&mut b, frame_type::HEADERS, &block);
    b
}

#[test]
fn connection_errors_on_control_streams() {
    // DATA on the control stream.
    let mut r = Raw::new();
    let id = r.control();
    let mut b = Vec::new();
    skiff_h3::frame::encode_frame(&mut b, frame_type::DATA, b"x");
    r.p.client.stream_write(id, &b, false).unwrap();
    assert_eq!(r.closed_with(), Some(H3_FRAME_UNEXPECTED));

    // First control frame not SETTINGS.
    let mut r = Raw::new();
    let mut b = vec![stream_type::CONTROL as u8];
    skiff_h3::frame::encode_frame(&mut b, frame_type::GOAWAY, &[0]);
    r.stream(false, &b, false);
    assert_eq!(r.closed_with(), Some(H3_MISSING_SETTINGS));

    // Two control streams.
    let mut r = Raw::new();
    r.control();
    r.control();
    assert_eq!(r.closed_with(), Some(H3_STREAM_CREATION_ERROR));

    // Closing the control stream.
    let mut r = Raw::new();
    let id = r.control();
    r.p.client.stream_write(id, &[], true).unwrap();
    assert_eq!(r.closed_with(), Some(H3_CLOSED_CRITICAL_STREAM));

    // STOP_SENDING on the server's control stream (its first uni stream, 3).
    let mut r = Raw::new();
    r.control();
    r.settle();
    r.p.client.stream_stop(3, H3_REQUEST_CANCELLED).unwrap();
    assert_eq!(r.closed_with(), Some(H3_CLOSED_CRITICAL_STREAM));

    // A reserved HTTP/2 setting.
    let mut r = Raw::new();
    let mut b = vec![stream_type::CONTROL as u8];
    skiff_h3::frame::encode_frame(&mut b, frame_type::SETTINGS, &[0x02, 0x00]);
    r.stream(false, &b, false);
    assert_eq!(r.closed_with(), Some(H3_SETTINGS_ERROR));

    // A push stream from a client.
    let mut r = Raw::new();
    r.stream(false, &[stream_type::PUSH as u8, 0], false);
    assert_eq!(r.closed_with(), Some(H3_STREAM_CREATION_ERROR));

    // An invalid QPACK encoder instruction (capacity above the maximum).
    let mut r = Raw::new();
    let mut b = vec![stream_type::QPACK_ENCODER as u8];
    b.extend([0x3f, 0xe1, 0x3f]); // Set Dynamic Table Capacity = 8192
    r.stream(false, &b, false);
    assert_eq!(r.closed_with(), Some(skiff_h3::qpack::ENCODER_STREAM_ERROR));

    // Unknown (grease) frame types on the control stream are skipped.
    let mut r = Raw::new();
    let id = r.control();
    let mut b = Vec::new();
    skiff_h3::frame::encode_frame(&mut b, 0x21, b"grease");
    skiff_h3::frame::encode_frame(&mut b, 0x1f * 7 + 0x21, &[]);
    r.p.client.stream_write(id, &b, false).unwrap();
    r.settle();
    r.assert_open();
    // ...and framing stays in step after the skip.
    let mut b = Vec::new();
    skiff_h3::frame::encode_frame(&mut b, frame_type::DATA, b"x");
    r.p.client.stream_write(id, &b, false).unwrap();
    assert_eq!(r.closed_with(), Some(H3_FRAME_UNEXPECTED));

    // An unknown stream type is ignored (STOP_SENDING), not an error.
    let mut r = Raw::new();
    let mut b = Vec::new();
    put_varint(&mut b, 0x21);
    b.extend([1, 2, 3]);
    r.stream(false, &b, false);
    r.settle();
    r.assert_open();
}

#[test]
fn request_stream_errors() {
    // DATA before HEADERS: connection error.
    let mut r = Raw::new();
    r.control();
    let mut b = Vec::new();
    skiff_h3::frame::encode_frame(&mut b, frame_type::DATA, b"x");
    r.stream(true, &b, true);
    assert_eq!(r.closed_with(), Some(H3_FRAME_UNEXPECTED));

    // A frame truncated by the end of the stream.
    let mut r = Raw::new();
    r.control();
    let mut b = headers_frame(&get("/size/1"));
    b.truncate(b.len() - 1);
    r.stream(true, &b, true);
    assert_eq!(r.closed_with(), Some(H3_FRAME_ERROR));

    // SETTINGS on a request stream.
    let mut r = Raw::new();
    r.control();
    let mut b = Vec::new();
    skiff_h3::frame::encode_frame(&mut b, frame_type::SETTINGS, &[]);
    r.stream(true, &b, true);
    assert_eq!(r.closed_with(), Some(H3_FRAME_UNEXPECTED));

    // Malformed requests (RFC 9114 4.1.2, 4.2, 4.3.1): each is a stream
    // error H3_MESSAGE_ERROR; the connection survives and a later request
    // is served.
    let mut r = Raw::new();
    r.control();
    let with = |extra: Field| {
        let mut v = get("/size/1");
        v.push(extra);
        v
    };
    let malformed: Vec<(&str, Vec<Field>)> = vec![
        ("uppercase name", with(f("X-Upper", "1"))),
        ("connection-specific field", with(f("connection", "close"))),
        ("te other than trailers", with(f("te", "gzip"))),
        (
            "pseudo-header after a regular field",
            with(f(":scheme", "https")),
        ),
        (
            "duplicate pseudo-header",
            vec![
                f(":method", "GET"),
                f(":scheme", "https"),
                f(":path", "/"),
                f(":path", "/"),
            ],
        ),
        (
            "response pseudo-header in a request",
            vec![
                f(":method", "GET"),
                f(":scheme", "https"),
                f(":path", "/"),
                f(":status", "200"),
            ],
        ),
        (
            "missing :method",
            vec![f(":scheme", "https"), f(":path", "/")],
        ),
        (
            "missing :path",
            vec![f(":method", "GET"), f(":scheme", "https")],
        ),
        (
            "empty :path",
            vec![f(":method", "GET"), f(":scheme", "https"), f(":path", "")],
        ),
        ("NUL in a value", with(f("x-bad", "a\0b"))),
    ];
    for (i, (what, fields)) in malformed.iter().enumerate() {
        let id = r.stream(true, &headers_frame(fields), true);
        r.settle();
        assert_eq!(r.server.resets.len(), i + 1, "{what}: no stream error");
        assert_eq!(r.server.resets[i], (id, H3_MESSAGE_ERROR), "{what}");
        r.assert_open();
    }
    // Content-Length must equal the DATA received (RFC 9114 4.1.2). Excess
    // data is an error before the stream ends (no FIN in that case); "4, 3"
    // would pass if only the last value were checked.
    let body_cases: [(&str, &str, &[u8], bool); 4] = [
        ("body shorter than content-length", "5", b"abc", true),
        ("body longer than content-length", "2", b"abc", false),
        ("non-numeric content-length", "3x", b"abc", true),
        ("disagreeing content-length list", "4, 3", b"abc", true),
    ];
    for (what, cl, body, fin) in body_cases {
        let mut b = headers_frame(&with(f("content-length", cl)));
        skiff_h3::frame::encode_frame(&mut b, frame_type::DATA, body);
        let before = r.server.resets.len();
        let id = r.stream(true, &b, fin);
        r.settle();
        assert_eq!(r.server.resets.len(), before + 1, "{what}: no stream error");
        assert_eq!(
            r.server.resets.last(),
            Some(&(id, H3_MESSAGE_ERROR)),
            "{what}"
        );
        r.assert_open();
    }
    assert_eq!(r.server.served, 0);
    // A request without HEADERS (FIN only): H3_REQUEST_INCOMPLETE.
    let id2 = r.stream(true, &[], true);
    r.settle();
    assert_eq!(r.server.resets.last(), Some(&(id2, H3_REQUEST_INCOMPLETE)));
    // Unknown frame types on a request stream are skipped.
    let mut b = Vec::new();
    skiff_h3::frame::encode_frame(&mut b, 0x21, b"grease");
    b.extend(headers_frame(&get("/size/1")));
    r.stream(true, &b, true);
    r.settle();
    assert_eq!(r.server.served, 1);
    // A matching Content-Length (as a list of equal values) is accepted.
    let mut b = headers_frame(&with(f("content-length", "3, 3")));
    skiff_h3::frame::encode_frame(&mut b, frame_type::DATA, b"abc");
    r.stream(true, &b, true);
    r.settle();
    assert_eq!(r.server.served, 2);
    r.assert_open();
}

/// After the server's GOAWAY, a request on a stream at or above the GOAWAY
/// ID is rejected with H3_REQUEST_REJECTED (RFC 9114 5.2) and not served.
#[test]
fn requests_after_goaway_are_rejected() {
    let mut r = Raw::new();
    r.control();
    r.stream(true, &headers_frame(&get("/goaway")), true);
    r.settle();
    assert_eq!(r.server.served, 1);
    let late = r.stream(true, &headers_frame(&get("/size/1")), true);
    r.settle();
    assert_eq!(r.server.served, 1, "request after GOAWAY was served");
    let mut buf = [0u8; 64];
    assert_eq!(
        r.p.client.stream_read(late, &mut buf),
        Err(ApiError::ResetByPeer(H3_REQUEST_REJECTED))
    );
    r.assert_open();
}

/// RFC 9204 2.2.2.2 / 4.4.2: a request stream blocked on QPACK inserts that
/// the peer resets leaves the decoder's blocked set (a Stream Cancellation
/// goes out), is reported as a Reset, and the late inserts still apply.
#[test]
fn reset_of_a_qpack_blocked_request_is_cancelled() {
    let mut r = Raw::new();
    r.control();
    r.settle();
    let mut enc = Encoder::new(4096);
    enc.apply_peer_settings(4096, 16, u64::MAX);
    let id = r.p.client.open_stream(true).unwrap();
    let block = enc.encode(id, &get("/size/1")).unwrap();
    assert_ne!(block[0], 0, "the section must reference inserts");
    let mut b = Vec::new();
    skiff_h3::frame::encode_frame(&mut b, frame_type::HEADERS, &block);
    r.p.client.stream_write(id, &b, false).unwrap();
    r.settle();
    assert_eq!(r.sh.qpack_decoder().blocked_streams(), 1);
    r.p.client.stream_reset(id, H3_REQUEST_CANCELLED).unwrap();
    r.settle();
    assert_eq!(
        r.sh.qpack_decoder().blocked_streams(),
        0,
        "reset stream still blocked"
    );
    assert_eq!(r.server.resets, vec![(id, H3_REQUEST_CANCELLED)]);
    // The inserts arrive after the reset.
    let mut e = vec![stream_type::QPACK_ENCODER as u8];
    e.extend(enc.take_instructions());
    r.stream(false, &e, false);
    r.settle();
    assert_eq!(
        r.sh.qpack_decoder().insert_count(),
        enc.table().insert_count()
    );
    assert_eq!(r.server.served, 0);
    r.assert_open();
}

/// Delivers datagrams and fires timers that are due within a second (so
/// the idle timeout never fires) until nothing moves, running `apps`
/// before every round.
fn pump(p: &mut Pair, mut apps: impl FnMut(&mut Pair)) {
    let start = p.now;
    loop {
        assert!(p.now - start < Duration::from_secs(20), "budget exceeded");
        apps(p);
        if p.exchange() {
            continue;
        }
        let next = [
            p.client.timeout(),
            p.server.as_ref().and_then(Connection::timeout),
        ]
        .into_iter()
        .flatten()
        .min();
        match next {
            Some(t) if t < p.now + Duration::from_secs(1) => {
                p.advance();
            }
            _ => break,
        }
    }
}

/// A request body the server application does not read is buffered only
/// up to the high-water mark, so QUIC flow control stops the client; the
/// whole body still arrives once the application reads it.
#[test]
fn unread_request_body_is_bounded_by_flow_control() {
    let (mut p, mut ch, mut sh, mut client, mut server) = setup();
    client.get("/size/1");
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.finished() == 1,
    );
    let body = body_for("sink", 3_000_000);
    let fields = [
        f(":method", "POST"),
        f(":scheme", "https"),
        f(":authority", "localhost"),
        f(":path", "/sink"),
    ];
    let id = ch.send_request(&mut p.client, &fields, false).unwrap();
    ch.send_data(&mut p.client, id, &body, true).unwrap();
    let sent_before = p.client.stats().bytes_sent;
    let mut finished = false;
    let mut events = |p: &mut Pair, ch: &mut H3Connection, sh: &mut H3Connection| {
        ch.poll(&mut p.client, p.now).unwrap();
        while ch.poll_event().is_some() {}
        sh.poll(p.server.as_mut().unwrap(), p.now).unwrap();
        while let Some(ev) = sh.poll_event() {
            finished |= ev == H3Event::Finished { stream_id: id };
        }
    };
    pump(&mut p, |p| events(p, &mut ch, &mut sh));
    let sent = p.client.stats().bytes_sent - sent_before;
    assert!(
        sent < 2_000_000,
        "client sent {sent} bytes to a server that reads nothing"
    );
    let mut got = Vec::new();
    let mut buf = vec![0u8; 100_000];
    let mut end = false;
    while !end {
        pump(&mut p, |p| events(p, &mut ch, &mut sh));
        let before = got.len();
        loop {
            let (n, e) = sh
                .recv_body(p.server.as_mut().unwrap(), id, &mut buf)
                .unwrap();
            got.extend_from_slice(&buf[..n]);
            end = e;
            if e || n == 0 {
                break;
            }
        }
        assert!(
            end || got.len() > before,
            "no progress at {} bytes",
            got.len()
        );
    }
    // The last read queued the Finished event.
    events(&mut p, &mut ch, &mut sh);
    assert!(finished);
    assert!(got == body, "3 MB body intact");
    assert_eq!(p.client.close_reason(), None);
}

/// A response the server application never finishes is cancelled by the
/// client; the server sees the reset and the client stops tracking it.
#[test]
fn client_cancels_request() {
    let (mut p, mut ch, mut sh, mut client, mut server) = setup();
    client.get("/size/1");
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.finished() == 1,
    );
    // Open a request whose body never ends, let it reach the server (by
    // exchanging datagrams only: advancing the clock with nothing in flight
    // would jump to the idle timeout), then cancel it.
    let id = ch
        .send_request(&mut p.client, &get("/echo"), false)
        .unwrap();
    ch.send_data(&mut p.client, id, b"partial", false).unwrap();
    for _ in 0..5 {
        ch.poll(&mut p.client, p.now).unwrap();
        p.exchange();
        server.poll(&mut sh, p.server.as_mut().unwrap(), p.now);
    }
    assert_eq!(sh.active_requests(), 1, "server is waiting for the body");
    assert_eq!(p.client.close_reason(), None);
    ch.reset_stream(&mut p.client, id, H3_REQUEST_CANCELLED)
        .unwrap();
    assert_eq!(ch.active_requests(), 0, "client forgot the stream");
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |_, s| !s.resets.is_empty(),
    );
    assert_eq!(server.resets, vec![(id, H3_REQUEST_CANCELLED)]);
    assert_eq!(ch.poll_event(), None);
    assert!(!client.responses.contains_key(&id));
    assert_eq!(p.client.close_reason(), None);
}

#[test]
fn graceful_close() {
    let (mut p, mut ch, mut sh, mut client, mut server) = setup();
    client.get("/size/10");
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.finished() == 1,
    );
    ch.close(&mut p.client, p.now);
    for _ in 0..20 {
        p.step();
    }
    sh.poll(p.server.as_mut().unwrap(), p.now).unwrap();
    let mut closed = None;
    while let Some(ev) = sh.poll_event() {
        if let H3Event::Closed(r) = ev {
            closed = Some(r);
        }
    }
    assert!(matches!(
        closed,
        Some(CloseReason::PeerApplication {
            code: H3_NO_ERROR,
            ..
        })
    ));
    assert!(sh.send_goaway(p.server.as_mut().unwrap()).is_err());
}

// ----- a raw server against an `H3Connection` client ---------------------------

/// An `H3Connection` client talking to a QUIC server that writes HTTP/3
/// frames by hand, so malformed responses can be provoked.
struct RawSrv {
    p: Pair,
    ch: H3Connection,
    events: Vec<H3Event>,
    err: Option<skiff_h3::H3Error>,
}

impl RawSrv {
    fn new() -> Self {
        let mut s = Self {
            p: Pair::new(),
            ch: H3Connection::new(H3Config::default()),
            events: Vec::new(),
            err: None,
        };
        let start = s.p.now;
        while !s
            .p
            .server
            .as_ref()
            .is_some_and(Connection::is_handshake_complete)
            || !s.p.client.is_handshake_complete()
        {
            s.settle();
            assert!(s.p.now - start < Duration::from_secs(5), "no handshake");
            if !s.p.step() {
                break;
            }
        }
        // The server's control stream with an empty SETTINGS frame.
        let mut b = vec![stream_type::CONTROL as u8];
        skiff_h3::frame::encode_frame(&mut b, frame_type::SETTINGS, &Settings::default().encode());
        let c = s.p.server.as_mut().unwrap();
        let id = c.open_stream(false).unwrap();
        c.stream_write(id, &b, false).unwrap();
        s.settle();
        assert!(s.ch.is_ready(), "client not ready");
        s
    }

    /// Runs the client and exchanges datagrams until nothing moves, without
    /// advancing the clock.
    fn settle(&mut self) {
        for _ in 0..1000 {
            if let Err(e) = self.ch.poll(&mut self.p.client, self.p.now) {
                self.err.get_or_insert(e);
            }
            while let Some(ev) = self.ch.poll_event() {
                self.events.push(ev);
            }
            if let Some(s) = self.p.server.as_mut() {
                while s.poll_event().is_some() {}
            }
            if !self.p.exchange() {
                break;
            }
        }
    }

    /// Sends a request and lets the server see it.
    fn request(&mut self, fields: &[Field]) -> u64 {
        let id = self
            .ch
            .send_request(&mut self.p.client, fields, true)
            .unwrap();
        self.settle();
        id
    }

    /// Writes raw bytes on a server-side request stream.
    fn reply(&mut self, id: u64, bytes: &[u8], fin: bool) {
        let c = self.p.server.as_mut().unwrap();
        assert_eq!(c.stream_write(id, bytes, fin).unwrap(), bytes.len());
        self.settle();
    }

    /// The events of one stream, in order.
    fn of(&self, id: u64) -> Vec<&H3Event> {
        self.events
            .iter()
            .filter(|e| match e {
                H3Event::Headers { stream_id, .. }
                | H3Event::Data { stream_id }
                | H3Event::Finished { stream_id }
                | H3Event::Reset { stream_id, .. }
                | H3Event::Stopped { stream_id, .. } => *stream_id == id,
                _ => false,
            })
            .collect()
    }

    fn reset_code(&self, id: u64) -> Option<u64> {
        match self.of(id).last() {
            Some(H3Event::Reset { code, .. }) => Some(*code),
            _ => None,
        }
    }

    fn body(&mut self, id: u64) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let (n, end) = self.ch.recv_body(&mut self.p.client, id, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            if end || n == 0 {
                return (out, end);
            }
        }
    }

    fn server_close_code(&self) -> Option<u64> {
        match self.p.server.as_ref().and_then(Connection::close_reason) {
            Some(CloseReason::PeerApplication { code, .. }) => Some(*code),
            _ => None,
        }
    }
}

fn resp(fields: &[(&str, &str)]) -> Vec<u8> {
    let v: Vec<Field> = fields.iter().map(|(n, v)| f(n, v)).collect();
    headers_frame(&v)
}

fn data_frame(d: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    skiff_h3::frame::encode_frame(&mut b, frame_type::DATA, d);
    b
}

type Section = Vec<(&'static str, &'static str)>;

/// RFC 9114 4.1.2 / 4.3.2: each malformed response is a stream error
/// H3_MESSAGE_ERROR (the request is abandoned, nothing of it is delivered)
/// and the connection survives to serve the next request.
#[test]
fn client_rejects_malformed_responses() {
    let mut s = RawSrv::new();
    let cl = |v: &'static str| -> Section { vec![(":status", "200"), ("content-length", v)] };
    // (what, header sections in order, DATA after the first, FIN?)
    let cases: Vec<(&str, Vec<Section>, &[u8], bool)> = vec![
        ("missing :status", vec![vec![("server", "x")]], b"", true),
        (
            "pseudo-header after a regular field",
            vec![vec![("server", "x"), (":status", "200")]],
            b"",
            true,
        ),
        (
            "duplicate :status",
            vec![vec![(":status", "200"), (":status", "200")]],
            b"",
            true,
        ),
        (
            "two-digit :status",
            vec![vec![(":status", "20")]],
            b"",
            true,
        ),
        (
            "non-numeric :status",
            vec![vec![(":status", "2x0")]],
            b"",
            true,
        ),
        (
            "request pseudo-header in a response",
            vec![vec![(":status", "200"), (":method", "GET")]],
            b"",
            true,
        ),
        (
            "uppercase field name",
            vec![vec![(":status", "200"), ("Server", "x")]],
            b"",
            true,
        ),
        (
            "connection-specific field",
            vec![vec![(":status", "200"), ("transfer-encoding", "chunked")]],
            b"",
            true,
        ),
        ("non-numeric content-length", vec![cl("3x")], b"abc", true),
        ("empty content-length", vec![cl("")], b"abc", true),
        ("signed content-length", vec![cl("+3")], b"abc", true),
        ("negative content-length", vec![cl("-3")], b"abc", true),
        (
            "overflowing content-length",
            vec![cl("99999999999999999999")],
            b"abc",
            true,
        ),
        (
            "disagreeing content-length list",
            vec![cl("4, 3")],
            b"abc",
            true,
        ),
        (
            "disagreeing content-length fields",
            vec![vec![
                (":status", "200"),
                ("content-length", "3"),
                ("content-length", "4"),
            ]],
            b"abc",
            true,
        ),
        (
            "body shorter than content-length",
            vec![cl("5")],
            b"abc",
            true,
        ),
        ("no body, content-length 1", vec![cl("1")], b"", true),
        // The excess is an error as soon as it arrives, with no FIN.
        (
            "body longer than content-length",
            vec![cl("2")],
            b"abc",
            false,
        ),
        (
            "pseudo-header in trailers",
            vec![cl("3"), vec![(":status", "200")]],
            b"abc",
            true,
        ),
        (
            "connection-specific field in trailers",
            vec![cl("3"), vec![("connection", "close")]],
            b"abc",
            true,
        ),
        (
            "1xx then a response without :status",
            vec![vec![(":status", "103")], vec![("server", "x")]],
            b"",
            true,
        ),
    ];
    for (what, sections, data, fin) in cases {
        let id = s.request(&get("/x"));
        let mut b = Vec::new();
        for (i, sec) in sections.iter().enumerate() {
            b.extend(resp(sec));
            if i == 0 && !data.is_empty() {
                b.extend(data_frame(data));
            }
        }
        s.reply(id, &b, fin);
        assert_eq!(s.reset_code(id), Some(H3_MESSAGE_ERROR), "{what}");
        assert!(
            !s.of(id)
                .iter()
                .any(|e| matches!(e, H3Event::Finished { .. })),
            "{what}: finished"
        );
        assert_eq!(s.err, None, "{what}: connection error");
        assert_eq!(s.p.client.close_reason(), None, "{what}");
        assert_eq!(s.server_close_code(), None, "{what}");
    }
    // The connection still works.
    let id = s.request(&get("/ok"));
    let mut b = resp(&cl("3"));
    b.extend(data_frame(b"abc"));
    s.reply(id, &b, true);
    assert_eq!(s.body(id), (b"abc".to_vec(), true));
    assert!(matches!(s.of(id).last(), Some(H3Event::Finished { .. })));
    // A list of equal values is fine.
    let id = s.request(&get("/ok"));
    let mut b = resp(&cl("3, 3"));
    b.extend(data_frame(b"abc"));
    s.reply(id, &b, true);
    assert_eq!(s.body(id), (b"abc".to_vec(), true));
    assert_eq!(s.err, None);
}

/// Frames that are illegal on a response stream are connection errors
/// (RFC 9114 7.2, 4.1): DATA before HEADERS, DATA after trailers, a second
/// trailer section, control frames, and truncated frames.
#[test]
fn client_connection_errors_on_response_stream() {
    let ok = || resp(&[(":status", "200")]);
    let frame = |ty: u64, payload: &[u8]| {
        let mut b = Vec::new();
        skiff_h3::frame::encode_frame(&mut b, ty, payload);
        b
    };
    let cat = |parts: Vec<Vec<u8>>| parts.concat();
    let trunc = |mut b: Vec<u8>| {
        b.truncate(b.len() - 1);
        b
    };
    let cases: Vec<(&str, Vec<u8>, bool, u64)> = vec![
        (
            "DATA before HEADERS",
            data_frame(b"x"),
            false,
            H3_FRAME_UNEXPECTED,
        ),
        (
            "DATA after only a 1xx",
            cat(vec![resp(&[(":status", "103")]), data_frame(b"x")]),
            false,
            H3_FRAME_UNEXPECTED,
        ),
        (
            "DATA after trailers",
            cat(vec![ok(), resp(&[("x-sum", "1")]), data_frame(b"x")]),
            false,
            H3_FRAME_UNEXPECTED,
        ),
        (
            "HEADERS after trailers",
            cat(vec![ok(), resp(&[("x-sum", "1")]), resp(&[("x-sum", "2")])]),
            false,
            H3_FRAME_UNEXPECTED,
        ),
        (
            "SETTINGS on a request stream",
            frame(frame_type::SETTINGS, &[]),
            false,
            H3_FRAME_UNEXPECTED,
        ),
        (
            "GOAWAY on a request stream",
            frame(frame_type::GOAWAY, &[0]),
            false,
            H3_FRAME_UNEXPECTED,
        ),
        (
            "HEADERS truncated by the end of the stream",
            trunc(ok()),
            true,
            H3_FRAME_ERROR,
        ),
        (
            "DATA truncated by the end of the stream",
            cat(vec![ok(), trunc(data_frame(b"abc"))]),
            true,
            H3_FRAME_ERROR,
        ),
    ];
    for (what, bytes, fin, code) in cases {
        let mut s = RawSrv::new();
        let id = s.request(&get("/x"));
        s.reply(id, &bytes, fin);
        assert!(
            matches!(&s.err, Some(skiff_h3::H3Error::Connection { code: c, .. }) if *c == code),
            "{what}: {:?}",
            s.err
        );
        s.settle();
        assert_eq!(s.server_close_code(), Some(code), "{what}");
    }
    // A response with no HEADERS at all (FIN only) is an incomplete
    // request, a stream error.
    let mut s = RawSrv::new();
    let id = s.request(&get("/x"));
    s.reply(id, &[], true);
    assert_eq!(s.reset_code(id), Some(H3_REQUEST_INCOMPLETE));
    assert_eq!(s.err, None);
}

/// RFC 9114 4.1: interim (1xx) responses precede the final one; the
/// Content-Length check applies to the final response only.
#[test]
fn client_handles_interim_responses() {
    let mut s = RawSrv::new();
    let id = s.request(&get("/x"));
    let mut b = resp(&[(":status", "103"), ("link", "</a>; rel=preload")]);
    b.extend(resp(&[(":status", "100"), ("content-length", "99")]));
    b.extend(resp(&[(":status", "200"), ("content-length", "3")]));
    b.extend(data_frame(b"abc"));
    s.reply(id, &b, true);
    let statuses: Vec<Vec<u8>> = s
        .events
        .iter()
        .filter_map(|e| match e {
            H3Event::Headers { stream_id, fields } if *stream_id == id => {
                value(fields, ":status").map(<[u8]>::to_vec)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        statuses,
        vec![b"103".to_vec(), b"100".to_vec(), b"200".to_vec()]
    );
    assert_eq!(s.body(id), (b"abc".to_vec(), true));
    assert_eq!(s.err, None);

    // Only 1xx and then the stream ends: the response never arrived.
    let id = s.request(&get("/x"));
    s.reply(id, &resp(&[(":status", "103")]), true);
    assert_eq!(s.reset_code(id), Some(H3_REQUEST_INCOMPLETE));

    // After the final response a 1xx-shaped section is trailers, and a
    // pseudo-header there is malformed.
    let id = s.request(&get("/x"));
    let mut b = resp(&[(":status", "200")]);
    b.extend(resp(&[(":status", "103")]));
    s.reply(id, &b, true);
    assert_eq!(s.reset_code(id), Some(H3_MESSAGE_ERROR));
    assert_eq!(s.err, None);
    assert_eq!(s.server_close_code(), None);
}

/// RFC 9110 6.4.1 / 9114 4.1.2: a response to HEAD, a 204 and a 304 have no
/// content whatever their Content-Length says; the same length on any other
/// response with no body is malformed.
#[test]
fn head_204_304_content_length_exemption() {
    let mut s = RawSrv::new();
    let mut head = get("/x");
    head[0] = f(":method", "HEAD");
    let cases: Vec<(&str, Vec<Field>, &str, &str)> = vec![
        ("HEAD 200", head.clone(), "200", "1234"),
        ("HEAD 404", head, "404", "10"),
        ("GET 204", get("/x"), "204", "7"),
        ("GET 304", get("/x"), "304", "7"),
    ];
    for (what, req, status, cl) in cases {
        let id = s.request(&req);
        s.reply(
            id,
            &resp(&[(":status", status), ("content-length", cl)]),
            true,
        );
        assert_eq!(s.of(id).len(), 2, "{what}: {:?}", s.of(id));
        assert!(
            matches!(s.of(id).last(), Some(H3Event::Finished { .. })),
            "{what}"
        );
        assert_eq!(s.body(id), (Vec::new(), true), "{what}");
        assert_eq!(s.err, None);
    }
    // Not exempt: GET with 200, 205 or 203 and a length but no body.
    for status in ["200", "205", "203"] {
        let id = s.request(&get("/x"));
        s.reply(
            id,
            &resp(&[(":status", status), ("content-length", "7")]),
            true,
        );
        assert_eq!(s.reset_code(id), Some(H3_MESSAGE_ERROR), "{status}");
    }
    // The exemption is per request: the HEAD earlier did not relax these.
    assert_eq!(s.err, None);
}

/// End to end: the test server answers HEAD with the GET headers
/// (Content-Length N) and no body.
#[test]
fn head_request_against_h3_server() {
    let (mut p, mut ch, mut sh, mut client, mut server) = setup();
    let mut h = get("/size/1000");
    h[0] = f(":method", "HEAD");
    client.queue.push((h, None, Vec::new()));
    client.get("/size/5");
    run(
        &mut p,
        &mut ch,
        &mut sh,
        &mut client,
        &mut server,
        |c, _| c.finished() == 2,
    );
    let head = &client.responses[&client.sent[0]];
    assert!(head.done && head.reset.is_none(), "{head:?}");
    assert_eq!(value(&head.headers, "content-length"), Some(&b"1000"[..]));
    assert!(head.body.is_empty());
    let get = &client.responses[&client.sent[1]];
    assert_eq!(get.body, body_for("/size/5", 5));
}

/// More malformed requests, RFC 9114 4.1 / 4.1.2 / 4.3.1: stream errors for
/// bad trailers, CONNECT and :protocol misuse, and Content-Length values;
/// connection errors for frames after the trailers.
#[test]
fn server_rejects_more_malformed_requests() {
    let mut r = Raw::new();
    r.control();
    let with = |extra: Field| {
        let mut v = get("/size/1");
        v.push(extra);
        v
    };
    let mut head = get("/size/1");
    head[0] = f(":method", "HEAD");
    head.push(f("content-length", "3"));
    let connect_ok = vec![f(":method", "CONNECT"), f(":authority", "example.com:443")];
    let mut connect_scheme = connect_ok.clone();
    connect_scheme.push(f(":scheme", "https"));
    let mut connect_path = connect_ok.clone();
    connect_path.push(f(":path", "/"));
    let mut protocol_on_get = get("/size/1");
    protocol_on_get.insert(0, f(":protocol", "websocket"));
    protocol_on_get.sort_by_key(|x| !x.name.starts_with(b":"));
    // (what, header section, DATA, trailers)
    type Case = (&'static str, Vec<Field>, &'static [u8], Option<Vec<Field>>);
    let cases: Vec<Case> = vec![
        (
            "pseudo-header in trailers",
            get("/size/1"),
            b"",
            Some(vec![f(":path", "/")]),
        ),
        (
            "connection-specific field in trailers",
            get("/size/1"),
            b"",
            Some(vec![f("connection", "close")]),
        ),
        (
            "uppercase field in trailers",
            get("/size/1"),
            b"",
            Some(vec![f("X-Sum", "1")]),
        ),
        ("CONNECT with :scheme", connect_scheme, b"", None),
        ("CONNECT with :path", connect_path, b"", None),
        (
            "CONNECT without :authority",
            vec![f(":method", "CONNECT")],
            b"",
            None,
        ),
        (
            "duplicate :method",
            vec![
                f(":method", "GET"),
                f(":method", "GET"),
                f(":scheme", "https"),
                f(":path", "/"),
            ],
            b"",
            None,
        ),
        ("HEAD request with a length and no body", head, b"", None),
        (
            "empty content-length",
            with(f("content-length", "")),
            b"abc",
            None,
        ),
        (
            "signed content-length",
            with(f("content-length", "+3")),
            b"abc",
            None,
        ),
        (
            "negative content-length",
            with(f("content-length", "-3")),
            b"abc",
            None,
        ),
        (
            "overflowing content-length",
            with(f("content-length", "99999999999999999999")),
            b"abc",
            None,
        ),
        (
            "content-length fields disagree",
            {
                let mut v = with(f("content-length", "3"));
                v.push(f("content-length", "4"));
                v
            },
            b"abc",
            None,
        ),
        (
            "body longer than content-length, trailers follow",
            with(f("content-length", "2")),
            b"abc",
            Some(vec![f("x-sum", "1")]),
        ),
        (
            "body shorter than content-length, trailers follow",
            with(f("content-length", "5")),
            b"abc",
            Some(vec![f("x-sum", "1")]),
        ),
        (":protocol on a GET", protocol_on_get, b"", None),
        (
            "extended CONNECT the server did not enable",
            vec![
                f(":method", "CONNECT"),
                f(":protocol", "websocket"),
                f(":scheme", "https"),
                f(":authority", "localhost"),
                f(":path", "/chat"),
            ],
            b"",
            None,
        ),
    ];
    for (what, fields, data, trailers) in cases {
        let mut b = headers_frame(&fields);
        if !data.is_empty() {
            b.extend(data_frame(data));
        }
        if let Some(t) = &trailers {
            b.extend(headers_frame(t));
        }
        let before = r.server.resets.len();
        let id = r.stream(true, &b, true);
        r.settle();
        assert_eq!(r.server.resets.len(), before + 1, "{what}: no stream error");
        assert_eq!(
            r.server.resets.last(),
            Some(&(id, H3_MESSAGE_ERROR)),
            "{what}"
        );
        r.assert_open();
    }
    assert_eq!(r.server.served, 0);

    // Frames that may not follow the trailers: connection errors.
    let trailers = || headers_frame(&[f("x-sum", "1")]);
    let after: Vec<(&str, Vec<u8>)> = vec![
        ("DATA after trailers", data_frame(b"x")),
        ("HEADERS after trailers", trailers()),
        ("PUSH_PROMISE", {
            let mut b = Vec::new();
            skiff_h3::frame::encode_frame(&mut b, frame_type::PUSH_PROMISE, &[0]);
            b
        }),
        ("CANCEL_PUSH", {
            let mut b = Vec::new();
            skiff_h3::frame::encode_frame(&mut b, frame_type::CANCEL_PUSH, &[0]);
            b
        }),
    ];
    for (what, extra) in after {
        let mut r = Raw::new();
        r.control();
        let mut b = headers_frame(&get("/size/1"));
        b.extend(trailers());
        b.extend(extra);
        r.stream(true, &b, false);
        assert_eq!(r.closed_with(), Some(H3_FRAME_UNEXPECTED), "{what}");
    }
}

/// RFC 9114 4.1.2 + RFC 9110 6.4.1 / 9.3.2: a response to HEAD and a 204 or
/// 304 response have no content. A DATA frame with any payload makes the
/// response malformed: stream error H3_MESSAGE_ERROR, no Data event, and
/// the connection survives. Zero-length DATA frames carry no content and
/// are accepted.
#[test]
fn client_rejects_content_on_responses_without_content() {
    let mut s = RawSrv::new();
    let mut head = get("/x");
    head[0] = f(":method", "HEAD");
    // (what, request, status, content-length, DATA in the first write,
    //  DATA in a second write after the headers were delivered)
    type Case = (
        &'static str,
        Vec<Field>,
        &'static str,
        &'static str,
        &'static [u8],
        &'static [u8],
    );
    let bad: Vec<Case> = vec![
        (
            "HEAD 200 with its body",
            head.clone(),
            "200",
            "5",
            b"hello",
            b"",
        ),
        (
            "HEAD 200, body arrives later",
            head.clone(),
            "200",
            "5",
            b"",
            b"hello",
        ),
        (
            "HEAD 404 with one byte",
            head.clone(),
            "404",
            "1",
            b"x",
            b"",
        ),
        ("GET 204 with DATA", get("/x"), "204", "0", b"x", b""),
        (
            "GET 204, DATA arrives later",
            get("/x"),
            "204",
            "0",
            b"",
            b"xy",
        ),
        ("GET 304 with DATA", get("/x"), "304", "3", b"abc", b""),
    ];
    for (what, req, status, cl, first, later) in bad {
        let id = s.request(&req);
        let mut b = resp(&[(":status", status), ("content-length", cl)]);
        if !first.is_empty() {
            b.extend(data_frame(first));
        }
        s.reply(id, &b, later.is_empty());
        if !later.is_empty() {
            assert!(
                matches!(s.of(id).first(), Some(H3Event::Headers { .. })),
                "{what}: headers first"
            );
            s.reply(id, &data_frame(later), true);
        }
        assert_eq!(
            s.reset_code(id),
            Some(H3_MESSAGE_ERROR),
            "{what}: {:?}",
            s.of(id)
        );
        assert!(
            !s.of(id).iter().any(|e| matches!(e, H3Event::Data { .. })),
            "{what}: no Data event"
        );
        assert_eq!(s.err, None, "{what}");
    }
    // Accepted: an empty DATA frame on a 204, and a 200 GET with its body.
    let id = s.request(&get("/x"));
    let mut b = resp(&[(":status", "204")]);
    b.extend(data_frame(b""));
    s.reply(id, &b, true);
    assert!(
        matches!(s.of(id).last(), Some(H3Event::Finished { .. })),
        "{:?}",
        s.of(id)
    );
    assert_eq!(s.body(id), (Vec::new(), true));
    let id = s.request(&get("/x"));
    let mut b = resp(&[(":status", "200"), ("content-length", "5")]);
    b.extend(data_frame(b"hello"));
    s.reply(id, &b, true);
    assert_eq!(s.body(id), (b"hello".to_vec(), true));
    assert_eq!(s.err, None);
    assert_eq!(s.p.client.close_reason(), None);
}

/// Client and server H3Connections driven by hand, events collected per side.
struct Manual {
    p: Pair,
    ch: H3Connection,
    sh: H3Connection,
    cev: Vec<H3Event>,
    sev: Vec<H3Event>,
}

impl Manual {
    fn new(client: H3Config, server: H3Config) -> Self {
        let mut m = Self {
            p: Pair::new(),
            ch: H3Connection::new(client),
            sh: H3Connection::new(server),
            cev: Vec::new(),
            sev: Vec::new(),
        };
        m.pump();
        assert!(m.ch.peer_settings().is_some() && m.sh.peer_settings().is_some());
        m
    }

    fn pump(&mut self) {
        let (ch, sh, cev, sev) = (&mut self.ch, &mut self.sh, &mut self.cev, &mut self.sev);
        pump(&mut self.p, |p| {
            ch.poll(&mut p.client, p.now).unwrap();
            cev.extend(std::iter::from_fn(|| ch.poll_event()));
            if let Some(s) = p.server.as_mut() {
                sh.poll(s, p.now).unwrap();
                sev.extend(std::iter::from_fn(|| sh.poll_event()));
            }
        });
    }

    fn read(h3: &mut H3Connection, c: &mut Connection, id: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let (n, end) = h3.recv_body(c, id, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            if end || n == 0 {
                return out;
            }
        }
    }
}

fn connect_ws() -> Vec<Field> {
    vec![
        f(":method", "CONNECT"),
        f(":protocol", "websocket"),
        f(":scheme", "https"),
        f(":authority", "localhost"),
        f(":path", "/chat"),
        f("sec-websocket-version", "13"),
    ]
}

/// Extended CONNECT (RFC 9220, RFC 8441): the server advertises
/// SETTINGS_ENABLE_CONNECT_PROTOCOL, the client may then send a CONNECT
/// with `:protocol` and both sides use the stream as a tunnel. A client
/// refuses to send one before the server's SETTINGS or when the server did
/// not enable it; a server that did not enable it rejects one with
/// H3_MESSAGE_ERROR (in `server_rejects_more_malformed_requests`); a
/// setting value other than 0 or 1 is H3_SETTINGS_ERROR.
#[test]
fn extended_connect_negotiation() {
    // Not enabled: the client refuses locally.
    let mut m = Manual::new(H3Config::default(), H3Config::default());
    assert!(!m.ch.peer_settings().unwrap().enable_connect_protocol);
    assert!(matches!(
        m.ch.send_request(&mut m.p.client, &connect_ws(), false),
        Err(skiff_h3::H3Error::InvalidState(_))
    ));
    // A plain CONNECT needs no setting.
    let plain = vec![f(":method", "CONNECT"), f(":authority", "example.com:443")];
    m.ch.send_request(&mut m.p.client, &plain, false).unwrap();

    // Before the server's SETTINGS arrive the client does not know.
    let mut early = H3Connection::new(H3Config::default());
    let mut p = Pair::new();
    pump(&mut p, |p| {
        let _ = early.poll(&mut p.client, p.now);
        while early.poll_event().is_some() {}
    });
    assert!(early.peer_settings().is_none());
    assert!(early
        .send_request(&mut p.client, &connect_ws(), false)
        .is_err());

    // Enabled by the server: a websocket-style tunnel both ways.
    let server_cfg = H3Config {
        enable_connect_protocol: true,
        ..H3Config::default()
    };
    let mut m = Manual::new(H3Config::default(), server_cfg);
    assert!(m.ch.peer_settings().unwrap().enable_connect_protocol);
    assert!(!m.sh.peer_settings().unwrap().enable_connect_protocol);
    let id =
        m.ch.send_request(&mut m.p.client, &connect_ws(), false)
            .unwrap();
    m.pump();
    let got = m.sev.iter().find_map(|e| match e {
        H3Event::Headers { stream_id, fields } if *stream_id == id => Some(fields.clone()),
        _ => None,
    });
    assert_eq!(
        got.as_deref().and_then(|f| value(f, ":protocol")),
        Some(&b"websocket"[..])
    );
    let s = m.p.server.as_mut().unwrap();
    m.sh.send_response(s, id, &[f(":status", "200")], false)
        .unwrap();
    m.ch.send_data(&mut m.p.client, id, b"ping", false).unwrap();
    m.pump();
    let s = m.p.server.as_mut().unwrap();
    assert_eq!(Manual::read(&mut m.sh, s, id), b"ping");
    m.sh.send_data(s, id, b"pong", true).unwrap();
    m.ch.send_data(&mut m.p.client, id, b"", true).unwrap();
    m.pump();
    assert_eq!(Manual::read(&mut m.ch, &mut m.p.client, id), b"pong");
    let reset = |e: &H3Event| matches!(e, H3Event::Reset { .. });
    assert!(!m.cev.iter().any(reset), "{:?}", m.cev);
    assert!(!m.sev.iter().any(reset), "{:?}", m.sev);
    assert!(m
        .sev
        .iter()
        .any(|e| matches!(e, H3Event::Finished { stream_id } if *stream_id == id)));
    assert_eq!(m.p.server.as_ref().unwrap().close_reason(), None);

    // A SETTINGS_ENABLE_CONNECT_PROTOCOL value of 2: H3_SETTINGS_ERROR.
    let mut r = Raw::new();
    let mut b = vec![stream_type::CONTROL as u8];
    skiff_h3::frame::encode_frame(&mut b, frame_type::SETTINGS, &[0x08, 0x02]);
    r.stream(false, &b, false);
    assert_eq!(r.closed_with(), Some(H3_SETTINGS_ERROR));
}

/// The server application cannot put content on a response to HEAD or on
/// a 204 / 304 response (`send_data` refuses non-empty bodies; an empty
/// one with FIN is fine); other responses are unaffected.
#[test]
fn server_refuses_content_on_responses_without_content() {
    let mut m = Manual::new(H3Config::default(), H3Config::default());
    let mut head = get("/x");
    head[0] = f(":method", "HEAD");
    let reqs = [
        (head, "200"),
        (get("/a"), "204"),
        (get("/b"), "304"),
        (get("/c"), "200"),
    ];
    let mut ids = Vec::new();
    for (req, _) in &reqs {
        ids.push(m.ch.send_request(&mut m.p.client, req, true).unwrap());
    }
    m.pump();
    for (&id, (_, status)) in ids.iter().zip(&reqs) {
        let s = m.p.server.as_mut().unwrap();
        let hdr = [f(":status", status), f("content-length", "4")];
        m.sh.send_response(s, id, &hdr, false).unwrap();
        let r = m.sh.send_data(s, id, b"body", true);
        if id == ids[3] {
            assert_eq!(r, Ok(()));
        } else {
            assert!(
                matches!(r, Err(skiff_h3::H3Error::InvalidState(_))),
                "{status}: {r:?}"
            );
            m.sh.send_data(s, id, b"", true).unwrap();
        }
    }
    m.pump();
    for &id in &ids {
        assert!(
            m.cev
                .iter()
                .any(|e| matches!(e, H3Event::Finished { stream_id } if *stream_id == id)),
            "{id}: {:?}",
            m.cev
        );
    }
    assert!(!m.cev.iter().any(|e| matches!(e, H3Event::Reset { .. })));
    assert_eq!(Manual::read(&mut m.ch, &mut m.p.client, ids[3]), b"body");
}
