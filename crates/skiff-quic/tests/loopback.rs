//! Two in-memory `Connection`s over a simulated link (virtual clock,
//! seeded loss / reordering / duplication): handshake with a self-signed
//! certificate, bidirectional and unidirectional stream transfer, flow
//! control and stream-limit credit, close, idle timeout and the client
//! anti-deadlock PTO.

use rustls::pki_types::PrivatePkcs8KeyDer;
use skiff_quic::conn::{ApiError, CloseReason, Connection, Event, TransportConfig};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const ALPN: &[u8] = b"skiff-test";

fn tls() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    static CFG: OnceLock<(Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>)> = OnceLock::new();
    CFG.get_or_init(|| {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        server.alpn_protocols = vec![ALPN.to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![ALPN.to_vec()];
        (Arc::new(client), Arc::new(server))
    })
    .clone()
}

/// One direction of the simulated network.
struct Link {
    queue: Vec<(Instant, Vec<u8>)>,
    delay: Duration,
    loss_pct: u64,
    reorder_pct: u64,
    dup_pct: u64,
    rng: u64,
    dropped: u64,
    /// Drops everything when set.
    blackhole: bool,
    /// Truncates each datagram to its first packet when set.
    first_packet_only: bool,
}

impl Link {
    fn new(seed: u64, delay_ms: u64) -> Self {
        Self {
            queue: Vec::new(),
            delay: Duration::from_millis(delay_ms),
            loss_pct: 0,
            reorder_pct: 0,
            dup_pct: 0,
            rng: seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1,
            dropped: 0,
            blackhole: false,
            first_packet_only: false,
        }
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn push(&mut self, now: Instant, d: &[u8]) {
        if self.blackhole || self.rand() % 100 < self.loss_pct {
            self.dropped += 1;
            return;
        }
        let mut d = d.to_vec();
        if self.first_packet_only {
            let h = skiff_wire::header::Header::parse(&d, 8).unwrap();
            d.truncate(h.packet_len);
        }
        let mut at = now + self.delay;
        if self.rand() % 100 < self.reorder_pct {
            let extra = self.rand() % (2 * self.delay.as_micros() as u64 + 1);
            at += Duration::from_micros(extra);
        }
        if self.rand() % 100 < self.dup_pct {
            self.queue.push((at + Duration::from_millis(1), d.clone()));
        }
        self.queue.push((at, d));
    }

    fn pop_due(&mut self, now: Instant) -> Option<Vec<u8>> {
        let i = (0..self.queue.len())
            .filter(|&i| self.queue[i].0 <= now)
            .min_by_key(|&i| self.queue[i].0)?;
        Some(self.queue.remove(i).1)
    }

    fn next_arrival(&self) -> Option<Instant> {
        self.queue.iter().map(|x| x.0).min()
    }
}

struct Sim {
    client: Connection,
    server: Option<Connection>,
    c2s: Link,
    s2c: Link,
    start: Instant,
    now: Instant,
    server_tls: Arc<rustls::ServerConfig>,
    config: TransportConfig,
    client_datagrams: u64,
    steps: u64,
    same_instant: u64,
}

impl Sim {
    fn new(config: TransportConfig, seed: u64, delay_ms: u64) -> Self {
        let (ctls, stls) = tls();
        let start = Instant::now();
        let client = Connection::connect(ctls, "localhost", config.clone(), start).unwrap();
        Self {
            client,
            server: None,
            c2s: Link::new(seed, delay_ms),
            s2c: Link::new(seed ^ 0xdead_beef, delay_ms),
            start,
            now: start,
            server_tls: stls,
            config,
            client_datagrams: 0,
            steps: 0,
            same_instant: 0,
        }
    }

    fn server(&mut self) -> &mut Connection {
        self.server.as_mut().expect("server not accepted yet")
    }

    fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Advances the simulation by one step; false when nothing can happen.
    fn step(&mut self) -> bool {
        let mut buf = vec![0u8; 1500];
        let mut progressed = false;
        self.steps += 1;
        assert!(self.steps < 3_000_000, "livelock: {} steps", self.steps);
        let mut burst = 0;
        loop {
            let n = self.client.send(&mut buf, self.now);
            if n == 0 {
                break;
            }
            burst += 1;
            assert!(
                burst < 10_000,
                "client send livelock: {:?}",
                self.client.stats()
            );
            let max = self.config.max_datagram_size.max(self.config.pmtu_max);
            assert!(n <= max, "datagram over the configured maximum: {n}");
            self.client_datagrams += 1;
            self.c2s.push(self.now, &buf[..n]);
            progressed = true;
        }
        if let Some(s) = self.server.as_mut() {
            loop {
                let n = s.send(&mut buf, self.now);
                if n == 0 {
                    break;
                }
                burst += 1;
                assert!(burst < 20_000, "server send livelock: {:?}", s.stats());
                self.s2c.push(self.now, &buf[..n]);
                progressed = true;
            }
        }
        while let Some(mut d) = self.c2s.pop_due(self.now) {
            progressed = true;
            if self.server.is_none() {
                if let Ok(s) =
                    Connection::accept(self.server_tls.clone(), self.config.clone(), &d, self.now)
                {
                    self.server = Some(s);
                }
            }
            if let Some(s) = self.server.as_mut() {
                s.recv(&mut d, self.now);
            }
        }
        while let Some(mut d) = self.s2c.pop_due(self.now) {
            progressed = true;
            self.client.recv(&mut d, self.now);
        }
        if progressed {
            self.same_instant += 1;
            assert!(
                self.same_instant < 100_000,
                "virtual time stuck at {:?}",
                self.elapsed()
            );
            return true;
        }
        self.same_instant = 0;
        let next = [
            self.c2s.next_arrival(),
            self.s2c.next_arrival(),
            self.client.timeout(),
            self.server.as_ref().and_then(Connection::timeout),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(t) = next else {
            return false;
        };
        self.now = if t > self.now {
            t
        } else {
            self.now + Duration::from_millis(1)
        };
        self.client.on_timeout(self.now);
        if let Some(s) = self.server.as_mut() {
            s.on_timeout(self.now);
        }
        true
    }
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_be_bytes()[0] ^ seed)
        .collect()
}

fn drain(c: &mut Connection, id: u64, out: &mut Vec<u8>) -> bool {
    let mut buf = [0u8; 4096];
    loop {
        match c.stream_read(id, &mut buf) {
            Ok((n, fin)) => {
                out.extend_from_slice(&buf[..n]);
                if fin {
                    return true;
                }
                if n == 0 {
                    return false;
                }
            }
            Err(e) => panic!("read on {id}: {e}"),
        }
    }
}

/// Server application: echoes every bidi stream, and once the handshake
/// completes sends `uni` bytes on a server-initiated unidirectional stream.
#[derive(Default)]
struct EchoServer {
    uni_sent: bool,
    seen_open: Vec<u64>,
}

impl EchoServer {
    fn poll(&mut self, s: &mut Connection, uni: &[u8]) {
        if !self.uni_sent && s.is_handshake_complete() {
            let id = s
                .open_stream(false)
                .unwrap_or_else(|e| panic!("{e}: {:?}", s.close_reason()));
            assert_eq!(s.stream_write(id, uni, true).unwrap(), uni.len());
            self.uni_sent = true;
        }
        while let Some(ev) = s.poll_event() {
            match ev {
                Event::StreamOpened(id) => self.seen_open.push(id),
                Event::StreamReadable(id) => {
                    let mut buf = [0u8; 4096];
                    loop {
                        let (n, fin) = s.stream_read(id, &mut buf).unwrap();
                        if n > 0 {
                            assert_eq!(s.stream_write(id, &buf[..n], false).unwrap(), n);
                        }
                        if fin {
                            s.stream_write(id, &[], true).unwrap();
                            break;
                        }
                        if n == 0 {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

struct Outcome {
    sim: Sim,
    echoed: BTreeMap<u64, Vec<u8>>,
    uni: Vec<u8>,
}

/// Client opens `streams` bidi streams (one at a time beyond the peer's
/// MAX_STREAMS), sends `per_stream` bytes + FIN on each and collects the
/// echoes; the server also pushes `uni_len` bytes on a uni stream.
fn echo_run(
    config: TransportConfig,
    seed: u64,
    link: impl FnOnce(&mut Sim),
    streams: usize,
    per_stream: usize,
    uni_len: usize,
    budget: Duration,
) -> Outcome {
    let mut sim = Sim::new(config, seed, 10);
    link(&mut sim);
    let uni_data = payload(uni_len, 0x5a);
    let mut srv = EchoServer::default();
    let mut opened: Vec<u64> = Vec::new();
    let mut echoed: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut done: Vec<u64> = Vec::new();
    let mut uni = Vec::new();
    let mut uni_done = false;
    let mut handshake = false;
    while sim.elapsed() < budget {
        if let Some(s) = sim.server.as_mut() {
            srv.poll(s, &uni_data);
        }
        let c = &mut sim.client;
        while let Some(ev) = c.poll_event() {
            match ev {
                Event::HandshakeCompleted => handshake = true,
                Event::StreamReadable(id) if id & 3 == 3 => {
                    uni_done |= drain(c, id, &mut uni);
                }
                Event::StreamReadable(id) => {
                    if drain(c, id, echoed.entry(id).or_default()) {
                        done.push(id);
                    }
                }
                Event::Closed(r) => panic!("unexpected close: {r:?}"),
                _ => {}
            }
        }
        if handshake && opened.len() < streams {
            match c.open_stream(true) {
                Ok(id) => {
                    let data = payload(per_stream, id as u8);
                    assert_eq!(c.stream_write(id, &data, true).unwrap(), data.len());
                    opened.push(id);
                }
                Err(ApiError::StreamsBlocked) => {}
                Err(e) => panic!("open: {e}"),
            }
        }
        if done.len() == streams && (uni_len == 0 || uni_done) {
            break;
        }
        assert!(sim.step(), "simulation stalled at {:?}", sim.elapsed());
    }
    assert!(handshake, "handshake did not complete");
    assert_eq!(done.len(), streams, "not all echoes finished in {budget:?}");
    for id in &opened {
        assert_eq!(
            echoed[id],
            payload(per_stream, *id as u8),
            "stream {id} corrupted"
        );
    }
    let mut seen = srv.seen_open.clone();
    seen.sort_unstable();
    assert_eq!(seen, opened, "server saw each client stream open once");
    Outcome { sim, echoed, uni }
}

#[test]
fn handshake_and_bidirectional_transfer() {
    // Small windows so the transfer depends on MAX_DATA/MAX_STREAM_DATA
    // updates, and a stream limit of 2 so later streams need MAX_STREAMS.
    let config = TransportConfig {
        initial_max_data: 24 * 1024,
        initial_max_stream_data: 8 * 1024,
        initial_max_streams_bidi: 2,
        ..TransportConfig::default()
    };
    let out = echo_run(
        config,
        1,
        |_| {},
        5,
        100_000,
        50_000,
        Duration::from_secs(30),
    );
    assert_eq!(out.echoed.len(), 5);
    assert_eq!(out.uni, payload(50_000, 0x5a), "server uni stream");
    let mut sim = out.sim;
    assert_eq!(sim.client.alpn_protocol(), Some(ALPN));
    assert!(sim.client.is_handshake_confirmed());
    assert!(sim.server().is_handshake_confirmed());
    let cs = sim.client.stats();
    assert_eq!(cs.packets_lost, 0, "lossless link");
    assert!(cs.srtt >= Duration::from_millis(20) && cs.srtt < Duration::from_millis(60));
}

#[test]
fn transfer_survives_loss_reordering_and_duplication() {
    for seed in 1..=6u64 {
        let out = echo_run(
            TransportConfig {
                initial_max_streams_bidi: 3,
                ..TransportConfig::default()
            },
            seed,
            |sim| {
                for l in [&mut sim.c2s, &mut sim.s2c] {
                    l.loss_pct = 10;
                    l.reorder_pct = 20;
                    l.dup_pct = 3;
                }
            },
            4,
            60_000,
            30_000,
            Duration::from_secs(120),
        );
        let mut sim = out.sim;
        let lost = sim.client.stats().packets_lost + sim.server().stats().packets_lost;
        assert!(
            sim.c2s.dropped + sim.s2c.dropped > 0 && lost > 0,
            "seed {seed}: the link must actually have lost packets"
        );
        assert_eq!(out.uni, payload(30_000, 0x5a), "seed {seed}: uni stream");
    }
}

#[test]
fn application_close_reaches_peer_and_both_terminate() {
    let mut out = echo_run(
        TransportConfig::default(),
        7,
        |_| {},
        1,
        1000,
        0,
        Duration::from_secs(5),
    );
    let sim = &mut out.sim;
    let now = sim.now;
    sim.client.close(42, b"bye", now);
    assert!(matches!(
        sim.client.stream_read(0, &mut [0u8; 8]),
        Err(ApiError::Closed)
    ));
    let mut peer_reason = None;
    for _ in 0..10_000 {
        while let Some(ev) = sim.server().poll_event() {
            if let Event::Closed(r) = ev {
                peer_reason = Some(r);
            }
        }
        if sim.client.is_closed() && sim.server().is_closed() {
            break;
        }
        if !sim.step() {
            break;
        }
    }
    assert_eq!(
        peer_reason,
        Some(CloseReason::PeerApplication {
            code: 42,
            reason: b"bye".to_vec()
        })
    );
    assert!(sim.client.is_closed() && sim.server().is_closed());
    assert!(
        sim.elapsed() < Duration::from_secs(5),
        "closed within 3 PTO"
    );
}

#[test]
fn idle_timeout_closes_both_sides() {
    let config = TransportConfig {
        max_idle_timeout: Duration::from_secs(2),
        ..TransportConfig::default()
    };
    let mut out = echo_run(config, 9, |_| {}, 1, 100, 0, Duration::from_secs(5));
    let sim = &mut out.sim;
    let quiet_since = sim.now;
    while sim.step() {
        if sim.client.is_closed() && sim.server().is_closed() {
            break;
        }
    }
    assert_eq!(sim.client.close_reason(), Some(&CloseReason::IdleTimeout));
    assert_eq!(sim.server().close_reason(), Some(&CloseReason::IdleTimeout));
    let idle = sim.now - quiet_since;
    assert!(
        idle >= Duration::from_millis(1900) && idle <= Duration::from_secs(3),
        "closed after {idle:?}"
    );
}

/// RFC 9002 6.2.2.1: the server's Handshake flight never arrives (only the
/// Initial packet of each server datagram gets through, then nothing), so
/// the client has nothing ack-eliciting in flight. It must still arm a PTO
/// and send a Handshake probe instead of waiting for the idle timeout.
#[test]
fn client_anti_deadlock_probe_without_inflight_data() {
    let mut sim = Sim::new(TransportConfig::default(), 11, 10);
    sim.s2c.first_packet_only = true;
    // Run until the client holds Handshake keys from the server's Initial.
    while sim.client.stats().packets_received == 0 {
        assert!(sim.step());
        assert!(sim.elapsed() < Duration::from_secs(5));
    }
    sim.s2c.blackhole = true;
    // Let the client send its Initial ACK, then count further datagrams.
    for _ in 0..3 {
        sim.step();
    }
    let before = sim.client_datagrams;
    let t0 = sim.now;
    while sim.now - t0 < Duration::from_secs(3) {
        assert!(sim.step());
    }
    assert!(
        sim.client_datagrams > before,
        "client sent no anti-deadlock probe within 3s (idle timeout is 30s)"
    );
    assert!(!sim.client.is_closed());
}

#[test]
fn accept_rejects_undersized_or_non_initial_datagrams() {
    let (_, stls) = tls();
    let now = Instant::now();
    let small = vec![0xc0u8; 600];
    assert_eq!(
        Connection::accept(stls.clone(), TransportConfig::default(), &small, now).err(),
        Some(ApiError::InvalidInitial)
    );
    let mut short = vec![0x40u8; 1200];
    short[1..9].copy_from_slice(&[1; 8]);
    assert_eq!(
        Connection::accept(stls, TransportConfig::default(), &short, now).err(),
        Some(ApiError::InvalidInitial)
    );
}

/// Garbage, truncated and bit-flipped copies of real datagrams must never
/// panic or disturb an established connection: they fail header parsing or
/// AEAD authentication and are dropped.
#[test]
fn corrupted_datagrams_are_dropped_without_harm() {
    let mut out = echo_run(
        TransportConfig::default(),
        13,
        |_| {},
        1,
        2000,
        0,
        Duration::from_secs(5),
    );
    let sim = &mut out.sim;
    let mut rng = 0x1234_5678_9abc_def1u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    // Capture a real 1-RTT datagram from each side to mutate.
    let id = sim.client.open_stream(true).unwrap();
    sim.client.stream_write(id, b"ping", false).unwrap();
    let mut buf = vec![0u8; 1500];
    let n = sim.client.send(&mut buf, sim.now);
    assert!(n > 0);
    let real = buf[..n].to_vec();
    for i in 0..3000u64 {
        let mut d = match i % 3 {
            0 => (0..(next() % 1400) as usize)
                .map(|_| next() as u8)
                .collect(),
            1 => real[..(next() as usize % real.len())].to_vec(),
            _ => {
                let mut d = real.clone();
                let k = next() as usize % d.len();
                d[k] ^= 1 << (next() % 8);
                d
            }
        };
        let now = sim.now;
        sim.server().recv(&mut d, now);
        sim.client.recv(&mut d, now);
    }
    assert!(!sim.client.is_closing(), "{:?}", sim.client.close_reason());
    assert!(
        !sim.server().is_closing(),
        "{:?}",
        sim.server().close_reason()
    );
    // The connection still works: deliver the real datagram and finish.
    let now = sim.now;
    sim.server().recv(&mut real.clone(), now);
    let mut got = Vec::new();
    for _ in 0..1000 {
        while let Some(ev) = sim.server().poll_event() {
            if ev == Event::StreamReadable(id) {
                let mut b = [0u8; 16];
                let (n, _) = sim.server().stream_read(id, &mut b).unwrap();
                got.extend_from_slice(&b[..n]);
            }
        }
        if got == b"ping" {
            break;
        }
        sim.step();
    }
    assert_eq!(got, b"ping");
}

/// Interop regression (quinn starts a key update after 10..1000 packets):
/// before key updates were supported, every 1-RTT packet after the peer
/// flipped the key phase failed AEAD and the connection idled out against
/// quinn. Five echo rounds; before each of rounds 1..=4 one side
/// (alternating) starts a key update while that round's data is in flight.
/// With and without reordering, both sides must count all four updates and
/// every round must echo intact.
#[test]
fn key_updates_from_either_side_mid_transfer() {
    for (seed, reorder) in [(21u64, 0u64), (22, 30)] {
        let mut sim = Sim::new(TransportConfig::default(), seed, 10);
        sim.c2s.reorder_pct = reorder;
        sim.s2c.reorder_pct = reorder;
        let mut srv = EchoServer::default();
        while !(sim.client.is_handshake_confirmed()
            && sim
                .server
                .as_ref()
                .is_some_and(Connection::is_handshake_confirmed))
        {
            assert!(sim.step());
        }
        for round in 0..5u8 {
            // First half, then (once the first half echoed and the chosen
            // side may update) the key update, then the second half + FIN.
            let data = payload(200_000, round);
            let half = data.len() / 2;
            let id = sim.client.open_stream(true).unwrap();
            assert_eq!(sim.client.stream_write(id, &data[..half], false), Ok(half));
            let mut updated = round == 0;
            let mut second_half_sent = false;
            let mut echoed = Vec::new();
            let mut done = false;
            let t0 = sim.now;
            while !done {
                assert!(
                    sim.now - t0 < Duration::from_secs(20),
                    "seed {seed} round {round}: stalled (updated {updated})"
                );
                srv.poll(sim.server(), b"");
                let now = sim.now;
                if !updated && echoed.len() >= half {
                    let side = if round % 2 == 1 {
                        sim.server()
                    } else {
                        &mut sim.client
                    };
                    if side.key_update_allowed() {
                        side.initiate_key_update(now).unwrap();
                        updated = true;
                    }
                }
                if updated && !second_half_sent {
                    let rest = &data[half..];
                    assert_eq!(sim.client.stream_write(id, rest, true), Ok(rest.len()));
                    second_half_sent = true;
                }
                while let Some(ev) = sim.client.poll_event() {
                    match ev {
                        Event::StreamReadable(r) if r == id => {
                            done = drain(&mut sim.client, id, &mut echoed);
                        }
                        Event::Closed(r) => panic!("seed {seed}: closed {r:?}"),
                        _ => {}
                    }
                }
                if !done {
                    assert!(sim.step());
                }
            }
            assert!(updated, "seed {seed} round {round}: no update started");
            assert_eq!(echoed, data, "seed {seed} round {round}");
            let n = u64::from(round);
            // The responder follows once a packet in the new phase reaches it.
            let t1 = sim.now;
            while sim.client.stats().key_updates != n || sim.server().stats().key_updates != n {
                assert!(
                    sim.now - t1 < Duration::from_secs(1),
                    "seed {seed} round {round}: update not followed"
                );
                srv.poll(sim.server(), b"");
                assert!(sim.step());
            }
            assert_eq!(sim.client.stats().key_updates, n, "seed {seed}: client");
            assert_eq!(sim.server().stats().key_updates, n, "seed {seed}: server");
        }
    }
}

/// A packet the peer protected with the previous key phase that arrives
/// after the update (reordering) must be opened with the retained previous
/// key, not dropped (RFC 9001 6.5).
#[test]
fn late_packet_from_previous_key_phase_is_accepted() {
    let mut out = echo_run(
        TransportConfig::default(),
        23,
        |_| {},
        1,
        3000,
        0,
        Duration::from_secs(5),
    );
    let sim = &mut out.sim;
    // RFC 9001 6.1: wait until the client acknowledged a 1-RTT packet.
    while !sim.server().key_update_allowed() {
        assert!(sim.step());
        assert!(sim.elapsed() < Duration::from_secs(5));
    }
    let now = sim.now;
    let mut buf = vec![0u8; 1500];
    let s = sim.server().open_stream(false).unwrap();
    sim.server().stream_write(s, b"old", true).unwrap();
    let n = sim.server().send(&mut buf, now);
    let mut old = buf[..n].to_vec();
    sim.server().initiate_key_update(now).unwrap();
    assert!(!sim.server().key_update_allowed(), "one update at a time");
    let s2 = sim.server().open_stream(false).unwrap();
    sim.server().stream_write(s2, b"new", true).unwrap();
    let n = sim.server().send(&mut buf, now);
    assert!(n > 0);
    let mut new = buf[..n].to_vec();
    sim.client.recv(&mut new, now);
    assert_eq!(
        sim.client.stats().key_updates,
        1,
        "client followed the update"
    );
    let before = sim.client.stats().packets_received;
    sim.client.recv(&mut old.clone(), now);
    assert_eq!(
        sim.client.stats().packets_received,
        before + 1,
        "late old-phase packet accepted"
    );
    let mut got = Vec::new();
    assert!(drain(&mut sim.client, s, &mut got));
    assert_eq!(got, b"old");
    sim.client.recv(&mut old, now);
    assert_eq!(
        sim.client.stats().packets_received,
        before + 1,
        "and only once"
    );
    assert!(!sim.client.is_closing());
}

/// A peer's empty stream (FIN, no data) is finished the moment it arrives.
/// When the ACK of our own stream data lands in the same packet, the stream
/// used to be retired at once and the application never saw the FIN: no
/// readable event, and the stream was unknown on the next read.
#[test]
fn empty_fin_reaches_the_application_even_when_acked_with_it() {
    let mut sim = Sim::new(TransportConfig::default(), 31, 10);
    while sim.server.is_none() || !sim.client.is_handshake_confirmed() {
        assert!(sim.step());
        assert!(sim.elapsed() < Duration::from_secs(5));
    }
    let id = sim.client.open_stream(true).unwrap();
    sim.client.stream_write(id, b"request", true).unwrap();
    let mut buf = [0u8; 64];
    // Until the server holds the request (its first read).
    let mut got = Vec::new();
    while got.len() < 7 {
        if let Some(s) = sim.server.as_mut() {
            if let Ok((n, _)) = s.stream_read(id, &mut buf) {
                got.extend_from_slice(&buf[..n]);
                continue;
            }
        }
        assert!(sim.step());
        assert!(sim.elapsed() < Duration::from_secs(5));
    }
    assert_eq!(got, b"request");
    // The server answers with an empty stream before the ACK is sent
    // back: both go out in one packet.
    sim.server().stream_write(id, &[], true).unwrap();
    let mut readable = false;
    let until = sim.elapsed() + Duration::from_millis(200);
    while !readable && sim.elapsed() < until {
        assert!(sim.step());
        while let Some(ev) = sim.client.poll_event() {
            readable |= ev == Event::StreamReadable(id);
        }
    }
    assert!(readable, "no readable event for the empty stream");
    assert_eq!(sim.client.stream_read(id, &mut buf), Ok((0, true)));
}
