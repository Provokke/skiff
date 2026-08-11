//! Connection behaviour under simulated network conditions (virtual time).
//! Bulk sizes are 50 MB in release builds (`cargo test -p skiff-sim
//! --release`) and 2 MB in debug builds so the workspace suite stays fast.

use ring::digest::{digest, Context, SHA256};
use skiff::echo::payload;
use skiff::tls;
use skiff_quic::{CloseReason, Connection, Event, TransportConfig};
use skiff_sim::{LinkConfig, Sim, SimConfig};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const ALPN: &[u8] = b"skiff-sim";
const BULK: usize = if cfg!(debug_assertions) {
    2_000_000
} else {
    50_000_000
};
const MSS: u64 = 1200;

fn tls_pair() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    static CFG: OnceLock<(Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>)> = OnceLock::new();
    CFG.get_or_init(|| {
        let (cert, key) = tls::self_signed(&["localhost"]).unwrap();
        (
            tls::client_config(vec![cert.clone()], &[ALPN]).unwrap(),
            tls::server_config(vec![cert], key, &[ALPN]).unwrap(),
        )
    })
    .clone()
}

fn sim(link: LinkConfig, config: TransportConfig, seed: u64) -> Sim {
    let (c, s) = tls_pair();
    Sim::new(SimConfig {
        client_tls: c,
        server_name: "localhost".into(),
        server_tls: s,
        client: config.clone(),
        server: config,
        c2s: link.clone(),
        s2c: link,
        seed,
    })
    .unwrap()
}

fn handshake(sim: &mut Sim) {
    sim.run(Duration::from_secs(30), |s| {
        s.client.is_handshake_confirmed()
            && s.server
                .as_ref()
                .is_some_and(Connection::is_handshake_confirmed)
    })
    .unwrap();
}

/// Reads everything readable on the server, hashing stream `id`.
struct Sink {
    hash: Context,
    len: usize,
    fin: bool,
}

impl Sink {
    fn new() -> Self {
        Self {
            hash: Context::new(&SHA256),
            len: 0,
            fin: false,
        }
    }

    fn drain(&mut self, c: &mut Connection, id: u64) {
        let mut buf = [0u8; 16 * 1024];
        while !self.fin {
            let (n, fin) = c.stream_read(id, &mut buf).unwrap();
            self.hash.update(&buf[..n]);
            self.len += n;
            self.fin = fin;
            if n == 0 {
                break;
            }
        }
    }
}

struct Bulk {
    sim: Sim,
    elapsed: Duration,
}

/// Client sends `len` bytes on one stream; the server hashes what arrives.
fn bulk(
    link: LinkConfig,
    config: TransportConfig,
    len: usize,
    seed: u64,
    budget: Duration,
) -> Bulk {
    let mut sim = sim(link, config, seed);
    handshake(&mut sim);
    let data = payload(len, seed as u8);
    let want = digest(&SHA256, &data);
    let id = sim.client.open_stream(false).unwrap();
    assert_eq!(sim.client.stream_write(id, &data, true).unwrap(), len);
    drop(data);
    let t0 = sim.elapsed();
    let mut sink = Sink::new();
    sim.run(budget, |s| {
        if let Some(srv) = s.server.as_mut() {
            while let Some(ev) = srv.poll_event() {
                if ev == Event::StreamReadable(id) {
                    sink.drain(srv, id);
                }
            }
        }
        sink.fin
    })
    .unwrap_or_else(|e| panic!("seed {seed}: {e}; received {} of {len}", sink.len));
    assert_eq!(sink.len, len);
    assert_eq!(
        sink.hash.finish().as_ref(),
        want.as_ref(),
        "sha256 of the received stream"
    );
    let elapsed = sim.elapsed() - t0;
    eprintln!(
        "seed {seed}: {len} bytes in {elapsed:?} virtual; client {:?}; c2s {:?}",
        sim.client.stats(),
        sim.c2s.stats
    );
    Bulk { sim, elapsed }
}

fn bottleneck() -> LinkConfig {
    // 10 ms one way, 100 Mbit/s, 256 KB of buffer (about one BDP).
    LinkConfig::new(Duration::from_millis(10)).bandwidth(12_500_000, 256 * 1024)
}

#[test]
fn handshake_completes_in_about_one_round_trip() {
    let mut s = sim(
        LinkConfig::new(Duration::from_millis(50)),
        TransportConfig::default(),
        1,
    );
    s.run(Duration::from_secs(5), |s| s.client.is_handshake_complete())
        .unwrap();
    let t = s.elapsed();
    assert!(
        t >= Duration::from_millis(100) && t < Duration::from_millis(250),
        "client handshake took {t:?} at 100 ms RTT"
    );
    handshake(&mut s);
    assert_eq!(s.client.alpn_protocol(), Some(ALPN));
    assert_eq!(s.client.stats().packets_lost, 0);
}

#[test]
fn bulk_transfer_intact_without_loss() {
    let b = bulk(
        bottleneck(),
        TransportConfig::default(),
        BULK,
        1,
        Duration::from_secs(600),
    );
    // 12.5 MB/s bottleneck: allow slow start and queueing overhead.
    let floor = Duration::from_secs_f64(BULK as f64 / 12_500_000.0);
    assert!(
        b.elapsed >= floor,
        "faster than the bottleneck: {:?}",
        b.elapsed
    );
    assert!(
        b.elapsed < 3 * floor + Duration::from_secs(1),
        "{BULK} bytes took {:?} (line rate {floor:?})",
        b.elapsed
    );
}

#[test]
fn bulk_transfer_intact_at_5_percent_loss() {
    let b = bulk(
        bottleneck().loss(0.05),
        TransportConfig::default(),
        BULK,
        5,
        Duration::from_secs(3600),
    );
    let lost = b.sim.client.stats().packets_lost;
    assert!(
        lost > 0 && b.sim.c2s.stats.lost > 0,
        "the link must lose packets"
    );
}

#[test]
fn bulk_transfer_intact_at_20_percent_loss_with_reordering() {
    let b = bulk(
        bottleneck().loss(0.20).reorder(0.05).duplicate(0.01),
        TransportConfig::default(),
        BULK,
        20,
        Duration::from_secs(36_000),
    );
    assert!(b.sim.c2s.stats.lost > 0 && b.sim.c2s.stats.reordered > 0);
}

/// The receiver does not read: the sender must stop at the advertised
/// stream window (single stream) and connection window (two streams), then
/// finish once the receiver reads and grants credit.
#[test]
fn flow_control_blocks_then_unblocks() {
    let config = TransportConfig {
        initial_max_data: 96 * 1024,
        initial_max_stream_data: 64 * 1024,
        ..TransportConfig::default()
    };
    let mut s = sim(LinkConfig::new(Duration::from_millis(5)), config, 3);
    handshake(&mut s);
    let a = s.client.open_stream(true).unwrap();
    let b = s.client.open_stream(true).unwrap();
    let len = 300_000;
    for (id, seed) in [(a, 1u8), (b, 2u8)] {
        s.client
            .stream_write(id, &payload(len, seed), true)
            .unwrap();
    }
    // Two seconds without reading: 400 RTTs, plenty to overrun any window.
    s.run_for(Duration::from_secs(2)).unwrap();
    assert!(!s.client.is_closing());
    let srv = s.server.as_mut().unwrap();
    let mut got: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut buf = vec![0u8; 1 << 20];
    for id in [a, b] {
        // Read only what already arrived, without letting credit flow back.
        let (n, _) = srv.stream_read(id, &mut buf).unwrap();
        assert!(
            n <= 64 * 1024,
            "stream {id}: {n} bytes beyond its 64 KiB window"
        );
        got.entry(id).or_default().extend_from_slice(&buf[..n]);
    }
    let total: usize = got.values().map(Vec::len).sum();
    assert_eq!(total, 96 * 1024, "exactly the connection window arrived");
    // Now read continuously; both streams complete.
    let mut fins = 0;
    s.run(Duration::from_secs(120), |s| {
        let srv = s.server.as_mut().unwrap();
        while let Some(ev) = srv.poll_event() {
            if let Event::StreamReadable(id) = ev {
                loop {
                    let (n, fin) = srv.stream_read(id, &mut buf).unwrap();
                    got.entry(id).or_default().extend_from_slice(&buf[..n]);
                    if fin {
                        fins += 1;
                    }
                    if fin || n == 0 {
                        break;
                    }
                }
            }
        }
        fins == 2
    })
    .unwrap();
    assert_eq!(got[&a], payload(len, 1));
    assert_eq!(got[&b], payload(len, 2));
}

/// 100 concurrent bidirectional streams echoed by the server.
#[test]
fn hundred_concurrent_streams_echo() {
    let mut s = sim(
        LinkConfig::new(Duration::from_millis(10))
            .loss(0.02)
            .reorder(0.05),
        TransportConfig::default(),
        4,
    );
    handshake(&mut s);
    let mut sent = BTreeMap::new();
    for i in 0..100u8 {
        let id = s.client.open_stream(true).unwrap();
        let data = payload(10_000 + usize::from(i) * 13, i);
        assert_eq!(s.client.stream_write(id, &data, true).unwrap(), data.len());
        sent.insert(id, data);
    }
    let mut echoed: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut done = 0;
    let mut buf = vec![0u8; 65536];
    s.run(Duration::from_secs(120), |s| {
        let srv = s.server.as_mut().unwrap();
        while let Some(ev) = srv.poll_event() {
            if let Event::StreamReadable(id) = ev {
                loop {
                    let (n, fin) = srv.stream_read(id, &mut buf).unwrap();
                    srv.stream_write(id, &buf[..n], fin).unwrap();
                    if fin || n == 0 {
                        break;
                    }
                }
            }
        }
        while let Some(ev) = s.client.poll_event() {
            if let Event::StreamReadable(id) = ev {
                loop {
                    let (n, fin) = s.client.stream_read(id, &mut buf).unwrap();
                    echoed.entry(id).or_default().extend_from_slice(&buf[..n]);
                    if fin {
                        done += 1;
                    }
                    if fin || n == 0 {
                        break;
                    }
                }
            }
        }
        done == 100
    })
    .unwrap();
    assert_eq!(echoed, sent);
}

#[test]
fn idle_timeout_closes_both_sides() {
    let config = TransportConfig {
        max_idle_timeout: Duration::from_secs(3),
        ..TransportConfig::default()
    };
    let mut s = sim(LinkConfig::new(Duration::from_millis(20)), config, 6);
    handshake(&mut s);
    let quiet = s.elapsed();
    s.run(Duration::from_secs(60), |s| {
        s.client.is_closed() && s.server.as_ref().is_some_and(Connection::is_closed)
    })
    .unwrap();
    assert_eq!(s.client.close_reason(), Some(&CloseReason::IdleTimeout));
    let idle = s.elapsed() - quiet;
    assert!(
        idle >= Duration::from_millis(2900) && idle <= Duration::from_millis(3500),
        "{idle:?}"
    );
}

/// Tail loss: every datagram of a short message is dropped, so no ACK can
/// reveal the loss. The probe timeout must resend it within a few RTTs
/// rather than the 30 s idle timeout.
#[test]
fn pto_recovers_tail_loss() {
    let mut s = sim(
        LinkConfig::new(Duration::from_millis(10)),
        TransportConfig::default(),
        7,
    );
    handshake(&mut s);
    // Let the handshake's last ACKs settle.
    s.run_for(Duration::from_millis(200)).unwrap();
    assert!(!s.client.is_closing());
    let id = s.client.open_stream(false).unwrap();
    let msg = payload(4000, 9);
    s.client.stream_write(id, &msg, true).unwrap();
    s.c2s.drop_next = 4; // the 4 datagrams of the message
    let t0 = s.elapsed();
    let mut sink = Sink::new();
    s.run(Duration::from_secs(10), |s| {
        let srv = s.server.as_mut().unwrap();
        while let Some(ev) = srv.poll_event() {
            if ev == Event::StreamReadable(id) {
                sink.drain(srv, id);
            }
        }
        sink.fin
    })
    .unwrap();
    assert_eq!(s.c2s.stats.forced_drops, 4);
    assert_eq!(sink.len, msg.len());
    let took = s.elapsed() - t0;
    assert!(
        took < Duration::from_millis(500),
        "tail loss recovered after {took:?}"
    );
}

/// Congestion window: grows well beyond the initial window on a path
/// without a bottleneck (and loses nothing there), stays bounded by the bottleneck's BDP + queue when the queue
/// overflows (drop-tail losses), and never falls below the minimum window.
#[test]
fn congestion_window_tracks_the_path() {
    let initial = 10 * MSS;
    let clean = bulk(
        LinkConfig::new(Duration::from_millis(10)),
        TransportConfig::default(),
        2_000_000,
        8,
        Duration::from_secs(60),
    );
    let cwnd_clean = clean.sim.client.stats().cwnd;
    assert!(
        cwnd_clean > 8 * initial,
        "slow start grew cwnd only to {cwnd_clean}"
    );
    assert_eq!(clean.sim.client.stats().packets_lost, 0);

    // 1.25 MB/s, 20 ms RTT (BDP 25 KB) and a 30 KB queue.
    let narrow = LinkConfig::new(Duration::from_millis(10)).bandwidth(1_250_000, 30_000);
    let b = bulk(
        narrow,
        TransportConfig::default(),
        2_000_000,
        9,
        Duration::from_secs(120),
    );
    let st = b.sim.client.stats();
    assert!(b.sim.c2s.stats.queue_drops > 0, "queue never overflowed");
    assert!(st.packets_lost > 0);
    assert!(st.cwnd >= 2 * MSS, "below the minimum window: {}", st.cwnd);
    assert!(
        st.cwnd < 4 * (25_000 + 30_000),
        "cwnd {} ignores the losses",
        st.cwnd
    );
    // Goodput stays within 2x of the bottleneck rate (1.6 s at line rate).
    assert!(b.elapsed < Duration::from_secs(4), "took {:?}", b.elapsed);
}

/// Mid-transfer over a lossy, reordering bottleneck the client's NAT
/// rebinds (new port), then the client moves to a new address and a new
/// CID: the server follows both moves, validates each new path and the
/// stream arrives intact.
#[test]
fn transfer_survives_rebinding_and_migration_on_a_lossy_link() {
    let len = 1_000_000;
    let seed = 11;
    let mut sim = sim(
        bottleneck().loss(0.02).reorder(0.05),
        TransportConfig::default(),
        seed,
    );
    handshake(&mut sim);
    let data = payload(len, seed as u8);
    let want = digest(&SHA256, &data);
    let id = sim.client.open_stream(false).unwrap();
    assert_eq!(sim.client.stream_write(id, &data, true).unwrap(), len);
    let mut sink = Sink::new();
    let mut moves = 0;
    sim.run(Duration::from_secs(600), |s| {
        if let Some(srv) = s.server.as_mut() {
            while let Some(ev) = srv.poll_event() {
                if ev == Event::StreamReadable(id) {
                    sink.drain(srv, id);
                }
            }
        }
        if moves == 0 && sink.len >= len / 3 {
            s.client_addr.set_port(6001);
            moves = 1;
        } else if moves == 1 && sink.len >= 2 * len / 3 {
            s.client.switch_remote_cid().unwrap();
            s.client_addr = "203.0.113.9:7000".parse().unwrap();
            moves = 2;
        }
        sink.fin
    })
    .unwrap_or_else(|e| panic!("{e}; received {} of {len}", sink.len));
    assert_eq!(moves, 2);
    assert_eq!(sink.len, len);
    assert_eq!(sink.hash.finish().as_ref(), want.as_ref());
    let srv = sim.server.as_ref().unwrap();
    let st = srv.stats();
    assert_eq!(st.migrations, 2);
    assert_eq!(st.paths_validated, 2);
    assert_eq!(st.path_validation_failures, 0);
    assert_eq!(srv.remote_address(), Some(sim.client_addr));
    assert!(sim.c2s.stats.lost > 0, "the link must lose packets");
}

/// Path MTU discovery: on a path that carries at most 1350 bytes, three
/// lost 1452-byte probes lower the ceiling and the search bisects to the
/// largest size within 20 bytes of the limit. Lost probes are no
/// congestion signal, and the larger datagrams then carry a transfer.
#[test]
fn path_mtu_discovery_finds_the_link_mtu() {
    let link = LinkConfig::new(Duration::from_millis(10)).mtu(1350);
    let mut s = sim(link, TransportConfig::default(), 11);
    handshake(&mut s);
    assert_eq!(s.client.max_datagram_size(), 1200);
    let done = |c: &Connection| c.stats().pmtu_probes_sent >= 11;
    s.run(Duration::from_secs(30), |s| {
        done(&s.client) && s.server.as_ref().is_some_and(done)
    })
    .unwrap();
    s.run_for(Duration::from_secs(5)).unwrap();
    for c in [&s.client, s.server.as_ref().unwrap()] {
        let st = c.stats();
        // 1452 x3 lost, 1326 acked, 1389 x3 lost, 1357 x3 lost, 1341
        // acked; the ceiling (1356) is then within 20 bytes: done.
        assert_eq!(c.max_datagram_size(), 1341);
        assert_eq!((st.pmtu_probes_sent, st.pmtu_probes_lost), (11, 9));
        assert_eq!(st.packets_lost, 0, "a lost probe is no congestion loss");
    }
    assert_eq!((s.c2s.stats.too_big, s.s2c.stats.too_big), (9, 9));

    let id = s.client.open_stream(false).unwrap();
    let data = payload(300_000, 3);
    assert_eq!(s.client.stream_write(id, &data, true).unwrap(), data.len());
    let mut sink = Sink::new();
    s.run(Duration::from_secs(60), |s| {
        let srv = s.server.as_mut().unwrap();
        while let Some(ev) = srv.poll_event() {
            if ev == Event::StreamReadable(id) {
                sink.drain(srv, id);
            }
        }
        sink.fin
    })
    .unwrap();
    assert_eq!(sink.hash.finish().as_ref(), digest(&SHA256, &data).as_ref());
    assert_eq!(s.c2s.stats.too_big, 9, "data datagrams fit the path");
    assert_eq!(s.client.stats().packets_lost, 0);
    // 300 KB in 1341-byte datagrams: about 230 rather than 260 at 1200.
    assert!(s.c2s.stats.delivered < 250, "{:?}", s.c2s.stats);

    // Congestion control counts in the new datagram size: after a
    // 3-second outage, persistent congestion collapses the window to two
    // 1341-byte datagrams.
    s.c2s.blackhole = true;
    s.s2c.blackhole = true;
    let id = s.client.open_stream(false).unwrap();
    assert_eq!(
        s.client.stream_write(id, &[1; 50_000], true).unwrap(),
        50_000
    );
    s.run_for(Duration::from_secs(3)).unwrap();
    s.c2s.blackhole = false;
    s.s2c.blackhole = false;
    while s.client.stats().packets_lost == 0 {
        assert!(s.step().unwrap() && s.elapsed() < Duration::from_secs(120));
    }
    assert_eq!(s.client.stats().cwnd, 2 * 1341);
}

fn sim_pair(client: TransportConfig, server: TransportConfig, link: LinkConfig) -> Sim {
    let (c, s) = tls_pair();
    Sim::new(SimConfig {
        client_tls: c,
        server_name: "localhost".into(),
        server_tls: s,
        client,
        server,
        c2s: link.clone(),
        s2c: link,
        seed: 13,
    })
    .unwrap()
}

/// Discovery reaches `pmtu_max` in one probe on a path without a limit,
/// stops at the peer's max_udp_payload_size, and is off when `pmtu_max`
/// is not above `max_datagram_size`.
#[test]
fn path_mtu_discovery_limits() {
    let link = LinkConfig::new(Duration::from_millis(10));
    let mtus = |s: &Sim| {
        (
            s.client.max_datagram_size(),
            s.server.as_ref().unwrap().max_datagram_size(),
        )
    };
    let small = TransportConfig {
        pmtu_max: 1300,
        ..TransportConfig::default()
    };
    let off = TransportConfig {
        pmtu_max: 1200,
        ..TransportConfig::default()
    };
    for (client, server, want) in [
        (
            TransportConfig::default(),
            TransportConfig::default(),
            (1452, 1452),
        ),
        (TransportConfig::default(), small.clone(), (1300, 1300)),
        (small, TransportConfig::default(), (1300, 1300)),
        (off.clone(), off, (1200, 1200)),
    ] {
        let mut s = sim_pair(client, server, link.clone());
        handshake(&mut s);
        s.run_for(Duration::from_secs(2)).unwrap();
        assert_eq!(mtus(&s), want);
        let probes = s.client.stats().pmtu_probes_sent;
        assert_eq!(probes, u64::from(want.0 > 1200));
        assert_eq!(s.client.stats().pmtu_probes_lost, 0);
    }
}

/// Pacing spreads each window over the round trip. On a path without a
/// bottleneck a whole window's ACKs arrive at one instant; unpaced, the
/// client answers with the whole next window at that instant, paced it
/// sends at most a bucket (2 ms at 1.25 * cwnd / srtt, 10 to 256
/// datagrams) at once, and the transfer takes about as long.
#[test]
fn pacing_spreads_each_window() {
    let link = LinkConfig::new(Duration::from_millis(10));
    let largest_burst = |config: TransportConfig| {
        let mut s = sim(link.clone(), config, 14);
        handshake(&mut s);
        let data = payload(2_000_000, 4);
        let id = s.client.open_stream(false).unwrap();
        assert_eq!(s.client.stream_write(id, &data, true).unwrap(), data.len());
        let t0 = s.elapsed();
        let mut sink = Sink::new();
        let (mut at, mut burst, mut largest) = (s.now, 0, 0);
        while !sink.fin {
            let before = s.c2s.stats.offered;
            assert!(s.step().unwrap());
            if s.now != at {
                (at, burst) = (s.now, 0);
            }
            burst += s.c2s.stats.offered - before;
            largest = largest.max(burst);
            let srv = s.server.as_mut().unwrap();
            while let Some(ev) = srv.poll_event() {
                if ev == Event::StreamReadable(id) {
                    sink.drain(srv, id);
                }
            }
            assert!(s.elapsed() < Duration::from_secs(60));
        }
        assert_eq!(sink.len, data.len());
        (largest, s.elapsed() - t0)
    };
    let (paced, paced_t) = largest_burst(TransportConfig::default());
    let (unpaced, unpaced_t) = largest_burst(TransportConfig {
        pacing: false,
        ..TransportConfig::default()
    });
    eprintln!("largest burst: paced {paced} in {paced_t:?}, unpaced {unpaced} in {unpaced_t:?}");
    assert!(paced <= 256, "paced burst {paced}");
    assert!(
        unpaced > 2 * paced,
        "unpaced burst {unpaced}, paced {paced}"
    );
    assert!(
        paced_t < unpaced_t * 2,
        "pacing slowed the transfer: {paced_t:?}"
    );
}
