//! Connection IDs and migration over an in-memory network with addresses
//! (virtual clock, fixed one-way delay): NEW_CONNECTION_ID issuance and
//! retirement, NAT rebinding, migration to a new address with a new CID,
//! path validation, the amplification limit on an unvalidated path,
//! falling back when validation fails, probes answered on their own
//! path, and stateless resets.

use rustls::pki_types::PrivatePkcs8KeyDer;
use skiff_quic::conn::{CloseReason, Connection, Event, TransportConfig};
use skiff_quic::ResetKey;
use std::collections::VecDeque;
use std::net::SocketAddr;
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

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Client and server joined by a network that knows addresses: server
/// datagrams reach the client only if sent to its current address.
struct Net {
    client: Connection,
    server: Option<Connection>,
    server_cfg: TransportConfig,
    now: Instant,
    delay: Duration,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    c2s: VecDeque<(Instant, Vec<u8>, SocketAddr)>,
    s2c: VecDeque<(Instant, Vec<u8>, SocketAddr)>,
    /// Server datagrams to an address the client is not at: (sent, to).
    stray: Vec<(Instant, SocketAddr)>,
    /// When the server last migrated.
    migrated_at: Option<Instant>,
    /// Server cwnd just before / after the datagram that made it migrate.
    cwnd_at_migration: Option<(u64, u64)>,
    received: u64,
    stream: Option<u64>,
    /// When set, every n-th datagram in each direction is lost.
    lose_every: Option<u64>,
    sent: [u64; 2],
    /// Datagrams shorter than this are dropped both ways (ACK-only and
    /// PING-only packets).
    drop_below: usize,
}

impl Net {
    fn new(client_cfg: TransportConfig, server_cfg: TransportConfig) -> Self {
        let (c, _) = tls();
        let now = Instant::now();
        let client = Connection::connect(c, "localhost", client_cfg, now).unwrap();
        let mut n = Self {
            client,
            server: None,
            server_cfg,
            now,
            delay: Duration::from_millis(10),
            server_addr: addr("192.0.2.1:443"),
            client_addr: addr("198.51.100.7:5000"),
            c2s: VecDeque::new(),
            s2c: VecDeque::new(),
            stray: Vec::new(),
            migrated_at: None,
            cwnd_at_migration: None,
            received: 0,
            stream: None,
            lose_every: None,
            sent: [0; 2],
            drop_below: 0,
        };
        n.run_until(|n| {
            n.client.is_handshake_confirmed()
                && n.server
                    .as_ref()
                    .is_some_and(Connection::is_handshake_confirmed)
        });
        n.settle();
        n
    }

    fn server(&mut self) -> &mut Connection {
        self.server.as_mut().unwrap()
    }

    /// Sends everything both sides have and delivers what is due.
    fn pump(&mut self) -> bool {
        let mut buf = vec![0u8; 2048];
        let mut moved = false;
        loop {
            let (n, to) = self.client.send_with_addr(&mut buf, self.now);
            if n == 0 {
                break;
            }
            assert!(to.is_none() || to == Some(self.server_addr));
            if self.lost(0) || n < self.drop_below {
                continue;
            }
            self.c2s
                .push_back((self.now + self.delay, buf[..n].to_vec(), self.client_addr));
            moved = true;
        }
        if let Some(s) = self.server.as_mut() {
            loop {
                let (n, to) = s.send_with_addr(&mut buf, self.now);
                if n == 0 {
                    break;
                }
                let to = to.expect("server knows the client address");
                self.sent[1] += 1;
                if self.lose_every.is_some_and(|k| self.sent[1] % k == 0) || n < self.drop_below {
                    continue;
                }
                self.s2c
                    .push_back((self.now + self.delay, buf[..n].to_vec(), to));
                moved = true;
            }
        }
        while self.c2s.front().is_some_and(|x| x.0 <= self.now) {
            let (_, mut d, from) = self.c2s.pop_front().unwrap();
            if self.server.is_none() {
                let (_, t) = tls();
                self.server = Connection::accept(t, self.server_cfg.clone(), &d, self.now).ok();
            }
            let now = self.now;
            let s = self.server.as_mut().unwrap();
            let (m, cwnd) = (s.stats().migrations, s.stats().cwnd);
            s.recv_from(&mut d, from, now);
            if s.stats().migrations > m {
                self.cwnd_at_migration = Some((cwnd, s.stats().cwnd));
                self.migrated_at = Some(now);
            }
            moved = true;
        }
        while self.s2c.front().is_some_and(|x| x.0 <= self.now) {
            let (at, mut d, to) = self.s2c.pop_front().unwrap();
            if to == self.client_addr {
                self.client.recv_from(&mut d, self.server_addr, self.now);
            } else {
                self.stray.push((at - self.delay, to));
            }
            moved = true;
        }
        self.app();
        moved
    }

    /// Pumps once, or advances the clock to the next event and fires the
    /// timers that are due.
    fn step(&mut self) -> bool {
        if self.pump() {
            return true;
        }
        let next = [
            self.c2s.front().map(|x| x.0),
            self.s2c.front().map(|x| x.0),
            self.client.timeout(),
            self.server.as_ref().and_then(Connection::timeout),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(t) = next else {
            return false;
        };
        self.now = t.max(self.now);
        if self.client.timeout().is_some_and(|x| x <= self.now) {
            self.client.on_timeout(self.now);
        }
        let now = self.now;
        if let Some(s) = self.server.as_mut() {
            if s.timeout().is_some_and(|x| x <= now) {
                s.on_timeout(now);
            }
        }
        true
    }

    fn lost(&mut self, dir: usize) -> bool {
        self.sent[dir] += 1;
        self.lose_every.is_some_and(|k| self.sent[dir] % k == 0)
    }

    /// Server application: reads every stream, counting bytes.
    fn app(&mut self) {
        while self.client.poll_event().is_some() {}
        let Some(s) = self.server.as_mut() else {
            return;
        };
        let mut buf = [0u8; 4096];
        while let Some(ev) = s.poll_event() {
            if let Event::StreamReadable(id) = ev {
                while let Ok((n, _)) = s.stream_read(id, &mut buf) {
                    if n == 0 {
                        break;
                    }
                    self.received += n as u64;
                }
            }
        }
    }

    fn run_until(&mut self, mut done: impl FnMut(&mut Self) -> bool) {
        let start = self.now;
        while !done(self) {
            assert!(
                self.now - start < Duration::from_secs(60),
                "stuck: server close {:?}, spare CIDs {}, server CIDs {:?}\nclient {:?}\nserver {:?}",
                self.server.as_ref().map(Connection::close_reason),
                self.client.spare_remote_cids(),
                self.server.as_ref().map(|s| s.local_cids().len()),
                self.client.stats(),
                self.server.as_ref().map(Connection::stats),
            );
            assert!(self.step(), "nothing left to happen");
            assert!(
                !self.client.is_closing(),
                "{:?}",
                self.client.close_reason()
            );
        }
    }

    /// Delivers what is in flight without letting timers fire.
    fn settle(&mut self) {
        for _ in 0..1000 {
            if self.pump() {
                continue;
            }
            let next = [self.c2s.front(), self.s2c.front()]
                .into_iter()
                .flatten()
                .map(|x| x.0)
                .min();
            match next {
                Some(t) => self.now = self.now.max(t),
                None => return,
            }
        }
        panic!("never settled");
    }

    /// Sends `n` bytes client -> server on one stream and waits for them.
    fn transfer(&mut self, n: usize) {
        let id = match self.stream {
            Some(id) => id,
            None => {
                let id = self.client.open_stream(false).unwrap();
                self.stream = Some(id);
                id
            }
        };
        let target = self.received + n as u64;
        let data = vec![0x5a; n];
        let mut off = 0;
        self.run_until(|net| {
            if off < data.len() {
                if let Ok(w) = net.client.stream_write(id, &data[off..], false) {
                    off += w;
                }
            }
            net.received >= target
        });
    }
}

/// Both sides issue CIDs up to the peer's active_connection_id_limit
/// (capped at 4); a client that switches to a spare CID retires the old
/// one and the server issues a replacement, ten times in a row, with data
/// flowing throughout. A smaller limit is respected.
#[test]
fn connection_ids_issued_switched_and_retired() {
    let mut n = Net::new(TransportConfig::default(), TransportConfig::default());
    assert_eq!(n.client.local_cids().len(), 4);
    assert_eq!(n.server().local_cids().len(), 4);
    assert_eq!(n.client.spare_remote_cids(), 3);
    assert_eq!(n.server().spare_remote_cids(), 3);
    n.transfer(10_000);
    let mut used = vec![n.client.remote_cid().to_vec()];
    for round in 0..10 {
        let gen = n.server().local_cids_generation();
        n.client.switch_remote_cid().unwrap();
        let now_cid = n.client.remote_cid().to_vec();
        assert!(!used.contains(&now_cid), "round {round}: CID reused");
        assert!(n.server().local_cids().contains(&now_cid));
        n.transfer(5_000);
        n.run_until(|n| n.client.spare_remote_cids() == 3);
        let server_cids = n.server().local_cids();
        assert_eq!(server_cids.len(), 4, "round {round}");
        for old in &used {
            assert!(
                !server_cids.contains(old),
                "round {round}: retired CID still active"
            );
        }
        assert!(n.server().local_cids_generation() > gen);
        used.push(now_cid);
    }
    assert_eq!(n.server().stats().migrations, 0);

    // Every third datagram lost both ways: lost NEW_CONNECTION_ID and
    // RETIRE_CONNECTION_ID frames are sent again.
    n.lose_every = Some(3);
    for round in 0..10 {
        n.client.switch_remote_cid().unwrap();
        n.transfer(3_000);
        n.run_until(|n| {
            n.client.spare_remote_cids() == 3 && n.server.as_ref().unwrap().local_cids().len() == 4
        });
        assert!(
            n.server()
                .local_cids()
                .contains(&n.client.remote_cid().to_vec()),
            "round {round}"
        );
    }
    assert!(n.client.stats().packets_lost > 0);

    // The server stores at most 2 CIDs: the client issues only one more.
    let small = TransportConfig {
        active_connection_id_limit: 2,
        ..TransportConfig::default()
    };
    let mut n = Net::new(TransportConfig::default(), small);
    assert_eq!(n.client.local_cids().len(), 2);
    assert_eq!(n.server().spare_remote_cids(), 1);
    assert_eq!(n.server().local_cids().len(), 4);
}

/// A lost packet is repaired by a PTO probe even when no acknowledgement
/// ever gets through: with nothing new to send, the probe carries the
/// oldest unacknowledged data rather than a bare PING (RFC 9002 6.2.4).
/// Found when the periodic loss above phase-locked with PING probes and
/// their single ACKs, and both sides idled out.
#[test]
fn pto_probe_resends_data_when_every_ack_is_lost() {
    let mut n = Net::new(TransportConfig::default(), TransportConfig::default());
    n.transfer(1000);
    let id = n.stream.unwrap();
    let target = n.received + 500;
    // From here no ACK-only or PING-only datagram gets through.
    n.drop_below = 100;
    n.client.stream_write(id, &[7; 500], false).unwrap();
    let mut buf = [0u8; 2048];
    let mut lost = 0;
    while n.client.send(&mut buf, n.now) > 0 {
        lost += 1;
    }
    assert!(lost > 0);
    n.run_until(|n| n.received >= target);
    assert!(n.client.stats().packets_lost == 0, "no ACK ever came back");
}

/// NAT rebinding: the client's port changes mid-transfer. The server
/// follows it, validates the new path, and keeps its congestion state
/// (only the port changed, RFC 9000 9.4).
#[test]
fn nat_rebinding_follows_the_client() {
    let mut n = Net::new(TransportConfig::default(), TransportConfig::default());
    n.transfer(300_000);
    n.client_addr = addr("198.51.100.7:6001");
    n.transfer(300_000);
    let s = n.server.as_ref().unwrap();
    assert_eq!(s.stats().migrations, 1);
    assert_eq!(s.stats().paths_validated, 1);
    assert!(s.path_validated());
    assert_eq!(s.remote_address(), Some(n.client_addr));
    let (before, after) = n.cwnd_at_migration.unwrap();
    assert_eq!(
        before, after,
        "port-only change keeps the congestion window"
    );
    // ...and the path MTU: no new probe.
    let s = n.server.as_ref().unwrap();
    assert_eq!(s.max_datagram_size(), 1452);
    assert_eq!(s.stats().pmtu_probes_sent, 1);
    assert!(n.received >= 600_000);
}

/// The client switches to a new CID and moves to a new IP address: the
/// server migrates, resets congestion control (new network path), moves
/// to a fresh client CID itself and retires its old one, validates the
/// path, and the transfer completes.
#[test]
fn migration_to_a_new_address_with_a_new_cid() {
    let mut n = Net::new(TransportConfig::default(), TransportConfig::default());
    n.transfer(300_000);
    let server_old_dcid = n.server().remote_cid().to_vec();
    n.client.switch_remote_cid().unwrap();
    n.client_addr = addr("203.0.113.9:7000");
    n.transfer(300_000);
    let (before, after) = n.cwnd_at_migration.unwrap();
    assert!(after < before, "cwnd {before} -> {after}: not reset");
    assert_eq!(after, 12_000, "a fresh NewReno window");
    let s = n.server.as_ref().unwrap();
    assert_eq!(s.stats().migrations, 1);
    assert_eq!(s.stats().paths_validated, 1);
    assert_eq!(s.remote_address(), Some(n.client_addr));
    assert_ne!(s.remote_cid(), &server_old_dcid[..]);
    // The path MTU is unknown again: discovery starts over from 1200 once
    // the new path is validated.
    assert_eq!(s.stats().pmtu_probes_sent, 2);
    n.run_until(|n| n.server.as_ref().unwrap().max_datagram_size() == 1452);
    n.run_until(|n| !n.client.local_cids().contains(&server_old_dcid));
    let moved = n.migrated_at.unwrap();
    assert!(
        !n.stray.is_empty(),
        "datagrams in flight to the old address"
    );
    for (sent, to) in &n.stray {
        assert!(*sent <= moved, "sent to {to} after the move");
    }
}

/// Before the new path is validated the server sends at most three times
/// what it received there (RFC 9000 9.3); when validation fails it returns
/// to the old, validated path (RFC 9000 9.3.2).
#[test]
fn unvalidated_path_is_amplification_limited_then_abandoned() {
    let mut n = Net::new(TransportConfig::default(), TransportConfig::default());
    n.transfer(50_000);
    // Lots of data queued at the server for the client.
    let sid = n.server().open_stream(false).unwrap();
    n.server()
        .stream_write(sid, &vec![7u8; 500_000], false)
        .unwrap();
    let old = n.client_addr;
    let new = addr("203.0.113.50:9000");
    // One client datagram from the new address.
    n.client
        .stream_write(n.stream.unwrap(), b"ping", false)
        .unwrap();
    let mut buf = vec![0u8; 2048];
    let len = n.client.send(&mut buf, n.now);
    assert!(len > 0);
    let now = n.now;
    n.server().recv_from(&mut buf[..len], new, now);
    assert_eq!(n.server().stats().migrations, 1);
    assert!(!n.server().path_validated());
    let mut to_new = 0;
    let mut challenge_sized = false;
    loop {
        let (k, to) = n.server().send_with_addr(&mut buf, now);
        if k == 0 {
            break;
        }
        assert_eq!(to, Some(new));
        challenge_sized |= k == (3 * len).min(1200);
        to_new += k;
    }
    assert!(to_new > 0, "the challenge goes out");
    assert!(to_new <= 3 * len, "{to_new} bytes for {len} received");
    assert!(
        challenge_sized,
        "the challenge datagram is padded as far as allowed"
    );
    // The client never answers from there: validation times out.
    let mut later = now;
    for _ in 0..1000 {
        let s = n.server.as_mut().unwrap();
        if s.stats().path_validation_failures > 0 || s.is_closing() {
            break;
        }
        later = s.timeout().unwrap().max(later + Duration::from_millis(1));
        s.on_timeout(later);
        while s.send_with_addr(&mut buf, later).0 > 0 {}
    }
    let s = n.server.as_ref().unwrap();
    assert_eq!(s.stats().path_validation_failures, 1);
    assert_eq!(s.remote_address(), Some(old), "back on the validated path");
    assert!(s.path_validated());
}

/// A probing packet (PATH_CHALLENGE only) from another address is answered
/// there, padded to 1200 bytes, without migrating; the client counts the
/// validated probe. A client drops datagrams that do not come from the
/// server's address.
#[test]
fn probe_is_answered_on_its_own_path() {
    let mut n = Net::new(TransportConfig::default(), TransportConfig::default());
    n.transfer(1000);
    let mut buf = vec![0u8; 2048];
    let len = n.client.send_path_probe(&mut buf, n.now);
    assert!(len >= 1200, "{len}");
    let probe_from = addr("203.0.113.77:4444");
    let now = n.now;
    n.server().recv_from(&mut buf[..len], probe_from, now);
    let (k, to) = n.server().send_with_addr(&mut buf, now);
    assert_eq!(to, Some(probe_from));
    assert!(k >= 1200, "{k}");
    assert_eq!(n.server().stats().migrations, 0);
    assert_eq!(n.server().remote_address(), Some(n.client_addr));
    // From a stranger: dropped.
    let mut copy = buf[..k].to_vec();
    let got = n.client.stats().packets_received;
    n.client.recv_from(&mut copy, addr("192.0.2.99:443"), now);
    assert_eq!(n.client.stats().packets_received, got);
    // From the server: the probe is validated.
    n.client.recv_from(&mut buf[..k], n.server_addr, now);
    assert_eq!(n.client.stats().paths_validated, 1);
    n.transfer(1000);
}

/// RFC 9000 10.3.1: a datagram that holds nothing decryptable and ends with
/// the reset token of the peer CID in use ends the connection (draining,
/// nothing more sent). Another CID's token, a spare CID's token and a
/// 20-byte datagram do not. The client's handshake CID has no token (only a
/// server sends one in its transport parameters), so the server recognises
/// the client's resets only after moving to a CID from NEW_CONNECTION_ID.
#[test]
fn stateless_reset_ends_the_connection() {
    let ckey = ResetKey::new(&[1; 32]);
    let skey = ResetKey::new(&[2; 32]);
    let cfg = |k: &ResetKey| TransportConfig {
        reset_key: Some(k.clone()),
        ..TransportConfig::default()
    };
    let mut n = Net::new(cfg(&ckey), cfg(&skey));
    n.transfer(1000);
    let now = n.now;
    let in_use = n.client.remote_cid().to_vec();
    let spare = n
        .server()
        .local_cids()
        .into_iter()
        .find(|c| *c != in_use)
        .unwrap();
    let mut buf = vec![0u8; 2048];
    for (what, mut d) in [
        (
            "another CID",
            skey.stateless_reset(b"not a cid of ours", 60).unwrap(),
        ),
        ("a spare CID", skey.stateless_reset(&spare, 60).unwrap()),
        ("another key", ckey.stateless_reset(&in_use, 60).unwrap()),
        (
            "20 bytes",
            skey.stateless_reset(&in_use, 60).unwrap()[23..].to_vec(),
        ),
    ] {
        assert!(!n.client.is_stateless_reset(&d), "{what}");
        n.client.recv_from(&mut d, n.server_addr, now);
        assert!(!n.client.is_closing(), "{what}");
    }
    n.transfer(1000);

    // The server: no token for the client's handshake CID...
    let client_cid = n.server().remote_cid().to_vec();
    let d = ckey.stateless_reset(&client_cid, 60).unwrap();
    assert!(!n.server().is_stateless_reset(&d));
    // ...but one for each CID the client issued.
    n.server().switch_remote_cid().unwrap();
    let client_cid = n.server().remote_cid().to_vec();
    let mut d = ckey.stateless_reset(&client_cid, 60).unwrap();
    assert!(n.server().is_stateless_reset(&d));
    let (now, from) = (n.now, n.client_addr);
    n.server().recv_from(&mut d, from, now);
    assert_eq!(
        n.server().close_reason(),
        Some(&CloseReason::StatelessReset)
    );
    assert_eq!(n.server().send_with_addr(&mut buf, now).0, 0, "silent");

    let mut d = skey.stateless_reset(&in_use, 60).unwrap();
    assert_eq!(d.len(), 43, "capped at 43 bytes");
    n.client.recv_from(&mut d, n.server_addr, now);
    assert_eq!(n.client.close_reason(), Some(&CloseReason::StatelessReset));
    assert!(n.client.is_closing());
    assert_eq!(
        n.client.send(&mut buf, now),
        0,
        "nothing sent after a reset"
    );
    let mut saw = false;
    while let Some(ev) = n.client.poll_event() {
        saw |= ev == Event::Closed(CloseReason::StatelessReset);
    }
    assert!(saw, "Closed event");
}

/// RFC 9000 10.3.1: a datagram is a reset only if nothing in it could be
/// processed. A server's long-header Handshake probe, with bytes after it
/// that end in the server's token, is processed and keeps the connection.
/// (Regression too: the server's PTO used to probe the Initial space, acked
/// and no longer decryptable by the client, instead of the Handshake one.)
#[test]
fn processed_datagram_ending_with_a_token_is_not_a_reset() {
    let (ct, st) = tls();
    let skey = ResetKey::new(&[2; 32]);
    let scfg = TransportConfig {
        reset_key: Some(skey.clone()),
        ..TransportConfig::default()
    };
    let mut now = Instant::now();
    let mut c = Connection::connect(ct, "localhost", TransportConfig::default(), now).unwrap();
    let mut buf = vec![0u8; 2048];
    let n = c.send(&mut buf, now);
    let mut s = Connection::accept(st, scfg, &buf[..n], now).unwrap();
    s.recv(&mut buf[..n], now);
    // The server's first flight reaches the client. Of the client's answer
    // only the Initial (its ACK) reaches the server, padded, so the server's
    // PTO resends Handshake data, which the client can still decrypt.
    loop {
        let n = s.send(&mut buf, now);
        if n == 0 {
            break;
        }
        c.recv(&mut buf[..n], now);
    }
    let n = c.send(&mut buf, now);
    let h = skiff_wire::header::Header::parse(&buf[..n], 0).unwrap();
    assert_eq!(h.ty, skiff_wire::header::PacketType::Initial);
    let mut initial = buf[..h.packet_len].to_vec();
    initial.resize(1200, 0);
    s.recv(&mut initial, now);
    while c.send(&mut buf, now) > 0 {}
    let reset = skey.stateless_reset(c.remote_cid(), 60).unwrap();
    assert!(c.is_stateless_reset(&reset), "the client has the token");
    now = s.timeout().unwrap();
    s.on_timeout(now);
    let n = s.send(&mut buf, now);
    let probe = skiff_wire::header::Header::parse(&buf[..n], 0).unwrap();
    assert_eq!(probe.ty, skiff_wire::header::PacketType::Handshake);
    let mut d = buf[..n].to_vec();
    d.extend_from_slice(&reset);
    assert!(c.is_stateless_reset(&d));
    let before = c.stats().packets_received;
    c.recv(&mut d, now);
    assert!(
        c.stats().packets_received > before,
        "the probe was processed"
    );
    assert!(!c.is_closing(), "{:?}", c.close_reason());
}
