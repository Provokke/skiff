//! Real UDP over 127.0.0.1: the endpoint's connection-ID demultiplexing,
//! routing of newly issued CIDs and NAT rebinding (through a relay),
//! Version Negotiation, stateless resets, Retry, certificate verification, and the skiff-server /
//! skiff-client binaries doing a handshake and stream echo.

use skiff::echo::{payload, run_client, EchoClient, EchoError, EchoServer, ALPN};
use skiff::{tls, Endpoint, EndpointStats};
use skiff_quic::{CloseReason, ResetKey, TransportConfig};
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

struct Server {
    addr: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    stop: Arc<AtomicBool>,
    thread: JoinHandle<(EndpointStats, u64, u64)>,
}

impl Server {
    fn spawn() -> Self {
        Self::spawn_on("127.0.0.1:0", TransportConfig::default())
    }

    fn spawn_on(bind: &str, transport: TransportConfig) -> Self {
        Self::spawn_with(bind, transport, false)
    }

    fn spawn_with(bind: &str, transport: TransportConfig, retry: bool) -> Self {
        let bind = bind.to_string();
        let (cert, key) = tls::self_signed(&["localhost"]).unwrap();
        let cfg = tls::server_config(vec![cert.clone()], key, &[ALPN]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut ep = Endpoint::bind(bind, Some(cfg), transport).unwrap();
            assert_eq!(ep.set_retry(retry), retry);
            tx.send(ep.local_addr().unwrap()).unwrap();
            let mut srv = EchoServer::default();
            srv.serve(&mut ep, |_| flag.load(Ordering::Relaxed))
                .unwrap();
            (ep.stats().clone(), srv.handshakes, srv.echoed)
        });
        let addr = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Self {
            addr,
            cert,
            stop,
            thread,
        }
    }

    fn finish(self) -> (EndpointStats, u64, u64) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().unwrap()
    }
}

#[test]
fn endpoint_and_connection_are_send() {
    fn send<T: Send>() {}
    send::<Endpoint>();
    send::<skiff_quic::Connection>();
}

/// Three connections from one client socket to one server socket: every
/// datagram must reach the right connection by DCID on both sides.
#[test]
fn three_connections_multiplexed_over_one_socket_each_side() {
    let server = Server::spawn();
    let ccfg = tls::client_config(vec![server.cert.clone()], &[ALPN]).unwrap();
    let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
    let mut clients = Vec::new();
    for k in 0..3u8 {
        let h = ep.connect(ccfg.clone(), "localhost", server.addr).unwrap();
        let payloads = (0..4u8)
            .map(|i| payload(150_000 + 1000 * usize::from(i), 16 * k + i))
            .collect();
        clients.push((h, EchoClient::new(payloads)));
    }
    let cids: std::collections::BTreeSet<Vec<u8>> = clients
        .iter()
        .map(|(h, _)| ep.connection(*h).unwrap().local_cid().to_vec())
        .collect();
    assert_eq!(cids.len(), 3, "distinct local CIDs");
    let start = Instant::now();
    while !clients.iter().all(|(_, c)| c.is_done()) {
        assert!(start.elapsed() < Duration::from_secs(30), "echo timed out");
        for (h, c) in clients.iter_mut() {
            c.poll(ep.connection(*h).unwrap()).unwrap();
        }
        ep.drive(Duration::from_millis(10)).unwrap();
    }
    for (h, c) in &clients {
        let conn = ep.connection(*h).unwrap();
        assert_eq!(conn.alpn_protocol(), Some(ALPN));
        assert_eq!(c.report(conn).bytes, 4 * 150_000 + 6000);
    }
    let client_stats = ep.stats().clone();
    for (h, _) in &clients {
        ep.connection(*h).unwrap().close(0, b"", Instant::now());
    }
    let t = Instant::now();
    while !ep.is_empty() && t.elapsed() < Duration::from_secs(5) {
        ep.drive(Duration::from_millis(10)).unwrap();
        ep.remove_closed();
    }
    assert_eq!(ep.len(), 0, "all client connections reached Closed");
    let (stats, handshakes, echoed) = server.finish();
    assert_eq!(stats.accepted, 3);
    assert_eq!(handshakes, 3);
    assert_eq!(echoed, 3 * (4 * 150_000 + 6000));
    assert_eq!(client_stats.datagrams_dropped, 0, "{client_stats:?}");
}

/// RFC 9000 6.1: a 1200-byte datagram with an unknown version gets a
/// Version Negotiation reply with the CIDs swapped; smaller ones are
/// dropped silently. RFC 9000 10.3: a short header for an unknown CID gets
/// a stateless reset one byte shorter, ending with the token for that CID,
/// unless it would be under 21 bytes.
#[test]
fn version_negotiation_and_unknown_cids() {
    let key = [0x4bu8; 32];
    let server = Server::spawn_on(
        "127.0.0.1:0",
        TransportConfig {
            reset_key: Some(ResetKey::new(&key)),
            ..TransportConfig::default()
        },
    );
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let dcid = [0xd1u8; 8];
    let scid = [0x5cu8; 5];
    let mut probe = vec![0xc0u8];
    probe.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes());
    probe.push(8);
    probe.extend_from_slice(&dcid);
    probe.push(5);
    probe.extend_from_slice(&scid);
    let mut buf = [0u8; 1500];

    // Too small to be a client Initial: no reply.
    sock.send_to(&probe[..], server.addr).unwrap();
    assert!(
        sock.recv_from(&mut buf).is_err(),
        "no VN for a small datagram"
    );
    // A short header for a CID nobody owns: too small for a reset...
    let mut short = vec![0x40u8];
    short.extend_from_slice(&[0xee; 20]);
    sock.send_to(&short, server.addr).unwrap();
    assert!(sock.recv_from(&mut buf).is_err(), "no 20-byte reset");
    // ...and large enough: a stateless reset.
    short.extend_from_slice(&[0xee; 20]);
    sock.send_to(&short, server.addr).unwrap();
    let (n, _) = sock.recv_from(&mut buf).expect("stateless reset");
    assert_eq!(n, short.len() - 1, "one byte shorter than the trigger");
    assert_eq!(buf[0] & 0xc0, 0x40, "looks like a short header");
    let token = ResetKey::new(&key).token(&[0xee; 8]);
    assert_eq!(&buf[n - 16..n], &token, "token for the unknown CID");

    probe.resize(1200, 0);
    sock.send_to(&probe, server.addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    let vn = &buf[..n];
    assert_eq!(vn[0] & 0x80, 0x80, "long header");
    assert_eq!(&vn[1..5], &[0, 0, 0, 0], "version 0");
    assert_eq!(usize::from(vn[5]), scid.len());
    assert_eq!(&vn[6..11], &scid, "DCID echoes our SCID");
    assert_eq!(usize::from(vn[11]), dcid.len());
    assert_eq!(&vn[12..20], &dcid, "SCID echoes our DCID");
    let versions: Vec<u32> = vn[20..]
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
        .collect();
    assert!(versions.contains(&1), "{versions:x?}");
    // A burst of 200 unknown short headers: resets are capped at 64 per
    // second (a burst spans at most two windows), so a flood cannot use
    // the server as a reflector.
    let short = [0x45u8; 100];
    for _ in 0..200 {
        sock.send_to(&short, server.addr).unwrap();
    }
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut replies = 0;
    while sock.recv_from(&mut buf).is_ok() {
        replies += 1;
    }
    assert!((63..=128).contains(&replies), "{replies}");
    let (stats, _, _) = server.finish();
    assert_eq!(stats.version_negotiations, 1);
    assert!(
        (64..=129).contains(&stats.stateless_resets_sent),
        "{}",
        stats.stateless_resets_sent
    );
    assert_eq!(stats.datagrams_dropped, 203);
    assert_eq!(stats.accepted, 0);
}

/// A UDP relay that stands in for a NAT: the client talks to `front`; the
/// relay talks to the server from `back[0]` until `rebind` is set, then
/// from `back[1]`, and drops whatever still arrives on the old binding.
struct Nat {
    front: SocketAddr,
    rebind: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: JoinHandle<[u64; 3]>,
}

impl Nat {
    fn spawn(server: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").unwrap();
        let back = [
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            UdpSocket::bind("127.0.0.1:0").unwrap(),
        ];
        for s in [&front, &back[0], &back[1]] {
            s.set_nonblocking(true).unwrap();
        }
        let addr = front.local_addr().unwrap();
        let rebind = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (r, st) = (rebind.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            // Datagrams relayed via back[0], via back[1], dropped on back[0].
            let mut counts = [0u64; 3];
            let mut client = None;
            let mut buf = [0u8; 2048];
            while !st.load(Ordering::Relaxed) {
                let mut idle = true;
                let i = usize::from(r.load(Ordering::Relaxed));
                while let Ok((n, from)) = front.recv_from(&mut buf) {
                    client = Some(from);
                    back[i].send_to(&buf[..n], server).unwrap();
                    idle = false;
                }
                for (j, b) in back.iter().enumerate() {
                    while let Ok((n, _)) = b.recv_from(&mut buf) {
                        idle = false;
                        if j != i {
                            counts[2] += 1;
                        } else if let Some(c) = client {
                            front.send_to(&buf[..n], c).unwrap();
                            counts[j] += 1;
                        }
                    }
                }
                if idle {
                    std::thread::sleep(Duration::from_micros(200));
                }
            }
            counts
        });
        Self {
            front: addr,
            rebind,
            stop,
            thread,
        }
    }

    fn finish(self) -> [u64; 3] {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().unwrap()
    }
}

fn echo(ep: &mut Endpoint, h: skiff::ConnectionHandle, payloads: Vec<Vec<u8>>) -> u64 {
    let mut c = EchoClient::new(payloads);
    let start = Instant::now();
    while !c.is_done() {
        let conn = ep.connection(h).unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "echo timed out: {:?} {:?}",
            conn.stats(),
            conn.close_reason()
        );
        c.poll(conn).unwrap();
        ep.drive(Duration::from_millis(5)).unwrap();
    }
    c.report(ep.connection(h).unwrap()).bytes
}

/// Over real sockets: the endpoints route every CID their connections
/// issue. The client switches to a fresh server CID and its NAT rebinds;
/// the server endpoint routes the new DCID to the connection, which
/// migrates and answers on the new binding (the old one is a black hole).
/// A probe from a second socket is answered on that socket.
#[test]
fn endpoint_follows_new_cids_and_nat_rebinding() {
    let server = Server::spawn();
    let nat = Nat::spawn(server.addr);
    let ccfg = tls::client_config(vec![server.cert.clone()], &[ALPN]).unwrap();
    let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
    let h = ep.connect(ccfg, "localhost", nat.front).unwrap();
    assert_eq!(echo(&mut ep, h, vec![payload(100_000, 1)]), 100_000);
    let conn = ep.connection(h).unwrap();
    // Path MTU discovery over real sockets: one 1452-byte probe, acked.
    assert_eq!(conn.max_datagram_size(), 1452);
    assert_eq!(
        (conn.stats().pmtu_probes_sent, conn.stats().pmtu_probes_lost),
        (1, 0)
    );
    let mut local: Vec<Vec<u8>> = conn.local_cids();
    let old_dcid = conn.remote_cid().to_vec();
    let mut routed = ep.routed_cids(h);
    local.sort();
    routed.sort();
    assert_eq!(local.len(), 4, "the client issued three more CIDs");
    assert_eq!(routed, local, "and its endpoint routes all of them");

    let conn = ep.connection(h).unwrap();
    conn.switch_remote_cid().unwrap();
    assert_ne!(conn.remote_cid(), &old_dcid[..]);
    nat.rebind.store(true, Ordering::Relaxed);
    assert_eq!(echo(&mut ep, h, vec![payload(300_000, 2)]), 300_000);
    assert_eq!(ep.peer_addr(h), Some(nat.front));

    // A probe sent from a second socket (another interface): the server
    // endpoint answers it there, padded, not on the connection's path.
    let side = UdpSocket::bind("127.0.0.1:0").unwrap();
    side.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = vec![0u8; 2048];
    let n = ep
        .connection(h)
        .unwrap()
        .send_path_probe(&mut buf, Instant::now());
    assert!(n >= 1200, "{n}");
    side.send_to(&buf[..n], server.addr).unwrap();
    let (k, from) = side
        .recv_from(&mut buf)
        .expect("PATH_RESPONSE on the probed path");
    assert_eq!(from, server.addr);
    assert!(k >= 1200, "{k}");
    let conn = ep.connection(h).unwrap();
    conn.recv_from(&mut buf[..k], nat.front, Instant::now());
    assert_eq!(conn.stats().paths_validated, 1, "the probe was answered");
    ep.connection(h).unwrap().close(0, b"", Instant::now());
    let t = Instant::now();
    while !ep.is_empty() && t.elapsed() < Duration::from_secs(5) {
        ep.drive(Duration::from_millis(10)).unwrap();
        ep.remove_closed();
    }
    let counts = nat.finish();
    let (stats, handshakes, echoed) = server.finish();
    assert_eq!(handshakes, 1);
    assert_eq!(echoed, 400_000);
    assert!(counts[0] > 0 && counts[1] > 0, "{counts:?}");
    assert_eq!(
        stats.datagrams_dropped, 0,
        "every DCID was routed: {stats:?}"
    );
}

/// A server restarted on the same port answers the old connection's
/// packets with stateless resets. With another reset key the client does
/// not recognise them and the connection stays open; with the key it had,
/// the client endpoint routes the reset to the connection, which ends at
/// once with `CloseReason::StatelessReset` instead of idling out.
#[test]
fn restarted_server_resets_old_connections() {
    let with_key = |k: u8| TransportConfig {
        reset_key: Some(ResetKey::new(&[k; 32])),
        ..TransportConfig::default()
    };
    let server = Server::spawn_on("127.0.0.1:0", with_key(1));
    let addr = server.addr.to_string();
    let ccfg = tls::client_config(vec![server.cert.clone()], &[ALPN]).unwrap();
    let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
    let h = ep.connect(ccfg, "localhost", server.addr).unwrap();
    assert_eq!(echo(&mut ep, h, vec![payload(10_000, 1)]), 10_000);
    server.finish();

    let mut pending = EchoClient::new(vec![payload(10_000, 2)]);
    let mut run = |ep: &mut Endpoint, d: Duration| {
        let t = Instant::now();
        while t.elapsed() < d {
            let conn = ep.connection(h).unwrap();
            if let Err(e) = pending.poll(conn) {
                return Some(e);
            }
            ep.drive(Duration::from_millis(5)).unwrap();
        }
        None
    };
    let wrong = Server::spawn_on(&addr, with_key(2));
    assert!(run(&mut ep, Duration::from_millis(800)).is_none());
    assert!(
        !ep.connection(h).unwrap().is_closing(),
        "a reset with another key"
    );
    let (stats, _, _) = wrong.finish();
    assert!(stats.stateless_resets_sent > 0, "{stats:?}");
    assert_eq!(ep.stats().stateless_resets_received, 0);

    let right = Server::spawn_on(&addr, with_key(1));
    let t = Instant::now();
    let err = run(&mut ep, Duration::from_secs(5)).expect("the connection ends");
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    assert!(
        matches!(err, EchoError::Closed(CloseReason::StatelessReset)),
        "{err:?}"
    );
    let (stats, handshakes, _) = right.finish();
    assert!(stats.stateless_resets_sent > 0);
    assert_eq!(handshakes, 0);
    assert!(ep.stats().stateless_resets_received >= 1);
    assert!(ep.connection(h).unwrap().is_closing());
}

/// A client Initial by hand: `token`, then zero bytes up to `size`. The
/// server endpoint checks the token before it decrypts anything.
fn raw_initial(dcid: &[u8], scid: &[u8], token: &[u8], size: usize) -> Vec<u8> {
    let mut d = vec![0xc0, 0, 0, 0, 1, dcid.len() as u8];
    d.extend_from_slice(dcid);
    d.push(scid.len() as u8);
    d.extend_from_slice(scid);
    assert!(token.len() < 64);
    d.push(token.len() as u8);
    d.extend_from_slice(token);
    let rest = size - d.len() - 2;
    d.extend_from_slice(&[0x40 | (rest >> 8) as u8, rest as u8]);
    d.resize(size, 0);
    d
}

/// A server endpoint with Retry on: a skiff client gets one Retry, comes
/// back with the token and completes the handshake and an echo; both
/// connections know a Retry happened. A token-less Initial under 1200
/// bytes gets nothing; a full-sized one gets a Retry whose token is
/// refused from another address, with a forged byte and for another CID,
/// and accepted once (then routed) from the right address.
#[test]
fn retry_validates_the_client_address() {
    let server = Server::spawn_with("127.0.0.1:0", TransportConfig::default(), true);
    let ccfg = tls::client_config(vec![server.cert.clone()], &[ALPN]).unwrap();
    let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
    let h = ep.connect(ccfg, "localhost", server.addr).unwrap();
    assert_eq!(echo(&mut ep, h, vec![payload(50_000, 1)]), 50_000);
    assert!(ep.connection(h).unwrap().retried());

    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    for s in [&a, &b] {
        s.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
    }
    let mut buf = vec![0u8; 2048];
    let (odcid, scid) = ([0x11u8; 8], [0x22u8; 8]);
    a.send_to(&raw_initial(&odcid, &scid, &[], 1100), server.addr)
        .unwrap();
    assert!(
        a.recv_from(&mut buf).is_err(),
        "no Retry for a short Initial"
    );
    a.send_to(&raw_initial(&odcid, &scid, &[], 1200), server.addr)
        .unwrap();
    let (n, _) = a.recv_from(&mut buf).expect("a Retry");
    let retry = skiff_wire::header::Header::parse(&buf[..n], 8).unwrap();
    assert_eq!(retry.ty, skiff_wire::header::PacketType::Retry);
    assert_eq!(retry.dcid, scid);
    assert!(skiff_quic::retry::verify_retry(&odcid, &buf[..n]));
    let (new_dcid, token) = (retry.scid.to_vec(), retry.token.to_vec());
    // The token from another address, and forged, is refused silently.
    b.send_to(&raw_initial(&new_dcid, &scid, &token, 1200), server.addr)
        .unwrap();
    let mut forged = token.clone();
    forged[3] ^= 1;
    a.send_to(&raw_initial(&new_dcid, &scid, &forged, 1200), server.addr)
        .unwrap();
    // A token sent to another CID than the Retry's.
    a.send_to(&raw_initial(&odcid, &scid, &token, 1200), server.addr)
        .unwrap();
    assert!(b.recv_from(&mut buf).is_err());
    assert!(a.recv_from(&mut buf).is_err());
    // The valid token from the right address creates one connection (its
    // payload is junk, so it never completes), routed by the Retry's CID:
    // a retransmission of that Initial reaches it instead of creating
    // another.
    for _ in 0..2 {
        a.send_to(&raw_initial(&new_dcid, &scid, &token, 1200), server.addr)
            .unwrap();
    }
    assert!(a.recv_from(&mut buf).is_err());

    ep.connection(h).unwrap().close(0, b"", Instant::now());
    let t = Instant::now();
    while !ep.is_empty() && t.elapsed() < Duration::from_secs(5) {
        ep.drive(Duration::from_millis(10)).unwrap();
        ep.remove_closed();
    }
    let (stats, handshakes, echoed) = server.finish();
    assert_eq!((handshakes, echoed), (1, 50_000));
    assert_eq!(stats.retries_sent, 2, "{stats:?}");
    assert_eq!(stats.accepted, 2);
    assert_eq!(stats.invalid_tokens, 3);
}

/// The client really verifies the certificate: a server whose certificate
/// is not the trusted root fails the handshake with a TLS alert.
#[test]
fn untrusted_certificate_fails_the_handshake() {
    let server = Server::spawn();
    let (other, _) = tls::self_signed(&["localhost"]).unwrap();
    let ccfg = tls::client_config(vec![other], &[ALPN]).unwrap();
    let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
    let h = ep.connect(ccfg, "localhost", server.addr).unwrap();
    let err = run_client(&mut ep, h, vec![b"x".to_vec()], Duration::from_secs(10)).unwrap_err();
    match err {
        EchoError::Closed(CloseReason::LocalTransport { code, .. }) => {
            assert!(
                (0x100..0x200).contains(&code),
                "CRYPTO_ERROR, got {code:#x}"
            )
        }
        e => panic!("expected a local TLS failure, got {e:?}"),
    }
    // The insecure verifier accepts the same server.
    let icfg = tls::insecure_client_config(&[ALPN]).unwrap();
    let h = ep.connect(icfg, "localhost", server.addr).unwrap();
    let r = run_client(&mut ep, h, vec![b"hello".to_vec()], Duration::from_secs(10)).unwrap();
    assert_eq!(r.bytes, 5);
    server.finish();
}

/// Kills the child process when dropped, so a failing assertion cannot
/// leave a server running (and holding the test's stdout pipe open).
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("skiff-{}-{name}", std::process::id()))
}

/// The binaries: skiff-server prints its address and writes its
/// self-signed certificate; skiff-client trusts that certificate, echoes
/// three streams and exits 0; a second client uses --insecure.
#[test]
fn binaries_handshake_and_echo_over_udp() {
    let cert = temp_path("cert.der");
    let mut server = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_skiff-server"))
            .args(["--listen", "127.0.0.1:0", "--exit-after", "2", "--cert-out"])
            .arg(&cert)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(server.0.stdout.take().unwrap()).lines();
    let first = lines.next().unwrap().unwrap();
    let addr = first.strip_prefix("listening on ").unwrap().to_string();

    let out = Command::new(env!("CARGO_BIN_EXE_skiff-client"))
        .args([
            "--connect",
            &addr,
            "--streams",
            "3",
            "--bytes",
            "300000",
            "--ca",
        ])
        .arg(&cert)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("verified echo of 900000 bytes on 3 streams"),
        "{stdout}"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_skiff-client"))
        .args(["--connect", &addr, "--insecure", "--message", "hello skiff"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.starts_with("hello skiff\n"), "{stdout}");

    // The server exits by itself once both connections have closed.
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = server.0.try_wait().unwrap() {
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "server did not exit after two connections"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success());
    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    assert!(
        rest.iter()
            .any(|l| l == &format!("served 2 connections, echoed {} bytes", 900_000 + 11)),
        "{rest:?}"
    );
    let _ = std::fs::remove_file(&cert);

    // A client without a trust anchor is refused up front.
    let out = Command::new(env!("CARGO_BIN_EXE_skiff-client"))
        .args(["--connect", &addr])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
