//! Stateless reset and Retry between skiff and quinn over real loopback
//! UDP, in both directions:
//! - a skiff server with Retry on, reached by a quinn client (quinn checks
//!   the integrity tag and `retry_source_connection_id`);
//! - a quinn server that retries every unvalidated address, reached by a
//!   skiff client;
//! - a skiff server restarted with the same reset key resets a quinn
//!   client's connection (`ConnectionError::Reset`);
//! - a quinn server replaced by another quinn endpoint with the same reset
//!   key resets a skiff client's connection (`CloseReason::StatelessReset`).

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use skiff::echo::{payload, run_client, EchoClient, EchoError, EchoServer, ALPN};
use skiff::{tls, Endpoint, EndpointStats};
use skiff_quic::{CloseReason, ResetKey, TransportConfig};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn quinn_client_config(cert: CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qcfg = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
    quinn::ClientConfig::new(Arc::new(qcfg))
}

/// One echo round trip on a new quinn stream.
async fn quinn_echo(conn: &quinn::Connection, data: &[u8]) -> Result<Vec<u8>, String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(data).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    recv.read_to_end(1 << 20).await.map_err(|e| e.to_string())
}

struct SkiffServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<(EndpointStats, u64, u64)>,
}

impl SkiffServer {
    fn spawn(
        bind: SocketAddr,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        reset: u8,
        retry: bool,
    ) -> Self {
        let scfg = tls::server_config(chain, key, &[ALPN]).unwrap();
        let transport = TransportConfig {
            reset_key: Some(ResetKey::new(&[reset; 32])),
            ..TransportConfig::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut ep = Endpoint::bind(bind, Some(scfg), transport).unwrap();
            assert_eq!(ep.set_retry(retry), retry);
            tx.send(ep.local_addr().unwrap()).unwrap();
            let mut srv = EchoServer::default();
            srv.serve(&mut ep, |_| flag.load(Ordering::Relaxed))
                .unwrap();
            (ep.stats().clone(), srv.handshakes, srv.echoed)
        });
        let addr = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Self { addr, stop, thread }
    }

    fn finish(self) -> (EndpointStats, u64, u64) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().unwrap()
    }
}

/// Random 8-byte CIDs with no keyed check. quinn's default generator
/// embeds a hash under a per-endpoint random key and drops (does not reset)
/// packets whose CID fails it, so a replacement endpoint must share that
/// key; servers that share a reset key share their CID scheme too.
struct RandomCids;

impl quinn::ConnectionIdGenerator for RandomCids {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let mut b = [0u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).unwrap();
        quinn::ConnectionId::new(&b)
    }
    fn cid_len(&self) -> usize {
        8
    }
    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

struct QuinnServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<u64>,
}

/// A quinn echo server with the given reset key that, with `retry`,
/// answers every Initial from an unvalidated address with a Retry.
/// Returns the number of handshakes it completed.
fn quinn_server(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    reset: u8,
    retry: bool,
) -> QuinnServer {
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qcfg = quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(qcfg));
    let hmac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[reset; 32]);
    let mut endpoint_config = quinn::EndpointConfig::new(Arc::new(hmac));
    endpoint_config.cid_generator(|| Box::new(RandomCids));
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        runtime().block_on(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let ep = quinn::Endpoint::new(
                endpoint_config,
                Some(server_config),
                socket,
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap();
            tx.send(ep.local_addr().unwrap()).unwrap();
            let mut handshakes = 0;
            while !flag.load(Ordering::Relaxed) {
                let incoming =
                    match tokio::time::timeout(Duration::from_millis(50), ep.accept()).await {
                        Ok(Some(i)) => i,
                        Ok(None) => break,
                        Err(_) => continue,
                    };
                if retry && !incoming.remote_address_validated() {
                    incoming.retry().unwrap();
                    continue;
                }
                let conn = incoming.await.expect("quinn server handshake");
                handshakes += 1;
                tokio::spawn(async move {
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65536];
                            while let Ok(Some(n)) = recv.read(&mut buf).await {
                                if send.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                            let _ = send.finish();
                            let _ = send.stopped().await;
                        });
                    }
                });
            }
            ep.close(0u32.into(), b"");
            handshakes
        })
    });
    let addr = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    QuinnServer { addr, stop, thread }
}

impl QuinnServer {
    fn finish(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().unwrap()
    }
}

/// A UDP relay: the client talks to `front`; datagrams go to the current
/// target and only the current target's replies come back, so a stopped
/// server's CONNECTION_CLOSE never reaches the client.
struct Relay {
    front: SocketAddr,
    target: Arc<Mutex<SocketAddr>>,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl Relay {
    fn spawn(target: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").unwrap();
        let back = UdpSocket::bind("127.0.0.1:0").unwrap();
        for s in [&front, &back] {
            s.set_read_timeout(Some(Duration::from_millis(2))).unwrap();
        }
        let addr = front.local_addr().unwrap();
        let target = Arc::new(Mutex::new(target));
        let stop = Arc::new(AtomicBool::new(false));
        let (t, flag) = (target.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut client = None;
            let mut buf = vec![0u8; 65536];
            while !flag.load(Ordering::Relaxed) {
                while let Ok((n, from)) = front.recv_from(&mut buf) {
                    client = Some(from);
                    let to = *t.lock().unwrap();
                    let _ = back.send_to(&buf[..n], to);
                }
                while let Ok((n, from)) = back.recv_from(&mut buf) {
                    if let (Some(c), true) = (client, from == *t.lock().unwrap()) {
                        let _ = front.send_to(&buf[..n], c);
                    }
                }
            }
        });
        Self {
            front: addr,
            target,
            stop,
            thread,
        }
    }

    fn finish(self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().unwrap();
    }
}

/// quinn client -> skiff server with Retry: quinn follows the Retry and
/// accepts skiff's `retry_source_connection_id`; the echo completes.
#[test]
fn quinn_client_skiff_server_with_retry() {
    let (c, k) = tls::self_signed(&["localhost"]).unwrap();
    let server = SkiffServer::spawn("127.0.0.1:0".parse().unwrap(), vec![c.clone()], k, 1, true);
    let addr = server.addr;
    let data = payload(100_000, 3);
    let expect = data.clone();
    runtime().block_on(async move {
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(quinn_client_config(c));
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            ep.connect(addr, "localhost").unwrap(),
        )
        .await
        .expect("handshake timed out")
        .expect("handshake failed");
        let echo = tokio::time::timeout(Duration::from_secs(20), quinn_echo(&conn, &data))
            .await
            .expect("echo timed out")
            .unwrap();
        assert!(echo == expect, "echoed different bytes");
        conn.close(0u32.into(), b"done");
        ep.wait_idle().await;
    });
    std::thread::sleep(Duration::from_millis(300));
    let (stats, handshakes, echoed) = server.finish();
    assert_eq!(stats.retries_sent, 1, "{stats:?}");
    assert_eq!(stats.invalid_tokens, 0);
    assert_eq!(stats.accepted, 1);
    assert_eq!((handshakes, echoed), (1, 100_000));
}

/// skiff client -> quinn server that retries: skiff follows quinn's Retry
/// (quinn's own token format, its integrity tag) and the echo completes.
#[test]
fn skiff_client_quinn_server_with_retry() {
    let (c, k) = tls::self_signed(&["localhost"]).unwrap();
    let server = quinn_server(vec![c.clone()], k, 1, true);
    let ccfg = tls::client_config(vec![c], &[ALPN]).unwrap();
    let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
    let h = ep.connect(ccfg, "localhost", server.addr).unwrap();
    let r = run_client(
        &mut ep,
        h,
        vec![payload(100_000, 4)],
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(r.bytes, 100_000);
    assert!(ep.connection(h).unwrap().retried(), "a Retry was followed");
    assert_eq!(server.finish(), 1);
}

/// quinn client -> skiff server, then the skiff server restarts on the same
/// port with the same reset key: the new endpoint does not know quinn's
/// connection and answers with a stateless reset, which quinn recognises.
#[test]
fn skiff_server_restart_resets_quinn_client() {
    let (c, k) = tls::self_signed(&["localhost"]).unwrap();
    let server = SkiffServer::spawn(
        "127.0.0.1:0".parse().unwrap(),
        vec![c.clone()],
        k.clone_key(),
        7,
        false,
    );
    let addr = server.addr;
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let client = std::thread::spawn(move || {
        runtime().block_on(async move {
            let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            ep.set_default_client_config(quinn_client_config(c));
            let conn = ep.connect(addr, "localhost").unwrap().await.unwrap();
            assert_eq!(quinn_echo(&conn, b"before").await.unwrap(), b"before");
            ready_tx.send(()).unwrap();
            while go_rx.try_recv().is_err() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let t = Instant::now();
            let _ = tokio::time::timeout(Duration::from_secs(5), quinn_echo(&conn, b"after")).await;
            let err = tokio::time::timeout(Duration::from_secs(5), conn.closed())
                .await
                .expect("the connection ends");
            (err, t.elapsed())
        })
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let (cert, key) = tls::self_signed(&["localhost"]).unwrap();
    server.finish();
    let restarted = SkiffServer::spawn(addr, vec![cert], key, 7, false);
    go_tx.send(()).unwrap();
    let (err, took) = client.join().unwrap();
    assert!(matches!(err, quinn::ConnectionError::Reset), "{err:?}");
    assert!(took < Duration::from_secs(3), "{took:?}");
    let (stats, handshakes, _) = restarted.finish();
    assert!(stats.stateless_resets_sent > 0, "{stats:?}");
    assert_eq!(handshakes, 0);
}

/// skiff client -> quinn server A through a relay; the relay then switches
/// to quinn server B with the same reset key, which does not know the
/// connection and resets it. skiff recognises the token quinn put in its
/// transport parameters and ends the connection at once.
#[test]
fn quinn_reset_ends_skiff_client() {
    let (c, k) = tls::self_signed(&["localhost"]).unwrap();
    let a = quinn_server(vec![c.clone()], k.clone_key(), 9, false);
    let b = quinn_server(vec![c.clone()], k, 9, false);
    let relay = Relay::spawn(a.addr);
    let ccfg = tls::client_config(vec![c], &[ALPN]).unwrap();
    let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
    let h = ep.connect(ccfg, "localhost", relay.front).unwrap();
    let mut first = EchoClient::new(vec![payload(10_000, 1)]);
    let t = Instant::now();
    while !first.is_done() {
        assert!(t.elapsed() < Duration::from_secs(20), "echo timed out");
        first.poll(ep.connection(h).unwrap()).unwrap();
        ep.drive(Duration::from_millis(5)).unwrap();
    }
    *relay.target.lock().unwrap() = b.addr;
    let mut second = EchoClient::new(vec![payload(10_000, 2)]);
    let t = Instant::now();
    let err = loop {
        assert!(t.elapsed() < Duration::from_secs(5), "no reset recognised");
        if let Err(e) = second.poll(ep.connection(h).unwrap()) {
            break e;
        }
        ep.drive(Duration::from_millis(5)).unwrap();
    };
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    assert!(
        matches!(err, EchoError::Closed(CloseReason::StatelessReset)),
        "{err:?}"
    );
    assert!(ep.stats().stateless_resets_received >= 1);
    relay.finish();
    assert_eq!(a.finish(), 1);
    assert_eq!(b.finish(), 0);
}
