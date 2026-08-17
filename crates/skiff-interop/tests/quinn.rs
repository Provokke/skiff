//! skiff <-> quinn over real loopback UDP with a self-signed certificate:
//! handshake, stream echo with flow-control updates, and MAX_STREAMS
//! credit beyond the initial stream limit, in both directions.

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use skiff::echo::{payload, run_client, EchoServer, ALPN};
use skiff::{tls, Endpoint};
use skiff_quic::TransportConfig;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

fn cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    tls::self_signed(&["localhost"]).unwrap()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Payload sizes: one 3 MB stream (several MAX_DATA / MAX_STREAM_DATA
/// updates at both stacks' default windows) plus small streams.
fn payloads(small: usize) -> Vec<Vec<u8>> {
    let mut p = vec![payload(3_000_000, 0xa5)];
    p.extend((0..small).map(|i| payload(1000 + i * 37, i as u8)));
    p
}

struct QuinnServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<Vec<quinn::ConnectionStats>>,
}

/// A quinn echo server (one task per bidirectional stream) on its own
/// runtime thread.
fn quinn_server(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> QuinnServer {
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qcfg = quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(qcfg));
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        runtime().block_on(async move {
            let ep =
                quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            tx.send(ep.local_addr().unwrap()).unwrap();
            let mut stats = Vec::new();
            while !flag.load(Ordering::Relaxed) {
                let incoming =
                    match tokio::time::timeout(Duration::from_millis(100), ep.accept()).await {
                        Ok(Some(i)) => i,
                        Ok(None) => break,
                        Err(_) => continue,
                    };
                let conn = incoming.await.expect("quinn server handshake");
                loop {
                    match conn.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 65536];
                                while let Some(n) = recv.read(&mut buf).await.unwrap() {
                                    send.write_all(&buf[..n]).await.unwrap();
                                }
                                send.finish().unwrap();
                                // Keep the stream alive until the data is acked.
                                let _ = send.stopped().await;
                            });
                        }
                        Err(quinn::ConnectionError::ApplicationClosed(c)) => {
                            assert_eq!(c.error_code, quinn::VarInt::from_u32(0));
                            break;
                        }
                        Err(e) => panic!("quinn server: {e}"),
                    }
                }
                stats.push(conn.stats());
            }
            ep.close(0u32.into(), b"");
            ep.wait_idle().await;
            stats
        })
    });
    let addr = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    QuinnServer { addr, stop, thread }
}

/// skiff client -> quinn server: handshake, 151 echoed streams (quinn
/// allows 100 concurrent, so the client needs quinn's MAX_STREAMS), one of
/// them 3 MB.
#[test]
fn skiff_client_quinn_server() {
    let (c, k) = cert();
    let server = quinn_server(vec![c.clone()], k);
    let ccfg = tls::client_config(vec![c], &[ALPN]).unwrap();
    let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
    let h = ep.connect(ccfg, "localhost", server.addr).unwrap();
    let p = payloads(150);
    let total: u64 = p.iter().map(|x| x.len() as u64).sum();
    let report = run_client(&mut ep, h, p, Duration::from_secs(60)).unwrap();
    assert_eq!(report.streams, 151);
    assert_eq!(report.bytes, total);
    let conn = ep.connection(h).unwrap();
    assert_eq!(conn.alpn_protocol(), Some(ALPN));
    assert!(conn.is_closed(), "close handshake finished");
    // Path MTU discovery both ways: quinn acked skiff's 1452-byte probe,
    // and skiff acked quinn's.
    assert_eq!(conn.max_datagram_size(), 1452);
    assert_eq!(conn.stats().pmtu_probes_lost, 0);
    server.stop.store(true, Ordering::Relaxed);
    let stats = server.thread.join().unwrap();
    assert_eq!(stats.len(), 1, "quinn saw exactly one connection");
    assert_eq!(stats[0].path.current_mtu, 1452);
}

/// quinn client -> skiff server: handshake, 151 concurrent echo streams
/// (skiff allows 100 bidi streams, so quinn needs skiff's MAX_STREAMS),
/// one of them 3 MB.
#[test]
fn quinn_client_skiff_server() {
    let (c, k) = cert();
    let scfg = tls::server_config(vec![c.clone()], k, &[ALPN]).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let (tx, rx) = mpsc::channel();
    let skiff = std::thread::spawn(move || {
        let mut ep = Endpoint::bind("127.0.0.1:0", Some(scfg), TransportConfig::default()).unwrap();
        tx.send(ep.local_addr().unwrap()).unwrap();
        let mut srv = EchoServer::default();
        srv.serve(&mut ep, |_| flag.load(Ordering::Relaxed))
            .unwrap();
        (ep.stats().clone(), srv.handshakes, srv.echoed)
    });
    let addr: SocketAddr = rx.recv_timeout(Duration::from_secs(10)).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(c).unwrap();
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qcfg = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
    let p = payloads(150);
    let total: u64 = p.iter().map(|x| x.len() as u64).sum();
    let quinn_stats = runtime().block_on(async move {
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(qcfg)));
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            ep.connect(addr, "localhost").unwrap(),
        )
        .await
        .expect("handshake timed out")
        .expect("handshake failed");
        let mut tasks = Vec::new();
        for data in p {
            let conn = conn.clone();
            tasks.push(tokio::spawn(async move {
                let (mut send, mut recv) = conn.open_bi().await.unwrap();
                let writer = {
                    let data = data.clone();
                    tokio::spawn(async move {
                        send.write_all(&data).await.unwrap();
                        send.finish().unwrap();
                    })
                };
                let echo = recv.read_to_end(4_000_000).await.unwrap();
                writer.await.unwrap();
                assert!(echo == data, "stream echoed different bytes");
            }));
        }
        for t in tasks {
            tokio::time::timeout(Duration::from_secs(60), t)
                .await
                .expect("echo timed out")
                .unwrap();
        }
        let stats = conn.stats();
        conn.close(0u32.into(), b"done");
        ep.wait_idle().await;
        stats
    });
    // Let skiff finish its draining period, then stop it.
    std::thread::sleep(Duration::from_millis(300));
    stop.store(true, Ordering::Relaxed);
    let (stats, handshakes, echoed) = skiff.join().unwrap();
    assert_eq!(stats.accepted, 1);
    assert_eq!(handshakes, 1);
    assert_eq!(echoed, total);
    assert!(quinn_stats.path.rtt < Duration::from_millis(500));
    // quinn's path MTU probes up to its 1452-byte default were acked by
    // skiff (which advertises max_udp_payload_size 1452).
    assert_eq!(quinn_stats.path.current_mtu, 1452);
}
