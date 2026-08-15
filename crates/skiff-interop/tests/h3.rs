//! skiff's HTTP/3 against the `h3` crate on quinn (`h3-quinn`), over real
//! loopback UDP with a self-signed certificate, in both directions. Both
//! `h3` endpoints send grease (reserved settings, frame and stream types).

use bytes::{Buf, Bytes};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use skiff::echo::payload;
use skiff::http3::{fetch, Content, H3Server, ServerStats, ALPN};
use skiff::{tls, Endpoint};
use skiff_quic::TransportConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

/// H3_NO_ERROR.
const H3_NO_ERROR: u64 = 0x100;

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

/// The body the h3 test server returns for `/size/N`.
fn body_for(n: usize) -> Vec<u8> {
    payload(n, (n % 251) as u8)
}

struct H3ServerThread {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    served: Arc<AtomicU64>,
    thread: std::thread::JoinHandle<Vec<Option<quinn::ConnectionError>>>,
}

/// An `h3` server on quinn: `GET /size/N` returns N deterministic bytes,
/// anything else 404. Returns each connection's close reason.
fn h3_server(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> H3ServerThread {
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
    let served = Arc::new(AtomicU64::new(0));
    let (flag, count) = (stop.clone(), served.clone());
    let thread = std::thread::spawn(move || {
        runtime().block_on(async move {
            let ep =
                quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            tx.send(ep.local_addr().unwrap()).unwrap();
            let mut reasons = Vec::new();
            while !flag.load(Ordering::Relaxed) {
                let incoming =
                    match tokio::time::timeout(Duration::from_millis(100), ep.accept()).await {
                        Ok(Some(i)) => i,
                        Ok(None) => break,
                        Err(_) => continue,
                    };
                let conn = incoming.await.expect("quinn server handshake");
                let mut h3c: h3::server::Connection<h3_quinn::Connection, Bytes> =
                    h3::server::Connection::new(h3_quinn::Connection::new(conn.clone()))
                        .await
                        .expect("h3 server setup");
                loop {
                    match h3c.accept().await {
                        Ok(Some(resolver)) => {
                            let count = count.clone();
                            tokio::spawn(async move {
                                let (req, mut stream) = resolver.resolve_request().await.unwrap();
                                let n = req
                                    .uri()
                                    .path()
                                    .strip_prefix("/size/")
                                    .and_then(|s| s.parse::<usize>().ok());
                                let (status, body) = match n {
                                    Some(n) if req.method() == http::Method::GET => {
                                        (200, body_for(n))
                                    }
                                    _ => (404, b"no".to_vec()),
                                };
                                let resp = http::Response::builder()
                                    .status(status)
                                    .header("content-length", body.len())
                                    .header("x-served-by", "h3")
                                    .body(())
                                    .unwrap();
                                stream.send_response(resp).await.unwrap();
                                for chunk in body.chunks(50_000) {
                                    stream
                                        .send_data(Bytes::copy_from_slice(chunk))
                                        .await
                                        .unwrap();
                                }
                                stream.finish().await.unwrap();
                                count.fetch_add(1, Ordering::Relaxed);
                            });
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
                // Let the close arrive, then record it.
                let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
                reasons.push(conn.close_reason());
            }
            ep.close(0u32.into(), b"");
            ep.wait_idle().await;
            reasons
        })
    });
    let addr = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    H3ServerThread {
        addr,
        stop,
        served,
        thread,
    }
}

/// skiff client (`skiff::http3::fetch`) -> h3 server on quinn: bodies from
/// 0 B to 3 MB plus 140 small ones (past quinn's 100-stream limit) and a
/// 404, byte for byte; the client then closes with H3_NO_ERROR.
#[test]
fn skiff_client_h3_server() {
    let (c, k) = cert();
    let server = h3_server(vec![c.clone()], k);
    let ccfg = tls::client_config(vec![c], &[ALPN]).unwrap();
    let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
    let h = ep.connect(ccfg, "localhost", server.addr).unwrap();
    let mut sizes = vec![0usize, 1, 1000, 100_000, 3_000_000];
    sizes.extend((0..140).map(|i| 100 + i * 13));
    let mut paths: Vec<String> = sizes.iter().map(|n| format!("/size/{n}")).collect();
    paths.push("/missing".into());
    let r = fetch(
        &mut ep,
        h,
        "localhost",
        "GET",
        &paths,
        Duration::from_secs(60),
    )
    .unwrap();
    for (resp, n) in r.iter().zip(&sizes) {
        assert_eq!(resp.status, 200, "{}", resp.path);
        assert!(resp.body == body_for(*n), "{} body differs", resp.path);
        assert_eq!(
            resp.header("content-length"),
            Some(n.to_string().as_bytes())
        );
        assert_eq!(resp.header("x-served-by"), Some(&b"h3"[..]));
    }
    let last = r.last().unwrap();
    assert_eq!((last.status, last.body.as_slice()), (404, &b"no"[..]));
    assert_eq!(ep.connection(h).unwrap().alpn_protocol(), Some(ALPN));
    server.stop.store(true, Ordering::Relaxed);
    let reasons = server.thread.join().unwrap();
    assert_eq!(server.served.load(Ordering::Relaxed), 146);
    assert_eq!(reasons.len(), 1, "one connection");
    match &reasons[0] {
        Some(quinn::ConnectionError::ApplicationClosed(a)) => {
            assert_eq!(a.error_code.into_inner(), H3_NO_ERROR)
        }
        other => panic!("expected an H3_NO_ERROR close, got {other:?}"),
    }
}

/// A temporary site directory, removed on drop.
struct Site(PathBuf);

impl Drop for Site {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// h3 client on quinn -> skiff `H3Server` serving files: 150 concurrent
/// GETs (past skiff's 100-stream limit) incl. a 3 MB file, HEAD, a 404 and
/// a POST with a 200 KB body and trailers (405), all byte for byte.
#[test]
fn h3_client_skiff_server() {
    let site = Site(std::env::temp_dir().join(format!("skiff-interop-h3-{}", std::process::id())));
    std::fs::create_dir_all(&site.0).unwrap();
    let big = payload(3_000_000, 0x5a);
    std::fs::write(site.0.join("big.bin"), &big).unwrap();
    for i in 0..149u8 {
        std::fs::write(
            site.0.join(format!("f{i}.txt")),
            payload(500 + 7 * usize::from(i), i),
        )
        .unwrap();
    }

    let (c, k) = cert();
    let scfg = tls::server_config(vec![c.clone()], k, &[ALPN]).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let (tx, rx) = mpsc::channel();
    let root = site.0.clone();
    let skiff = std::thread::spawn(move || -> ServerStats {
        let mut ep = Endpoint::bind("127.0.0.1:0", Some(scfg), TransportConfig::default()).unwrap();
        tx.send(ep.local_addr().unwrap()).unwrap();
        let mut srv = H3Server::new(Content::Root(root));
        srv.serve(&mut ep, |_| flag.load(Ordering::Relaxed))
            .unwrap();
        srv.stats().clone()
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
    let expect: Vec<(String, Vec<u8>)> = std::iter::once(("/big.bin".to_string(), big.clone()))
        .chain((0..149u8).map(|i| (format!("/f{i}.txt"), payload(500 + 7 * usize::from(i), i))))
        .collect();
    runtime().block_on(async move {
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(qcfg)));
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            ep.connect(addr, "localhost").unwrap(),
        )
        .await
        .expect("handshake timed out")
        .expect("handshake failed");
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .expect("h3 client setup");
        let drive =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        // Concurrent GETs.
        let mut tasks = Vec::new();
        for (path, want) in expect {
            let mut send = send.clone();
            tasks.push(tokio::spawn(async move {
                let req = http::Request::get(format!("https://localhost{path}"))
                    .body(())
                    .unwrap();
                let mut s = send.send_request(req).await.unwrap();
                s.finish().await.unwrap();
                let resp = s.recv_response().await.unwrap();
                assert_eq!(resp.status(), 200, "{path}");
                assert_eq!(
                    resp.headers()["content-length"],
                    want.len().to_string().as_str()
                );
                let mut body = Vec::new();
                while let Some(mut chunk) = s.recv_data().await.unwrap() {
                    body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                }
                assert!(body == want, "{path} body differs");
            }));
        }
        for t in tasks {
            tokio::time::timeout(Duration::from_secs(60), t)
                .await
                .expect("GET timed out")
                .unwrap();
        }

        let mut send = send.clone();
        // HEAD: the length, no body.
        let req = http::Request::head("https://localhost/big.bin")
            .body(())
            .unwrap();
        let mut s = send.send_request(req).await.unwrap();
        s.finish().await.unwrap();
        let resp = s.recv_response().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["content-length"], "3000000");
        assert!(s.recv_data().await.unwrap().is_none(), "HEAD has no body");

        // 404.
        let req = http::Request::get("https://localhost/nope")
            .body(())
            .unwrap();
        let mut s = send.send_request(req).await.unwrap();
        s.finish().await.unwrap();
        assert_eq!(s.recv_response().await.unwrap().status(), 404);

        // POST with a body and trailers: 405 (the body is read and dropped).
        let req = http::Request::post("https://localhost/big.bin")
            .body(())
            .unwrap();
        let mut s = send.send_request(req).await.unwrap();
        s.send_data(Bytes::from(payload(200_000, 9))).await.unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        s.send_trailers(trailers).await.unwrap();
        s.finish().await.unwrap();
        let resp = s.recv_response().await.unwrap();
        assert_eq!(resp.status(), 405);
        assert_eq!(resp.headers()["allow"], "GET, HEAD");

        conn.close(quinn::VarInt::from_u32(H3_NO_ERROR as u32), b"done");
        let _ = drive.await;
        ep.wait_idle().await;
    });
    std::thread::sleep(Duration::from_millis(300));
    stop.store(true, Ordering::Relaxed);
    let stats = skiff.join().unwrap();
    assert_eq!(stats.requests, 153);
    assert_eq!(stats.ok, 151);
    assert_eq!(stats.not_found, 1);
    assert_eq!(
        stats.h3_errors, 0,
        "skiff closed the connection with an error"
    );
}
