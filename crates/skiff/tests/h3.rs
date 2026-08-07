//! HTTP/3 over real UDP on 127.0.0.1: `skiff::http3` serving files and a
//! fixed body to `fetch`, and the skiff-server / skiff-client binaries in
//! `--h3` mode.

use skiff::echo::payload;
use skiff::http3::{fetch, Content, H3Server, ServerStats, ALPN};
use skiff::{tls, Endpoint};
use skiff_quic::TransportConfig;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("skiff-h3-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `TMP/root/{small.txt, big.bin, sub/nested.txt}` plus `TMP/secret.txt`
/// next to (outside) the root.
fn site(tmp: &Path) -> (PathBuf, Vec<u8>) {
    let root = tmp.join("root");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("small.txt"), b"small file\n").unwrap();
    let big = payload(3_000_000, 7);
    std::fs::write(root.join("big.bin"), &big).unwrap();
    std::fs::write(root.join("sub/nested.txt"), b"nested\n").unwrap();
    std::fs::write(tmp.join("secret.txt"), b"outside the root\n").unwrap();
    // A symlink that leaves the root (on Windows the path simply does not
    // exist, so the expected 404 is the same).
    #[cfg(unix)]
    std::os::unix::fs::symlink(tmp.join("secret.txt"), root.join("escape.txt")).unwrap();
    (root, big)
}

struct Server {
    addr: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    stop: Arc<AtomicBool>,
    thread: JoinHandle<ServerStats>,
}

impl Server {
    fn spawn(content: Content) -> Self {
        let (cert, key) = tls::self_signed(&["localhost"]).unwrap();
        let cfg = tls::server_config(vec![cert.clone()], key, &[ALPN]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut ep =
                Endpoint::bind("127.0.0.1:0", Some(cfg), TransportConfig::default()).unwrap();
            tx.send(ep.local_addr().unwrap()).unwrap();
            let mut srv = H3Server::new(content);
            srv.serve(&mut ep, |_| flag.load(Ordering::Relaxed))
                .unwrap();
            srv.stats().clone()
        });
        let addr = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Self {
            addr,
            cert,
            stop,
            thread,
        }
    }

    fn client(&self) -> (Endpoint, skiff::ConnectionHandle) {
        let ccfg = tls::client_config(vec![self.cert.clone()], &[ALPN]).unwrap();
        let mut ep = Endpoint::bind("127.0.0.1:0", None, TransportConfig::default()).unwrap();
        let h = ep.connect(ccfg, "localhost", self.addr).unwrap();
        (ep, h)
    }

    fn finish(self) -> ServerStats {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().unwrap()
    }
}

fn paths(p: &[&str]) -> Vec<String> {
    p.iter().map(|s| s.to_string()).collect()
}

#[test]
fn serves_files_under_a_root_only() {
    let tmp = TempDir::new("files");
    let (root, big) = site(&tmp.0);
    let server = Server::spawn(Content::Root(root));
    let (mut ep, h) = server.client();
    let want = paths(&[
        "/small.txt",
        "/big.bin",
        "/sub/nested.txt",
        "/small.txt?x=1",
        "/missing",
        "/sub",
        "/",
        "/../secret.txt",
        "/sub/../../secret.txt",
        "/sub/./nested.txt",
        "//small.txt",
        "/escape.txt",
    ]);
    let r = fetch(
        &mut ep,
        h,
        "localhost",
        "GET",
        &want,
        Duration::from_secs(30),
    )
    .unwrap();
    let status: Vec<u16> = r.iter().map(|r| r.status).collect();
    assert_eq!(
        status,
        [200, 200, 200, 200, 404, 404, 404, 404, 404, 404, 404, 404]
    );
    assert_eq!(r[0].body, b"small file\n");
    assert!(r[1].body == big, "3 MB file intact");
    assert_eq!(
        r[1].header("content-length"),
        Some(&b"3000000"[..]),
        "{:?}",
        r[1].headers
    );
    assert_eq!(r[2].body, b"nested\n");
    assert_eq!(r[3].body, b"small file\n");
    for x in &r[4..] {
        assert_eq!(x.body, b"not found\n", "{}", x.path);
    }
    assert_eq!(ep.connection(h).map(|c| c.is_closed()), Some(true));

    // HEAD has the length but no body; other methods are 405.
    let (mut ep, h) = server.client();
    let r = fetch(
        &mut ep,
        h,
        "localhost",
        "HEAD",
        &paths(&["/big.bin"]),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(r[0].status, 200);
    assert_eq!(r[0].header("content-length"), Some(&b"3000000"[..]));
    assert!(r[0].body.is_empty());
    let (mut ep, h) = server.client();
    let r = fetch(
        &mut ep,
        h,
        "localhost",
        "DELETE",
        &paths(&["/small.txt"]),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(r[0].status, 405);
    assert_eq!(r[0].header("allow"), Some(&b"GET, HEAD"[..]));
    let stats = server.finish();
    assert_eq!(stats.requests, 14);
    assert_eq!(stats.ok, 5);
    assert_eq!(stats.not_found, 8);
    assert_eq!(stats.h3_errors, 0);
}

#[test]
fn serves_a_fixed_body_on_many_streams() {
    let body = payload(70_000, 3);
    let server = Server::spawn(Content::Fixed(Arc::new(body.clone())));
    let (mut ep, h) = server.client();
    // More requests than the server's 100-stream limit.
    let want: Vec<String> = (0..150).map(|i| format!("/item/{i}")).collect();
    let r = fetch(
        &mut ep,
        h,
        "localhost",
        "GET",
        &want,
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(r.len(), 150);
    for x in &r {
        assert_eq!(x.status, 200, "{}", x.path);
        assert!(x.body == body, "{} body", x.path);
    }
    let stats = server.finish();
    assert_eq!(stats.ok, 150);
    assert_eq!(stats.body_bytes, 150 * 70_000);
}

/// Kills the child process when dropped.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// skiff-server --h3 --root serves a file that skiff-client --h3 --out
/// writes byte for byte; a 404 makes the client exit non-zero; the server
/// exits after two connections and reports them.
#[test]
fn binaries_get_a_file_over_http3() {
    let tmp = TempDir::new("bins");
    let (root, big) = site(&tmp.0);
    let cert = tmp.0.join("cert.der");
    let out = tmp.0.join("out.bin");
    let mut server = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_skiff-server"))
            .args(["--listen", "127.0.0.1:0", "--exit-after", "2", "--h3"])
            .arg("--root")
            .arg(&root)
            .arg("--cert-out")
            .arg(&cert)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(server.0.stdout.take().unwrap()).lines();
    let first = lines.next().unwrap().unwrap();
    let addr = first.strip_prefix("listening on ").unwrap().to_string();

    let o = Command::new(env!("CARGO_BIN_EXE_skiff-client"))
        .args(["--connect", &addr, "--h3", "--path", "/big.bin", "--ca"])
        .arg(&cert)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "{stdout} {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(stdout, "GET /big.bin: 200, 3000000 bytes\n");
    assert!(
        std::fs::read(&out).unwrap() == big,
        "downloaded file differs"
    );

    let o = Command::new(env!("CARGO_BIN_EXE_skiff-client"))
        .args([
            "--connect",
            &addr,
            "--h3",
            "--insecure",
            "--path",
            "/small.txt",
            "--path",
            "/nope",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(!o.status.success(), "a 404 must fail the client");
    assert_eq!(
        stdout,
        "GET /small.txt: 200, 11 bytes\nGET /nope: 404, 10 bytes\n"
    );

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = server.0.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "server did not exit");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success());
    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    assert_eq!(
        rest,
        ["served 2 connections, 3 requests (2 ok, 1 not found), 3000021 body bytes"]
    );
}

/// Without --root the server answers every path with --body.
#[test]
fn binary_serves_a_fixed_body() {
    let mut server = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_skiff-server"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--exit-after",
                "1",
                "--h3",
                "--body",
                "fixed!",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(server.0.stdout.take().unwrap()).lines();
    let first = lines.next().unwrap().unwrap();
    let addr = first.strip_prefix("listening on ").unwrap().to_string();
    let tmp = TempDir::new("fixed");
    let out = tmp.0.join("body");
    let o = Command::new(env!("CARGO_BIN_EXE_skiff-client"))
        .args(["--connect", &addr, "--h3", "--insecure", "--path", "/any"])
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), b"fixed!");
    // Bad flag combinations are refused up front.
    let o = Command::new(env!("CARGO_BIN_EXE_skiff-client"))
        .args(["--connect", &addr, "--insecure", "--path", "/x"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    let deadline = Instant::now() + Duration::from_secs(20);
    while server.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "server did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}
