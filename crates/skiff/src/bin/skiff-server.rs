//! skiff-server: a QUIC stream-echo or HTTP/3 server over UDP.
//!
//! ```text
//! skiff-server [--listen ADDR] [--cert-out PATH] [--cert PATH --key PATH]
//!              [--max-connections N] [--exit-after N]
//!              [--h3 [--root DIR | --body TEXT]]
//! ```
//! Without `--cert`/`--key` (DER files) a self-signed certificate for
//! `localhost` is generated; `--cert-out` writes it (DER) so a client can
//! trust it. `--exit-after N` exits after N connections have closed.
//! Prints `listening on <addr>` once bound.
//!
//! By default the server echoes streams (ALPN `skiff-echo`). With `--h3` it
//! speaks HTTP/3 (ALPN `h3`) and answers GET and HEAD: with `--root` from
//! the regular files under DIR (404 for anything else), otherwise with
//! `--body` TEXT (default `hello from skiff` and a newline) for every path.

use skiff::echo::{self, EchoServer};
use skiff::http3::{self, Content, H3Server};
use skiff::tls;
use skiff::Endpoint;
use skiff_quic::TransportConfig;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

const USAGE: &str =
    "usage: skiff-server [--listen ADDR] [--cert-out PATH] [--cert PATH --key PATH] \
                     [--max-connections N] [--exit-after N] [--h3 [--root DIR | --body TEXT]]";

struct Args {
    listen: String,
    cert_out: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    max_connections: usize,
    exit_after: Option<u64>,
    h3: bool,
    root: Option<PathBuf>,
    body: Option<String>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        listen: "127.0.0.1:4433".into(),
        cert_out: None,
        cert: None,
        key: None,
        max_connections: 1024,
        exit_after: None,
        h3: false,
        root: None,
        body: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => a.listen = val()?,
            "--cert-out" => a.cert_out = Some(val()?.into()),
            "--cert" => a.cert = Some(val()?.into()),
            "--key" => a.key = Some(val()?.into()),
            "--max-connections" => {
                a.max_connections = val()?.parse().map_err(|e| format!("{flag}: {e}"))?
            }
            "--exit-after" => {
                a.exit_after = Some(val()?.parse().map_err(|e| format!("{flag}: {e}"))?)
            }
            "--h3" => a.h3 = true,
            "--root" => a.root = Some(val()?.into()),
            "--body" => a.body = Some(val()?),
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if !a.h3 && (a.root.is_some() || a.body.is_some()) {
        return Err("--root and --body need --h3".into());
    }
    if a.root.is_some() && a.body.is_some() {
        return Err("--root and --body are exclusive".into());
    }
    Ok(a)
}

/// The application the server runs on every connection.
enum App {
    Echo(EchoServer),
    H3(H3Server),
}

impl App {
    fn poll(&mut self, ep: &mut Endpoint) {
        match self {
            App::Echo(s) => s.poll(ep),
            App::H3(s) => s.poll(ep),
        }
    }

    fn summary(&self, connections: u64) -> String {
        match self {
            App::Echo(s) => format!(
                "served {} connections, echoed {} bytes",
                s.handshakes, s.echoed
            ),
            App::H3(s) => {
                let st = s.stats();
                format!(
                    "served {connections} connections, {} requests ({} ok, {} not found), {} body bytes",
                    st.requests, st.ok, st.not_found, st.body_bytes
                )
            }
        }
    }
}

fn run() -> Result<(), String> {
    let a = parse()?;
    let (cert, key) = match (&a.cert, &a.key) {
        (Some(c), Some(k)) => (
            tls::read_cert_der(c).map_err(|e| e.to_string())?,
            tls::read_key_der(k).map_err(|e| e.to_string())?,
        ),
        (None, None) => tls::self_signed(&["localhost"]).map_err(|e| e.to_string())?,
        _ => return Err("--cert and --key go together".into()),
    };
    if let Some(p) = &a.cert_out {
        std::fs::write(p, cert.as_ref()).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    let mut app = if a.h3 {
        let content = match (&a.root, &a.body) {
            (Some(root), _) if !root.is_dir() => {
                return Err(format!("--root {}: not a directory", root.display()))
            }
            (Some(root), _) => Content::Root(root.clone()),
            (None, Some(b)) => Content::Fixed(Arc::new(b.as_bytes().to_vec())),
            (None, None) => Content::Fixed(Arc::new(b"hello from skiff\n".to_vec())),
        };
        App::H3(H3Server::new(content))
    } else {
        App::Echo(EchoServer::default())
    };
    let alpn = if a.h3 { http3::ALPN } else { echo::ALPN };
    let cfg = tls::server_config(vec![cert], key, &[alpn]).map_err(|e| e.to_string())?;
    let mut ep = Endpoint::bind(a.listen.as_str(), Some(cfg), TransportConfig::default())
        .map_err(|e| e.to_string())?;
    ep.set_max_connections(a.max_connections);
    let addr = ep.local_addr().map_err(|e| e.to_string())?;
    let mut out = std::io::stdout();
    writeln!(out, "listening on {addr}").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    let exit_after = a.exit_after;
    let mut closed = 0u64;
    loop {
        ep.drive(std::time::Duration::from_millis(50))
            .map_err(|e| e.to_string())?;
        let before = ep.len();
        app.poll(&mut ep);
        closed += (before - ep.len()) as u64;
        if exit_after.is_some_and(|n| closed >= n) {
            writeln!(out, "{}", app.summary(closed)).map_err(|e| e.to_string())?;
            return Ok(());
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("skiff-server: {e}");
            ExitCode::FAILURE
        }
    }
}
