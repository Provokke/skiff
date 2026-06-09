//! skiff-client: connects to a skiff-server and either verifies a stream
//! echo or fetches paths over HTTP/3.
//!
//! ```text
//! skiff-client [--connect ADDR] [--server-name NAME] (--ca DER | --insecure)
//!              [--streams N] [--bytes N] [--message TEXT] [--timeout-secs N]
//!              [--h3 [--path PATH]... [--out FILE]]
//! ```
//! Echo (default, ALPN `skiff-echo`): `--message` sends TEXT on one stream
//! and prints the echo; otherwise `--streams` streams of `--bytes`
//! pseudo-random bytes each are sent. Exits non-zero unless every echo
//! matches.
//!
//! HTTP/3 (`--h3`, ALPN `h3`): GETs every `--path` (default `/`) on one
//! connection and prints `GET PATH: STATUS, N bytes` per response; with
//! `--out` (one path only) the body is written to FILE. Exits non-zero
//! unless every response arrived with status 200.

use skiff::echo::{self, payload, run_client};
use skiff::http3::{self, fetch};
use skiff::tls;
use skiff::Endpoint;
use skiff_quic::TransportConfig;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: skiff-client [--connect ADDR] [--server-name NAME] \
                     (--ca DER | --insecure) [--streams N] [--bytes N] [--message TEXT] \
                     [--timeout-secs N] [--h3 [--path PATH]... [--out FILE]]";

struct Args {
    connect: String,
    server_name: String,
    ca: Option<PathBuf>,
    insecure: bool,
    streams: usize,
    bytes: usize,
    message: Option<String>,
    timeout: Duration,
    h3: bool,
    paths: Vec<String>,
    out: Option<PathBuf>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        connect: "127.0.0.1:4433".into(),
        server_name: "localhost".into(),
        ca: None,
        insecure: false,
        streams: 1,
        bytes: 100_000,
        message: None,
        timeout: Duration::from_secs(30),
        h3: false,
        paths: Vec::new(),
        out: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        let num = |s: String| s.parse::<usize>().map_err(|e| format!("{s}: {e}"));
        match flag.as_str() {
            "--connect" => a.connect = val()?,
            "--server-name" => a.server_name = val()?,
            "--ca" => a.ca = Some(val()?.into()),
            "--insecure" => a.insecure = true,
            "--streams" => a.streams = num(val()?)?,
            "--bytes" => a.bytes = num(val()?)?,
            "--message" => a.message = Some(val()?),
            "--timeout-secs" => a.timeout = Duration::from_secs(num(val()?)? as u64),
            "--h3" => a.h3 = true,
            "--path" => a.paths.push(val()?),
            "--out" => a.out = Some(val()?.into()),
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if a.ca.is_none() && !a.insecure {
        return Err("pass --ca CERT.der or --insecure".into());
    }
    if !a.h3 && (!a.paths.is_empty() || a.out.is_some()) {
        return Err("--path and --out need --h3".into());
    }
    if a.paths.is_empty() {
        a.paths.push("/".into());
    }
    if a.out.is_some() && a.paths.len() != 1 {
        return Err("--out takes exactly one --path".into());
    }
    Ok(a)
}

fn run() -> Result<(), String> {
    let a = parse()?;
    let alpn = if a.h3 { http3::ALPN } else { echo::ALPN };
    let cfg = match &a.ca {
        Some(p) => tls::client_config(
            vec![tls::read_cert_der(p).map_err(|e| e.to_string())?],
            &[alpn],
        ),
        None => tls::insecure_client_config(&[alpn]),
    }
    .map_err(|e| e.to_string())?;
    let bind = if a.connect.starts_with('[') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let mut ep =
        Endpoint::bind(bind, None, TransportConfig::default()).map_err(|e| e.to_string())?;
    let h = ep
        .connect(cfg, &a.server_name, a.connect.as_str())
        .map_err(|e| e.to_string())?;
    if a.h3 {
        return run_h3(&a, &mut ep, h);
    }
    let payloads: Vec<Vec<u8>> = match &a.message {
        Some(m) => vec![m.as_bytes().to_vec()],
        None => (0..a.streams).map(|i| payload(a.bytes, i as u8)).collect(),
    };
    let r = run_client(&mut ep, h, payloads, a.timeout).map_err(|e| e.to_string())?;
    if let Some(m) = &a.message {
        println!("{m}");
    }
    println!(
        "verified echo of {} bytes on {} streams: handshake {:?}, total {:?}, \
         {} packets sent, {} lost, srtt {:?}",
        r.bytes,
        r.streams,
        r.handshake,
        r.elapsed,
        r.stats.packets_sent,
        r.stats.packets_lost,
        r.stats.srtt
    );
    Ok(())
}

fn run_h3(a: &Args, ep: &mut Endpoint, h: skiff::ConnectionHandle) -> Result<(), String> {
    let responses =
        fetch(ep, h, &a.server_name, "GET", &a.paths, a.timeout).map_err(|e| e.to_string())?;
    let mut failed = 0;
    for r in &responses {
        println!("GET {}: {}, {} bytes", r.path, r.status, r.body.len());
        if r.status != 200 {
            failed += 1;
        }
    }
    if let (Some(out), Some(r)) = (&a.out, responses.first()) {
        std::fs::write(out, &r.body).map_err(|e| format!("{}: {e}", out.display()))?;
    }
    if failed > 0 {
        return Err(format!("{failed} responses without status 200"));
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("skiff-client: {e}");
            ExitCode::FAILURE
        }
    }
}
