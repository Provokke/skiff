//! Shared helpers for the HTTP/3 tests: a self-signed TLS pair and small
//! server / client applications on top of `H3Connection`.
#![allow(dead_code)]

use rustls::pki_types::PrivatePkcs8KeyDer;
use skiff_h3::qpack::Field;
use skiff_h3::{H3Connection, H3Event};
use skiff_quic::Connection;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

pub const ALPN: &[u8] = b"h3";

pub fn tls() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
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

pub fn f(n: &str, v: &str) -> Field {
    Field::new(n.as_bytes(), v.as_bytes())
}

/// Deterministic body of `len` bytes for `path`.
pub fn body_for(path: &str, len: usize) -> Vec<u8> {
    let seed = path
        .bytes()
        .fold(7u32, |a, b| a.wrapping_mul(31).wrapping_add(u32::from(b)));
    (0..len)
        .map(|i| ((i as u32).wrapping_mul(2_654_435_761) ^ seed).to_be_bytes()[0])
        .collect()
}

pub fn get(path: &str) -> Vec<Field> {
    vec![
        f(":method", "GET"),
        f(":scheme", "https"),
        f(":authority", "localhost"),
        f(":path", path),
        f("user-agent", "skiff-h3-test"),
        f("x-trace-id", "0123456789abcdef"),
    ]
}

pub fn value<'a>(fields: &'a [Field], name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|f| f.name == name.as_bytes())
        .map(|f| f.value.as_slice())
}

#[derive(Default)]
struct ServerReq {
    path: String,
    method: String,
    body: Vec<u8>,
    trailers: Vec<Field>,
    responded: bool,
}

/// Test server: `GET /size/N` returns N deterministic bytes, `POST /echo`
/// echoes the body (and request trailers become response trailers),
/// `GET /goaway` also sends GOAWAY.
#[derive(Default)]
pub struct Server {
    reqs: BTreeMap<u64, ServerReq>,
    pub served: usize,
    pub resets: Vec<(u64, u64)>,
}

impl Server {
    pub fn poll(&mut self, h3: &mut H3Connection, c: &mut Connection, now: Instant) {
        let _ = h3.poll(c, now);
        let mut buf = vec![0u8; 64 * 1024];
        while let Some(ev) = h3.poll_event() {
            match ev {
                H3Event::Headers { stream_id, fields } => {
                    let r = self.reqs.entry(stream_id).or_default();
                    if r.path.is_empty() {
                        r.path =
                            String::from_utf8(value(&fields, ":path").unwrap().to_vec()).unwrap();
                        r.method =
                            String::from_utf8(value(&fields, ":method").unwrap().to_vec()).unwrap();
                    } else {
                        r.trailers = fields;
                    }
                }
                H3Event::Data { stream_id } | H3Event::Finished { stream_id } => loop {
                    // A reset stream's Reset event follows; never respond.
                    let (n, end) = match h3.recv_body(c, stream_id, &mut buf) {
                        Err(skiff_h3::H3Error::StreamReset { .. }) => break,
                        r => r.unwrap(),
                    };
                    if let Some(r) = self.reqs.get_mut(&stream_id) {
                        r.body.extend_from_slice(&buf[..n]);
                    }
                    if end {
                        self.respond(h3, c, stream_id);
                        break;
                    }
                    if n == 0 {
                        break;
                    }
                },
                H3Event::Reset { stream_id, code } => {
                    self.resets.push((stream_id, code));
                    self.reqs.remove(&stream_id);
                }
                _ => {}
            }
        }
        let _ = h3.poll(c, now);
    }

    fn respond(&mut self, h3: &mut H3Connection, c: &mut Connection, id: u64) {
        let Some(r) = self.reqs.get_mut(&id) else {
            return;
        };
        if r.responded {
            return;
        }
        r.responded = true;
        self.served += 1;
        if r.path == "/goaway" {
            h3.send_goaway(c).unwrap();
        }
        if r.method == "HEAD" {
            // Same headers as the GET, no content.
            let n = r.path.strip_prefix("/size/").unwrap_or("0");
            let hdr = vec![f(":status", "200"), f("content-length", n)];
            h3.send_response(c, id, &hdr, true).unwrap();
        } else if r.method == "POST" && r.path == "/echo" {
            let len = r.body.len().to_string();
            let hdr = vec![
                f(":status", "200"),
                f("content-length", &len),
                f("content-type", "application/octet-stream"),
            ];
            h3.send_response(c, id, &hdr, false).unwrap();
            let fin = r.trailers.is_empty();
            h3.send_data(c, id, &r.body, fin).unwrap();
            if !fin {
                h3.send_response(c, id, &r.trailers, true).unwrap();
            }
        } else if let Some(n) = r.path.strip_prefix("/size/") {
            let n: usize = n.parse().unwrap();
            let body = body_for(&r.path, n);
            let hdr = vec![
                f(":status", "200"),
                f("content-length", &n.to_string()),
                f("content-type", "text/plain"),
                f("server", "skiff-h3-test"),
            ];
            h3.send_response(c, id, &hdr, n == 0).unwrap();
            if n > 0 {
                h3.send_data(c, id, &body, true).unwrap();
            }
        } else {
            h3.send_response(c, id, &[f(":status", "404")], true)
                .unwrap();
        }
        self.reqs.remove(&id);
    }
}

#[derive(Debug, Default, Clone)]
pub struct Response {
    pub headers: Vec<Field>,
    pub body: Vec<u8>,
    pub trailers: Vec<Field>,
    pub done: bool,
    pub reset: Option<u64>,
}

/// A queued request: headers, optional body, trailers.
pub type Queued = (Vec<Field>, Option<Vec<u8>>, Vec<Field>);

/// Test client: sends queued requests as streams allow and collects
/// responses by stream.
#[derive(Default)]
pub struct Client {
    pub queue: Vec<Queued>,
    pub sent: Vec<u64>,
    pub responses: BTreeMap<u64, Response>,
    pub going_away: bool,
}

impl Client {
    pub fn get(&mut self, path: &str) {
        self.queue.push((get(path), None, Vec::new()));
    }

    pub fn post(&mut self, path: &str, body: Vec<u8>, trailers: Vec<Field>) {
        let mut h = get(path);
        h[0] = f(":method", "POST");
        self.queue.push((h, Some(body), trailers));
    }

    pub fn finished(&self) -> usize {
        self.responses
            .values()
            .filter(|r| r.done || r.reset.is_some())
            .count()
    }

    pub fn poll(&mut self, h3: &mut H3Connection, c: &mut Connection, now: Instant) {
        let _ = h3.poll(c, now);
        let mut buf = vec![0u8; 64 * 1024];
        while let Some(ev) = h3.poll_event() {
            match ev {
                H3Event::Headers { stream_id, fields } => {
                    let r = self.responses.entry(stream_id).or_default();
                    if r.headers.is_empty() {
                        r.headers = fields;
                    } else {
                        r.trailers = fields;
                    }
                }
                H3Event::Data { stream_id } | H3Event::Finished { stream_id } => loop {
                    let (n, end) = match h3.recv_body(c, stream_id, &mut buf) {
                        Err(skiff_h3::H3Error::StreamReset { .. }) => break,
                        r => r.unwrap(),
                    };
                    let r = self.responses.entry(stream_id).or_default();
                    r.body.extend_from_slice(&buf[..n]);
                    if end {
                        r.done = true;
                        break;
                    }
                    if n == 0 {
                        break;
                    }
                },
                H3Event::Reset { stream_id, code } => {
                    self.responses.entry(stream_id).or_default().reset = Some(code);
                }
                H3Event::GoAway { .. } => self.going_away = true,
                _ => {}
            }
        }
        while !self.queue.is_empty() && h3.is_ready() {
            let (hdr, body, trailers) = self.queue[0].clone();
            match h3.send_request(c, &hdr, body.is_none()) {
                Ok(id) => {
                    self.queue.remove(0);
                    self.sent.push(id);
                    self.responses.insert(id, Response::default());
                    if let Some(b) = body {
                        h3.send_data(c, id, &b, trailers.is_empty()).unwrap();
                        if !trailers.is_empty() {
                            h3.send_response(c, id, &trailers, true).unwrap();
                        }
                    }
                }
                Err(skiff_h3::H3Error::Quic(skiff_quic::ApiError::StreamsBlocked)) => break,
                Err(skiff_h3::H3Error::GoingAway) => {
                    self.queue.remove(0);
                    self.going_away = true;
                }
                Err(e) => panic!("send_request: {e}"),
            }
        }
        let _ = h3.poll(c, now);
    }

    /// Checks every `/size/N` response against the expected body.
    pub fn verify_sizes(&self, paths: &BTreeMap<u64, String>) {
        for (id, path) in paths {
            let r = &self.responses[id];
            assert!(r.done, "stream {id} ({path}) not done: {r:?}");
            let n: usize = path.strip_prefix("/size/").unwrap().parse().unwrap();
            // The whole field section, so a QPACK fault in any field shows.
            let want = vec![
                f(":status", "200"),
                f("content-length", &n.to_string()),
                f("content-type", "text/plain"),
                f("server", "skiff-h3-test"),
            ];
            assert_eq!(r.headers, want, "{path}");
            assert!(r.body == body_for(path, n), "{path}: body differs");
        }
    }
}
