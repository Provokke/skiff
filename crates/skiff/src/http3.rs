//! HTTP/3 (ALPN [`ALPN`]) over an [`Endpoint`], built on
//! [`skiff_h3::H3Connection`]: [`H3Server`] answers GET and HEAD with a
//! fixed body or with files under a root directory, and [`fetch`] runs
//! requests on one client connection and collects the responses.

use crate::endpoint::{ConnectionHandle, Endpoint, EndpointError};
use skiff_h3::frame::error_code::H3_INTERNAL_ERROR;
use skiff_h3::qpack::Field;
use skiff_h3::{H3Config, H3Connection, H3Error, H3Event};
use skiff_quic::{ApiError, CloseReason, Connection};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// ALPN protocol identifier of HTTP/3.
pub const ALPN: &[u8] = b"h3";

/// Body bytes read or sent per step.
const CHUNK: usize = 64 * 1024;
/// Response bytes a stream may hold that the peer has not acknowledged;
/// more of the body is read only below this.
const SEND_AHEAD: usize = 1 << 20;

/// What [`H3Server`] serves.
#[derive(Debug, Clone)]
pub enum Content {
    /// The same body for every path.
    Fixed(Arc<Vec<u8>>),
    /// Regular files under this directory, by path (`/a/b` is `ROOT/a/b`);
    /// anything else, including paths that leave the root, is 404.
    Root(PathBuf),
}

enum Body {
    Bytes { data: Arc<Vec<u8>>, off: usize },
    File { file: File, left: u64 },
}

impl Body {
    /// Copies the next piece into `buf`; returns its length and whether it
    /// is the last. `Err` if a file ended before its announced length.
    fn next_chunk(&mut self, buf: &mut [u8]) -> Result<(usize, bool), ()> {
        match self {
            Body::Bytes { data, off } => {
                let rest = data.get(*off..).unwrap_or_default();
                let n = rest.len().min(buf.len());
                buf.get_mut(..n)
                    .ok_or(())?
                    .copy_from_slice(rest.get(..n).ok_or(())?);
                *off += n;
                Ok((n, *off >= data.len()))
            }
            Body::File { file, left } => {
                let want = usize::try_from(*left).unwrap_or(usize::MAX).min(buf.len());
                let n = file.read(buf.get_mut(..want).ok_or(())?).map_err(|_| ())?;
                if n == 0 && *left > 0 {
                    return Err(());
                }
                *left -= n as u64;
                Ok((n, *left == 0))
            }
        }
    }
}

/// Server counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// Request header sections answered.
    pub requests: u64,
    /// Responses with status 200.
    pub ok: u64,
    /// Responses with status 404.
    pub not_found: u64,
    /// Response body bytes handed to QUIC.
    pub body_bytes: u64,
    /// Connections the HTTP/3 layer closed with an error.
    pub h3_errors: u64,
}

struct ServerConn {
    h3: H3Connection,
    /// Streams whose request was answered and that may still carry
    /// trailers.
    answered: BTreeSet<u64>,
    bodies: BTreeMap<u64, Body>,
    failed: bool,
}

/// Serves [`Content`] over HTTP/3 to every connection of an endpoint.
pub struct H3Server {
    content: Content,
    config: H3Config,
    conns: BTreeMap<ConnectionHandle, ServerConn>,
    stats: ServerStats,
}

fn header<'a>(fields: &'a [Field], name: &[u8]) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.as_slice())
}

fn field(name: &str, value: &str) -> Field {
    Field::new(name.as_bytes(), value.as_bytes())
}

/// Opens the regular file `path` names under `root`. Rejects empty, `.`
/// and `..` segments, backslashes, colons and NUL, and anything whose
/// canonical path (symlinks resolved) is outside the canonical root.
fn open_under(root: &Path, path: &[u8]) -> Option<(File, u64)> {
    let path = std::str::from_utf8(path).ok()?;
    let path = path.split(['?', '#']).next()?;
    let rel = path.strip_prefix('/')?;
    let mut p = root.to_path_buf();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.contains(['\\', ':', '\0']) {
            return None;
        }
        p.push(seg);
    }
    let canon = p.canonicalize().ok()?;
    if !canon.starts_with(root.canonicalize().ok()?) {
        return None;
    }
    let file = File::open(&canon).ok()?;
    let meta = file.metadata().ok()?;
    meta.is_file().then_some((file, meta.len()))
}

const NOT_FOUND: &[u8] = b"not found\n";

impl H3Server {
    /// A server for `content` with the default HTTP/3 settings.
    pub fn new(content: Content) -> Self {
        Self {
            content,
            config: H3Config::default(),
            conns: BTreeMap::new(),
            stats: ServerStats::default(),
        }
    }

    /// Counters.
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// Services every connection once (call after each
    /// [`Endpoint::drive`]); forgets closed connections.
    pub fn poll(&mut self, ep: &mut Endpoint) {
        while ep.accept().is_some() {}
        let now = Instant::now();
        let mut buf = vec![0u8; CHUNK];
        for h in ep.handles() {
            let Some(c) = ep.connection(h) else {
                continue;
            };
            let sc = self.conns.entry(h).or_insert_with(|| ServerConn {
                h3: H3Connection::new(self.config.clone()),
                answered: BTreeSet::new(),
                bodies: BTreeMap::new(),
                failed: false,
            });
            poll_conn(&self.content, &mut self.stats, sc, c, now, &mut buf);
        }
        for h in ep.remove_closed() {
            self.conns.remove(&h);
        }
    }

    /// Runs the server loop until `stop` returns true.
    pub fn serve(
        &mut self,
        ep: &mut Endpoint,
        mut stop: impl FnMut(&Self) -> bool,
    ) -> Result<(), EndpointError> {
        while !stop(self) {
            ep.drive(Duration::from_millis(20))?;
            self.poll(ep);
        }
        Ok(())
    }
}

fn poll_conn(
    content: &Content,
    stats: &mut ServerStats,
    sc: &mut ServerConn,
    c: &mut Connection,
    now: Instant,
    buf: &mut [u8],
) {
    if sc.h3.poll(c, now).is_err() {
        if !sc.failed {
            sc.failed = true;
            stats.h3_errors += 1;
        }
        return;
    }
    while let Some(ev) = sc.h3.poll_event() {
        match ev {
            H3Event::Headers { stream_id, fields } => {
                if sc.answered.insert(stream_id) {
                    respond(content, stats, sc, c, stream_id, &fields);
                }
            }
            H3Event::Data { stream_id } | H3Event::Finished { stream_id } => {
                // Request bodies are read and discarded.
                while let Ok((n, end)) = sc.h3.recv_body(c, stream_id, buf) {
                    if end {
                        sc.answered.remove(&stream_id);
                        break;
                    }
                    if n == 0 {
                        break;
                    }
                }
            }
            H3Event::Reset { stream_id, .. } => {
                sc.bodies.remove(&stream_id);
                sc.answered.remove(&stream_id);
            }
            H3Event::Stopped { stream_id, .. } => {
                sc.bodies.remove(&stream_id);
            }
            _ => {}
        }
    }
    send_bodies(stats, sc, c, buf);
}

fn respond(
    content: &Content,
    stats: &mut ServerStats,
    sc: &mut ServerConn,
    c: &mut Connection,
    id: u64,
    fields: &[Field],
) {
    stats.requests += 1;
    let method = header(fields, b":method").unwrap_or_default();
    let path = header(fields, b":path").unwrap_or_default();
    let head = method == b"HEAD";
    let (status, len, body) = if method != b"GET" && !head {
        ("405", 0, None)
    } else {
        let found = match content {
            Content::Fixed(d) => Some((
                d.len() as u64,
                Body::Bytes {
                    data: d.clone(),
                    off: 0,
                },
            )),
            Content::Root(root) => {
                open_under(root, path).map(|(file, len)| (len, Body::File { file, left: len }))
            }
        };
        match found {
            Some((len, body)) => ("200", len, Some(body)),
            None => (
                "404",
                NOT_FOUND.len() as u64,
                Some(Body::Bytes {
                    data: Arc::new(NOT_FOUND.to_vec()),
                    off: 0,
                }),
            ),
        }
    };
    match status {
        "200" => stats.ok += 1,
        "404" => stats.not_found += 1,
        _ => {}
    }
    let mut hdrs = vec![
        field(":status", status),
        field("content-length", &len.to_string()),
        field("server", "skiff"),
    ];
    if status == "405" {
        hdrs.push(field("allow", "GET, HEAD"));
    }
    let end = head || len == 0;
    if sc.h3.send_response(c, id, &hdrs, end).is_err() {
        return;
    }
    if let (false, Some(b)) = (end, body) {
        sc.bodies.insert(id, b);
    }
}

/// Moves response bodies into QUIC while each stream holds less than
/// [`SEND_AHEAD`] unacknowledged bytes.
fn send_bodies(stats: &mut ServerStats, sc: &mut ServerConn, c: &mut Connection, buf: &mut [u8]) {
    let ids: Vec<u64> = sc.bodies.keys().copied().collect();
    for id in ids {
        loop {
            let queued = sc.h3.pending_send(id) + c.stream_send_buffered(id).unwrap_or(0);
            if queued >= SEND_AHEAD {
                break;
            }
            let Some(b) = sc.bodies.get_mut(&id) else {
                break;
            };
            let Ok((n, last)) = b.next_chunk(buf) else {
                // The file shrank below its Content-Length: abandon.
                let _ = sc.h3.reset_stream(c, id, H3_INTERNAL_ERROR);
                sc.bodies.remove(&id);
                break;
            };
            let chunk = buf.get(..n).unwrap_or_default();
            if sc.h3.send_data(c, id, chunk, last).is_err() {
                sc.bodies.remove(&id);
                break;
            }
            stats.body_bytes += n as u64;
            if last {
                sc.bodies.remove(&id);
                break;
            }
        }
    }
}

/// A response collected by [`fetch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The request path.
    pub path: String,
    /// Final status code.
    pub status: u16,
    /// Final response header section.
    pub headers: Vec<Field>,
    /// Body.
    pub body: Vec<u8>,
}

impl Response {
    /// The first value of header `name`.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header(&self.headers, name.as_bytes())
    }
}

/// HTTP/3 client failures.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The endpoint failed.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    /// The HTTP/3 layer failed (a connection error closes the connection).
    #[error(transparent)]
    H3(#[from] H3Error),
    /// The connection closed before every response arrived.
    #[error("connection closed: {0:?}")]
    Closed(CloseReason),
    /// A request stream was reset.
    #[error("request for {path} reset with code {code:#x}")]
    Reset {
        /// Request path.
        path: String,
        /// Error code.
        code: u64,
    },
    /// The response had no valid final status.
    #[error("bad response for {0}")]
    BadResponse(String),
    /// The connection is unknown to the endpoint.
    #[error("unknown connection")]
    UnknownConnection,
    /// Not every response arrived in time.
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

#[derive(Default)]
struct Pending {
    status: u16,
    headers: Vec<Field>,
    body: Vec<u8>,
    complete: bool,
}

/// Sends `method` requests for `paths` (no request bodies) on connection
/// `h`, at most as many at once as the server's stream limit allows,
/// collects every response, then closes the connection with H3_NO_ERROR.
pub fn fetch(
    ep: &mut Endpoint,
    h: ConnectionHandle,
    authority: &str,
    method: &str,
    paths: &[String],
    timeout: Duration,
) -> Result<Vec<Response>, FetchError> {
    let mut h3 = H3Connection::new(H3Config::default());
    let mut queue: VecDeque<usize> = (0..paths.len()).collect();
    let mut streams: BTreeMap<u64, usize> = BTreeMap::new();
    let mut pending: Vec<Pending> = paths.iter().map(|_| Pending::default()).collect();
    let mut done = 0;
    let mut buf = vec![0u8; CHUNK];
    let start = Instant::now();
    let path_of = |i: usize| paths.get(i).cloned().unwrap_or_default();
    loop {
        let c = ep.connection(h).ok_or(FetchError::UnknownConnection)?;
        h3.poll(c, Instant::now())?;
        while let Some(ev) = h3.poll_event() {
            match ev {
                H3Event::Headers { stream_id, fields } => {
                    let Some(p) = streams.get(&stream_id).and_then(|&i| pending.get_mut(i)) else {
                        continue;
                    };
                    if p.status != 0 {
                        continue; // trailers
                    }
                    let status = header(&fields, b":status")
                        .and_then(|s| std::str::from_utf8(s).ok())
                        .and_then(|s| s.parse::<u16>().ok())
                        .unwrap_or(0);
                    if status >= 200 {
                        p.status = status;
                        p.headers = fields;
                    }
                }
                H3Event::Data { stream_id } | H3Event::Finished { stream_id } => {
                    let Some(&i) = streams.get(&stream_id) else {
                        continue;
                    };
                    let Some(p) = pending.get_mut(i) else {
                        continue;
                    };
                    while !p.complete {
                        let (n, end) = h3.recv_body(c, stream_id, &mut buf)?;
                        p.body.extend_from_slice(buf.get(..n).unwrap_or_default());
                        if end {
                            if p.status == 0 {
                                return Err(FetchError::BadResponse(path_of(i)));
                            }
                            p.complete = true;
                            done += 1;
                        } else if n == 0 {
                            break;
                        }
                    }
                }
                H3Event::Reset { stream_id, code } => {
                    let i = streams.get(&stream_id).copied().unwrap_or(usize::MAX);
                    return Err(FetchError::Reset {
                        path: path_of(i),
                        code,
                    });
                }
                H3Event::Closed(r) if done < paths.len() => return Err(FetchError::Closed(r)),
                _ => {}
            }
        }
        if done == paths.len() {
            break;
        }
        if let Some(r) = c.close_reason() {
            return Err(FetchError::Closed(r.clone()));
        }
        if h3.is_ready() {
            while let Some(&i) = queue.front() {
                let fields = [
                    field(":method", method),
                    field(":scheme", "https"),
                    field(":authority", authority),
                    field(":path", &path_of(i)),
                    field("user-agent", "skiff-client"),
                ];
                match h3.send_request(c, &fields, true) {
                    Ok(id) => {
                        streams.insert(id, i);
                        queue.pop_front();
                    }
                    Err(H3Error::Quic(ApiError::StreamsBlocked)) => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if start.elapsed() > timeout {
            return Err(FetchError::Timeout(timeout));
        }
        ep.drive(Duration::from_millis(20))?;
    }
    let c = ep.connection(h).ok_or(FetchError::UnknownConnection)?;
    h3.close(c, Instant::now());
    let close_start = Instant::now();
    while close_start.elapsed() < Duration::from_secs(2) {
        ep.drive(Duration::from_millis(20))?;
        if ep.connection(h).map_or(true, |c| c.is_closed()) {
            break;
        }
    }
    Ok(paths
        .iter()
        .zip(pending)
        .map(|(path, p)| Response {
            path: path.clone(),
            status: p.status,
            headers: p.headers,
            body: p.body,
        })
        .collect())
}
