//! The stream-echo application protocol (ALPN [`ALPN`]): the client opens
//! bidirectional streams, writes a payload and FIN on each; the server
//! writes every byte back on the same stream and FINs when the client did.
//! Unidirectional streams from the peer are read and discarded.

use crate::endpoint::{ConnectionHandle, Endpoint, EndpointError};
use skiff_quic::conn::Stats;
use skiff_quic::{ApiError, CloseReason, Connection, Event};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// ALPN protocol identifier of the echo application.
pub const ALPN: &[u8] = b"skiff-echo";

/// Bytes read per `stream_read` call.
const CHUNK: usize = 16 * 1024;

/// Echo failures.
#[derive(Debug, thiserror::Error)]
pub enum EchoError {
    /// The endpoint failed.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    /// A stream operation failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The connection closed before the echo finished.
    #[error("connection closed: {0:?}")]
    Closed(CloseReason),
    /// The connection is unknown to the endpoint.
    #[error("unknown connection")]
    UnknownConnection,
    /// The echo did not finish in time.
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    /// A stream echoed different bytes than were sent.
    #[error("stream {0} echoed different bytes")]
    Mismatch(u64),
}

#[derive(Default)]
struct Backlog {
    data: Vec<u8>,
    fin: bool,
}

/// Server side: echoes every client bidirectional stream of every
/// connection on the endpoint.
#[derive(Default)]
pub struct EchoServer {
    backlog: BTreeMap<(ConnectionHandle, u64), Backlog>,
    /// Connections that completed the handshake.
    pub handshakes: u64,
    /// Bytes echoed.
    pub echoed: u64,
}

impl EchoServer {
    /// Services every connection once (call after each
    /// [`Endpoint::drive`]); forgets closed connections.
    pub fn poll(&mut self, ep: &mut Endpoint) {
        while ep.accept().is_some() {}
        for h in ep.handles() {
            let Some(c) = ep.connection(h) else {
                continue;
            };
            self.poll_conn(h, c);
        }
        for h in ep.remove_closed() {
            self.backlog.retain(|(ch, _), _| *ch != h);
        }
    }

    fn poll_conn(&mut self, h: ConnectionHandle, c: &mut Connection) {
        let mut buf = vec![0u8; CHUNK];
        while let Some(ev) = c.poll_event() {
            match ev {
                Event::HandshakeCompleted => self.handshakes += 1,
                Event::StreamReadable(id) => {
                    let echo = id & 0x2 == 0;
                    while let Ok((n, fin)) = c.stream_read(id, &mut buf) {
                        if echo {
                            let b = self.backlog.entry((h, id)).or_default();
                            b.data.extend_from_slice(buf.get(..n).unwrap_or_default());
                            b.fin |= fin;
                        }
                        if fin || n == 0 {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        // Write back what the stream accepts; keep the rest for next time.
        let keys: Vec<u64> = self
            .backlog
            .range((h, 0)..=(h, u64::MAX))
            .map(|((_, id), _)| *id)
            .collect();
        for id in keys {
            let Some(b) = self.backlog.get_mut(&(h, id)) else {
                continue;
            };
            let wrote = if b.data.is_empty() {
                Ok(0)
            } else {
                c.stream_write(id, &b.data, false)
            };
            let Ok(n) = wrote else {
                // Stopped or reset by the peer: give up on this stream.
                self.backlog.remove(&(h, id));
                continue;
            };
            b.data.drain(..n.min(b.data.len()));
            self.echoed += n as u64;
            if b.data.is_empty() && b.fin {
                let _ = c.stream_write(id, &[], true);
                self.backlog.remove(&(h, id));
            }
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

struct ClientStream {
    sent: usize,
    fin_sent: bool,
    echo: Vec<u8>,
    done: bool,
}

/// Client side of one echo connection: sends each payload on its own
/// bidirectional stream and checks the echo.
pub struct EchoClient {
    payloads: Vec<Vec<u8>>,
    next: usize,
    streams: BTreeMap<u64, (usize, ClientStream)>,
    handshake_at: Option<Instant>,
    started: Instant,
    finished: usize,
}

/// Result of a completed echo exchange.
#[derive(Debug, Clone)]
pub struct EchoReport {
    /// Streams echoed.
    pub streams: usize,
    /// Payload bytes sent (and received back).
    pub bytes: u64,
    /// Time to handshake completion.
    pub handshake: Duration,
    /// Time to the last echo.
    pub elapsed: Duration,
    /// Connection counters at the end.
    pub stats: Stats,
}

impl EchoClient {
    /// A client that will echo `payloads`, one stream each.
    pub fn new(payloads: Vec<Vec<u8>>) -> Self {
        Self {
            payloads,
            next: 0,
            streams: BTreeMap::new(),
            handshake_at: None,
            started: Instant::now(),
            finished: 0,
        }
    }

    /// Whether every echo arrived intact.
    pub fn is_done(&self) -> bool {
        self.finished == self.payloads.len()
    }

    /// Advances the exchange; returns an error if the connection closed or
    /// an echo differs from what was sent.
    pub fn poll(&mut self, c: &mut Connection) -> Result<(), EchoError> {
        let mut buf = vec![0u8; CHUNK];
        while let Some(ev) = c.poll_event() {
            match ev {
                Event::HandshakeCompleted => self.handshake_at = Some(Instant::now()),
                Event::StreamReadable(id) => self.read(c, id, &mut buf)?,
                Event::Closed(r) if !self.is_done() => return Err(EchoError::Closed(r)),
                _ => {}
            }
        }
        if let Some(r) = c.close_reason() {
            if !self.is_done() {
                return Err(EchoError::Closed(r.clone()));
            }
        }
        if self.handshake_at.is_none() {
            // Attached to a connection whose handshake event was consumed.
            if !c.is_handshake_complete() {
                return Ok(());
            }
            self.handshake_at = Some(Instant::now());
        }
        while self.next < self.payloads.len() {
            match c.open_stream(true) {
                Ok(id) => {
                    let s = ClientStream {
                        sent: 0,
                        fin_sent: false,
                        echo: Vec::new(),
                        done: false,
                    };
                    self.streams.insert(id, (self.next, s));
                    self.next += 1;
                }
                Err(ApiError::StreamsBlocked) => break,
                Err(e) => return Err(e.into()),
            }
        }
        for (id, (i, s)) in self.streams.iter_mut() {
            if s.fin_sent {
                continue;
            }
            let data = self.payloads.get(*i).map_or(&[][..], |p| p.as_slice());
            let rest = data.get(s.sent..).unwrap_or_default();
            s.sent += c.stream_write(*id, rest, false)?;
            if s.sent == data.len() {
                c.stream_write(*id, &[], true)?;
                s.fin_sent = true;
            }
        }
        Ok(())
    }

    fn read(&mut self, c: &mut Connection, id: u64, buf: &mut [u8]) -> Result<(), EchoError> {
        let Some((i, s)) = self.streams.get_mut(&id) else {
            return Ok(());
        };
        loop {
            let (n, fin) = c.stream_read(id, buf)?;
            s.echo.extend_from_slice(buf.get(..n).unwrap_or_default());
            if fin {
                let sent = self.payloads.get(*i).map_or(&[][..], |p| p.as_slice());
                if s.echo != sent {
                    return Err(EchoError::Mismatch(id));
                }
                if !s.done {
                    s.done = true;
                    s.echo = Vec::new();
                    self.finished += 1;
                }
                return Ok(());
            }
            if n == 0 {
                return Ok(());
            }
        }
    }

    /// The report once [`EchoClient::is_done`].
    pub fn report(&self, c: &Connection) -> EchoReport {
        let now = Instant::now();
        EchoReport {
            streams: self.payloads.len(),
            bytes: self.payloads.iter().map(|p| p.len() as u64).sum(),
            handshake: self.handshake_at.unwrap_or(now) - self.started,
            elapsed: now - self.started,
            stats: c.stats(),
        }
    }
}

/// Runs one echo exchange on connection `h` to completion, then closes the
/// connection with code 0 and waits (briefly) for the close to finish.
pub fn run_client(
    ep: &mut Endpoint,
    h: ConnectionHandle,
    payloads: Vec<Vec<u8>>,
    timeout: Duration,
) -> Result<EchoReport, EchoError> {
    let mut client = EchoClient::new(payloads);
    let start = Instant::now();
    loop {
        let c = ep.connection(h).ok_or(EchoError::UnknownConnection)?;
        client.poll(c)?;
        if client.is_done() {
            break;
        }
        if start.elapsed() > timeout {
            return Err(EchoError::Timeout(timeout));
        }
        ep.drive(Duration::from_millis(20))?;
    }
    let c = ep.connection(h).ok_or(EchoError::UnknownConnection)?;
    let report = client.report(c);
    c.close(0, b"done", Instant::now());
    let close_start = Instant::now();
    while close_start.elapsed() < Duration::from_secs(2) {
        ep.drive(Duration::from_millis(20))?;
        if ep.connection(h).map_or(true, |c| c.is_closed()) {
            break;
        }
    }
    Ok(report)
}

/// A deterministic payload of `len` bytes, varied by `seed`.
pub fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_be_bytes()[0] ^ seed)
        .collect()
}
