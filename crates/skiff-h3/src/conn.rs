//! An HTTP/3 connection (RFC 9114) driven over a sans-I/O
//! [`skiff_quic::Connection`]: control and QPACK unidirectional streams,
//! SETTINGS, request/response streams with HEADERS and DATA frames, GOAWAY
//! and stream/connection error handling.
//!
//! The application owns the QUIC connection and passes it to every call;
//! [`H3Connection::poll`] consumes the QUIC events (so the application must
//! not call `poll_event` itself) and turns them into [`H3Event`]s.

use crate::frame::error_code::*;
use crate::frame::{
    frame_type, parse_single_varint, put_varint, stream_type, FrameError, FrameHeader, Settings,
};
use crate::qpack::{self, Decoded, Decoder, Encoder, Field, QpackError};
use skiff_quic::crypto::Side;
use skiff_quic::send::SendError;
use skiff_quic::{ApiError, CloseReason, Connection, Event};
use skiff_wire::codec::Reader;
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

/// Bytes read from QUIC per `stream_read` call.
const READ_CHUNK: usize = 16 * 1024;
/// Request bodies buffered per stream before reading pauses (QUIC flow
/// control then stops the peer).
const BODY_HIGH_WATER: usize = 256 * 1024;
/// Largest control-stream frame payload accepted (SETTINGS, GOAWAY, ...).
const MAX_CONTROL_FRAME: u64 = 16 * 1024;

/// HTTP/3 settings for one connection.
#[derive(Debug, Clone)]
pub struct H3Config {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY we advertise (our decoder's table).
    pub qpack_max_table_capacity: u64,
    /// SETTINGS_QPACK_BLOCKED_STREAMS we advertise.
    pub qpack_blocked_streams: u64,
    /// SETTINGS_MAX_FIELD_SECTION_SIZE we advertise and enforce.
    pub max_field_section_size: u64,
    /// Largest dynamic table our encoder uses (also capped by the peer).
    pub encoder_table_capacity: u64,
    /// Advertise SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 and accept extended
    /// CONNECT requests (`:protocol`, RFC 9220). A server that leaves this
    /// off rejects them with H3_MESSAGE_ERROR (RFC 8441 5).
    pub enable_connect_protocol: bool,
}

impl Default for H3Config {
    fn default() -> Self {
        Self {
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 16,
            max_field_section_size: 64 * 1024,
            encoder_table_capacity: 4096,
            enable_connect_protocol: false,
        }
    }
}

/// HTTP/3 failures returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum H3Error {
    /// A connection error: the QUIC connection was closed with this
    /// HTTP/3 (or QPACK) error code.
    #[error("HTTP/3 connection error {code:#x}: {reason}")]
    Connection {
        /// Error code sent in CONNECTION_CLOSE.
        code: u64,
        /// Diagnostic.
        reason: &'static str,
    },
    /// The connection is closed (see [`H3Event::Closed`]).
    #[error("connection closed")]
    Closed,
    /// The QUIC layer refused the operation (e.g. `StreamsBlocked`).
    #[error(transparent)]
    Quic(#[from] ApiError),
    /// Encoding a field section failed locally (nothing was sent).
    #[error(transparent)]
    Qpack(#[from] QpackError),
    /// The handshake has not completed or the control streams are not
    /// open yet; retry after [`H3Connection::poll`].
    #[error("HTTP/3 not ready")]
    NotReady,
    /// No such request stream (unknown, finished or reset).
    #[error("unknown request stream {0}")]
    UnknownStream(u64),
    /// The peer sent GOAWAY: no new requests.
    #[error("peer is going away")]
    GoingAway,
    /// The call is not valid for this side or stream state.
    #[error("invalid call: {0}")]
    InvalidState(&'static str),
    /// The request stream was abandoned (an [`H3Event::Reset`] for it is
    /// queued): body bytes already announced by a `Data` event are dropped
    /// and must not be taken as a complete message.
    #[error("request stream {stream_id} was reset with code {code:#x}")]
    StreamReset {
        /// Request stream.
        stream_id: u64,
        /// Application error code.
        code: u64,
    },
}

/// What happened, from [`H3Connection::poll_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Event {
    /// The peer's SETTINGS arrived.
    Settings(Settings),
    /// A header section arrived: the request (server), a response or
    /// interim response (client), or trailers (after body data).
    Headers {
        /// Request stream.
        stream_id: u64,
        /// Decoded field lines.
        fields: Vec<Field>,
    },
    /// Body bytes are available to [`H3Connection::recv_body`].
    Data {
        /// Request stream.
        stream_id: u64,
    },
    /// The peer finished the stream; the rest of the body (if any) is
    /// buffered for [`H3Connection::recv_body`].
    Finished {
        /// Request stream.
        stream_id: u64,
    },
    /// The stream was abandoned: reset by the peer, or by us after a stream
    /// error (malformed message, incomplete request, ...).
    Reset {
        /// Request stream.
        stream_id: u64,
        /// Application error code.
        code: u64,
    },
    /// The peer asked us to stop sending on this stream (STOP_SENDING);
    /// pending response data was dropped.
    Stopped {
        /// Request stream.
        stream_id: u64,
        /// Application error code.
        code: u64,
    },
    /// The peer sent GOAWAY with this stream (client) or push (server) ID.
    GoAway {
        /// First ID the peer will not process.
        id: u64,
    },
    /// The QUIC connection closed.
    Closed(CloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UniKind {
    Pending,
    Control,
    Encoder,
    Decoder,
    Ignored,
}

#[derive(Debug)]
struct UniIn {
    kind: UniKind,
    buf: Vec<u8>,
    skip: u64,
}

#[derive(Debug, Default)]
struct ReqIn {
    /// Unparsed bytes (frame headers, HEADERS payloads).
    buf: Vec<u8>,
    /// DATA payload bytes still to come in the current frame.
    data_left: u64,
    /// Unknown-frame payload bytes still to skip.
    skip_left: u64,
    body: VecDeque<u8>,
    /// The request (server) or final response (client) header section was
    /// delivered.
    final_headers: bool,
    trailers: bool,
    /// A HEADERS payload waiting for QPACK inserts.
    blocked: Option<Vec<u8>>,
    /// QUIC FIN read.
    fin: bool,
    finished_event: bool,
    /// The receive side is over (consumed to the end, reset or abandoned).
    recv_done: bool,
    /// Our send side is over (FIN written, reset or stopped).
    send_done: bool,
    /// Headers were sent on this stream (response or request).
    sent_headers: bool,
    /// Content-Length of the received message, when it must match the
    /// DATA received (RFC 9114 4.1.2).
    content_length: Option<u64>,
    /// DATA payload bytes received.
    data_received: u64,
    /// The request was HEAD, so the response has no content whatever its
    /// Content-Length says (RFC 9110 9.3.2).
    head_request: bool,
    /// Server: the final response sent has no content (a response to HEAD,
    /// 204 or 304), so `send_data` refuses body bytes.
    send_no_content: bool,
}

/// Whether a final response's status forbids content (RFC 9110 6.4.1:
/// 204 and 304; 1xx are interim and never reach this check).
fn status_without_content(fields: &[Field]) -> bool {
    fields
        .iter()
        .any(|f| f.name == b":status" && matches!(f.value.as_slice(), b"204" | b"304"))
}

fn has_protocol(fields: &[Field]) -> bool {
    fields.iter().any(|f| f.name == b":protocol")
}

/// The Content-Length of a header section: `Ok(None)` if absent, an error
/// if a value is not a decimal number or values disagree (a list of equal
/// values is allowed, RFC 9110 8.6).
fn content_length(fields: &[Field]) -> Result<Option<u64>, ()> {
    let mut cl = None;
    for f in fields.iter().filter(|f| f.name == b"content-length") {
        let s = std::str::from_utf8(&f.value).map_err(|_| ())?;
        for part in s.split(',').map(str::trim) {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(());
            }
            let v: u64 = part.parse().map_err(|_| ())?;
            if cl.is_some_and(|c| c != v) {
                return Err(());
            }
            cl = Some(v);
        }
    }
    Ok(cl)
}

#[derive(Debug, Default)]
struct Out {
    buf: Vec<u8>,
    fin: bool,
}

/// One HTTP/3 connection (client or server side).
#[derive(Debug)]
pub struct H3Connection {
    config: H3Config,
    side: Option<Side>,
    control: Option<u64>,
    encoder_stream: Option<u64>,
    decoder_stream: Option<u64>,
    out: BTreeMap<u64, Out>,
    uni: BTreeMap<u64, UniIn>,
    peer_control: Option<u64>,
    peer_encoder: Option<u64>,
    peer_decoder: Option<u64>,
    peer_settings: Option<Settings>,
    requests: BTreeMap<u64, ReqIn>,
    encoder: Encoder,
    decoder: Decoder,
    events: VecDeque<H3Event>,
    goaway_recv: Option<u64>,
    goaway_sent: Option<u64>,
    max_request_seen: Option<u64>,
    error: Option<H3Error>,
    /// A connection error found outside `poll`, closed by the next `poll`.
    deferred: Option<H3Error>,
    closed: bool,
    /// Streams whose `Reset` event is queued but not yet polled, with the
    /// code (bounded by the event queue).
    reset_pending: BTreeMap<u64, u64>,
    /// Request streams accepted (server) or opened (client).
    pub requests_started: u64,
}

fn conn_err(code: u64, reason: &'static str) -> H3Error {
    H3Error::Connection { code, reason }
}

impl From<FrameError> for H3Error {
    fn from(e: FrameError) -> Self {
        conn_err(e.code, e.reason)
    }
}

fn is_bidi(id: u64) -> bool {
    id & 0x2 == 0
}

fn is_client_initiated(id: u64) -> bool {
    id & 0x1 == 0
}

/// Kind of header section being validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Request,
    Response,
    Trailers,
}

/// RFC 9114 4.2 / 4.3 checks. Returns whether a response is informational
/// (1xx).
fn check_message(fields: &[Field], kind: Section) -> Result<bool, &'static str> {
    let mut regular = false;
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut method: Option<&[u8]> = None;
    let mut status: Option<&[u8]> = None;
    for f in fields {
        if f.name.is_empty() {
            return Err("empty field name");
        }
        if f.name.iter().any(|b| b.is_ascii_uppercase()) {
            return Err("uppercase field name");
        }
        let bad = |b: &u8| matches!(b, 0 | b'\r' | b'\n');
        if f.name.iter().any(bad) || f.value.iter().any(bad) {
            return Err("invalid character in field");
        }
        if f.name.first() == Some(&b':') {
            if regular {
                return Err("pseudo-header after regular field");
            }
            if seen.contains(&f.name.as_slice()) {
                return Err("duplicate pseudo-header");
            }
            seen.push(&f.name);
            match (kind, f.name.as_slice()) {
                (Section::Request, b":method") => method = Some(&f.value),
                (Section::Request, b":scheme" | b":authority" | b":path" | b":protocol") => {}
                (Section::Response, b":status") => status = Some(&f.value),
                _ => return Err("invalid pseudo-header"),
            }
            continue;
        }
        regular = true;
        match f.name.as_slice() {
            b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
            | b"upgrade" => return Err("connection-specific field"),
            b"te" if f.value != b"trailers" => return Err("te other than trailers"),
            _ => {}
        }
    }
    let has = |n: &[u8]| seen.contains(&n);
    match kind {
        Section::Request => {
            let m = method.ok_or("missing :method")?;
            // RFC 8441 4 / RFC 9220: :protocol belongs to extended CONNECT.
            if has(b":protocol") && m != b"CONNECT" {
                return Err("`:protocol` outside CONNECT");
            }
            if m == b"CONNECT" && !has(b":protocol") {
                if has(b":scheme") || has(b":path") || !has(b":authority") {
                    return Err("malformed CONNECT");
                }
            } else if !has(b":scheme") || !has(b":path") {
                return Err("missing :scheme or :path");
            }
            if fields
                .iter()
                .any(|f| f.name == b":path" && f.value.is_empty())
            {
                return Err("empty :path");
            }
            Ok(false)
        }
        Section::Response => {
            let s = status.ok_or("missing :status")?;
            if s.len() != 3 || !s.iter().all(u8::is_ascii_digit) {
                return Err("invalid :status");
            }
            Ok(s.first() == Some(&b'1'))
        }
        Section::Trailers => Ok(false),
    }
}

impl H3Connection {
    /// A new HTTP/3 layer; the side is taken from the QUIC connection on
    /// the first [`H3Connection::poll`].
    pub fn new(config: H3Config) -> Self {
        let encoder = Encoder::new(config.encoder_table_capacity);
        let decoder = Decoder::new(
            config.qpack_max_table_capacity,
            config.qpack_blocked_streams,
            config.max_field_section_size,
        );
        Self {
            config,
            side: None,
            control: None,
            encoder_stream: None,
            decoder_stream: None,
            out: BTreeMap::new(),
            uni: BTreeMap::new(),
            peer_control: None,
            peer_encoder: None,
            peer_decoder: None,
            peer_settings: None,
            requests: BTreeMap::new(),
            encoder,
            decoder,
            events: VecDeque::new(),
            goaway_recv: None,
            goaway_sent: None,
            max_request_seen: None,
            error: None,
            deferred: None,
            closed: false,
            reset_pending: BTreeMap::new(),
            requests_started: 0,
        }
    }

    /// The peer's settings, once its SETTINGS frame arrived.
    pub fn peer_settings(&self) -> Option<&Settings> {
        self.peer_settings.as_ref()
    }

    /// Our QPACK encoder (dynamic table state, for diagnostics).
    pub fn qpack_encoder(&self) -> &Encoder {
        &self.encoder
    }

    /// Our QPACK decoder (dynamic table state, for diagnostics).
    pub fn qpack_decoder(&self) -> &Decoder {
        &self.decoder
    }

    /// Whether our control and QPACK streams are open (requests can be sent).
    pub fn is_ready(&self) -> bool {
        self.control.is_some() && self.encoder_stream.is_some() && self.decoder_stream.is_some()
    }

    /// The GOAWAY ID received from the peer, if any.
    pub fn goaway_received(&self) -> Option<u64> {
        self.goaway_recv
    }

    /// Request streams still tracked (not yet finished in both directions).
    pub fn active_requests(&self) -> usize {
        self.requests.len()
    }

    /// Next event.
    pub fn poll_event(&mut self) -> Option<H3Event> {
        let ev = self.events.pop_front();
        if let Some(H3Event::Reset { stream_id, .. }) = &ev {
            self.reset_pending.remove(stream_id);
        }
        ev
    }

    fn check_open(&self) -> Result<(), H3Error> {
        if let Some(e) = self.error.as_ref().or(self.deferred.as_ref()) {
            return Err(e.clone());
        }
        if self.closed {
            return Err(H3Error::Closed);
        }
        Ok(())
    }

    /// Records a connection error and closes the QUIC connection with it.
    fn fail(&mut self, conn: &mut Connection, e: H3Error, now: Instant) -> H3Error {
        if self.error.is_none() {
            if let H3Error::Connection { code, reason } = &e {
                conn.close(*code, reason.as_bytes(), now);
            }
            self.error = Some(e.clone());
        }
        e
    }

    /// Processes QUIC events, opens the control and QPACK streams once the
    /// handshake completes, and writes pending frames. Call after every
    /// `Connection::recv` / `on_timeout` and before `Connection::send`.
    /// Returns an error once the HTTP/3 layer closed the connection.
    pub fn poll(&mut self, conn: &mut Connection, now: Instant) -> Result<(), H3Error> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let res = match self.deferred.take() {
            Some(e) => Err(e),
            None => self.poll_inner(conn),
        };
        match res {
            Ok(()) => Ok(()),
            Err(e @ H3Error::Connection { .. }) => Err(self.fail(conn, e, now)),
            // Other errors (e.g. the QUIC connection closing under us) are
            // reported through events.
            Err(_) => Ok(()),
        }
    }

    fn poll_inner(&mut self, conn: &mut Connection) -> Result<(), H3Error> {
        if self.side.is_none() {
            self.side = Some(conn.side());
        }
        while let Some(ev) = conn.poll_event() {
            match ev {
                Event::HandshakeCompleted => {}
                Event::StreamOpened(id) => self.on_opened(conn, id)?,
                Event::StreamReadable(id) => self.on_readable(conn, id)?,
                Event::StreamStopped { id, error } => self.on_stopped(id, error)?,
                Event::Closed(r) => {
                    if !self.closed {
                        self.closed = true;
                        self.events.push_back(H3Event::Closed(r));
                    }
                }
            }
        }
        if self.closed {
            return Ok(());
        }
        if conn.is_handshake_complete() && !self.is_ready() {
            self.open_local_streams(conn)?;
        }
        self.flush(conn);
        Ok(())
    }

    fn is_server(&self) -> bool {
        self.side == Some(Side::Server)
    }

    fn open_local_streams(&mut self, conn: &mut Connection) -> Result<(), H3Error> {
        let settings = Settings {
            qpack_max_table_capacity: self.config.qpack_max_table_capacity,
            qpack_blocked_streams: self.config.qpack_blocked_streams,
            max_field_section_size: Some(self.config.max_field_section_size),
            enable_connect_protocol: self.config.enable_connect_protocol,
        };
        let mut open = |slot: &mut Option<u64>, out: &mut BTreeMap<u64, Out>, preface: Vec<u8>| {
            if slot.is_some() {
                return Ok(());
            }
            match conn.open_stream(false) {
                Ok(id) => {
                    *slot = Some(id);
                    out.entry(id).or_default().buf.extend(preface);
                    Ok(())
                }
                Err(ApiError::StreamsBlocked | ApiError::NotEstablished) => Ok(()),
                Err(e) => Err(H3Error::from(e)),
            }
        };
        let mut control = vec![stream_type::CONTROL as u8];
        crate::frame::encode_frame(&mut control, frame_type::SETTINGS, &settings.encode());
        open(&mut self.control, &mut self.out, control)?;
        open(
            &mut self.encoder_stream,
            &mut self.out,
            vec![stream_type::QPACK_ENCODER as u8],
        )?;
        open(
            &mut self.decoder_stream,
            &mut self.out,
            vec![stream_type::QPACK_DECODER as u8],
        )?;
        Ok(())
    }

    /// Writes QPACK instructions and buffered frames to QUIC.
    fn flush(&mut self, conn: &mut Connection) {
        if let Some(id) = self.encoder_stream {
            let b = self.encoder.take_instructions();
            self.out.entry(id).or_default().buf.extend(b);
        }
        if let Some(id) = self.decoder_stream {
            let b = self.decoder.take_instructions();
            self.out.entry(id).or_default().buf.extend(b);
        }
        let mut done = Vec::new();
        for (id, o) in self.out.iter_mut() {
            if o.buf.is_empty() && !o.fin {
                continue;
            }
            match conn.stream_write(*id, &o.buf, o.fin) {
                Ok(n) => {
                    o.buf.drain(..n.min(o.buf.len()));
                    if o.buf.is_empty() && o.fin {
                        done.push(*id);
                    }
                }
                Err(ApiError::Send(SendError::WouldBlock)) => {}
                Err(_) => done.push(*id),
            }
        }
        for id in done {
            self.out.remove(&id);
            if let Some(r) = self.requests.get_mut(&id) {
                r.send_done = true;
            }
            self.maybe_forget(id);
        }
    }

    fn maybe_forget(&mut self, id: u64) {
        if self
            .requests
            .get(&id)
            .is_some_and(|r| r.recv_done && r.send_done)
        {
            self.requests.remove(&id);
        }
    }

    fn on_opened(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        if !is_bidi(id) {
            self.uni.insert(
                id,
                UniIn {
                    kind: UniKind::Pending,
                    buf: Vec::new(),
                    skip: 0,
                },
            );
            return Ok(());
        }
        if !self.is_server() || !is_client_initiated(id) {
            return Err(conn_err(
                H3_STREAM_CREATION_ERROR,
                "server-initiated bidirectional stream",
            ));
        }
        self.max_request_seen = Some(self.max_request_seen.map_or(id, |m| m.max(id)));
        if self.goaway_sent.is_some_and(|g| id >= g) {
            let _ = conn.stream_stop(id, H3_REQUEST_REJECTED);
            let _ = conn.stream_reset(id, H3_REQUEST_REJECTED);
            return Ok(());
        }
        self.requests_started += 1;
        self.requests.insert(id, ReqIn::default());
        Ok(())
    }

    fn on_stopped(&mut self, id: u64, code: u64) -> Result<(), H3Error> {
        if [self.control, self.encoder_stream, self.decoder_stream].contains(&Some(id)) {
            return Err(conn_err(
                H3_CLOSED_CRITICAL_STREAM,
                "critical stream stopped by peer",
            ));
        }
        self.out.remove(&id);
        if let Some(r) = self.requests.get_mut(&id) {
            r.send_done = true;
            self.events.push_back(H3Event::Stopped {
                stream_id: id,
                code,
            });
        }
        self.maybe_forget(id);
        Ok(())
    }

    fn on_readable(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        if is_bidi(id) {
            self.read_request(conn, id)
        } else {
            self.read_uni(conn, id)
        }
    }

    // ----- unidirectional streams ----------------------------------------------

    fn read_uni(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            let Some(u) = self.uni.get_mut(&id) else {
                return Ok(());
            };
            let critical = matches!(
                u.kind,
                UniKind::Control | UniKind::Encoder | UniKind::Decoder
            );
            match conn.stream_read(id, &mut chunk) {
                Ok((n, fin)) => {
                    u.buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    self.process_uni(conn, id)?;
                    let critical = critical
                        || self.uni.get(&id).is_some_and(|u| {
                            matches!(
                                u.kind,
                                UniKind::Control | UniKind::Encoder | UniKind::Decoder
                            )
                        });
                    if fin {
                        if critical {
                            return Err(conn_err(
                                H3_CLOSED_CRITICAL_STREAM,
                                "critical stream closed",
                            ));
                        }
                        self.uni.remove(&id);
                        return Ok(());
                    }
                    if n == 0 {
                        return Ok(());
                    }
                }
                Err(ApiError::ResetByPeer(_)) if critical => {
                    return Err(conn_err(H3_CLOSED_CRITICAL_STREAM, "critical stream reset"));
                }
                Err(_) => {
                    self.uni.remove(&id);
                    return Ok(());
                }
            }
        }
    }

    fn process_uni(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        let Some(mut u) = self.uni.remove(&id) else {
            return Ok(());
        };
        let res = self.process_uni_inner(conn, id, &mut u);
        self.uni.insert(id, u);
        res
    }

    fn process_uni_inner(
        &mut self,
        conn: &mut Connection,
        id: u64,
        u: &mut UniIn,
    ) -> Result<(), H3Error> {
        if u.kind == UniKind::Pending {
            let mut r = Reader::new(&u.buf);
            let Ok(ty) = r.varint() else {
                return Ok(());
            };
            let used = r.position();
            u.buf.drain(..used);
            let dup = |slot: &mut Option<u64>| {
                if slot.is_some() {
                    return Err(conn_err(
                        H3_STREAM_CREATION_ERROR,
                        "duplicate critical stream",
                    ));
                }
                *slot = Some(id);
                Ok(())
            };
            u.kind = match ty {
                stream_type::CONTROL => {
                    dup(&mut self.peer_control)?;
                    UniKind::Control
                }
                stream_type::QPACK_ENCODER => {
                    dup(&mut self.peer_encoder)?;
                    UniKind::Encoder
                }
                stream_type::QPACK_DECODER => {
                    dup(&mut self.peer_decoder)?;
                    UniKind::Decoder
                }
                stream_type::PUSH if self.is_server() => {
                    return Err(conn_err(
                        H3_STREAM_CREATION_ERROR,
                        "push stream from client",
                    ));
                }
                // We never send MAX_PUSH_ID, so no push ID is valid.
                stream_type::PUSH => return Err(conn_err(H3_ID_ERROR, "push without MAX_PUSH_ID")),
                _ => {
                    let _ = conn.stream_stop(id, H3_STREAM_CREATION_ERROR);
                    UniKind::Ignored
                }
            };
        }
        match u.kind {
            UniKind::Pending => Ok(()),
            UniKind::Ignored => {
                u.buf.clear();
                Ok(())
            }
            UniKind::Encoder => {
                let data = std::mem::take(&mut u.buf);
                self.decoder
                    .on_encoder_stream(&data)
                    .map_err(|e| conn_err(e.code(), "QPACK encoder stream"))?;
                self.unblock(conn)
            }
            UniKind::Decoder => {
                let data = std::mem::take(&mut u.buf);
                self.encoder
                    .on_decoder_stream(&data)
                    .map_err(|e| conn_err(e.code(), "QPACK decoder stream"))
            }
            UniKind::Control => self.process_control(u),
        }
    }

    fn process_control(&mut self, u: &mut UniIn) -> Result<(), H3Error> {
        let mut pos = 0;
        loop {
            let rest = u.buf.get(pos..).unwrap_or_default();
            if u.skip > 0 {
                let n = (u.skip as usize).min(rest.len());
                pos += n;
                u.skip -= n as u64;
                if u.skip > 0 {
                    break;
                }
                continue;
            }
            let Some((h, hl)) = FrameHeader::parse(rest) else {
                break;
            };
            if self.peer_settings.is_none() && h.ty != frame_type::SETTINGS {
                return Err(conn_err(
                    H3_MISSING_SETTINGS,
                    "first control frame not SETTINGS",
                ));
            }
            let known = matches!(
                h.ty,
                frame_type::SETTINGS
                    | frame_type::GOAWAY
                    | frame_type::MAX_PUSH_ID
                    | frame_type::CANCEL_PUSH
            );
            if !known {
                if matches!(
                    h.ty,
                    frame_type::DATA | frame_type::HEADERS | frame_type::PUSH_PROMISE
                ) || frame_type::is_reserved_h2(h.ty)
                {
                    return Err(conn_err(
                        H3_FRAME_UNEXPECTED,
                        "frame not allowed on control stream",
                    ));
                }
                pos += hl;
                u.skip = h.len;
                continue;
            }
            if h.len > MAX_CONTROL_FRAME {
                return Err(conn_err(H3_EXCESSIVE_LOAD, "control frame too large"));
            }
            let end = hl + h.len as usize;
            let Some(payload) = rest.get(hl..end) else {
                break;
            };
            match h.ty {
                frame_type::SETTINGS => {
                    if self.peer_settings.is_some() {
                        return Err(conn_err(H3_FRAME_UNEXPECTED, "second SETTINGS"));
                    }
                    let s = Settings::decode(payload)?;
                    self.encoder.apply_peer_settings(
                        s.qpack_max_table_capacity,
                        s.qpack_blocked_streams,
                        s.max_field_section_size.unwrap_or(u64::MAX),
                    );
                    self.peer_settings = Some(s);
                    self.events.push_back(H3Event::Settings(s));
                }
                frame_type::GOAWAY => {
                    let id = parse_single_varint(payload)?;
                    if !self.is_server() && (!is_bidi(id) || !is_client_initiated(id)) {
                        return Err(conn_err(H3_ID_ERROR, "GOAWAY with a non-request stream ID"));
                    }
                    if self.goaway_recv.is_some_and(|g| id > g) {
                        return Err(conn_err(H3_ID_ERROR, "GOAWAY ID increased"));
                    }
                    self.goaway_recv = Some(id);
                    self.events.push_back(H3Event::GoAway { id });
                }
                frame_type::MAX_PUSH_ID => {
                    if !self.is_server() {
                        return Err(conn_err(H3_FRAME_UNEXPECTED, "MAX_PUSH_ID from server"));
                    }
                    parse_single_varint(payload)?;
                }
                // CANCEL_PUSH: we neither push nor accept pushes.
                _ => {
                    parse_single_varint(payload)?;
                }
            }
            pos += end;
        }
        u.buf.drain(..pos.min(u.buf.len()));
        Ok(())
    }

    // ----- request streams --------------------------------------------------------

    fn read_request(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            let Some(r) = self.requests.get_mut(&id) else {
                return Ok(());
            };
            if r.recv_done || r.fin {
                break;
            }
            // A stream waiting on QPACK inserts or with a full body buffer
            // reads nothing more (QUIC flow control holds the peer back),
            // but a zero-length read still reports a peer reset or FIN.
            let paused = r.blocked.is_some() || r.body.len() >= BODY_HIGH_WATER;
            let want = if paused { 0 } else { READ_CHUNK };
            match conn.stream_read(id, chunk.get_mut(..want).unwrap_or_default()) {
                Ok((n, fin)) => {
                    r.buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    r.fin |= fin;
                    self.process_request(conn, id)?;
                    if paused || (n == 0 && !fin) {
                        break;
                    }
                }
                Err(ApiError::ResetByPeer(code)) => {
                    self.abandon(conn, id, code, false);
                    return Ok(());
                }
                Err(_) => {
                    if let Some(r) = self.requests.get_mut(&id) {
                        r.recv_done = true;
                    }
                    self.maybe_forget(id);
                    return Ok(());
                }
            }
        }
        self.process_request(conn, id)
    }

    /// Abandons the receive side (and with `local`, our send side too):
    /// a peer reset (`local == false`) or a stream error of ours.
    fn abandon(&mut self, conn: &mut Connection, id: u64, code: u64, local: bool) {
        let Some(r) = self.requests.get_mut(&id) else {
            return;
        };
        if !(r.fin && r.buf.is_empty() && r.blocked.is_none()) {
            self.decoder.cancel_stream(id);
        }
        r.recv_done = true;
        r.body.clear();
        if local {
            let _ = conn.stream_stop(id, code);
            let _ = conn.stream_reset(id, code);
            r.send_done = true;
            self.out.remove(&id);
        }
        self.events.push_back(H3Event::Reset {
            stream_id: id,
            code,
        });
        self.reset_pending.insert(id, code);
        self.maybe_forget(id);
    }

    fn process_request(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        let Some(mut r) = self.requests.remove(&id) else {
            return Ok(());
        };
        let res = self.process_request_inner(&mut r, id);
        let stream_error = match res {
            Ok(code) => code,
            Err(e) => {
                self.requests.insert(id, r);
                return Err(e);
            }
        };
        self.requests.insert(id, r);
        if let Some(code) = stream_error {
            self.abandon(conn, id, code, true);
        }
        self.maybe_forget(id);
        Ok(())
    }

    /// Parses frames; returns a stream error code if the stream must be
    /// abandoned.
    fn process_request_inner(&mut self, r: &mut ReqIn, id: u64) -> Result<Option<u64>, H3Error> {
        if r.recv_done {
            r.buf.clear();
            return Ok(None);
        }
        let mut pos = 0;
        let mut new_data = false;
        let mut stream_error = None;
        while r.blocked.is_none() && stream_error.is_none() {
            let rest = r.buf.get(pos..).unwrap_or_default();
            if r.data_left > 0 || r.skip_left > 0 {
                let left = r.data_left.max(r.skip_left);
                let n = (left as usize).min(rest.len());
                if n == 0 {
                    break;
                }
                if r.data_left > 0 {
                    r.body.extend(rest.get(..n).unwrap_or_default());
                    r.data_left -= n as u64;
                    r.data_received += n as u64;
                    new_data = true;
                    if r.content_length.is_some_and(|cl| r.data_received > cl) {
                        stream_error = Some(H3_MESSAGE_ERROR);
                    }
                } else {
                    r.skip_left -= n as u64;
                }
                pos += n;
                continue;
            }
            let Some((h, hl)) = FrameHeader::parse(rest) else {
                break;
            };
            match h.ty {
                frame_type::DATA => {
                    if !r.final_headers || r.trailers {
                        return Err(conn_err(
                            H3_FRAME_UNEXPECTED,
                            "DATA before HEADERS or after trailers",
                        ));
                    }
                    pos += hl;
                    r.data_left = h.len;
                }
                frame_type::HEADERS => {
                    if r.trailers {
                        return Err(conn_err(H3_FRAME_UNEXPECTED, "HEADERS after trailers"));
                    }
                    if h.len > self.config.max_field_section_size.max(16 * 1024) {
                        return Err(conn_err(H3_EXCESSIVE_LOAD, "HEADERS frame too large"));
                    }
                    let end = hl + h.len as usize;
                    let Some(payload) = rest.get(hl..end) else {
                        break;
                    };
                    let payload = payload.to_vec();
                    pos += end;
                    stream_error = self.on_headers(r, id, payload)?;
                }
                frame_type::PUSH_PROMISE if !self.is_server() => {
                    return Err(conn_err(H3_ID_ERROR, "PUSH_PROMISE without MAX_PUSH_ID"));
                }
                frame_type::CANCEL_PUSH
                | frame_type::SETTINGS
                | frame_type::GOAWAY
                | frame_type::MAX_PUSH_ID
                | frame_type::PUSH_PROMISE => {
                    return Err(conn_err(
                        H3_FRAME_UNEXPECTED,
                        "control frame on request stream",
                    ));
                }
                t if frame_type::is_reserved_h2(t) => {
                    return Err(conn_err(H3_FRAME_UNEXPECTED, "reserved HTTP/2 frame type"));
                }
                _ => {
                    pos += hl;
                    r.skip_left = h.len;
                }
            }
        }
        r.buf.drain(..pos.min(r.buf.len()));
        if stream_error.is_some() {
            // No Data event: the stream is abandoned and its body dropped.
            return Ok(stream_error);
        }
        if new_data {
            self.events.push_back(H3Event::Data { stream_id: id });
        }
        if r.fin && r.blocked.is_none() && !r.finished_event {
            if !r.buf.is_empty() || r.data_left > 0 || r.skip_left > 0 {
                return Err(conn_err(H3_FRAME_ERROR, "frame truncated by end of stream"));
            }
            if !r.final_headers {
                return Ok(Some(H3_REQUEST_INCOMPLETE));
            }
            if r.content_length.is_some_and(|cl| cl != r.data_received) {
                return Ok(Some(H3_MESSAGE_ERROR));
            }
            r.finished_event = true;
            self.events.push_back(H3Event::Finished { stream_id: id });
        }
        if r.finished_event && r.body.is_empty() {
            r.recv_done = true;
        }
        Ok(None)
    }

    /// Decodes a HEADERS payload; returns a stream error code if the
    /// message is malformed.
    fn on_headers(
        &mut self,
        r: &mut ReqIn,
        id: u64,
        payload: Vec<u8>,
    ) -> Result<Option<u64>, H3Error> {
        match self.decoder.decode(id, &payload) {
            Ok(Decoded::Blocked { .. }) => {
                r.blocked = Some(payload);
                Ok(None)
            }
            Ok(Decoded::Fields(fields)) => Ok(self.deliver_headers(r, id, fields)),
            Err(QpackError::FieldSectionTooLarge { .. }) => Ok(Some(qpack::DECOMPRESSION_FAILED)),
            Err(e) => Err(conn_err(e.code(), "QPACK field section")),
        }
    }

    fn deliver_headers(&mut self, r: &mut ReqIn, id: u64, fields: Vec<Field>) -> Option<u64> {
        let kind = if r.final_headers {
            Section::Trailers
        } else if self.is_server() {
            Section::Request
        } else {
            Section::Response
        };
        match check_message(&fields, kind) {
            Err(_) => return Some(H3_MESSAGE_ERROR),
            Ok(informational) => {
                if kind == Section::Trailers {
                    r.trailers = true;
                } else if !informational {
                    r.final_headers = true;
                    let Ok(cl) = content_length(&fields) else {
                        return Some(H3_MESSAGE_ERROR);
                    };
                    // Extended CONNECT only if we advertised it (RFC 8441 5,
                    // RFC 9220 3): otherwise the request is malformed.
                    if kind == Section::Request
                        && has_protocol(&fields)
                        && !self.config.enable_connect_protocol
                    {
                        return Some(H3_MESSAGE_ERROR);
                    }
                    if kind == Section::Request {
                        r.head_request = fields
                            .iter()
                            .any(|f| f.name == b":method" && f.value == b"HEAD");
                    }
                    // Responses to HEAD and 204/304 responses have no
                    // content whatever Content-Length says (RFC 9110 6.4.1):
                    // they may carry a non-zero Content-Length, but a DATA
                    // frame with any payload makes the response malformed
                    // (RFC 9114 4.1.2), a stream error H3_MESSAGE_ERROR.
                    let no_content = kind == Section::Response
                        && (r.head_request || status_without_content(&fields));
                    r.content_length = if no_content { Some(0) } else { cl };
                }
            }
        }
        self.events.push_back(H3Event::Headers {
            stream_id: id,
            fields,
        });
        None
    }

    /// Retries request streams blocked on QPACK inserts.
    fn unblock(&mut self, conn: &mut Connection) -> Result<(), H3Error> {
        let ids: Vec<u64> = self
            .requests
            .iter()
            .filter(|(_, r)| r.blocked.is_some())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            let Some(mut r) = self.requests.remove(&id) else {
                continue;
            };
            let Some(payload) = r.blocked.take() else {
                self.requests.insert(id, r);
                continue;
            };
            let res = self.on_headers(&mut r, id, payload);
            let unblocked = r.blocked.is_none();
            self.requests.insert(id, r);
            match res? {
                Some(code) => self.abandon(conn, id, code, true),
                None if unblocked => {
                    self.process_request(conn, id)?;
                    self.read_request(conn, id)?;
                }
                None => {}
            }
        }
        Ok(())
    }

    // ----- sending ---------------------------------------------------------------

    fn queue_headers(&mut self, id: u64, fields: &[Field], fin: bool) -> Result<(), H3Error> {
        let block = self.encoder.encode(id, fields)?;
        let o = self.out.entry(id).or_default();
        crate::frame::encode_frame(&mut o.buf, frame_type::HEADERS, &block);
        o.fin |= fin;
        Ok(())
    }

    /// Client: sends a request header section on a new stream and returns
    /// its ID. With `end_stream` the request has no body; otherwise send it
    /// with [`H3Connection::send_data`].
    pub fn send_request(
        &mut self,
        conn: &mut Connection,
        fields: &[Field],
        end_stream: bool,
    ) -> Result<u64, H3Error> {
        self.check_open()?;
        if self.is_server() {
            return Err(H3Error::InvalidState("servers do not send requests"));
        }
        if !self.is_ready() {
            return Err(H3Error::NotReady);
        }
        check_message(fields, Section::Request).map_err(H3Error::InvalidState)?;
        // RFC 8441 4 / RFC 9220 3: extended CONNECT only once the server's
        // SETTINGS enabled it.
        if has_protocol(fields)
            && !self
                .peer_settings
                .is_some_and(|s| s.enable_connect_protocol)
        {
            return Err(H3Error::InvalidState(
                "peer did not enable extended CONNECT",
            ));
        }
        let id = conn.open_stream(true)?;
        if self.goaway_recv.is_some_and(|g| id >= g) {
            let _ = conn.stream_reset(id, H3_REQUEST_CANCELLED);
            return Err(H3Error::GoingAway);
        }
        self.queue_headers(id, fields, end_stream)?;
        self.requests_started += 1;
        self.requests.insert(
            id,
            ReqIn {
                sent_headers: true,
                head_request: fields
                    .iter()
                    .any(|f| f.name == b":method" && f.value == b"HEAD"),
                ..ReqIn::default()
            },
        );
        self.flush(conn);
        Ok(id)
    }

    /// Server: sends the response header section (call again for trailers
    /// after the body). With `end_stream` the stream is finished.
    pub fn send_response(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        fields: &[Field],
        end_stream: bool,
    ) -> Result<(), H3Error> {
        self.check_open()?;
        let server = self.is_server();
        let r = self
            .requests
            .get_mut(&stream_id)
            .ok_or(H3Error::UnknownStream(stream_id))?;
        if r.send_done || self.out.get(&stream_id).is_some_and(|o| o.fin) {
            return Err(H3Error::InvalidState("stream already finished"));
        }
        let kind = if r.sent_headers {
            Section::Trailers
        } else if server {
            Section::Response
        } else {
            return Err(H3Error::InvalidState("clients send requests"));
        };
        let informational = check_message(fields, kind).map_err(H3Error::InvalidState)?;
        if kind == Section::Response && !informational {
            r.sent_headers = true;
            r.send_no_content = r.head_request || status_without_content(fields);
        }
        self.queue_headers(stream_id, fields, end_stream)?;
        self.flush(conn);
        Ok(())
    }

    /// Sends body bytes in one DATA frame (all of `data` is buffered); with
    /// `end_stream` the stream is finished.
    pub fn send_data(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<(), H3Error> {
        self.check_open()?;
        let r = self
            .requests
            .get(&stream_id)
            .ok_or(H3Error::UnknownStream(stream_id))?;
        if !r.sent_headers {
            return Err(H3Error::InvalidState("DATA before HEADERS"));
        }
        if r.send_done || self.out.get(&stream_id).is_some_and(|o| o.fin) {
            return Err(H3Error::InvalidState("stream already finished"));
        }
        if r.send_no_content && !data.is_empty() {
            return Err(H3Error::InvalidState(
                "response to HEAD, 204 or 304 has no content",
            ));
        }
        let o = self.out.entry(stream_id).or_default();
        if !data.is_empty() {
            FrameHeader {
                ty: frame_type::DATA,
                len: data.len() as u64,
            }
            .encode(&mut o.buf);
            o.buf.extend_from_slice(data);
        }
        o.fin |= end_stream;
        self.flush(conn);
        Ok(())
    }

    /// Bytes queued on a stream that QUIC has not accepted yet.
    pub fn pending_send(&self, stream_id: u64) -> usize {
        self.out.get(&stream_id).map_or(0, |o| o.buf.len())
    }

    /// Reads buffered body bytes; returns `(bytes, end_of_body)`. A stream
    /// whose [`H3Event::Reset`] is still queued returns
    /// [`H3Error::StreamReset`] (its body was dropped and is not complete);
    /// any other stream that is no longer tracked (its body was consumed)
    /// reads as `(0, true)`.
    pub fn recv_body(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), H3Error> {
        self.check_open()?;
        if let Some(&code) = self.reset_pending.get(&stream_id) {
            return Err(H3Error::StreamReset { stream_id, code });
        }
        let Some(r) = self.requests.get_mut(&stream_id) else {
            return Ok((0, true));
        };
        let n = buf.len().min(r.body.len());
        for (dst, src) in buf.iter_mut().zip(r.body.drain(..n)) {
            *dst = src;
        }
        let refill = r.body.len() < BODY_HIGH_WATER && !r.fin;
        let end = r.finished_event && r.body.is_empty();
        if end {
            r.recv_done = true;
        }
        if refill {
            if let Err(e) = self.read_request(conn, stream_id) {
                // Closed (with the caller's clock) by the next poll.
                if matches!(e, H3Error::Connection { .. }) {
                    self.deferred = Some(e.clone());
                }
                return Err(e);
            }
        }
        self.maybe_forget(stream_id);
        Ok((n, end))
    }

    /// Abandons a request stream in both directions with `code` (e.g.
    /// H3_REQUEST_CANCELLED).
    pub fn reset_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        code: u64,
    ) -> Result<(), H3Error> {
        if !self.requests.contains_key(&stream_id) {
            return Err(H3Error::UnknownStream(stream_id));
        }
        self.abandon(conn, stream_id, code, true);
        // The application asked for this: no Reset event.
        if let Some(H3Event::Reset { stream_id: s, .. }) = self.events.back() {
            if *s == stream_id {
                self.events.pop_back();
                self.reset_pending.remove(&stream_id);
            }
        }
        Ok(())
    }

    /// Sends GOAWAY: a server refuses requests on streams at or above the
    /// first one it has not seen; a client sends push ID 0.
    pub fn send_goaway(&mut self, conn: &mut Connection) -> Result<(), H3Error> {
        self.check_open()?;
        let control = self.control.ok_or(H3Error::NotReady)?;
        let id = if self.is_server() {
            self.max_request_seen.map_or(0, |m| m + 4)
        } else {
            0
        };
        if self.goaway_sent.is_some_and(|g| g <= id) {
            return Ok(());
        }
        self.goaway_sent = Some(id);
        let mut payload = Vec::new();
        put_varint(&mut payload, id);
        crate::frame::encode_frame(
            &mut self.out.entry(control).or_default().buf,
            frame_type::GOAWAY,
            &payload,
        );
        self.flush(conn);
        Ok(())
    }

    /// Closes the connection gracefully (H3_NO_ERROR).
    pub fn close(&mut self, conn: &mut Connection, now: Instant) {
        conn.close(H3_NO_ERROR, b"", now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(n: &str, v: &str) -> Field {
        Field::new(n.as_bytes(), v.as_bytes())
    }

    #[test]
    fn message_validation() {
        let req = [
            f(":method", "GET"),
            f(":scheme", "https"),
            f(":authority", "x"),
            f(":path", "/"),
            f("accept", "*/*"),
        ];
        assert_eq!(check_message(&req, Section::Request), Ok(false));
        let bad: &[&[Field]] = &[
            &[f(":method", "GET"), f(":scheme", "https")],
            &[f(":method", "GET"), f(":scheme", "https"), f(":path", "")],
            &[f(":scheme", "https"), f(":path", "/")],
            &[
                f(":method", "GET"),
                f("a", "b"),
                f(":scheme", "h"),
                f(":path", "/"),
            ],
            &[
                f(":method", "GET"),
                f(":method", "GET"),
                f(":scheme", "h"),
                f(":path", "/"),
            ],
            &[
                f(":method", "GET"),
                f(":scheme", "h"),
                f(":path", "/"),
                f("Accept", "x"),
            ],
            &[
                f(":method", "GET"),
                f(":scheme", "h"),
                f(":path", "/"),
                f("connection", "x"),
            ],
            &[
                f(":method", "GET"),
                f(":scheme", "h"),
                f(":path", "/"),
                f("te", "gzip"),
            ],
            &[
                f(":method", "GET"),
                f(":scheme", "h"),
                f(":path", "/"),
                f("x", "a\nb"),
            ],
            &[
                f(":method", "GET"),
                f(":scheme", "h"),
                f(":path", "/"),
                f(":status", "200"),
            ],
            &[
                f(":method", "CONNECT"),
                f(":scheme", "h"),
                f(":authority", "x"),
            ],
        ];
        for (i, b) in bad.iter().enumerate() {
            assert!(check_message(b, Section::Request).is_err(), "case {i}");
        }
        // :protocol only with CONNECT (extended CONNECT, RFC 8441).
        assert!(check_message(
            &[
                f(":method", "GET"),
                f(":protocol", "websocket"),
                f(":scheme", "h"),
                f(":path", "/"),
            ],
            Section::Request
        )
        .is_err());
        assert_eq!(
            check_message(
                &[
                    f(":method", "CONNECT"),
                    f(":protocol", "websocket"),
                    f(":scheme", "h"),
                    f(":path", "/"),
                    f(":authority", "x"),
                ],
                Section::Request
            ),
            Ok(false)
        );
        assert_eq!(
            check_message(
                &[f(":method", "CONNECT"), f(":authority", "x:1")],
                Section::Request
            ),
            Ok(false)
        );
        assert_eq!(
            check_message(&[f(":status", "200")], Section::Response),
            Ok(false)
        );
        assert_eq!(
            check_message(&[f(":status", "103")], Section::Response),
            Ok(true)
        );
        assert!(check_message(&[f(":status", "20")], Section::Response).is_err());
        assert!(check_message(&[f("x", "y")], Section::Response).is_err());
        assert_eq!(
            check_message(&[f("x-sum", "1")], Section::Trailers),
            Ok(false)
        );
        assert!(check_message(&[f(":status", "200")], Section::Trailers).is_err());
    }
}
