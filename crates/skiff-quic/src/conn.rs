//! The sans-I/O QUIC connection state machine (RFC 9000/9001/9002).
//!
//! A [`Connection`] owns no socket and no clock: the caller feeds received
//! datagrams to [`Connection::recv`], drains outgoing datagrams with
//! [`Connection::send`] until it returns 0, and calls
//! [`Connection::on_timeout`] once [`Connection::timeout`] has passed.
//!
//! Scope: QUIC v1, TLS 1.3 via `rustls::quic`, 8-byte connection IDs issued
//! with NEW_CONNECTION_ID up to the peer's active_connection_id_limit, peer
//! address changes (migration, NAT rebinding) with path validation. The
//! caller reports where datagrams came from with [`Connection::recv_from`]
//! and learns where to send them with [`Connection::send_with_addr`]; the
//! address-less [`Connection::recv`] / [`Connection::send`] keep everything
//! on one path. Not supported: 0-RTT, ECN.

use crate::cid::{LocalCids, NewCidError, RemoteCids, ResetKey, MIN_RESET_LEN, RESET_TOKEN_LEN};
use crate::crypto::{Keys as InitialKeys, PacketProtection, Side, TAG_LEN};
use crate::packet;
use crate::send::{ConnSendFlow, SendError, SendStream};
use crate::space::PacketNumberSpace;
use crate::stream::{ConnFlow, RecvStream, StreamError};
use crate::streams::{Streams, StreamsError, Windows};
use crate::tls::{HeaderOnly, PacketOnly, Split, TlsKeys};
use skiff_recovery::loss::{SentPacket, Space, TimerAction};
use skiff_recovery::pacer::Pacer;
use skiff_recovery::recovery::Recovery;
use skiff_recovery::{CongestionController, Cubic, NewReno};
use skiff_wire::frame::{self, Frame};
use skiff_wire::header::{self, Header, PacketType, VERSION_1};
use skiff_wire::params::TransportParams;
use skiff_wire::Writer;
use std::collections::{BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Transport error codes (RFC 9000 Section 20.1).
pub mod codes {
    /// NO_ERROR.
    pub const NO_ERROR: u64 = 0x00;
    /// INTERNAL_ERROR.
    pub const INTERNAL_ERROR: u64 = 0x01;
    /// FLOW_CONTROL_ERROR.
    pub const FLOW_CONTROL_ERROR: u64 = 0x03;
    /// STREAM_LIMIT_ERROR.
    pub const STREAM_LIMIT_ERROR: u64 = 0x04;
    /// STREAM_STATE_ERROR.
    pub const STREAM_STATE_ERROR: u64 = 0x05;
    /// FINAL_SIZE_ERROR.
    pub const FINAL_SIZE_ERROR: u64 = 0x06;
    /// FRAME_ENCODING_ERROR.
    pub const FRAME_ENCODING_ERROR: u64 = 0x07;
    /// TRANSPORT_PARAMETER_ERROR.
    pub const TRANSPORT_PARAMETER_ERROR: u64 = 0x08;
    /// CONNECTION_ID_LIMIT_ERROR.
    pub const CONNECTION_ID_LIMIT_ERROR: u64 = 0x09;
    /// PROTOCOL_VIOLATION.
    pub const PROTOCOL_VIOLATION: u64 = 0x0a;
    /// APPLICATION_ERROR (application close before 1-RTT keys exist).
    pub const APPLICATION_ERROR: u64 = 0x0c;
    /// CRYPTO_BUFFER_EXCEEDED.
    pub const CRYPTO_BUFFER_EXCEEDED: u64 = 0x0d;
    /// CRYPTO_ERROR base; the TLS alert is added to it.
    pub const CRYPTO_ERROR: u64 = 0x100;
}

/// Length of the connection IDs we issue.
pub const LOCAL_CID_LEN: usize = 8;
/// Minimum size of datagrams carrying Initial packets (RFC 9000 14.1).
pub const MIN_INITIAL_SIZE: usize = 1200;
const ACK_DELAY_EXPONENT: u32 = 3;
const CRYPTO_WINDOW: u64 = 1 << 16;
const UNLIMITED: u64 = 1 << 62;
// Smallest room worth starting a packet in: longest long header + tag + a frame.
const MIN_PACKET_ROOM: usize = 80;
const SPACES: [Space; 3] = [Space::Initial, Space::Handshake, Space::Data];
/// Most CIDs we keep issued at once (also capped by the peer's limit).
const MAX_ISSUED_CIDS: u64 = 4;
/// PATH_CHALLENGE data values remembered per path.
const MAX_CHALLENGES: usize = 8;
/// Off-path PATH_RESPONSEs queued at once.
const MAX_OFF_PATH_RESPONSES: usize = 4;

/// Congestion controller selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    /// RFC 9002 NewReno.
    NewReno,
    /// RFC 9438 CUBIC.
    Cubic,
}

/// Transport settings for one connection.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Our max_idle_timeout (zero disables our side of the idle timer).
    pub max_idle_timeout: Duration,
    /// UDP payload size we start with (clamped to 1200..=16000).
    pub max_datagram_size: usize,
    /// Largest UDP payload path MTU discovery probes for once the handshake
    /// is confirmed (at most the peer's max_udp_payload_size; at or below
    /// `max_datagram_size` turns discovery off). We advertise the larger of
    /// the two as our max_udp_payload_size.
    pub pmtu_max: usize,
    /// Pace 1-RTT data at 1.25 * cwnd / srtt (RFC 9002 7.7) instead of
    /// sending a whole window at once.
    pub pacing: bool,
    /// initial_max_data we advertise (connection receive window).
    pub initial_max_data: u64,
    /// initial_max_stream_data_* we advertise (per-stream receive window).
    pub initial_max_stream_data: u64,
    /// initial_max_streams_bidi we advertise.
    pub initial_max_streams_bidi: u64,
    /// initial_max_streams_uni we advertise.
    pub initial_max_streams_uni: u64,
    /// max_ack_delay we advertise and honour.
    pub max_ack_delay: Duration,
    /// Congestion controller.
    pub congestion: Congestion,
    /// active_connection_id_limit we advertise: how many of the peer's CIDs
    /// we store (at least 2).
    pub active_connection_id_limit: u64,
    /// Key for the stateless reset tokens of the CIDs we issue. Endpoints
    /// share one key so they can reset connections they lost; `None` makes
    /// a random key per connection.
    pub reset_key: Option<ResetKey>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout: Duration::from_secs(30),
            max_datagram_size: 1200,
            pmtu_max: 1452,
            pacing: true,
            initial_max_data: 4 << 20,
            initial_max_stream_data: 1 << 20,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_ack_delay: Duration::from_millis(25),
            congestion: Congestion::NewReno,
            active_connection_id_limit: 4,
            reset_key: None,
        }
    }
}

/// Errors returned by the application-facing API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// TLS or connection setup failed.
    #[error("connection setup failed: {0}")]
    Setup(String),
    /// `accept` was given something other than a valid client Initial datagram.
    #[error("not a valid client Initial datagram")]
    InvalidInitial,
    /// Streams are unavailable until the peer's transport parameters arrive.
    #[error("connection not established")]
    NotEstablished,
    /// The connection is closing, draining or closed.
    #[error("connection closed")]
    Closed,
    /// No such live stream.
    #[error("unknown stream {0}")]
    UnknownStream(u64),
    /// The stream has no half in the requested direction.
    #[error("stream {0} cannot be used in this direction")]
    WrongDirection(u64),
    /// The peer's MAX_STREAMS limit is reached.
    #[error("blocked on peer MAX_STREAMS")]
    StreamsBlocked,
    /// Writing to the stream failed.
    #[error(transparent)]
    Send(#[from] SendError),
    /// The peer reset the stream with this application error code.
    #[error("stream reset by peer with code {0}")]
    ResetByPeer(u64),
    /// A key update needs a confirmed handshake and an acknowledged packet
    /// sent with the current keys (RFC 9001 6.1).
    #[error("key update not allowed yet")]
    KeyUpdateBlocked,
    /// No unused connection ID from the peer to switch to.
    #[error("no spare connection ID from the peer")]
    NoSpareConnectionId,
}

/// Why a connection closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// We closed with a transport error.
    LocalTransport {
        /// Transport error code.
        code: u64,
        /// Frame type that triggered it, if any.
        frame_type: Option<u64>,
        /// Diagnostic reason.
        reason: String,
    },
    /// The application closed the connection.
    LocalApplication {
        /// Application error code.
        code: u64,
        /// Reason phrase.
        reason: Vec<u8>,
    },
    /// The peer sent a transport CONNECTION_CLOSE (0x1c).
    PeerTransport {
        /// Transport error code.
        code: u64,
        /// Frame type reported by the peer.
        frame_type: Option<u64>,
        /// Reason phrase.
        reason: Vec<u8>,
    },
    /// The peer sent an application CONNECTION_CLOSE (0x1d).
    PeerApplication {
        /// Application error code.
        code: u64,
        /// Reason phrase.
        reason: Vec<u8>,
    },
    /// No packet was received for the idle timeout.
    IdleTimeout,
    /// The server does not support QUIC v1 (Version Negotiation received).
    VersionNegotiation,
    /// The peer sent a stateless reset (RFC 9000 10.3): it lost the
    /// connection's state.
    StatelessReset,
}

/// Notifications for the application, from [`Connection::poll_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The TLS handshake completed; streams are usable.
    HandshakeCompleted,
    /// The peer opened a stream.
    StreamOpened(u64),
    /// Data, FIN or a reset is available to [`Connection::stream_read`].
    StreamReadable(u64),
    /// The peer sent STOP_SENDING; our send half was reset with this code.
    StreamStopped {
        /// Stream ID.
        id: u64,
        /// Application error code.
        error: u64,
    },
    /// The connection is closing or closed.
    Closed(CloseReason),
}

/// Connection counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// Packets sent.
    pub packets_sent: u64,
    /// Packets received and successfully processed.
    pub packets_received: u64,
    /// Packets declared lost.
    pub packets_lost: u64,
    /// Datagram bytes sent.
    pub bytes_sent: u64,
    /// Datagram bytes received.
    pub bytes_received: u64,
    /// Current congestion window.
    pub cwnd: u64,
    /// Smoothed RTT.
    pub srtt: Duration,
    /// Completed 1-RTT key updates (initiated by either side).
    pub key_updates: u64,
    /// Times the peer moved to a new address (we switched paths).
    pub migrations: u64,
    /// Paths validated by a PATH_RESPONSE (ours after a migration, or a
    /// probe sent with [`Connection::send_path_probe`]).
    pub paths_validated: u64,
    /// Path validations abandoned (timer expired without a response).
    pub path_validation_failures: u64,
    /// Path MTU probes sent.
    pub pmtu_probes_sent: u64,
    /// Path MTU probes that were not acknowledged in time (not counted in
    /// `packets_lost`: their loss is no congestion signal).
    pub pmtu_probes_lost: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Handshake,
    Established,
    Closing { until: Instant },
    Draining { until: Instant },
    Closed,
}

#[derive(Debug, Clone)]
struct TransportError {
    code: u64,
    frame_type: Option<u64>,
    reason: &'static str,
}

fn terr(code: u64, reason: &'static str) -> TransportError {
    TransportError {
        code,
        frame_type: None,
        reason,
    }
}

fn stream_err(e: StreamError) -> TransportError {
    match e {
        StreamError::FlowControl => terr(codes::FLOW_CONTROL_ERROR, "flow control"),
        StreamError::FinalSize => terr(codes::FINAL_SIZE_ERROR, "final size"),
    }
}

fn streams_err(e: StreamsError) -> TransportError {
    match e {
        StreamsError::StreamLimit => terr(codes::STREAM_LIMIT_ERROR, "stream limit"),
        StreamsError::StreamState | StreamsError::Blocked => {
            terr(codes::STREAM_STATE_ERROR, "stream state")
        }
    }
}

#[derive(Debug, Clone)]
enum CloseFrame {
    Transport {
        code: u64,
        frame_type: Option<u64>,
        reason: Vec<u8>,
    },
    Application {
        code: u64,
        reason: Vec<u8>,
    },
}

struct LevelKeys {
    local: Box<dyn PacketProtection>,
    remote: Box<dyn PacketProtection>,
}

/// 1-RTT packet (AEAD) keys across key updates (RFC 9001 6). Header
/// protection never changes and stays in the Data space's [`LevelKeys`].
struct OneRtt {
    secrets: rustls::quic::Secrets,
    /// Key phase bit of the current generation.
    phase: bool,
    local: Box<dyn PacketProtection>,
    remote: Box<dyn PacketProtection>,
    /// The next generation (local, remote), derived on first need.
    next: Option<(Box<dyn PacketProtection>, Box<dyn PacketProtection>)>,
    /// The previous remote key, kept until the instant given to open
    /// packets the peer sent before the update.
    prev_remote: Option<(Box<dyn PacketProtection>, Instant)>,
    /// Smallest packet number the peer sent with the current keys.
    first_recv_pn: Option<u64>,
    /// First packet number we sent with the current keys.
    first_sent_pn: Option<u64>,
    updates: u64,
}

impl OneRtt {
    fn new(keys: rustls::quic::Keys, secrets: rustls::quic::Secrets) -> (LevelKeys, Self) {
        let hp = LevelKeys {
            local: Box::new(HeaderOnly(keys.local.header)),
            remote: Box::new(HeaderOnly(keys.remote.header)),
        };
        let k = Self {
            secrets,
            phase: false,
            local: Box::new(PacketOnly(keys.local.packet)),
            remote: Box::new(PacketOnly(keys.remote.packet)),
            next: None,
            prev_remote: None,
            first_recv_pn: None,
            first_sent_pn: None,
            updates: 0,
        };
        (hp, k)
    }

    fn next_remote(&mut self) -> &dyn PacketProtection {
        let secrets = &mut self.secrets;
        let next = self.next.get_or_insert_with(|| {
            let k = secrets.next_packet_keys();
            (
                Box::new(PacketOnly(k.local)) as Box<dyn PacketProtection>,
                Box::new(PacketOnly(k.remote)) as Box<dyn PacketProtection>,
            )
        });
        &*next.1
    }

    /// Switches both directions to the next generation; the old remote key
    /// opens late packets until `keep_prev_until`.
    fn rotate(&mut self, keep_prev_until: Instant) {
        self.next_remote();
        let Some((local, remote)) = self.next.take() else {
            return;
        };
        let old = core::mem::replace(&mut self.remote, remote);
        self.local = local;
        self.prev_remote = Some((old, keep_prev_until));
        self.phase = !self.phase;
        self.first_recv_pn = None;
        self.first_sent_pn = None;
        self.updates += 1;
    }
}

struct SpaceState {
    keys: Option<LevelKeys>,
    pn: PacketNumberSpace,
    largest_acked: Option<u64>,
    crypto_send: SendStream,
    crypto_send_flow: ConnSendFlow,
    crypto_recv: RecvStream,
    crypto_recv_flow: ConnFlow,
    probes: u8,
}

impl SpaceState {
    fn new() -> Self {
        Self {
            keys: None,
            pn: PacketNumberSpace::default(),
            largest_acked: None,
            crypto_send: SendStream::new(UNLIMITED),
            crypto_send_flow: ConnSendFlow::new(UNLIMITED),
            crypto_recv: RecvStream::new(CRYPTO_WINDOW),
            crypto_recv_flow: ConnFlow::new(UNLIMITED),
            probes: 0,
        }
    }
}

/// A frame that must be retransmitted (with current values) if lost.
#[derive(Debug, Clone)]
enum Ctrl {
    MaxData,
    MaxStreamData(u64),
    MaxStreams(bool),
    ResetStream {
        id: u64,
        error: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        error: u64,
    },
    HandshakeDone,
    NewConnectionId(u64),
    RetireConnectionId(u64),
}

#[derive(Debug, Clone, Copy)]
struct StreamRange {
    id: u64,
    offset: u64,
    len: u64,
    fin: bool,
}

/// Retransmittable contents of a sent packet (the recovery payload).
#[derive(Debug, Default, Clone)]
struct Sent {
    crypto: Vec<(u64, u64)>,
    streams: Vec<StreamRange>,
    ctrl: Vec<Ctrl>,
}

impl Sent {
    fn is_empty(&self) -> bool {
        self.crypto.is_empty() && self.streams.is_empty() && self.ctrl.is_empty()
    }
}

#[derive(Debug, Default)]
struct Pending {
    max_data: bool,
    max_stream_data: BTreeSet<u64>,
    max_streams: [bool; 2],
    resets: Vec<(u64, u64, u64)>,
    stop_sending: Vec<(u64, u64)>,
    handshake_done: bool,
    path_responses: Vec<[u8; 8]>,
    new_cids: Vec<u64>,
    retire_cids: Vec<u64>,
    streams_blocked: Option<(bool, u64)>,
    // Last STREAMS_BLOCKED limit signalled per [bidi, uni] (once per limit).
    streams_blocked_signalled: [Option<u64>; 2],
}

impl Pending {
    fn any(&self) -> bool {
        self.max_data
            || !self.max_stream_data.is_empty()
            || self.max_streams.iter().any(|b| *b)
            || !self.resets.is_empty()
            || !self.stop_sending.is_empty()
            || self.handshake_done
            || !self.path_responses.is_empty()
            || !self.new_cids.is_empty()
            || !self.retire_cids.is_empty()
            || self.streams_blocked.is_some()
    }
}

/// The network path packets are sent on (RFC 9000 8.2, 9).
#[derive(Debug, Clone)]
struct Path {
    /// Peer address; `None` until the caller reports one.
    remote: Option<SocketAddr>,
    /// The peer proved it receives at this address. Until then we send at
    /// most three times what we received from it (RFC 9000 8, 9.3).
    validated: bool,
    recv: u64,
    sent: u64,
    /// Data of the PATH_CHALLENGEs sent on this path.
    challenges: Vec<[u8; 8]>,
    challenge_pending: bool,
    next_challenge: Option<Instant>,
    /// Validation is abandoned at this instant.
    deadline: Option<Instant>,
}

impl Path {
    fn new(remote: Option<SocketAddr>, validated: bool) -> Self {
        Self {
            remote,
            validated,
            recv: 0,
            sent: 0,
            challenges: Vec::new(),
            challenge_pending: false,
            next_challenge: None,
            deadline: None,
        }
    }

    /// Bytes we may still send before the path is validated.
    fn allowance(&self) -> Option<u64> {
        (!self.validated).then(|| (3 * self.recv).saturating_sub(self.sent))
    }
}

/// What a processed packet tells the migration logic.
#[derive(Debug, Clone, Copy)]
struct PacketInfo {
    space: Space,
    /// Highest packet number received in its space so far.
    newest: bool,
    /// Only PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID or PADDING
    /// (RFC 9000 9.1).
    probing: bool,
}

/// Lost probes of one size before the ceiling drops below it.
const PMTU_MAX_PROBES: u8 = 3;
/// The search stops once the ceiling is within this many bytes.
const PMTU_GRANULARITY: usize = 20;

/// Path MTU discovery, DPLPMTUD-lite (RFC 8899; RFC 9000 14.3): once the
/// handshake is confirmed, PING + PADDING probes; an acknowledged probe
/// raises the datagram size, three lost probes of one size lower the
/// ceiling below it, and the search bisects between the two. Probes are
/// not handed to congestion control: their loss is no congestion signal
/// (RFC 9000 14.4).
#[derive(Debug, Clone)]
struct Pmtud {
    /// Datagram size before discovery (again on a new path).
    base: usize,
    /// Largest size discovery may reach (ours and the peer's limit).
    max: usize,
    /// Largest size not yet known to be too big.
    ceiling: usize,
    /// Probing between the size and the ceiling (after the ceiling failed).
    bisect: bool,
    /// The probe in flight: packet number, size, when it counts as lost.
    probe: Option<(u64, usize, Instant)>,
    /// Lost probes of the current size.
    failures: u8,
}

impl Pmtud {
    fn new(base: usize, max: usize) -> Self {
        Self {
            base,
            max,
            ceiling: max,
            bisect: false,
            probe: None,
            failures: 0,
        }
    }

    /// Size of the next probe above `mtu`, or `None` once the search is over.
    fn next_size(&self, mtu: usize) -> Option<usize> {
        if self.ceiling < mtu + PMTU_GRANULARITY {
            return None;
        }
        Some(if self.bisect {
            mtu + (self.ceiling - mtu).div_ceil(2)
        } else {
            self.ceiling
        })
    }

    fn on_lost(&mut self, size: usize) {
        self.failures += 1;
        if self.failures >= PMTU_MAX_PROBES {
            self.ceiling = size.saturating_sub(1);
            self.failures = 0;
            self.bisect = true;
        }
    }
}

/// A packet whose plaintext is written but not yet sealed.
struct Building {
    space: Space,
    start: usize,
    pn_offset: usize,
    pn: u64,
    len_off: Option<usize>,
    payload_end: usize,
    ack_eliciting: bool,
    sent: Sent,
    /// A path MTU probe: not handed to loss recovery or congestion control.
    pmtu_probe: bool,
}

fn put(buf: &mut [u8], pos: &mut usize, end: usize, f: &Frame<'_>) -> bool {
    if *pos > end || end > buf.len() {
        return false;
    }
    let mut w = Writer::new(&mut buf[*pos..end]);
    if f.encode(&mut w).is_ok() {
        *pos += w.position();
        true
    } else {
        false
    }
}

fn random_cid() -> Result<Vec<u8>, ApiError> {
    let mut cid = vec![0u8; LOCAL_CID_LEN];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut cid)
        .map_err(|_| ApiError::Setup("random number generator failed".into()))?;
    Ok(cid)
}

fn random_challenge() -> [u8; 8] {
    let mut d = [0u8; 8];
    // A failing system RNG leaves zeros: the challenge is then guessable,
    // which only weakens path validation, never memory safety.
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut d);
    d
}

/// Makes sure `config` carries a reset key (random if the caller set none).
fn with_reset_key(mut config: TransportConfig) -> Result<(TransportConfig, ResetKey), ApiError> {
    let key = match config.reset_key.clone() {
        Some(k) => k,
        None => ResetKey::random()
            .ok_or_else(|| ApiError::Setup("random number generator failed".into()))?,
    };
    config.reset_key = Some(key.clone());
    Ok((config, key))
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A QUIC connection (client or server).
pub struct Connection {
    side: Side,
    tls: rustls::quic::Connection,
    config: TransportConfig,
    state: State,
    local_cid: Vec<u8>,
    remote_cid: Vec<u8>,
    remote_cid_set: bool,
    /// Destination CID of the client's first Initial (before any Retry).
    odcid: Vec<u8>,
    /// Destination CID the client's Initials use now: `odcid`, or the
    /// Source CID of the Retry. Initial keys derive from it.
    initial_dcid: Vec<u8>,
    /// Source CID of the Retry (client: the one processed; server: the one
    /// this connection was accepted after).
    retry_scid: Option<Vec<u8>>,
    /// Token from a Retry, carried in every later client Initial.
    initial_token: Vec<u8>,
    reset_key: ResetKey,
    local_cids: LocalCids,
    remote_cids: RemoteCids,
    path: Path,
    /// The last validated path, restored if validating a new one fails.
    prev_path: Option<Path>,
    /// Source address and size of the datagram being processed.
    rx_from: Option<SocketAddr>,
    rx_len: u64,
    /// Sequence number of our CID the packet being processed was sent to.
    rx_dcid_seq: Option<u64>,
    /// Sequence number of our CID the peer last sent non-probing packets to.
    peer_dcid_seq: u64,
    /// PATH_RESPONSEs owed to addresses other than the current path:
    /// (data, address, bytes received from it).
    off_path_responses: Vec<([u8; 8], SocketAddr, u64)>,
    /// PATH_CHALLENGE data of probes sent with `send_path_probe`.
    probes_sent: Vec<[u8; 8]>,
    /// The datagram being built carries a path frame: pad it to 1200 bytes.
    pad_datagram: bool,
    spaces: [SpaceState; 3],
    one_rtt: Option<OneRtt>,
    write_level: Space,
    recovery: Recovery<Sent>,
    streams: Option<Streams>,
    recv_flow: ConnFlow,
    send_flow: ConnSendFlow,
    peer_params: Option<TransportParams>,
    pending: Pending,
    events: VecDeque<Event>,
    readable: BTreeSet<u64>,
    recv_closed: BTreeSet<u64>,
    handshake_complete: bool,
    handshake_confirmed: bool,
    handshake_acked: bool,
    received_any: bool,
    pmtud: Pmtud,
    pacer: Pacer,
    /// Per space: the packet number from which the next PTO probe looks
    /// for data in flight to send again.
    probe_cursor: [u64; 3],
    /// Set when the pacer held data back: when to try again.
    pacing_until: Option<Instant>,
    address_validated: bool,
    idle_timeout: Option<Duration>,
    last_activity: Instant,
    sent_eliciting_since_recv: bool,
    mtu: usize,
    close_frame: Option<CloseFrame>,
    close_pending: bool,
    close_reason: Option<CloseReason>,
    next_rr: u64,
    stats: Stats,
}

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connection")
            .field("side", &self.side)
            .field("state", &self.state)
            .field("local_cid", &self.local_cid)
            .field("remote_cid", &self.remote_cids.current())
            .field("remote_addr", &self.path.remote)
            .finish_non_exhaustive()
    }
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        side: Side,
        tls: rustls::quic::Connection,
        config: TransportConfig,
        local_cid: Vec<u8>,
        remote_cid: Vec<u8>,
        odcid: Vec<u8>,
        initial_dcid: Vec<u8>,
        now: Instant,
    ) -> Result<Self, ApiError> {
        let initial = InitialKeys::initial(&initial_dcid, side)
            .map_err(|_| ApiError::Setup("initial keys".into()))?;
        let mut spaces = [SpaceState::new(), SpaceState::new(), SpaceState::new()];
        spaces[0].keys = Some(LevelKeys {
            local: Box::new(initial.local),
            remote: Box::new(initial.remote),
        });
        let mtu = config.max_datagram_size.clamp(MIN_INITIAL_SIZE, 16_000);
        let cc: Box<dyn CongestionController> = match config.congestion {
            Congestion::NewReno => Box::new(NewReno::new(mtu as u64)),
            Congestion::Cubic => Box::new(Cubic::new(mtu as u64)),
        };
        let idle = (!config.max_idle_timeout.is_zero()).then_some(config.max_idle_timeout);
        let (config, reset_key) = with_reset_key(config)?;
        let local_cids = LocalCids::new(local_cid.clone(), reset_key.token(&local_cid));
        let remote_cids =
            RemoteCids::new(remote_cid.clone(), config.active_connection_id_limit.max(2));
        Ok(Self {
            side,
            tls,
            recv_flow: ConnFlow::new(config.initial_max_data),
            config,
            state: State::Handshake,
            local_cid,
            remote_cid_set: side == Side::Server,
            remote_cid,
            retry_scid: (initial_dcid != odcid).then(|| initial_dcid.clone()),
            odcid,
            initial_dcid,
            initial_token: Vec::new(),
            reset_key,
            local_cids,
            remote_cids,
            path: Path::new(None, true),
            prev_path: None,
            rx_from: None,
            rx_len: 0,
            rx_dcid_seq: None,
            peer_dcid_seq: 0,
            off_path_responses: Vec::new(),
            probes_sent: Vec::new(),
            pad_datagram: false,
            spaces,
            one_rtt: None,
            write_level: Space::Initial,
            recovery: Recovery::new(cc, Duration::from_millis(25)),
            streams: None,
            send_flow: ConnSendFlow::new(0),
            peer_params: None,
            pending: Pending::default(),
            events: VecDeque::new(),
            readable: BTreeSet::new(),
            recv_closed: BTreeSet::new(),
            handshake_complete: false,
            handshake_confirmed: false,
            handshake_acked: false,
            received_any: false,
            pmtud: Pmtud::new(mtu, mtu),
            pacer: Pacer::new(),
            probe_cursor: [0; 3],
            pacing_until: None,
            address_validated: side == Side::Client,
            idle_timeout: idle,
            last_activity: now,
            sent_eliciting_since_recv: false,
            mtu,
            close_frame: None,
            close_pending: false,
            close_reason: None,
            next_rr: 0,
            stats: Stats::default(),
        })
    }

    fn local_params(
        side: Side,
        c: &TransportConfig,
        key: &ResetKey,
        local_cid: &[u8],
        odcid: &[u8],
        retry_scid: Option<&[u8]>,
    ) -> Result<Vec<u8>, ApiError> {
        let p = TransportParams {
            original_dcid: (side == Side::Server).then(|| odcid.to_vec()),
            retry_scid: retry_scid.map(<[u8]>::to_vec),
            stateless_reset_token: (side == Side::Server).then(|| key.token(local_cid)),
            active_connection_id_limit: c.active_connection_id_limit.max(2),
            max_idle_timeout: ms(c.max_idle_timeout),
            max_udp_payload_size: c
                .max_datagram_size
                .max(c.pmtu_max)
                .clamp(MIN_INITIAL_SIZE, 16_000) as u64,
            initial_max_data: c.initial_max_data,
            initial_max_stream_data_bidi_local: c.initial_max_stream_data,
            initial_max_stream_data_bidi_remote: c.initial_max_stream_data,
            initial_max_stream_data_uni: c.initial_max_stream_data,
            initial_max_streams_bidi: c.initial_max_streams_bidi,
            initial_max_streams_uni: c.initial_max_streams_uni,
            max_ack_delay: ms(c.max_ack_delay),
            initial_scid: Some(local_cid.to_vec()),
            ..TransportParams::default()
        };
        let mut out = Vec::new();
        p.encode(&mut out)
            .map_err(|_| ApiError::Setup("transport parameters".into()))?;
        Ok(out)
    }

    /// Starts a client connection to `server_name` (used for SNI and
    /// certificate verification). The first [`Connection::send`] yields the
    /// client Initial; the caller's buffer must hold at least 1200 bytes.
    pub fn connect(
        tls: Arc<rustls::ClientConfig>,
        server_name: &str,
        config: TransportConfig,
        now: Instant,
    ) -> Result<Self, ApiError> {
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|_| ApiError::Setup("invalid server name".into()))?;
        let local_cid = random_cid()?;
        let odcid = random_cid()?;
        let (config, key) = with_reset_key(config)?;
        let params = Self::local_params(Side::Client, &config, &key, &local_cid, &odcid, None)?;
        let session =
            rustls::quic::ClientConnection::new(tls, rustls::quic::Version::V1, name, params)
                .map_err(|e| ApiError::Setup(e.to_string()))?;
        let mut conn = Self::new(
            Side::Client,
            session.into(),
            config,
            local_cid,
            odcid.clone(),
            odcid.clone(),
            odcid,
            now,
        )?;
        conn.drive_tls()
            .map_err(|e| ApiError::Setup(e.reason.into()))?;
        Ok(conn)
    }

    /// Creates a server connection from a client's first datagram, which
    /// must then be passed to [`Connection::recv`]. Endpoints route later
    /// datagrams by [`Connection::local_cid`] (and, for the client's
    /// retransmitted Initials, [`Connection::original_dcid`]).
    pub fn accept(
        tls: Arc<rustls::ServerConfig>,
        config: TransportConfig,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Self, ApiError> {
        Self::accept_inner(tls, config, datagram, None, now)
    }

    /// Like [`Connection::accept`], for a client Initial that carried a
    /// valid Retry token: `odcid` is the Destination CID of the client's
    /// first Initial (from the token); the Destination CID of this Initial
    /// is the Retry's Source CID. Both go into the transport parameters
    /// (RFC 9000 7.3), and the client's address counts as validated (no
    /// amplification limit).
    pub fn accept_retried(
        tls: Arc<rustls::ServerConfig>,
        config: TransportConfig,
        datagram: &[u8],
        odcid: &[u8],
        now: Instant,
    ) -> Result<Self, ApiError> {
        Self::accept_inner(tls, config, datagram, Some(odcid), now)
    }

    fn accept_inner(
        tls: Arc<rustls::ServerConfig>,
        config: TransportConfig,
        datagram: &[u8],
        retried: Option<&[u8]>,
        now: Instant,
    ) -> Result<Self, ApiError> {
        if datagram.len() < MIN_INITIAL_SIZE {
            return Err(ApiError::InvalidInitial);
        }
        let h = Header::parse(datagram, LOCAL_CID_LEN).map_err(|_| ApiError::InvalidInitial)?;
        if h.ty != PacketType::Initial || h.dcid.len() < 8 {
            return Err(ApiError::InvalidInitial);
        }
        let initial_dcid = h.dcid.to_vec();
        let odcid = retried.map_or_else(|| initial_dcid.clone(), <[u8]>::to_vec);
        let remote = h.scid.to_vec();
        let local_cid = random_cid()?;
        let (config, key) = with_reset_key(config)?;
        let retry_scid = retried.is_some().then_some(h.dcid);
        let params =
            Self::local_params(Side::Server, &config, &key, &local_cid, &odcid, retry_scid)?;
        let session = rustls::quic::ServerConnection::new(tls, rustls::quic::Version::V1, params)
            .map_err(|e| ApiError::Setup(e.to_string()))?;
        let mut conn = Self::new(
            Side::Server,
            session.into(),
            config,
            local_cid,
            remote,
            odcid,
            initial_dcid,
            now,
        )?;
        conn.address_validated |= retried.is_some();
        Ok(conn)
    }

    // ----- accessors -------------------------------------------------------

    /// Which side we are.
    pub fn side(&self) -> Side {
        self.side
    }
    /// The connection ID the peer uses to reach us.
    pub fn local_cid(&self) -> &[u8] {
        &self.local_cid
    }
    /// The Destination CID of the client's first Initial.
    pub fn original_dcid(&self) -> &[u8] {
        &self.odcid
    }
    /// The Destination CID the client's Initials carry now: the original
    /// one, or after a Retry the Retry's Source CID. A server endpoint routes
    /// it so retransmitted client Initials reach this connection.
    pub fn initial_dcid(&self) -> &[u8] {
        &self.initial_dcid
    }
    /// Whether a Retry was part of the handshake (client: one was
    /// processed; server: accepted with [`Connection::accept_retried`]).
    pub fn retried(&self) -> bool {
        self.retry_scid.is_some()
    }
    /// Every CID we issued that the peer has not retired (the handshake
    /// CID included until retired). Endpoints route datagrams carrying any
    /// of them to this connection.
    pub fn local_cids(&self) -> Vec<Vec<u8>> {
        self.local_cids.cids().map(<[u8]>::to_vec).collect()
    }
    /// Changes whenever [`Connection::local_cids`] changes.
    pub fn local_cids_generation(&self) -> u64 {
        self.local_cids.generation()
    }
    /// The CID our packets carry as Destination CID.
    pub fn remote_cid(&self) -> &[u8] {
        self.remote_cids.current()
    }
    /// Unused CIDs from the peer, available to [`Connection::switch_remote_cid`].
    pub fn spare_remote_cids(&self) -> usize {
        self.remote_cids.spares()
    }
    /// Whether `datagram` ends with the stateless reset token of the peer
    /// CID in use (RFC 9000 10.3.1; compared in constant time). An endpoint
    /// that cannot route a datagram asks its connections this and hands the
    /// datagram to the one that matches; [`Connection::recv_from`] then
    /// ends the connection if nothing in it decrypts.
    pub fn is_stateless_reset(&self, datagram: &[u8]) -> bool {
        if datagram.len() < MIN_RESET_LEN {
            return false;
        }
        let (Some(tail), Some(token)) = (
            datagram.get(datagram.len() - RESET_TOKEN_LEN..),
            self.remote_cids.current_token(),
        ) else {
            return false;
        };
        token.iter().zip(tail).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
    }
    /// The peer address of the current path (as reported to
    /// [`Connection::recv_from`]), if known.
    pub fn remote_address(&self) -> Option<SocketAddr> {
        self.path.remote
    }
    /// Whether the current path is validated (always true until the peer
    /// moves to a new address).
    pub fn path_validated(&self) -> bool {
        self.path.validated
    }
    /// Switches our packets to an unused CID from the peer and retires the
    /// old one (RETIRE_CONNECTION_ID). A client does this before it moves
    /// to a new local address, so the paths cannot be linked by CID
    /// (RFC 9000 9.5).
    pub fn switch_remote_cid(&mut self) -> Result<(), ApiError> {
        if self.is_closing() {
            return Err(ApiError::Closed);
        }
        if !self.handshake_confirmed {
            return Err(ApiError::NotEstablished);
        }
        let old = self
            .remote_cids
            .switch()
            .ok_or(ApiError::NoSpareConnectionId)?;
        self.pending.retire_cids.push(old);
        Ok(())
    }
    /// Whether the TLS handshake completed.
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }
    /// Whether the handshake is confirmed (RFC 9001 4.1.2).
    pub fn is_handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }
    /// Whether the connection reached its terminal state.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }
    /// Whether the connection is closing, draining or closed.
    pub fn is_closing(&self) -> bool {
        matches!(
            self.state,
            State::Closing { .. } | State::Draining { .. } | State::Closed
        )
    }
    /// Why the connection closed, once it has.
    pub fn close_reason(&self) -> Option<&CloseReason> {
        self.close_reason.as_ref()
    }
    /// The peer's transport parameters, once received.
    pub fn peer_params(&self) -> Option<&TransportParams> {
        self.peer_params.as_ref()
    }
    /// The negotiated ALPN protocol.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.tls.alpn_protocol()
    }
    /// Counters.
    /// The UDP payload size in use: `max_datagram_size` (or the peer's
    /// limit), raised by path MTU discovery.
    pub fn max_datagram_size(&self) -> usize {
        self.mtu
    }
    /// Statistics.
    pub fn stats(&self) -> Stats {
        Stats {
            cwnd: self.recovery.window(),
            srtt: self.recovery.loss.rtt.smoothed(),
            key_updates: self.one_rtt.as_ref().map_or(0, |k| k.updates),
            ..self.stats.clone()
        }
    }
    /// Next application event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events
            .pop_front()
            .or_else(|| self.readable.pop_first().map(Event::StreamReadable))
    }

    fn pto(&self) -> Duration {
        let mad = self
            .peer_params
            .as_ref()
            .map_or(Duration::from_millis(25), |p| {
                Duration::from_millis(p.max_ack_delay)
            });
        self.recovery.loss.rtt.pto(mad)
    }

    fn idle_deadline(&self) -> Option<Instant> {
        self.idle_timeout
            .map(|t| self.last_activity + t.max(3 * self.pto()))
    }

    // ----- timers ------------------------------------------------------------

    /// The next instant at which [`Connection::on_timeout`] must be called.
    pub fn timeout(&self) -> Option<Instant> {
        match self.state {
            State::Closed => None,
            State::Closing { until } | State::Draining { until } => Some(until),
            State::Handshake | State::Established => {
                let mut t = self.idle_deadline();
                let mut consider = |x: Option<Instant>| {
                    if let Some(x) = x {
                        t = Some(t.map_or(x, |t| t.min(x)));
                    }
                };
                consider(self.recovery.loss.timeout().map(|x| x.0));
                consider(self.path.deadline);
                consider(self.path.next_challenge.filter(|_| !self.path.validated));
                consider(self.pmtud.probe.map(|p| p.2));
                consider(self.pacing_until);
                for sp in SPACES {
                    let s = &self.spaces[sp as usize];
                    if s.keys.is_some() {
                        consider(s.pn.ack_deadline(self.config.max_ack_delay, sp != Space::Data));
                    }
                }
                t
            }
        }
    }

    /// Handles expired timers (idle, loss detection, PTO, close/drain).
    pub fn on_timeout(&mut self, now: Instant) {
        match self.state {
            State::Closed => return,
            State::Closing { until } | State::Draining { until } => {
                if now >= until {
                    self.state = State::Closed;
                }
                return;
            }
            State::Handshake | State::Established => {}
        }
        if self.idle_deadline().is_some_and(|d| now >= d) {
            self.state = State::Closed;
            self.set_close_reason(CloseReason::IdleTimeout);
            return;
        }
        if self.path.deadline.is_some_and(|d| now >= d) {
            // Validation failed (RFC 9000 8.2.4, 9.3.2): go back to the last
            // validated path, or stay (still amplification-limited).
            self.stats.path_validation_failures += 1;
            match self.prev_path.take() {
                Some(prev) => self.path = prev,
                None => {
                    self.path.challenges.clear();
                    self.path.challenge_pending = false;
                    self.path.next_challenge = None;
                    self.path.deadline = None;
                }
            }
        } else if !self.path.validated && self.path.next_challenge.is_some_and(|t| now >= t) {
            self.path.challenge_pending = true;
            self.path.next_challenge = None;
        }
        if let Some((_, size, deadline)) = self.pmtud.probe {
            if now >= deadline {
                self.pmtud.probe = None;
                self.pmtud.on_lost(size);
                self.stats.pmtu_probes_lost += 1;
            }
        }
        if let Some((deadline, space)) = self.recovery.loss.timeout() {
            if now >= deadline {
                match self.recovery.loss.on_timeout(now) {
                    TimerAction::Lost(lost) => {
                        self.recovery.on_lost(&lost, now);
                        for (_, p) in lost {
                            self.on_packet_lost(space, p.payload);
                        }
                    }
                    TimerAction::Probe(sp) => {
                        self.spaces[sp as usize].probes = 2;
                        self.requeue_for_probe(sp);
                    }
                    TimerAction::None => {}
                }
            }
        }
        self.update_anti_deadlock();
    }

    fn update_anti_deadlock(&mut self) {
        let arm = (self.side == Side::Client && !self.handshake_confirmed && !self.handshake_acked)
            .then(|| {
                if self.spaces[Space::Handshake as usize].keys.is_some() {
                    Space::Handshake
                } else {
                    Space::Initial
                }
            });
        self.recovery.loss.set_anti_deadlock(arm);
    }

    // ----- closing -------------------------------------------------------------

    fn set_close_reason(&mut self, r: CloseReason) {
        if self.close_reason.is_none() {
            self.close_reason = Some(r.clone());
            self.events.push_back(Event::Closed(r));
        }
    }

    fn enter_closing(&mut self, frame: CloseFrame, reason: CloseReason, now: Instant) {
        if self.is_closing() {
            return;
        }
        self.close_frame = Some(frame);
        self.close_pending = true;
        self.state = State::Closing {
            until: now + 3 * self.pto(),
        };
        self.set_close_reason(reason);
    }

    fn close_with(&mut self, e: TransportError, now: Instant) {
        self.enter_closing(
            CloseFrame::Transport {
                code: e.code,
                frame_type: e.frame_type,
                reason: e.reason.as_bytes().to_vec(),
            },
            CloseReason::LocalTransport {
                code: e.code,
                frame_type: e.frame_type,
                reason: e.reason.into(),
            },
            now,
        );
    }

    /// Closes the connection with an application error code: sends
    /// CONNECTION_CLOSE and enters the closing state for three PTOs.
    pub fn close(&mut self, code: u64, reason: &[u8], now: Instant) {
        self.enter_closing(
            CloseFrame::Application {
                code,
                reason: reason.to_vec(),
            },
            CloseReason::LocalApplication {
                code,
                reason: reason.to_vec(),
            },
            now,
        );
    }

    // ----- TLS -------------------------------------------------------------------

    fn install(&mut self, space: Space, keys: rustls::quic::Keys) {
        self.spaces[space as usize].keys = Some(LevelKeys {
            local: Box::new(TlsKeys(keys.local)),
            remote: Box::new(TlsKeys(keys.remote)),
        });
    }

    fn drive_tls(&mut self) -> Result<(), TransportError> {
        loop {
            let mut buf = Vec::new();
            let change = self.tls.write_hs(&mut buf);
            if !buf.is_empty() {
                // Bytes written before a key change belong to the old level.
                let sp = &mut self.spaces[self.write_level as usize];
                sp.crypto_send
                    .write(&buf, false)
                    .map_err(|_| terr(codes::INTERNAL_ERROR, "crypto buffer"))?;
            }
            match change {
                None => break,
                Some(rustls::quic::KeyChange::Handshake { keys }) => {
                    self.install(Space::Handshake, keys);
                    self.write_level = Space::Handshake;
                }
                Some(rustls::quic::KeyChange::OneRtt { keys, next }) => {
                    let (hp, packet_keys) = OneRtt::new(keys, next);
                    self.spaces[Space::Data as usize].keys = Some(hp);
                    self.one_rtt = Some(packet_keys);
                    self.write_level = Space::Data;
                }
            }
        }
        // A resuming client gets the *remembered* server parameters from
        // rustls before the handshake (for 0-RTT); only the ones from this
        // handshake's EncryptedExtensions count, which are in place once the
        // 1-RTT keys (derived after the server's Finished) are.
        let params_ready =
            self.side == Side::Server || self.spaces[Space::Data as usize].keys.is_some();
        if self.peer_params.is_none() && params_ready {
            if let Some(raw) = self.tls.quic_transport_parameters() {
                let raw = raw.to_vec();
                self.apply_peer_params(&raw)?;
            }
        }
        if !self.handshake_complete && !self.tls.is_handshaking() {
            if self.peer_params.is_none() {
                return Err(terr(
                    codes::TRANSPORT_PARAMETER_ERROR,
                    "missing transport parameters",
                ));
            }
            self.handshake_complete = true;
            if self.state == State::Handshake {
                self.state = State::Established;
            }
            self.events.push_back(Event::HandshakeCompleted);
            if self.side == Side::Server {
                self.pending.handshake_done = true;
                self.confirm_handshake();
            }
            self.top_up_cids();
        }
        Ok(())
    }

    fn apply_peer_params(&mut self, raw: &[u8]) -> Result<(), TransportError> {
        let bad = |r| terr(codes::TRANSPORT_PARAMETER_ERROR, r);
        let p = TransportParams::decode(raw).map_err(|_| bad("malformed"))?;
        if p.initial_scid.as_deref() != Some(&self.remote_cid[..]) {
            return Err(bad("initial_source_connection_id mismatch"));
        }
        match self.side {
            Side::Client => {
                if p.original_dcid.as_deref() != Some(&self.odcid[..]) {
                    return Err(bad("original_destination_connection_id mismatch"));
                }
                // RFC 9000 7.3: present exactly when a Retry was processed.
                if p.retry_scid != self.retry_scid {
                    return Err(bad("retry_source_connection_id mismatch"));
                }
            }
            Side::Server => {
                if p.original_dcid.is_some()
                    || p.retry_scid.is_some()
                    || p.stateless_reset_token.is_some()
                {
                    return Err(bad("server-only parameter from client"));
                }
            }
        }
        let local = self.config.max_idle_timeout;
        let peer = Duration::from_millis(p.max_idle_timeout);
        self.idle_timeout = match (local.is_zero(), peer.is_zero()) {
            (true, true) => None,
            (true, false) => Some(peer),
            (false, true) => Some(local),
            (false, false) => Some(local.min(peer)),
        };
        self.recovery
            .set_max_ack_delay(Duration::from_millis(p.max_ack_delay));
        if let Some(t) = p.stateless_reset_token {
            self.remote_cids.set_handshake_token(t);
        }
        self.send_flow = ConnSendFlow::new(p.initial_max_data);
        let peer_max = usize::try_from(p.max_udp_payload_size).unwrap_or(usize::MAX);
        self.mtu = self.mtu.min(peer_max).max(MIN_INITIAL_SIZE);
        let pmtu_max = self.config.pmtu_max.min(16_000).min(peer_max).max(self.mtu);
        self.pmtud = Pmtud::new(self.mtu, pmtu_max);
        let c = &self.config;
        self.streams = Some(Streams::new(
            self.side,
            [c.initial_max_streams_bidi, c.initial_max_streams_uni],
            [p.initial_max_streams_bidi, p.initial_max_streams_uni],
            Windows {
                local_recv: c.initial_max_stream_data,
                peer_for_local: p.initial_max_stream_data_bidi_remote,
                peer_for_remote: p.initial_max_stream_data_bidi_local,
                peer_uni: p.initial_max_stream_data_uni,
            },
        ));
        self.peer_params = Some(p);
        Ok(())
    }

    /// Issues CIDs with NEW_CONNECTION_ID until the peer holds as many as
    /// its active_connection_id_limit allows (at most [`MAX_ISSUED_CIDS`]).
    fn top_up_cids(&mut self) {
        let Some(limit) = self
            .peer_params
            .as_ref()
            .map(|p| p.active_connection_id_limit)
        else {
            return;
        };
        let target = limit.min(MAX_ISSUED_CIDS);
        while (self.local_cids.len() as u64) < target {
            let Ok(cid) = random_cid() else {
                return;
            };
            if self.local_cids.seq_of(&cid).is_some() {
                continue;
            }
            let token = self.reset_key.token(&cid);
            let seq = self.local_cids.issue(cid, token);
            self.pending.new_cids.push(seq);
        }
    }

    fn discard_space(&mut self, space: Space) {
        let s = &mut self.spaces[space as usize];
        if s.keys.is_none() {
            return;
        }
        *s = SpaceState::new();
        self.recovery.loss.discard_space(space);
    }

    fn confirm_handshake(&mut self) {
        if self.handshake_confirmed {
            return;
        }
        self.handshake_confirmed = true;
        self.recovery.loss.set_handshake_confirmed();
        self.discard_space(Space::Handshake);
        self.update_anti_deadlock();
    }

    // ----- receive ---------------------------------------------------------------

    /// Processes one received UDP datagram (possibly several coalesced
    /// packets) on the current path. Undecryptable or unexpected packets are
    /// dropped; protocol violations close the connection.
    pub fn recv(&mut self, datagram: &mut [u8], now: Instant) {
        self.recv_inner(datagram, None, now);
    }

    /// Like [`Connection::recv`], for a datagram from `from`. The first
    /// address reported becomes the path. Later, a server that receives
    /// its highest-numbered non-probing packet from another address
    /// migrates there (RFC 9000 9.3): it validates the new path with
    /// PATH_CHALLENGE, sends at most three times what it received there
    /// until then, resets congestion control and RTT unless only the port
    /// changed, and returns to the old path if validation fails. Probing
    /// packets from another address are answered there without migrating.
    /// A client drops datagrams that do not come from the server's address,
    /// and a server drops other-address datagrams before the handshake is
    /// confirmed.
    pub fn recv_from(&mut self, datagram: &mut [u8], from: SocketAddr, now: Instant) {
        self.recv_inner(datagram, Some(from), now);
    }

    fn recv_inner(&mut self, datagram: &mut [u8], from: Option<SocketAddr>, now: Instant) {
        if matches!(self.state, State::Closed | State::Draining { .. }) {
            return;
        }
        // Decryption works in place: keep what a stateless reset check needs.
        let reset = self.is_stateless_reset(datagram);
        let processed = self.stats.packets_received;
        if self.path.remote.is_none() {
            self.path.remote = from;
        }
        let other_addr = from.is_some() && from != self.path.remote;
        if other_addr && (self.side == Side::Client || !self.handshake_confirmed) {
            return;
        }
        self.stats.bytes_received += datagram.len() as u64;
        if !other_addr {
            self.path.recv += datagram.len() as u64;
        }
        self.rx_from = from;
        self.rx_len = datagram.len() as u64;
        let migrate = self.recv_packets(datagram, now);
        self.rx_from = None;
        if reset && self.stats.packets_received == processed && !self.is_closing() {
            // RFC 9000 10.3.1: nothing in the datagram could be processed and
            // it ends with a token of the peer's: drain, send nothing more.
            self.state = State::Draining {
                until: now + 3 * self.pto(),
            };
            self.set_close_reason(CloseReason::StatelessReset);
            return;
        }
        if let (true, Some(addr), true) = (other_addr, from, migrate) {
            if !self.is_closing() {
                self.migrate(addr, datagram.len() as u64, now);
            }
        }
        self.update_anti_deadlock();
    }

    /// Switches the current path to `to` after a non-probing packet from
    /// there (RFC 9000 9.3, 9.4, 9.5).
    fn migrate(&mut self, to: SocketAddr, received: u64, now: Instant) {
        let mut new = Path::new(Some(to), false);
        new.recv = received;
        let old = core::mem::replace(&mut self.path, new);
        let same_host = old.remote.map(|a| a.ip()) == Some(to.ip());
        if old.validated {
            self.prev_path = Some(old);
        }
        if !same_host {
            // A new network path: its capacity, RTT and MTU are unknown.
            self.mtu = self.pmtud.base;
            self.pmtud = Pmtud::new(self.pmtud.base, self.pmtud.max);
            self.pacer = Pacer::new();
            let cc: Box<dyn CongestionController> = match self.config.congestion {
                Congestion::NewReno => Box::new(NewReno::new(self.mtu as u64)),
                Congestion::Cubic => Box::new(Cubic::new(self.mtu as u64)),
            };
            self.recovery.reset_for_new_path(cc);
        }
        // The peer moved to a new CID of ours: do not link the paths by
        // using our old CID for it either.
        if let Some(seq) = self.rx_dcid_seq {
            if seq != self.peer_dcid_seq {
                self.peer_dcid_seq = seq;
                if let Some(old) = self.remote_cids.switch() {
                    self.pending.retire_cids.push(old);
                }
            }
        }
        self.path.challenge_pending = true;
        let pto = self.pto().max(6 * skiff_recovery::INITIAL_RTT);
        self.path.deadline = Some(now + 3 * pto);
        self.stats.migrations += 1;
    }

    /// Handles the packets of one datagram; returns whether one of them
    /// was the highest-numbered non-probing 1-RTT packet so far.
    fn recv_packets(&mut self, datagram: &mut [u8], now: Instant) -> bool {
        let mut migrate = false;
        if let State::Closing { .. } = self.state {
            // RFC 9000 10.2.1: answer incoming packets with CONNECTION_CLOSE.
            self.close_pending = true;
            return false;
        }
        let total = datagram.len();
        let mut off = 0;
        while off < total {
            let Some(rest) = datagram.get_mut(off..) else {
                break;
            };
            let (ty, pn_offset, packet_len, dcid_ok, scid, versions) =
                match Header::parse(rest, LOCAL_CID_LEN) {
                    Ok(h) => {
                        self.rx_dcid_seq = self.local_cids.seq_of(h.dcid);
                        let dcid_ok = self.rx_dcid_seq.is_some()
                            || (self.side == Side::Server
                                && h.ty == PacketType::Initial
                                && h.dcid == self.initial_dcid.as_slice());
                        // Version list (VN) or token (Retry).
                        let versions =
                            matches!(h.ty, PacketType::VersionNegotiation | PacketType::Retry)
                                .then(|| h.token.to_vec());
                        (
                            h.ty,
                            h.pn_offset,
                            h.packet_len,
                            dcid_ok,
                            h.scid.to_vec(),
                            versions,
                        )
                    }
                    Err(_) => break,
                };
            if self.side == Side::Server && ty == PacketType::Initial && total < MIN_INITIAL_SIZE {
                // RFC 9000 14.1: drop undersized datagrams carrying Initials.
                return false;
            }
            off += packet_len;
            if !dcid_ok {
                continue;
            }
            if let Some(v) = versions {
                if ty == PacketType::Retry {
                    self.on_retry(rest, scid, v);
                } else {
                    self.on_version_negotiation(&v);
                }
                return false;
            }
            let Some(pkt) = rest.get_mut(..packet_len) else {
                break;
            };
            match self.recv_packet(ty, pkt, pn_offset, scid, now) {
                Err(e) => {
                    self.close_with(e, now);
                    return false;
                }
                Ok(Some(i)) if i.space == Space::Data && i.newest && !i.probing => migrate = true,
                Ok(_) => {}
            }
            if self.state == State::Closed || matches!(self.state, State::Draining { .. }) {
                return false;
            }
        }
        migrate
    }

    /// A Retry (RFC 9000 17.2.5.2): accepted once, before any packet from
    /// the server was processed, from a Source CID other than the original
    /// Destination CID, with a non-empty token and a valid integrity tag. The client then sends its Initials to the Retry's
    /// Source CID under keys derived from it, carrying the token, and resends
    /// the ClientHello. Packet numbers continue; congestion control and loss
    /// recovery start over (RFC 9002 6.3).
    fn on_retry(&mut self, packet: &[u8], scid: Vec<u8>, token: Vec<u8>) {
        if self.side != Side::Client
            || self.state != State::Handshake
            || self.received_any
            || self.retry_scid.is_some()
            || token.is_empty()
            || scid == self.odcid
            || !crate::retry::verify_retry(&self.odcid, packet)
        {
            return;
        }
        let Ok(keys) = InitialKeys::initial(&scid, Side::Client) else {
            return;
        };
        self.spaces[Space::Initial as usize].keys = Some(LevelKeys {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        });
        self.remote_cids.set_handshake_cid(scid.clone());
        self.remote_cid = scid.clone();
        self.initial_dcid = scid.clone();
        self.retry_scid = Some(scid);
        self.initial_token = token;
        let cc: Box<dyn CongestionController> = match self.config.congestion {
            Congestion::NewReno => Box::new(NewReno::new(self.mtu as u64)),
            Congestion::Cubic => Box::new(Cubic::new(self.mtu as u64)),
        };
        self.recovery.reset_for_new_path(cc);
        for (_, p) in self.recovery.loss.take_space(Space::Initial) {
            self.on_packet_lost(Space::Initial, p.payload);
        }
        self.update_anti_deadlock();
    }

    fn on_version_negotiation(&mut self, versions: &[u8]) {
        if self.side != Side::Client || self.received_any || self.state != State::Handshake {
            return;
        }
        let ours = versions
            .chunks_exact(4)
            .any(|c| c == VERSION_1.to_be_bytes().as_slice());
        if !ours {
            self.state = State::Closed;
            self.set_close_reason(CloseReason::VersionNegotiation);
        }
    }

    fn recv_packet(
        &mut self,
        ty: PacketType,
        pkt: &mut [u8],
        pn_offset: usize,
        scid: Vec<u8>,
        now: Instant,
    ) -> Result<Option<PacketInfo>, TransportError> {
        let space = match ty {
            PacketType::Initial => Space::Initial,
            PacketType::Handshake => Space::Handshake,
            PacketType::Short => Space::Data,
            // No 0-RTT or Retry support: drop.
            _ => return Ok(None),
        };
        if space == Space::Data && self.side == Side::Server && !self.handshake_complete {
            // RFC 9001 5.7: no 1-RTT processing before the handshake completes.
            return Ok(None);
        }
        let si = space as usize;
        let largest = self.spaces[si].pn.largest_received();
        let opened = if space == Space::Data {
            match self.open_one_rtt(pkt, pn_offset, largest, now) {
                Some(o) => o,
                None => return Ok(None),
            }
        } else {
            let Some(keys) = self.spaces[si].keys.as_ref() else {
                return Ok(None);
            };
            match packet::unprotect(keys.remote.as_ref(), pkt, pn_offset, largest) {
                Ok(o) => o,
                Err(_) => return Ok(None),
            }
        };
        let first = pkt.first().copied().unwrap_or(0);
        let reserved = if first & 0x80 != 0 { 0x0c } else { 0x18 };
        if first & reserved != 0 {
            return Err(terr(codes::PROTOCOL_VIOLATION, "reserved bits set"));
        }
        if self.spaces[si].pn.is_duplicate(opened.pn) {
            return Ok(None);
        }
        self.received_any = true;
        self.stats.packets_received += 1;
        if self.side == Side::Client && space == Space::Initial && !self.remote_cid_set {
            self.remote_cids.set_handshake_cid(scid.clone());
            self.remote_cid = scid;
            self.remote_cid_set = true;
        }
        if self.side == Side::Server && space == Space::Handshake && !self.address_validated {
            // RFC 9000 8.1 / RFC 9001 4.9.1.
            self.address_validated = true;
            self.discard_space(Space::Initial);
        }
        let end = opened.payload_offset + opened.payload_len;
        let payload = pkt
            .get(opened.payload_offset..end)
            .ok_or_else(|| terr(codes::INTERNAL_ERROR, "payload bounds"))?;
        if payload.is_empty() {
            return Err(terr(codes::PROTOCOL_VIOLATION, "empty packet"));
        }
        let mut ack_eliciting = false;
        let mut probing = true;
        for f in frame::parse_all(payload) {
            let f = f.map_err(|e| match e {
                skiff_wire::WireError::InvalidFrame(t) => TransportError {
                    code: codes::FRAME_ENCODING_ERROR,
                    frame_type: Some(t),
                    reason: "malformed frame",
                },
                _ => terr(codes::FRAME_ENCODING_ERROR, "malformed frame"),
            })?;
            if space != Space::Data
                && !matches!(
                    f,
                    Frame::Padding { .. }
                        | Frame::Ping
                        | Frame::Ack { .. }
                        | Frame::Crypto { .. }
                        | Frame::ConnectionClose {
                            frame_type: Some(_),
                            ..
                        }
                )
            {
                return Err(terr(codes::PROTOCOL_VIOLATION, "frame not allowed here"));
            }
            ack_eliciting |= f.ack_eliciting();
            probing &= matches!(
                f,
                Frame::Padding { .. }
                    | Frame::PathChallenge(_)
                    | Frame::PathResponse(_)
                    | Frame::NewConnectionId { .. }
            );
            self.on_frame(space, f, now)?;
            if self.is_closing() {
                return Ok(None);
            }
            if self.spaces[si].keys.is_none() {
                // The space was discarded by this very packet (e.g. the
                // server completing the handshake on the client's
                // Finished); its remaining frames (typically an ACK of our
                // discarded Handshake packets) no longer apply.
                break;
            }
        }
        // The space may have been discarded while processing (e.g. a
        // client confirming the handshake); recording then is harmless.
        self.spaces[si]
            .pn
            .on_packet_received(opened.pn, ack_eliciting, now);
        self.last_activity = now;
        self.sent_eliciting_since_recv = false;
        Ok(Some(PacketInfo {
            space,
            newest: largest.map_or(true, |l| opened.pn > l),
            probing,
        }))
    }

    /// Opens a 1-RTT packet with the packet key its key phase bit selects
    /// (RFC 9001 6.3/6.5): the current key; the previous key for packets
    /// numbered below the first one of the current phase; otherwise the next
    /// key, whose success means the peer started a key update, which we
    /// follow at once for both directions.
    fn open_one_rtt(
        &mut self,
        pkt: &mut [u8],
        pn_offset: usize,
        largest: Option<u64>,
        now: Instant,
    ) -> Option<packet::Opened> {
        let keep_prev_until = now + 3 * self.pto();
        let Self {
            spaces, one_rtt, ..
        } = self;
        let hp = spaces[Space::Data as usize].keys.as_ref()?;
        let k = one_rtt.as_mut()?;
        if k.prev_remote
            .as_ref()
            .is_some_and(|(_, until)| now >= *until)
        {
            k.prev_remote = None;
        }
        let (pn, hdr_len) =
            packet::remove_header_protection(hp.remote.as_ref(), pkt, pn_offset, largest).ok()?;
        let phase = pkt.first()? & 0x04 != 0;
        if phase == k.phase {
            let o = packet::open_payload(k.remote.as_ref(), pkt, hdr_len, pn).ok()?;
            k.first_recv_pn = Some(k.first_recv_pn.map_or(pn, |f| f.min(pn)));
            return Some(o);
        }
        if let Some((prev, _)) = k.prev_remote.as_ref() {
            if k.first_recv_pn.map_or(true, |f| pn < f) {
                return packet::open_payload(prev.as_ref(), pkt, hdr_len, pn).ok();
            }
        }
        let o = packet::open_payload(k.next_remote(), pkt, hdr_len, pn).ok()?;
        k.rotate(keep_prev_until);
        k.first_recv_pn = Some(pn);
        Some(o)
    }

    /// Starts a 1-RTT key update (RFC 9001 6.1): later packets use the next
    /// key generation and flip the key phase bit. Allowed once the handshake
    /// is confirmed and a packet sent with the current keys was acknowledged.
    pub fn initiate_key_update(&mut self, now: Instant) -> Result<(), ApiError> {
        if self.is_closing() {
            return Err(ApiError::Closed);
        }
        if !self.key_update_allowed() {
            return Err(ApiError::KeyUpdateBlocked);
        }
        let keep_prev_until = now + 3 * self.pto();
        if let Some(k) = self.one_rtt.as_mut() {
            k.rotate(keep_prev_until);
        }
        Ok(())
    }

    /// Whether [`Connection::initiate_key_update`] would succeed now.
    pub fn key_update_allowed(&self) -> bool {
        let largest_acked = self.spaces[Space::Data as usize].largest_acked;
        self.handshake_confirmed
            && !self.is_closing()
            && self.one_rtt.as_ref().is_some_and(|k| {
                k.first_sent_pn
                    .is_some_and(|f| largest_acked.is_some_and(|l| l >= f))
            })
    }

    fn streams_mut(&mut self) -> Result<&mut Streams, TransportError> {
        self.streams
            .as_mut()
            .ok_or_else(|| terr(codes::PROTOCOL_VIOLATION, "stream frame before parameters"))
    }

    fn note_peer_opened(&mut self, before: [u64; 2], id: u64) {
        let bidi = crate::streams::is_bidi(id);
        let Some(s) = self.streams.as_ref() else {
            return;
        };
        let after = s.peer_opened(bidi);
        let from = before[usize::from(!bidi)];
        let low = id & 3;
        for index in from..after {
            self.events
                .push_back(Event::StreamOpened((index << 2) | low));
        }
    }

    fn peer_opened_counts(&self) -> [u64; 2] {
        self.streams
            .as_ref()
            .map_or([0, 0], |s| [s.peer_opened(true), s.peer_opened(false)])
    }

    fn on_frame(&mut self, space: Space, f: Frame<'_>, now: Instant) -> Result<(), TransportError> {
        match f {
            Frame::Padding { .. } | Frame::Ping => {}
            Frame::Ack { delay, ranges, .. } => self.on_ack(space, delay, &ranges, now)?,
            Frame::Crypto { offset, data } => self.on_crypto(space, offset, data)?,
            Frame::NewToken { .. } => {
                if self.side == Side::Server {
                    return Err(terr(codes::PROTOCOL_VIOLATION, "NEW_TOKEN from client"));
                }
            }
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => {
                let before = self.peer_opened_counts();
                let Self {
                    streams, recv_flow, ..
                } = self;
                let streams = streams.as_mut().ok_or_else(|| {
                    terr(codes::PROTOCOL_VIOLATION, "stream frame before parameters")
                })?;
                if let Some(st) = streams.get_for_recv(id).map_err(streams_err)? {
                    let recv = st
                        .recv
                        .as_mut()
                        .ok_or_else(|| terr(codes::STREAM_STATE_ERROR, "send-only stream"))?;
                    // A stream already read to its FIN stays quiet on duplicates.
                    let was_finished = recv.is_finished();
                    recv.on_frame(offset, data, fin, recv_flow)
                        .map_err(stream_err)?;
                    if !was_finished && recv.is_readable() {
                        self.readable.insert(id);
                    }
                }
                self.note_peer_opened(before, id);
            }
            Frame::ResetStream {
                id,
                error,
                final_size,
            } => {
                let before = self.peer_opened_counts();
                let Self {
                    streams, recv_flow, ..
                } = self;
                let streams = streams.as_mut().ok_or_else(|| {
                    terr(codes::PROTOCOL_VIOLATION, "stream frame before parameters")
                })?;
                if let Some(st) = streams.get_for_recv(id).map_err(streams_err)? {
                    let recv = st
                        .recv
                        .as_mut()
                        .ok_or_else(|| terr(codes::STREAM_STATE_ERROR, "send-only stream"))?;
                    recv.on_reset(error, final_size, recv_flow)
                        .map_err(stream_err)?;
                    self.readable.insert(id);
                }
                self.note_peer_opened(before, id);
                if self.recv_flow.take_update().is_some() {
                    self.pending.max_data = true;
                }
            }
            Frame::StopSending { id, error } => {
                let before = self.peer_opened_counts();
                let streams = self.streams_mut()?;
                let mut reset = None;
                if let Some(st) = streams.get_for_send(id).map_err(streams_err)? {
                    let send = st
                        .send
                        .as_mut()
                        .ok_or_else(|| terr(codes::STREAM_STATE_ERROR, "receive-only stream"))?;
                    reset = send.on_stop_sending(error);
                }
                self.note_peer_opened(before, id);
                if let Some((code, final_size)) = reset {
                    self.pending.resets.push((id, code, final_size));
                    self.events.push_back(Event::StreamStopped { id, error });
                    self.maybe_retire(id);
                }
            }
            Frame::MaxData(max) => self.send_flow.on_max_data(max),
            Frame::MaxStreamData { id, max } => {
                let before = self.peer_opened_counts();
                let streams = self.streams_mut()?;
                if let Some(st) = streams.get_for_send(id).map_err(streams_err)? {
                    if let Some(send) = st.send.as_mut() {
                        send.on_max_stream_data(max);
                    }
                }
                self.note_peer_opened(before, id);
            }
            Frame::MaxStreams { bidi, max } => self.streams_mut()?.on_max_streams(bidi, max),
            Frame::StreamDataBlocked { id, .. } => {
                let before = self.peer_opened_counts();
                self.streams_mut()?.get_for_recv(id).map_err(streams_err)?;
                self.note_peer_opened(before, id);
            }
            Frame::DataBlocked(_) | Frame::StreamsBlocked { .. } => {}
            Frame::PathResponse(d) => self.on_path_response(d),
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                reset_token,
            } => {
                // A peer that uses zero-length CIDs cannot issue more.
                if self.remote_cid.is_empty() {
                    return Err(terr(codes::PROTOCOL_VIOLATION, "NEW_CONNECTION_ID"));
                }
                match self
                    .remote_cids
                    .on_new(seq, retire_prior_to, cid, reset_token)
                {
                    Ok(retire) => self.pending.retire_cids.extend(retire),
                    Err(NewCidError::Conflict) => {
                        return Err(terr(codes::PROTOCOL_VIOLATION, "conflicting CID"))
                    }
                    Err(NewCidError::Limit) => {
                        return Err(terr(
                            codes::CONNECTION_ID_LIMIT_ERROR,
                            "active_connection_id_limit exceeded",
                        ))
                    }
                }
            }
            Frame::RetireConnectionId(seq) => {
                // RFC 9000 19.16: never the CID this packet was sent to.
                if Some(seq) == self.rx_dcid_seq {
                    return Err(terr(codes::PROTOCOL_VIOLATION, "retired the CID in use"));
                }
                match self.local_cids.retire(seq) {
                    Err(_) => return Err(terr(codes::PROTOCOL_VIOLATION, "retired unissued CID")),
                    Ok(true) => self.top_up_cids(),
                    Ok(false) => {}
                }
            }
            Frame::PathChallenge(d) => match self.rx_from {
                Some(a) if Some(a) != self.path.remote => {
                    if self.off_path_responses.len() < MAX_OFF_PATH_RESPONSES {
                        self.off_path_responses.push((d, a, self.rx_len));
                    }
                }
                _ => {
                    if self.pending.path_responses.len() < 4 {
                        self.pending.path_responses.push(d);
                    }
                }
            },
            Frame::ConnectionClose {
                error,
                frame_type,
                reason,
            } => {
                let r = match frame_type {
                    Some(_) => CloseReason::PeerTransport {
                        code: error,
                        frame_type,
                        reason: reason.to_vec(),
                    },
                    None => CloseReason::PeerApplication {
                        code: error,
                        reason: reason.to_vec(),
                    },
                };
                self.state = State::Draining {
                    until: now + 3 * self.pto(),
                };
                self.set_close_reason(r);
            }
            Frame::HandshakeDone => {
                if self.side == Side::Server {
                    return Err(terr(
                        codes::PROTOCOL_VIOLATION,
                        "HANDSHAKE_DONE from client",
                    ));
                }
                self.confirm_handshake();
            }
        }
        Ok(())
    }

    /// A PATH_RESPONSE validates the path its challenge was sent on,
    /// whichever path it arrives on (RFC 9000 8.2.3).
    fn on_path_response(&mut self, d: [u8; 8]) {
        if self.path.challenges.contains(&d) {
            self.path.validated = true;
            self.path.challenges.clear();
            self.path.challenge_pending = false;
            self.path.next_challenge = None;
            self.path.deadline = None;
            self.prev_path = None;
            self.stats.paths_validated += 1;
        } else if let Some(i) = self.probes_sent.iter().position(|p| *p == d) {
            self.probes_sent.remove(i);
            self.stats.paths_validated += 1;
        }
    }

    fn on_crypto(&mut self, space: Space, offset: u64, data: &[u8]) -> Result<(), TransportError> {
        let sp = &mut self.spaces[space as usize];
        sp.crypto_recv
            .on_frame(offset, data, false, &mut sp.crypto_recv_flow)
            .map_err(|_| terr(codes::CRYPTO_BUFFER_EXCEEDED, "crypto buffer exceeded"))?;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let (n, _) = sp.crypto_recv.read(&mut chunk, &mut sp.crypto_recv_flow);
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
        let _ = sp.crypto_recv.take_update();
        let _ = sp.crypto_recv_flow.take_update();
        if bytes.is_empty() {
            return Ok(());
        }
        if let Err(_e) = self.tls.read_hs(&bytes) {
            let alert = self.tls.alert().map_or(0x50, u8::from);
            return Err(TransportError {
                code: codes::CRYPTO_ERROR + u64::from(alert),
                frame_type: None,
                reason: "TLS handshake failed",
            });
        }
        self.drive_tls()
    }

    fn on_ack(
        &mut self,
        space: Space,
        delay: u64,
        ranges: &[(u64, u64)],
        now: Instant,
    ) -> Result<(), TransportError> {
        let si = space as usize;
        let Some(&(_, largest)) = ranges.first() else {
            return Ok(());
        };
        if largest >= self.spaces[si].pn.next_pn {
            return Err(terr(codes::PROTOCOL_VIOLATION, "ACK of unsent packet"));
        }
        let exp = self
            .peer_params
            .as_ref()
            .map_or(u64::from(ACK_DELAY_EXPONENT), |p| p.ack_delay_exponent)
            .min(20);
        let ack_delay = Duration::from_micros(delay.saturating_mul(1u64 << exp));
        if let (Space::Data, Some((pn, size, _))) = (space, self.pmtud.probe) {
            if ranges.iter().any(|&(lo, hi)| lo <= pn && pn <= hi) {
                self.pmtud.probe = None;
                self.pmtud.failures = 0;
                if size > self.mtu {
                    self.mtu = size;
                    self.recovery.set_max_datagram_size(size as u64);
                }
            }
        }
        let out = self.recovery.on_ack_received(space, ranges, ack_delay, now);
        if out.acked.is_empty() {
            return Ok(());
        }
        let s = &mut self.spaces[si];
        s.largest_acked = Some(s.largest_acked.map_or(largest, |l| l.max(largest)));
        for (_, p) in out.acked {
            self.on_packet_acked(space, p.payload);
        }
        for (_, p) in out.lost {
            self.on_packet_lost(space, p.payload);
        }
        if self.side == Side::Client {
            if space == Space::Handshake {
                self.handshake_acked = true;
            }
            if space == Space::Data && self.handshake_complete {
                self.confirm_handshake();
            }
        }
        Ok(())
    }

    fn on_packet_acked(&mut self, space: Space, sent: Sent) {
        let sp = &mut self.spaces[space as usize];
        for (off, len) in sent.crypto {
            sp.crypto_send.on_ack(off, len, false);
        }
        for r in sent.streams {
            if let Some(send) = self
                .streams
                .as_mut()
                .and_then(|s| s.get_mut(r.id))
                .and_then(|st| st.send.as_mut())
            {
                send.on_ack(r.offset, r.len, r.fin);
            }
            self.maybe_retire(r.id);
        }
    }

    /// A PTO probe with nothing new to send carries data still in flight
    /// (RFC 9002 6.2.4) instead of a bare PING, so a probe that gets
    /// through can repair what was lost even when every acknowledgement of
    /// a PING is lost too. Each probe takes the next packet in flight that
    /// has any data, oldest first and round robin, so every one is resent
    /// in turn. The packet stays in flight; whichever copy is acknowledged
    /// first counts.
    fn requeue_for_probe(&mut self, space: Space) {
        if self.has_eliciting_data(space) {
            return;
        }
        let si = space as usize;
        let loss = &self.recovery.loss;
        let next_from = |from: u64| {
            loss.in_flight(space)
                .find(|(pn, p)| *pn >= from && !p.payload.is_empty())
                .map(|(pn, p)| (pn, p.payload.clone()))
        };
        let next = next_from(self.probe_cursor[si]).or_else(|| next_from(0));
        if let Some((pn, sent)) = next {
            self.probe_cursor[si] = pn + 1;
            self.requeue(space, sent);
        }
    }

    fn on_packet_lost(&mut self, space: Space, sent: Sent) {
        self.stats.packets_lost += 1;
        self.requeue(space, sent);
    }

    /// Queues the frames of `sent` to be sent again.
    fn requeue(&mut self, space: Space, sent: Sent) {
        let sp = &mut self.spaces[space as usize];
        for (off, len) in sent.crypto {
            sp.crypto_send.on_lost(off, len, false);
        }
        for r in sent.streams {
            if let Some(send) = self
                .streams
                .as_mut()
                .and_then(|s| s.get_mut(r.id))
                .and_then(|st| st.send.as_mut())
            {
                send.on_lost(r.offset, r.len, r.fin);
            }
        }
        for c in sent.ctrl {
            match c {
                Ctrl::MaxData => self.pending.max_data = true,
                Ctrl::MaxStreamData(id) => {
                    if self.recv_open(id) {
                        self.pending.max_stream_data.insert(id);
                    }
                }
                Ctrl::MaxStreams(bidi) => self.pending.max_streams[usize::from(!bidi)] = true,
                Ctrl::ResetStream {
                    id,
                    error,
                    final_size,
                } => self.pending.resets.push((id, error, final_size)),
                Ctrl::StopSending { id, error } => {
                    if self.streams.as_mut().and_then(|s| s.get_mut(id)).is_some() {
                        self.pending.stop_sending.push((id, error));
                    }
                }
                Ctrl::HandshakeDone => self.pending.handshake_done = true,
                Ctrl::NewConnectionId(seq) => {
                    if self.local_cids.get(seq).is_some() {
                        self.pending.new_cids.push(seq);
                    }
                }
                Ctrl::RetireConnectionId(seq) => self.pending.retire_cids.push(seq),
            }
        }
    }

    fn recv_open(&mut self, id: u64) -> bool {
        self.streams
            .as_mut()
            .and_then(|s| s.get_mut(id))
            .and_then(|st| st.recv.as_ref())
            .is_some_and(|r| !r.is_finished() && r.reset_code().is_none())
    }

    fn maybe_retire(&mut self, id: u64) {
        let Some(streams) = self.streams.as_mut() else {
            return;
        };
        let Some(st) = streams.get_mut(id) else {
            return;
        };
        let send_done = st
            .send
            .as_ref()
            .map_or(true, |s| s.is_complete() || s.reset_code().is_some());
        let recv_done = self.recv_closed.contains(&id)
            || st
                .recv
                .as_ref()
                .map_or(true, |r| r.fin_delivered() && r.reset_code().is_none());
        if send_done && recv_done {
            if streams.retire(id).is_some() {
                self.pending.max_streams[usize::from(!crate::streams::is_bidi(id))] = true;
            }
            self.recv_closed.remove(&id);
            self.readable.remove(&id);
            self.pending.max_stream_data.remove(&id);
        }
    }

    // ----- application stream API ---------------------------------------------

    fn app_streams(&mut self) -> Result<&mut Streams, ApiError> {
        if self.is_closing() {
            return Err(ApiError::Closed);
        }
        self.streams.as_mut().ok_or(ApiError::NotEstablished)
    }

    /// Opens a new locally initiated stream and returns its ID.
    pub fn open_stream(&mut self, bidi: bool) -> Result<u64, ApiError> {
        let streams = self.app_streams()?;
        match streams.open(bidi) {
            Ok(id) => Ok(id),
            Err(_) => {
                let limit = streams.peer_limit(bidi);
                let k = usize::from(!bidi);
                if self.pending.streams_blocked_signalled[k] != Some(limit) {
                    self.pending.streams_blocked_signalled[k] = Some(limit);
                    self.pending.streams_blocked = Some((bidi, limit));
                }
                Err(ApiError::StreamsBlocked)
            }
        }
    }

    /// Buffers `data` (and optionally FIN) on a stream; returns bytes accepted.
    pub fn stream_write(&mut self, id: u64, data: &[u8], fin: bool) -> Result<usize, ApiError> {
        let st = self
            .app_streams()?
            .get_mut(id)
            .ok_or(ApiError::UnknownStream(id))?;
        let send = st.send.as_mut().ok_or(ApiError::WrongDirection(id))?;
        Ok(send.write(data, fin)?)
    }

    /// Bytes written to a stream that the peer has not acknowledged yet
    /// (sent or not); `None` for an unknown or receive-only stream. Lets an
    /// application bound how much it queues ahead of the network.
    pub fn stream_send_buffered(&self, id: u64) -> Option<usize> {
        let st = self.streams.as_ref()?.get(id)?;
        st.send.as_ref().map(crate::send::SendStream::buffered)
    }

    /// Reads contiguous data; returns `(bytes, fin_reached)`. A stream reset
    /// by the peer returns [`ApiError::ResetByPeer`] (once; the stream is
    /// then forgotten).
    pub fn stream_read(&mut self, id: u64, buf: &mut [u8]) -> Result<(usize, bool), ApiError> {
        if self.is_closing() {
            return Err(ApiError::Closed);
        }
        let Self {
            streams,
            recv_flow,
            pending,
            ..
        } = self;
        let st = streams
            .as_mut()
            .ok_or(ApiError::NotEstablished)?
            .get_mut(id)
            .ok_or(ApiError::UnknownStream(id))?;
        let recv = st.recv.as_mut().ok_or(ApiError::WrongDirection(id))?;
        if let Some(code) = recv.reset_code() {
            self.recv_closed.insert(id);
            self.maybe_retire(id);
            return Err(ApiError::ResetByPeer(code));
        }
        let (n, fin) = recv.read(buf, recv_flow);
        if recv.take_update().is_some() {
            pending.max_stream_data.insert(id);
        }
        if recv_flow.take_update().is_some() {
            pending.max_data = true;
        }
        if fin {
            self.maybe_retire(id);
        }
        Ok((n, fin))
    }

    /// Abandons sending on a stream (RESET_STREAM).
    pub fn stream_reset(&mut self, id: u64, code: u64) -> Result<(), ApiError> {
        let st = self
            .app_streams()?
            .get_mut(id)
            .ok_or(ApiError::UnknownStream(id))?;
        let send = st.send.as_mut().ok_or(ApiError::WrongDirection(id))?;
        if let Some((e, final_size)) = send.reset(code) {
            self.pending.resets.push((id, e, final_size));
        }
        self.maybe_retire(id);
        Ok(())
    }

    /// Asks the peer to stop sending on a stream (STOP_SENDING).
    pub fn stream_stop(&mut self, id: u64, code: u64) -> Result<(), ApiError> {
        if self.is_closing() {
            return Err(ApiError::Closed);
        }
        let Self {
            streams,
            recv_flow,
            pending,
            ..
        } = self;
        let st = streams
            .as_mut()
            .ok_or(ApiError::NotEstablished)?
            .get_mut(id)
            .ok_or(ApiError::UnknownStream(id))?;
        let recv = st.recv.as_mut().ok_or(ApiError::WrongDirection(id))?;
        if let Some(e) = recv.stop_sending(code, recv_flow) {
            pending.stop_sending.push((id, e));
        }
        if recv_flow.take_update().is_some() {
            pending.max_data = true;
        }
        self.recv_closed.insert(id);
        self.maybe_retire(id);
        Ok(())
    }

    // ----- send ------------------------------------------------------------------

    /// Writes the next datagram into `buf` and returns its length (0 when
    /// there is nothing to send). Call repeatedly until it returns 0. For
    /// callers that report addresses, [`Connection::send_with_addr`] also
    /// says where each datagram goes.
    pub fn send(&mut self, buf: &mut [u8], now: Instant) -> usize {
        self.send_with_addr(buf, now).0
    }

    /// Like [`Connection::send`], also returning the destination: the
    /// current path's address, or another address a PATH_RESPONSE is owed
    /// to; `None` if no address was ever reported.
    pub fn send_with_addr(&mut self, buf: &mut [u8], now: Instant) -> (usize, Option<SocketAddr>) {
        match self.state {
            State::Closed | State::Draining { .. } => return (0, None),
            State::Closing { .. } if !self.close_pending => return (0, None),
            _ => {}
        }
        // Responses owed to the current path ride in normal packets.
        let here = self.path.remote;
        let (now_here, elsewhere): (Vec<_>, Vec<_>) = core::mem::take(&mut self.off_path_responses)
            .into_iter()
            .partition(|(_, a, _)| Some(*a) == here);
        self.off_path_responses = elsewhere;
        for (d, _, _) in now_here {
            if self.pending.path_responses.len() < 4 {
                self.pending.path_responses.push(d);
            }
        }
        if !self.is_closing() {
            if let Some((d, to, received)) = self.off_path_responses.pop() {
                let n = self.send_path_frame(buf, Frame::PathResponse(d), received, now);
                if n > 0 {
                    return (n, Some(to));
                }
            }
        }
        self.pacing_until = None;
        let n = self.send_pmtu_probe(buf, now);
        if n > 0 {
            return (n, self.path.remote);
        }
        let n = self.send_on_path(buf, now);
        (n, self.path.remote.filter(|_| n > 0))
    }

    /// Writes a PATH_CHALLENGE probe for a path the application is about
    /// to try (RFC 9000 8.2, 9.1): one 1200-byte probing packet the
    /// application sends from the new local address. A PATH_RESPONSE for it
    /// counts in [`Stats::paths_validated`]. Returns 0 before the handshake
    /// is confirmed or if `buf` is too small.
    pub fn send_path_probe(&mut self, buf: &mut [u8], now: Instant) -> usize {
        if !self.handshake_confirmed || self.is_closing() {
            return 0;
        }
        let d = random_challenge();
        let n = self.send_path_frame(buf, Frame::PathChallenge(d), u64::MAX / 4, now);
        if n > 0 {
            if self.probes_sent.len() >= MAX_CHALLENGES {
                self.probes_sent.remove(0);
            }
            self.probes_sent.push(d);
        }
        n
    }

    /// A path MTU probe (PING padded to the next probe size) when one is
    /// due: handshake confirmed, none in flight, the current path
    /// validated, and room in the congestion window.
    fn send_pmtu_probe(&mut self, buf: &mut [u8], now: Instant) -> usize {
        if !self.handshake_confirmed
            || self.is_closing()
            || self.pmtud.probe.is_some()
            || !self.path.validated
        {
            return 0;
        }
        let Some(size) = self.pmtud.next_size(self.mtu) else {
            return 0;
        };
        if buf.len() < size || !self.recovery.can_send(size as u64) {
            return 0;
        }
        let pn = self.spaces[Space::Data as usize].pn.next_pn;
        let n = self.send_single(buf, Frame::Ping, size, size, true, now);
        if n > 0 {
            self.pmtud.probe = Some((pn, size, now + 3 * self.pto()));
            self.stats.pmtu_probes_sent += 1;
            self.path.sent += n as u64;
        }
        n
    }

    /// One 1-RTT packet holding only `frame` and padding, padded to 1200
    /// bytes or three times `received`, whichever is smaller (RFC 9000
    /// 8.2.1, 8.2.2). It is not counted against the current path.
    fn send_path_frame(
        &mut self,
        buf: &mut [u8],
        frame: Frame<'_>,
        received: u64,
        now: Instant,
    ) -> usize {
        let cap = usize::try_from(received.saturating_mul(3)).unwrap_or(usize::MAX);
        let max = self.mtu.min(cap.max(MIN_PACKET_ROOM));
        self.send_single(buf, frame, max, MIN_INITIAL_SIZE.min(max), false, now)
    }

    /// One 1-RTT packet of at most `max` bytes holding only `frame`, padded
    /// to `pad`.
    fn send_single(
        &mut self,
        buf: &mut [u8],
        frame: Frame<'_>,
        max: usize,
        pad: usize,
        pmtu_probe: bool,
        now: Instant,
    ) -> usize {
        let max = buf.len().min(max);
        let Some(buf) = buf.get_mut(..max) else {
            return 0;
        };
        if self.spaces[Space::Data as usize].keys.is_none() || max < MIN_PACKET_ROOM {
            return 0;
        }
        let si = Space::Data as usize;
        let pn = self.spaces[si].pn.next_pn;
        let pn_len = skiff_wire::pn::encoded_len(pn, self.spaces[si].largest_acked);
        let Some(end_limit) = buf.len().checked_sub(TAG_LEN) else {
            return 0;
        };
        let header_len = {
            let Some(dst) = buf.get_mut(..end_limit) else {
                return 0;
            };
            let mut w = Writer::new(dst);
            let phase = self.one_rtt.as_ref().is_some_and(|k| k.phase);
            if header::write_short(&mut w, self.remote_cids.current(), phase, pn, pn_len).is_err() {
                return 0;
            }
            w.position()
        };
        let mut pos = header_len;
        if !put(buf, &mut pos, end_limit, &frame) {
            return 0;
        }
        self.spaces[si].pn.take_pn();
        let b = Building {
            space: Space::Data,
            start: 0,
            pn_offset: header_len - pn_len,
            pn,
            len_off: None,
            payload_end: pos,
            ack_eliciting: true,
            sent: Sent::default(),
            pmtu_probe,
        };
        let n = self.finish(b, buf, Some(pad), now).unwrap_or(0);
        self.stats.bytes_sent += n as u64;
        n
    }

    /// Whether the pacer lets a full datagram of 1-RTT data go now;
    /// otherwise remembers when to try again.
    fn pacing_allows(&mut self, space: Space, now: Instant) -> bool {
        if !self.config.pacing || space != Space::Data {
            return true;
        }
        let mtu = self.mtu as u64;
        let srtt = self.recovery.loss.rtt.smoothed();
        match self
            .pacer
            .delay(now, mtu, self.recovery.window(), srtt, mtu)
        {
            None => true,
            Some(t) => {
                self.pacing_until = Some(t);
                false
            }
        }
    }

    fn send_on_path(&mut self, buf: &mut [u8], now: Instant) -> usize {
        let mut max = buf.len().min(self.mtu);
        if self.side == Side::Server && !self.address_validated {
            let allowance = (3 * self.stats.bytes_received).saturating_sub(self.stats.bytes_sent);
            max = max.min(usize::try_from(allowance).unwrap_or(usize::MAX));
        }
        if let Some(a) = self.path.allowance() {
            // RFC 9000 9.3: amplification limit on an unvalidated new path.
            max = max.min(usize::try_from(a).unwrap_or(usize::MAX));
        }
        if max < MIN_PACKET_ROOM {
            return 0;
        }
        self.pad_datagram = false;
        let Some(buf) = buf.get_mut(..max) else {
            return 0;
        };
        let mut open: Option<Building> = None;
        let mut has_initial = false;
        let mut any_eliciting = false;
        let mut end = 0;
        for space in SPACES {
            if self.spaces[space as usize].keys.is_none() {
                continue;
            }
            let start = open.as_ref().map_or(0, |b| b.payload_end + TAG_LEN);
            if start + MIN_PACKET_ROOM > max {
                break;
            }
            if let Some(b) = self.build_packet(space, buf, start, now) {
                if let Some(prev) = open.take() {
                    match self.finish(prev, buf, None, now) {
                        Some(e) => end = e,
                        None => return 0,
                    }
                }
                has_initial |= space == Space::Initial;
                any_eliciting |= b.ack_eliciting;
                open = Some(b);
            }
        }
        if let Some(last) = open {
            let pad = ((has_initial && (self.side == Side::Client || any_eliciting))
                || self.pad_datagram)
                .then_some(MIN_INITIAL_SIZE.min(max));
            match self.finish(last, buf, pad, now) {
                Some(e) => end = e,
                None => return 0,
            }
        }
        if matches!(self.state, State::Closing { .. }) {
            self.close_pending = false;
        }
        if end > 0 {
            self.stats.bytes_sent += end as u64;
            self.path.sent += end as u64;
        }
        self.update_anti_deadlock();
        end
    }

    fn has_eliciting_data(&mut self, space: Space) -> bool {
        let sp = &self.spaces[space as usize];
        if sp.crypto_send.wants_send(&sp.crypto_send_flow) {
            return true;
        }
        if space != Space::Data {
            return false;
        }
        if self.pending.any() {
            return true;
        }
        let Some(streams) = self.streams.as_mut() else {
            return false;
        };
        for id in streams.ids() {
            if let Some(send) = streams.get_mut(id).and_then(|s| s.send.as_ref()) {
                if send.wants_send(&self.send_flow) {
                    return true;
                }
            }
        }
        false
    }

    fn close_frame_for(&self, space: Space) -> Option<Frame<'_>> {
        Some(match self.close_frame.as_ref()? {
            CloseFrame::Application { code, reason } if space == Space::Data => {
                Frame::ConnectionClose {
                    error: *code,
                    frame_type: None,
                    reason,
                }
            }
            CloseFrame::Application { .. } => Frame::ConnectionClose {
                error: codes::APPLICATION_ERROR,
                frame_type: Some(0),
                reason: &[],
            },
            CloseFrame::Transport {
                code,
                frame_type,
                reason,
            } => Frame::ConnectionClose {
                error: *code,
                frame_type: Some(frame_type.unwrap_or(0)),
                reason,
            },
        })
    }

    fn build_packet(
        &mut self,
        space: Space,
        buf: &mut [u8],
        start: usize,
        now: Instant,
    ) -> Option<Building> {
        let si = space as usize;
        let closing = matches!(self.state, State::Closing { .. });
        let probe = !closing && self.spaces[si].probes > 0;
        let ack_deadline = self.spaces[si]
            .pn
            .ack_deadline(self.config.max_ack_delay, space != Space::Data);
        let ack_due = !closing && ack_deadline.is_some_and(|d| d <= now);
        let cwnd_ok = probe || self.recovery.can_send(self.mtu as u64);
        let eliciting_wanted = !closing
            && cwnd_ok
            && self.has_eliciting_data(space)
            && (probe || self.pacing_allows(space, now));
        // Path validation frames are not held back by congestion control.
        let path_frames = !closing
            && space == Space::Data
            && (self.path.challenge_pending || !self.pending.path_responses.is_empty());
        if !(ack_due || eliciting_wanted || probe || path_frames || (closing && self.close_pending))
        {
            return None;
        }
        let end_limit = buf.len().checked_sub(TAG_LEN)?;
        if start >= end_limit {
            return None;
        }
        let pn = self.spaces[si].pn.next_pn;
        let pn_len = skiff_wire::pn::encoded_len(pn, self.spaces[si].largest_acked);
        let (len_off, header_len) = {
            let mut w = Writer::new(buf.get_mut(start..end_limit)?);
            let len_off = match space {
                Space::Data => {
                    let phase = self.one_rtt.as_ref().is_some_and(|k| k.phase);
                    header::write_short(&mut w, self.remote_cids.current(), phase, pn, pn_len)
                        .ok()?;
                    None
                }
                _ => {
                    let ty = if space == Space::Initial {
                        PacketType::Initial
                    } else {
                        PacketType::Handshake
                    };
                    let off = header::write_long(
                        &mut w,
                        ty,
                        VERSION_1,
                        &self.remote_cid,
                        &self.local_cid,
                        if space == Space::Initial {
                            &self.initial_token
                        } else {
                            &[]
                        },
                        pn,
                        pn_len,
                    )
                    .ok()?;
                    Some(start + off)
                }
            };
            (len_off, w.position())
        };
        let pn_offset = start + header_len - pn_len;
        let payload_start = start + header_len;
        let mut pos = payload_start;
        let mut sent = Sent::default();
        let mut eliciting = false;

        if closing {
            if let Some(f) = self.close_frame_for(space) {
                let mut tmp = [0u8; 1100];
                let mut p = 0;
                if put(&mut tmp, &mut p, 1100, &f) {
                    if let Some(dst) = buf.get_mut(pos..pos + p) {
                        dst.copy_from_slice(&tmp[..p]);
                        pos += p;
                    }
                }
            }
        } else {
            // Reserve room for an ACK, written last so it is only spent
            // when the packet is actually sent.
            let mut ack_bytes = [0u8; 1100];
            let mut ack_len = 0;
            if let Some(ack) =
                ack_deadline.and_then(|_| self.spaces[si].pn.ack_frame(now, ACK_DELAY_EXPONENT))
            {
                if !put(&mut ack_bytes, &mut ack_len, 1100, &ack) {
                    ack_len = 0;
                }
            }
            let ack_fits = ack_len > 0 && pos + ack_len <= end_limit;
            let limit = if ack_fits {
                end_limit - ack_len
            } else {
                end_limit
            };
            if path_frames {
                eliciting |= self.write_path_frames(buf, &mut pos, limit, now);
            }
            if cwnd_ok {
                eliciting |= self.write_crypto(space, buf, &mut pos, limit, &mut sent);
                if space == Space::Data {
                    eliciting |= self.write_ctrl(buf, &mut pos, limit, &mut sent);
                    eliciting |= self.write_streams(buf, &mut pos, limit, &mut sent);
                }
                if probe && !eliciting && put(buf, &mut pos, limit, &Frame::Ping) {
                    eliciting = true;
                }
            }
            if ack_fits && (eliciting || ack_due) {
                if let Some(dst) = buf.get_mut(pos..pos + ack_len) {
                    dst.copy_from_slice(&ack_bytes[..ack_len]);
                    pos += ack_len;
                    self.spaces[si].pn.on_ack_sent();
                }
            }
        }
        if pos == payload_start {
            return None;
        }
        self.spaces[si].pn.take_pn();
        Some(Building {
            space,
            start,
            pn_offset,
            pn,
            len_off,
            payload_end: pos,
            ack_eliciting: eliciting,
            sent,
            pmtu_probe: false,
        })
    }

    fn write_crypto(
        &mut self,
        space: Space,
        buf: &mut [u8],
        pos: &mut usize,
        limit: usize,
        sent: &mut Sent,
    ) -> bool {
        let mut wrote = false;
        let sp = &mut self.spaces[space as usize];
        loop {
            // type + offset (<= 8) + length (2) + at least one byte.
            let overhead = 1 + 8 + 2;
            let Some(room) = limit.checked_sub(*pos) else {
                break;
            };
            if room <= overhead {
                break;
            }
            let Some(c) = sp
                .crypto_send
                .emit(room - overhead, &mut sp.crypto_send_flow)
            else {
                break;
            };
            let f = Frame::Crypto {
                offset: c.offset,
                data: &c.data,
            };
            if put(buf, pos, limit, &f) {
                sent.crypto.push((c.offset, c.data.len() as u64));
                wrote = true;
            } else {
                sp.crypto_send.on_lost(c.offset, c.data.len() as u64, false);
                break;
            }
        }
        wrote
    }

    /// PATH_CHALLENGE for an unvalidated path and PATH_RESPONSEs owed on
    /// this path; the datagram is then padded to 1200 bytes (RFC 9000
    /// 8.2.1, 8.2.2).
    fn write_path_frames(
        &mut self,
        buf: &mut [u8],
        pos: &mut usize,
        limit: usize,
        now: Instant,
    ) -> bool {
        let mut wrote = false;
        if self.path.challenge_pending {
            let d = random_challenge();
            if put(buf, pos, limit, &Frame::PathChallenge(d)) {
                if self.path.challenges.len() >= MAX_CHALLENGES {
                    self.path.challenges.remove(0);
                }
                self.path.challenges.push(d);
                self.path.challenge_pending = false;
                self.path.next_challenge = Some(now + self.pto());
                wrote = true;
            }
        }
        while let Some(d) = self.pending.path_responses.last().copied() {
            if !put(buf, pos, limit, &Frame::PathResponse(d)) {
                break;
            }
            self.pending.path_responses.pop();
            wrote = true;
        }
        self.pad_datagram |= wrote;
        wrote
    }

    fn write_ctrl(
        &mut self,
        buf: &mut [u8],
        pos: &mut usize,
        limit: usize,
        sent: &mut Sent,
    ) -> bool {
        let mut wrote = false;
        let p = &mut self.pending;
        if p.handshake_done && put(buf, pos, limit, &Frame::HandshakeDone) {
            p.handshake_done = false;
            sent.ctrl.push(Ctrl::HandshakeDone);
            wrote = true;
        }
        while let Some(&seq) = p.new_cids.last() {
            if let Some(c) = self.local_cids.get(seq) {
                let f = Frame::NewConnectionId {
                    seq,
                    retire_prior_to: 0,
                    cid: &c.cid,
                    reset_token: c.token,
                };
                if !put(buf, pos, limit, &f) {
                    break;
                }
                sent.ctrl.push(Ctrl::NewConnectionId(seq));
                wrote = true;
            }
            p.new_cids.pop();
        }
        while let Some(&seq) = p.retire_cids.last() {
            if !put(buf, pos, limit, &Frame::RetireConnectionId(seq)) {
                break;
            }
            p.retire_cids.pop();
            sent.ctrl.push(Ctrl::RetireConnectionId(seq));
            wrote = true;
        }
        if p.max_data && put(buf, pos, limit, &Frame::MaxData(self.recv_flow.max_data())) {
            p.max_data = false;
            sent.ctrl.push(Ctrl::MaxData);
            wrote = true;
        }
        while let Some(&(id, error, final_size)) = p.resets.last() {
            if !put(
                buf,
                pos,
                limit,
                &Frame::ResetStream {
                    id,
                    error,
                    final_size,
                },
            ) {
                break;
            }
            p.resets.pop();
            sent.ctrl.push(Ctrl::ResetStream {
                id,
                error,
                final_size,
            });
            wrote = true;
        }
        while let Some(&(id, error)) = p.stop_sending.last() {
            if !put(buf, pos, limit, &Frame::StopSending { id, error }) {
                break;
            }
            p.stop_sending.pop();
            sent.ctrl.push(Ctrl::StopSending { id, error });
            wrote = true;
        }
        if let Some((bidi, limit_v)) = p.streams_blocked {
            if put(
                buf,
                pos,
                limit,
                &Frame::StreamsBlocked {
                    bidi,
                    limit: limit_v,
                },
            ) {
                p.streams_blocked = None;
                wrote = true;
            }
        }
        let Some(streams) = self.streams.as_mut() else {
            return wrote;
        };
        for bidi in [true, false] {
            let k = usize::from(!bidi);
            if p.max_streams[k] {
                let max = streams.local_limit(bidi);
                if !put(buf, pos, limit, &Frame::MaxStreams { bidi, max }) {
                    break;
                }
                p.max_streams[k] = false;
                sent.ctrl.push(Ctrl::MaxStreams(bidi));
                wrote = true;
            }
        }
        while let Some(&id) = p.max_stream_data.first() {
            let max = streams
                .get_mut(id)
                .and_then(|s| s.recv.as_ref())
                .map(RecvStream::max_stream_data);
            if let Some(max) = max {
                if !put(buf, pos, limit, &Frame::MaxStreamData { id, max }) {
                    break;
                }
                sent.ctrl.push(Ctrl::MaxStreamData(id));
                wrote = true;
            }
            p.max_stream_data.pop_first();
        }
        wrote
    }

    fn write_streams(
        &mut self,
        buf: &mut [u8],
        pos: &mut usize,
        limit: usize,
        sent: &mut Sent,
    ) -> bool {
        let mut wrote = false;
        let Some(streams) = self.streams.as_mut() else {
            return false;
        };
        let ids = streams.ids();
        if ids.is_empty() {
            return false;
        }
        let first = ids.partition_point(|&i| i < self.next_rr);
        'outer: for k in 0..ids.len() {
            let id = ids[(first + k) % ids.len()];
            loop {
                let id_len = skiff_wire::codec::varint_len(id).unwrap_or(8);
                let overhead = 1 + id_len + 8 + 2;
                let Some(room) = limit.checked_sub(*pos) else {
                    break 'outer;
                };
                if room <= overhead {
                    break 'outer;
                }
                let Some(send) = streams.get_mut(id).and_then(|s| s.send.as_mut()) else {
                    break;
                };
                let Some(c) = send.emit(room - overhead, &mut self.send_flow) else {
                    if let Some(l) = send.take_blocked() {
                        if put(buf, pos, limit, &Frame::StreamDataBlocked { id, limit: l }) {
                            wrote = true;
                        }
                    }
                    break;
                };
                let f = Frame::Stream {
                    id,
                    offset: c.offset,
                    data: &c.data,
                    fin: c.fin,
                };
                if put(buf, pos, limit, &f) {
                    sent.streams.push(StreamRange {
                        id,
                        offset: c.offset,
                        len: c.data.len() as u64,
                        fin: c.fin,
                    });
                    wrote = true;
                    self.next_rr = id + 1;
                } else {
                    send.on_lost(c.offset, c.data.len() as u64, c.fin);
                    break 'outer;
                }
            }
        }
        if let Some(l) = self.send_flow.take_blocked() {
            if put(buf, pos, limit, &Frame::DataBlocked(l)) {
                wrote = true;
            }
        }
        wrote
    }

    /// Pads, fixes the Length field, seals the packet and records it.
    /// Returns the end offset of the protected packet.
    fn finish(
        &mut self,
        b: Building,
        buf: &mut [u8],
        pad_to: Option<usize>,
        now: Instant,
    ) -> Option<usize> {
        let mut end = b.payload_end;
        // Header protection samples 16 bytes starting 4 after the PN.
        let mut target = b.pn_offset + 4;
        if let Some(p) = pad_to {
            target = target.max(p.saturating_sub(TAG_LEN));
        }
        if end < target {
            buf.get_mut(end..target)?.fill(0);
            end = target;
        }
        if let Some(len_off) = b.len_off {
            let len = (end + TAG_LEN - b.pn_offset) as u64;
            Writer::new(buf.get_mut(len_off..len_off + 2)?)
                .varint_with_len(len, 2)
                .ok()?;
        }
        let si = b.space as usize;
        let keys = self.spaces[si].keys.as_ref()?;
        let out = buf.get_mut(b.start..end + TAG_LEN)?;
        let total = match (b.space, self.one_rtt.as_mut()) {
            (Space::Data, Some(k)) => {
                let split = Split {
                    hp: keys.local.as_ref(),
                    aead: k.local.as_ref(),
                };
                let n = packet::protect(&split, out, b.pn_offset - b.start, b.pn, end - b.start);
                k.first_sent_pn.get_or_insert(b.pn);
                n
            }
            _ => packet::protect(
                keys.local.as_ref(),
                out,
                b.pn_offset - b.start,
                b.pn,
                end - b.start,
            ),
        }
        .ok()?;
        self.stats.packets_sent += 1;
        if b.ack_eliciting {
            if !self.sent_eliciting_since_recv {
                self.last_activity = now;
                self.sent_eliciting_since_recv = true;
            }
            if !b.pmtu_probe {
                let sp = &mut self.spaces[si];
                sp.probes = sp.probes.saturating_sub(1);
                if b.space == Space::Data {
                    self.pacer.on_sent(total as u64);
                }
            }
        }
        let closing = matches!(self.state, State::Closing { .. });
        if !closing && !b.pmtu_probe {
            self.recovery.on_packet_sent(
                b.space,
                b.pn,
                SentPacket {
                    time_sent: now,
                    size: total as u64,
                    ack_eliciting: b.ack_eliciting,
                    payload: b.sent,
                },
            );
        }
        if self.side == Side::Client && b.space == Space::Handshake {
            // RFC 9001 4.9.1: the client discards Initial keys once it
            // sends its first Handshake packet.
            self.discard_space(Space::Initial);
        }
        Some(b.start + total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Connection {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        Connection::connect(
            Arc::new(tls),
            "localhost",
            TransportConfig::default(),
            Instant::now(),
        )
        .unwrap()
    }

    fn new_cid(seq: u64, rpt: u64, cid: &[u8]) -> Frame<'_> {
        Frame::NewConnectionId {
            seq,
            retire_prior_to: rpt,
            cid,
            reset_token: [seq as u8; 16],
        }
    }

    fn code(r: Result<(), TransportError>) -> Option<u64> {
        r.err().map(|e| e.code)
    }

    /// RFC 9000 7.3: retry_source_connection_id must be absent without a
    /// Retry and equal to the Retry's Source CID after one.
    #[test]
    fn retry_source_connection_id_must_match() {
        let mut c = client();
        c.remote_cid = vec![5; 8];
        let params = |c: &Connection, retry: Option<Vec<u8>>| {
            let p = TransportParams {
                initial_scid: Some(vec![5; 8]),
                original_dcid: Some(c.odcid.clone()),
                retry_scid: retry,
                ..TransportParams::default()
            };
            let mut v = Vec::new();
            p.encode(&mut v).unwrap();
            v
        };
        let tpe = Some(codes::TRANSPORT_PARAMETER_ERROR);
        let p = params(&c, Some(vec![7; 8]));
        assert_eq!(code(c.apply_peer_params(&p)), tpe, "without a Retry");
        let p = params(&c, None);
        assert_eq!(code(c.apply_peer_params(&p)), None);
        c.retry_scid = Some(vec![7; 8]);
        let p = params(&c, None);
        assert_eq!(code(c.apply_peer_params(&p)), tpe, "missing after a Retry");
        let p = params(&c, Some(vec![8; 8]));
        assert_eq!(code(c.apply_peer_params(&p)), tpe, "another CID");
        let p = params(&c, Some(vec![7; 8]));
        assert_eq!(code(c.apply_peer_params(&p)), None);
    }

    /// RFC 9000 19.16: retiring a sequence number never issued, or the CID
    /// the packet itself was sent to, is a PROTOCOL_VIOLATION.
    #[test]
    fn retire_connection_id_errors() {
        let mut c = client();
        let now = Instant::now();
        let f = Frame::RetireConnectionId(5);
        assert_eq!(
            code(c.on_frame(Space::Data, f, now)),
            Some(codes::PROTOCOL_VIOLATION)
        );
        c.rx_dcid_seq = Some(0);
        let f = Frame::RetireConnectionId(0);
        assert_eq!(
            code(c.on_frame(Space::Data, f, now)),
            Some(codes::PROTOCOL_VIOLATION)
        );
        // Sent to another CID: retiring seq 0 is allowed.
        c.local_cids.issue(vec![9; 8], [9; 16]);
        c.rx_dcid_seq = Some(1);
        let f = Frame::RetireConnectionId(0);
        assert_eq!(code(c.on_frame(Space::Data, f, now)), None);
        assert_eq!(c.local_cids.len(), 1);
    }

    /// RFC 9000 5.1.1 / 19.15: more active CIDs than our
    /// active_connection_id_limit is CONNECTION_ID_LIMIT_ERROR; the same
    /// sequence number with a different CID is a PROTOCOL_VIOLATION; a
    /// repeat is ignored; retire_prior_to retires the old ones.
    #[test]
    fn new_connection_id_errors_and_retire_prior_to() {
        let now = Instant::now();
        let mut c = client();
        for seq in 1..4u64 {
            let cid = [seq as u8; 8];
            assert_eq!(
                code(c.on_frame(Space::Data, new_cid(seq, 0, &cid), now)),
                None
            );
        }
        assert_eq!(
            code(c.on_frame(Space::Data, new_cid(3, 0, &[3; 8]), now)),
            None
        );
        assert_eq!(
            code(c.on_frame(Space::Data, new_cid(3, 0, &[7; 8]), now)),
            Some(codes::PROTOCOL_VIOLATION)
        );
        assert_eq!(
            code(c.on_frame(Space::Data, new_cid(4, 0, &[4; 8]), now)),
            Some(codes::CONNECTION_ID_LIMIT_ERROR)
        );

        let mut c = client();
        for seq in 1..4u64 {
            let cid = [seq as u8; 8];
            assert_eq!(
                code(c.on_frame(Space::Data, new_cid(seq, 0, &cid), now)),
                None
            );
        }
        // Retiring 0..=2 makes room: the client moves to seq 3 and
        // queues three RETIRE_CONNECTION_ID frames.
        assert_eq!(
            code(c.on_frame(Space::Data, new_cid(4, 3, &[4; 8]), now)),
            None
        );
        assert_eq!(c.remote_cids.current(), &[3; 8][..]);
        let mut retired = c.pending.retire_cids.clone();
        retired.sort_unstable();
        assert_eq!(retired, vec![0, 1, 2]);
        assert_eq!(c.spare_remote_cids(), 1);
    }
}
