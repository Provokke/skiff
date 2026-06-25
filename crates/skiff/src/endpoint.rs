//! A single-threaded UDP endpoint: one socket, many connections.
//!
//! Incoming datagrams are routed by their destination connection ID (DCID):
//! short headers carry one of our 8-byte CIDs, long headers carry an
//! explicit DCID. A short header for an unknown CID is either a stateless
//! reset for one of our connections (its last 16 bytes are the peer's token;
//! [`Connection::is_stateless_reset`]) or gets a stateless reset in return
//! (rate limited). Every CID a connection issued (NEW_CONNECTION_ID) and the
//! peer has not retired is routed, so a peer may switch CIDs at any time. A
//! server also routes the client's original DCID until the connection ends,
//! so retransmitted client Initials reach the connection they created. The
//! source address of every datagram goes to the connection
//! ([`Connection::recv_from`]), which decides whether the peer migrated;
//! datagrams go wherever the connection says
//! ([`Connection::send_with_addr`]). An Initial for an unknown DCID creates a server connection
//! (with [`Endpoint::set_retry`], only once it carries a valid Retry token);
//! a long header with an unsupported version gets a Version Negotiation
//! packet (RFC 9000 6.1) when it is large enough to be a client Initial.
//! Everything else that matches no connection is dropped.
//!
//! The socket is blocking: [`Endpoint::drive`] waits for at most the
//! earliest connection timer (or the caller's limit) for one datagram, then
//! drains whatever else is queued without blocking, runs expired timers and
//! flushes every connection's outgoing datagrams.

use skiff_quic::conn::LOCAL_CID_LEN;
use skiff_quic::retry::{new_cid, retry_packet};
use skiff_quic::{ApiError, Connection, ResetKey, TokenKey, TransportConfig};
use skiff_wire::header::{self, Header, VERSION_1};
use skiff_wire::Writer;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Largest UDP payload we read.
const RECV_BUF: usize = 65_535;
/// Datagrams handled per [`Endpoint::drive`] call before timers and sends
/// get a turn.
const MAX_BATCH: usize = 256;
/// Smallest datagram we answer with Version Negotiation (RFC 9000 14.1).
const MIN_VN_TRIGGER: usize = 1200;
/// Stateless resets sent per second at most (RFC 9000 10.3: they cost
/// little to trigger, so they are rate limited).
const MAX_RESETS_PER_SEC: u32 = 64;
/// How long a Retry token stays valid.
const RETRY_TOKEN_LIFETIME_SECS: u64 = 10;

/// Errors from the endpoint.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// A socket operation failed.
    #[error("socket: {0}")]
    Io(#[from] io::Error),
    /// Creating a connection failed.
    #[error(transparent)]
    Connection(#[from] ApiError),
    /// The address did not resolve.
    #[error("address {0} did not resolve")]
    Resolve(String),
}

/// Identifies a connection owned by an [`Endpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionHandle(pub u64);

/// Endpoint counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointStats {
    /// Datagrams read from the socket.
    pub datagrams_received: u64,
    /// Datagrams written to the socket.
    pub datagrams_sent: u64,
    /// Datagrams that matched no connection and were dropped.
    pub datagrams_dropped: u64,
    /// Server connections created from client Initials.
    pub accepted: u64,
    /// Version Negotiation packets sent.
    pub version_negotiations: u64,
    /// `send_to` failures (the datagram is lost; recovery resends).
    pub send_errors: u64,
    /// Stateless resets sent for short-header datagrams to unknown CIDs.
    pub stateless_resets_sent: u64,
    /// Unroutable datagrams handed to a connection because they ended with
    /// its peer's stateless reset token.
    pub stateless_resets_received: u64,
    /// Retry packets sent (server with [`Endpoint::set_retry`]).
    pub retries_sent: u64,
    /// Client Initials dropped because their token was not a valid Retry
    /// token for that address and CID (forged, expired or replayed from
    /// elsewhere).
    pub invalid_tokens: u64,
}

struct Entry {
    conn: Connection,
    peer: SocketAddr,
    cids: Vec<Vec<u8>>,
    /// The client's original DCID (server connections).
    odcid: Option<Vec<u8>>,
    /// [`Connection::local_cids_generation`] when `cids` was last synced.
    cid_gen: u64,
    routed: bool,
}

/// What the invariant header fields (RFC 8999) say about a datagram.
#[derive(Debug, PartialEq, Eq)]
enum Kind<'a> {
    /// Short header; the DCID is our CID length.
    Short { dcid: &'a [u8] },
    /// Long header of QUIC v1 (or Version Negotiation, version 0).
    Long { dcid: &'a [u8], initial: bool },
    /// Long header with a version we do not support.
    Unsupported { dcid: &'a [u8], scid: &'a [u8] },
}

fn classify(d: &[u8]) -> Option<Kind<'_>> {
    let first = *d.first()?;
    if first & 0x80 == 0 {
        return Some(Kind::Short {
            dcid: d.get(1..1 + LOCAL_CID_LEN)?,
        });
    }
    let version = u32::from_be_bytes(d.get(1..5)?.try_into().ok()?);
    let dlen = usize::from(*d.get(5)?);
    if dlen > header::MAX_CID_LEN {
        return None;
    }
    let dcid = d.get(6..6 + dlen)?;
    let slen = usize::from(*d.get(6 + dlen)?);
    if slen > header::MAX_CID_LEN {
        return None;
    }
    let scid = d.get(7 + dlen..7 + dlen + slen)?;
    match version {
        VERSION_1 => Some(Kind::Long {
            dcid,
            initial: (first >> 4) & 0x03 == 0,
        }),
        0 => Some(Kind::Long {
            dcid,
            initial: false,
        }),
        _ => Some(Kind::Unsupported { dcid, scid }),
    }
}

/// A UDP socket plus the connections multiplexed over it.
pub struct Endpoint {
    socket: UdpSocket,
    nonblocking: bool,
    server: Option<Arc<rustls::ServerConfig>>,
    config: TransportConfig,
    conns: BTreeMap<ConnectionHandle, Entry>,
    routes: HashMap<Vec<u8>, ConnectionHandle>,
    incoming: VecDeque<ConnectionHandle>,
    next_handle: u64,
    max_connections: usize,
    recv_buf: Vec<u8>,
    send_buf: Vec<u8>,
    stats: EndpointStats,
    reset_key: Option<ResetKey>,
    /// Start of the current one-second reset window and resets sent in it.
    reset_window: (Instant, u32),
    /// Key for Retry tokens; `Some` when Retry is on.
    retry: Option<TokenKey>,
}

impl core::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Endpoint")
            .field("local_addr", &self.socket.local_addr().ok())
            .field("server", &self.server.is_some())
            .field("connections", &self.conns.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl Endpoint {
    /// Binds a UDP socket. With `server` set, client Initials for unknown
    /// connection IDs are accepted as new connections (see
    /// [`Endpoint::accept`]); without it only [`Endpoint::connect`] creates
    /// connections.
    pub fn bind(
        addr: impl ToSocketAddrs,
        server: Option<Arc<rustls::ServerConfig>>,
        config: TransportConfig,
    ) -> Result<Self, EndpointError> {
        Ok(Self::new(UdpSocket::bind(addr)?, server, config))
    }

    /// Wraps an already bound socket (switched to blocking mode on use).
    ///
    /// Every connection gets the same stateless reset key:
    /// `config.reset_key`, or a random one. Give a fixed key to answer, after
    /// a restart, packets for connections the endpoint no longer knows with
    /// a stateless reset the peer recognises.
    pub fn new(
        socket: UdpSocket,
        server: Option<Arc<rustls::ServerConfig>>,
        mut config: TransportConfig,
    ) -> Self {
        let reset_key = config.reset_key.clone().or_else(ResetKey::random);
        config.reset_key.clone_from(&reset_key);
        Self {
            reset_key,
            reset_window: (Instant::now(), 0),
            retry: None,
            socket,
            nonblocking: false,
            server,
            config,
            conns: BTreeMap::new(),
            routes: HashMap::new(),
            incoming: VecDeque::new(),
            next_handle: 0,
            max_connections: 1024,
            recv_buf: vec![0; RECV_BUF],
            send_buf: vec![0; 16_384],
            stats: EndpointStats::default(),
        }
    }

    /// Caps the number of live connections; further client Initials are
    /// dropped. The default is 1024.
    pub fn set_max_connections(&mut self, n: usize) {
        self.max_connections = n;
    }

    /// Server: answers every client Initial that carries no valid token with
    /// a Retry (RFC 9000 8.1.2), so a connection is only created once the
    /// client proved it receives packets at its address. Tokens are
    /// HMAC-bound to the address and CIDs and live 10 seconds. Returns
    /// whether Retry is on (it stays off if the system RNG fails).
    pub fn set_retry(&mut self, on: bool) -> bool {
        self.retry = if on { TokenKey::random() } else { None };
        self.retry.is_some()
    }

    /// Server: like [`Endpoint::set_retry`] with a given token key (e.g.
    /// shared by several endpoints).
    pub fn set_retry_key(&mut self, key: Option<TokenKey>) {
        self.retry = key;
    }

    /// The bound address.
    pub fn local_addr(&self) -> Result<SocketAddr, EndpointError> {
        Ok(self.socket.local_addr()?)
    }

    /// Counters.
    pub fn stats(&self) -> &EndpointStats {
        &self.stats
    }

    /// Starts a client connection to `addr`, verifying the certificate
    /// against `server_name`. The handshake runs in [`Endpoint::drive`].
    pub fn connect(
        &mut self,
        tls: Arc<rustls::ClientConfig>,
        server_name: &str,
        addr: impl ToSocketAddrs,
    ) -> Result<ConnectionHandle, EndpointError> {
        let peer = resolve(addr)?;
        let conn = Connection::connect(tls, server_name, self.config.clone(), Instant::now())?;
        Ok(self.insert(conn, peer, None))
    }

    fn insert(
        &mut self,
        conn: Connection,
        peer: SocketAddr,
        odcid: Option<Vec<u8>>,
    ) -> ConnectionHandle {
        let h = ConnectionHandle(self.next_handle);
        self.next_handle += 1;
        let mut cids = conn.local_cids();
        cids.extend(odcid.clone());
        for c in &cids {
            self.routes.insert(c.clone(), h);
        }
        self.conns.insert(
            h,
            Entry {
                cid_gen: conn.local_cids_generation(),
                conn,
                peer,
                cids,
                odcid,
                routed: true,
            },
        );
        h
    }

    /// Routes the CIDs a connection issued since the last sync and stops
    /// routing the ones its peer retired.
    fn sync_routes(&mut self, h: ConnectionHandle) {
        let Some(e) = self.conns.get_mut(&h) else {
            return;
        };
        let gen = e.conn.local_cids_generation();
        if !e.routed || gen == e.cid_gen {
            return;
        }
        e.cid_gen = gen;
        let mut now = e.conn.local_cids();
        now.extend(e.odcid.clone());
        let old = core::mem::replace(&mut e.cids, now.clone());
        for c in old.iter().filter(|c| !now.contains(c)) {
            if self.routes.get(c) == Some(&h) {
                self.routes.remove(c);
            }
        }
        for c in now {
            self.routes.entry(c).or_insert(h);
        }
    }

    /// The CIDs routed to a connection.
    pub fn routed_cids(&self, h: ConnectionHandle) -> Vec<Vec<u8>> {
        self.routes
            .iter()
            .filter(|(_, v)| **v == h)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The next server connection created since the last call.
    pub fn accept(&mut self) -> Option<ConnectionHandle> {
        self.incoming.pop_front()
    }

    /// A connection by handle (also after it closed, until
    /// [`Endpoint::remove_closed`]).
    pub fn connection(&mut self, h: ConnectionHandle) -> Option<&mut Connection> {
        self.conns.get_mut(&h).map(|e| &mut e.conn)
    }

    /// The peer address of a connection (follows the peer when it
    /// migrates).
    pub fn peer_addr(&self, h: ConnectionHandle) -> Option<SocketAddr> {
        self.conns.get(&h).map(|e| e.peer)
    }

    /// Handles of all connections, in creation order.
    pub fn handles(&self) -> Vec<ConnectionHandle> {
        self.conns.keys().copied().collect()
    }

    /// Number of connections (closed ones included until removed).
    pub fn len(&self) -> usize {
        self.conns.len()
    }

    /// Whether there are no connections.
    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    /// Forgets connections that reached their terminal state and returns
    /// their handles.
    pub fn remove_closed(&mut self) -> Vec<ConnectionHandle> {
        let closed: Vec<ConnectionHandle> = self
            .conns
            .iter()
            .filter(|(_, e)| e.conn.is_closed())
            .map(|(h, _)| *h)
            .collect();
        for h in &closed {
            if let Some(e) = self.conns.remove(h) {
                self.unroute(*h, &e.cids);
            }
        }
        closed
    }

    fn unroute(&mut self, h: ConnectionHandle, cids: &[Vec<u8>]) {
        for c in cids {
            if self.routes.get(c) == Some(&h) {
                self.routes.remove(c);
            }
        }
    }

    /// The earliest timer of any connection.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.conns.values().filter_map(|e| e.conn.timeout()).min()
    }

    /// One round of I/O: flushes pending sends, waits up to `max_wait` (or
    /// the earliest connection timer, if sooner) for a datagram, handles
    /// every queued datagram, runs expired timers and flushes again.
    pub fn drive(&mut self, max_wait: Duration) -> Result<(), EndpointError> {
        self.fire_timers(Instant::now());
        self.flush();
        let now = Instant::now();
        let limit = now + max_wait;
        let deadline = self.next_timeout().map_or(limit, |t| t.min(limit));
        let mut wait = deadline.saturating_duration_since(now);
        for _ in 0..MAX_BATCH {
            let Some((n, from)) = self.recv_from(wait)? else {
                break;
            };
            wait = Duration::ZERO;
            self.handle_datagram(n, from, Instant::now());
        }
        self.fire_timers(Instant::now());
        self.flush();
        Ok(())
    }

    fn recv_from(&mut self, wait: Duration) -> Result<Option<(usize, SocketAddr)>, EndpointError> {
        if wait.is_zero() {
            if !self.nonblocking {
                self.socket.set_nonblocking(true)?;
                self.nonblocking = true;
            }
        } else {
            if self.nonblocking {
                self.socket.set_nonblocking(false)?;
                self.nonblocking = false;
            }
            self.socket.set_read_timeout(Some(wait))?;
        }
        match self.socket.recv_from(&mut self.recv_buf) {
            Ok((n, from)) => {
                self.stats.datagrams_received += 1;
                Ok(Some((n, from)))
            }
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted
                // ICMP errors surface on some platforms; they carry nothing
                // for us (connections time out on their own).
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionRefused => Ok(None),
                _ => Err(e.into()),
            },
        }
    }

    fn handle_datagram(&mut self, n: usize, from: SocketAddr, now: Instant) {
        let Some(d) = self.recv_buf.get(..n) else {
            return;
        };
        let target = match classify(d) {
            Some(Kind::Short { dcid }) | Some(Kind::Long { dcid, .. })
                if self.routes.contains_key(dcid) =>
            {
                self.routes.get(dcid).copied()
            }
            Some(Kind::Long { initial: true, .. }) => self.accept_initial(n, from, now),
            Some(Kind::Short { dcid }) => {
                let dcid = dcid.to_vec();
                self.unknown_short(n, &dcid, from, now)
            }
            Some(Kind::Unsupported { dcid, scid }) => {
                if self.server.is_some() && n >= MIN_VN_TRIGGER {
                    let (dcid, scid) = (dcid.to_vec(), scid.to_vec());
                    self.send_version_negotiation(&dcid, &scid, from);
                } else {
                    self.stats.datagrams_dropped += 1;
                }
                None
            }
            _ => {
                self.stats.datagrams_dropped += 1;
                None
            }
        };
        let Some(h) = target else {
            return;
        };
        let Some(d) = self.recv_buf.get_mut(..n) else {
            return;
        };
        if let Some(e) = self.conns.get_mut(&h) {
            e.conn.recv_from(d, from, now);
        }
        self.sync_routes(h);
    }

    /// A short header for a CID nobody owns: a stateless reset from a peer
    /// that lost one of our connections (RFC 9000 10.3.1), or a packet for a
    /// connection we lost, which gets a stateless reset in return.
    fn unknown_short(
        &mut self,
        n: usize,
        dcid: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Option<ConnectionHandle> {
        self.stats.datagrams_dropped += 1;
        let d = self.recv_buf.get(..n)?;
        let reset_for = self
            .conns
            .iter()
            .find(|(_, e)| e.routed && e.conn.is_stateless_reset(d))
            .map(|(h, _)| *h);
        if reset_for.is_some() {
            self.stats.datagrams_dropped -= 1;
            self.stats.stateless_resets_received += 1;
            return reset_for;
        }
        let key = self.reset_key.as_ref()?;
        if now.duration_since(self.reset_window.0) >= Duration::from_secs(1) {
            self.reset_window = (now, 0);
        }
        if self.reset_window.1 >= MAX_RESETS_PER_SEC {
            return None;
        }
        let reset = key.stateless_reset(dcid, n)?;
        self.reset_window.1 += 1;
        self.stats.stateless_resets_sent += 1;
        self.send_datagram_to(&reset, from);
        None
    }

    fn accept_initial(
        &mut self,
        n: usize,
        from: SocketAddr,
        now: Instant,
    ) -> Option<ConnectionHandle> {
        let (Some(tls), Some(d)) = (self.server.clone(), self.recv_buf.get(..n)) else {
            self.stats.datagrams_dropped += 1;
            return None;
        };
        if self.conns.len() >= self.max_connections {
            self.stats.datagrams_dropped += 1;
            return None;
        }
        let accepted = match &self.retry {
            None => Connection::accept(tls, self.config.clone(), d, now),
            Some(key) => {
                let Ok(h) = Header::parse(d, LOCAL_CID_LEN) else {
                    self.stats.datagrams_dropped += 1;
                    return None;
                };
                let secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |t| t.as_secs());
                if h.token.is_empty() {
                    // RFC 9000 14.1: only a full-sized Initial earns a Retry.
                    if n >= skiff_quic::conn::MIN_INITIAL_SIZE {
                        let (dcid, scid) = (h.dcid.to_vec(), h.scid.to_vec());
                        self.send_retry(&dcid, &scid, from, secs);
                    } else {
                        self.stats.datagrams_dropped += 1;
                    }
                    return None;
                }
                match key.validate(h.token, from, h.dcid, secs, RETRY_TOKEN_LIFETIME_SECS) {
                    Some(odcid) => {
                        Connection::accept_retried(tls, self.config.clone(), d, &odcid, now)
                    }
                    None => {
                        self.stats.invalid_tokens += 1;
                        self.stats.datagrams_dropped += 1;
                        return None;
                    }
                }
            }
        };
        let Ok(conn) = accepted else {
            self.stats.datagrams_dropped += 1;
            return None;
        };
        let initial_dcid = conn.initial_dcid().to_vec();
        let h = self.insert(conn, from, Some(initial_dcid));
        self.stats.accepted += 1;
        self.incoming.push_back(h);
        Some(h)
    }

    /// Answers a token-less client Initial (to `odcid`, from `client_scid`)
    /// with a Retry from a fresh CID, which the client's next Initial must
    /// use as its Destination CID.
    fn send_retry(&mut self, odcid: &[u8], client_scid: &[u8], to: SocketAddr, secs: u64) {
        let Some(key) = &self.retry else {
            return;
        };
        let Some(scid) = new_cid() else {
            return;
        };
        let Some(token) = key.retry_token(to, odcid, &scid, secs) else {
            return;
        };
        let Some(pkt) = retry_packet(client_scid, &scid, odcid, &token) else {
            return;
        };
        self.stats.retries_sent += 1;
        self.send_datagram_to(&pkt, to);
    }

    fn send_version_negotiation(&mut self, dcid: &[u8], scid: &[u8], to: SocketAddr) {
        let mut out = [0u8; 64];
        let mut w = Writer::new(&mut out);
        // The response swaps the client's CIDs (RFC 9000 17.2.1).
        if header::write_version_negotiation(&mut w, scid, dcid, &[VERSION_1]).is_err() {
            return;
        }
        let len = w.position();
        let Some(pkt) = out.get(..len) else {
            return;
        };
        self.stats.version_negotiations += 1;
        self.send_datagram_to(pkt, to);
    }

    fn fire_timers(&mut self, now: Instant) {
        let mut closed = Vec::new();
        for (h, e) in self.conns.iter_mut() {
            if e.conn.timeout().is_some_and(|t| t <= now) {
                e.conn.on_timeout(now);
            }
            if e.routed && e.conn.is_closed() {
                e.routed = false;
                closed.push((*h, e.cids.clone()));
            }
        }
        // A closed connection no longer claims its CIDs.
        for (h, cids) in closed {
            self.unroute(h, &cids);
        }
    }

    /// Writes every connection's pending datagrams to the socket.
    pub fn flush(&mut self) {
        if self.nonblocking && self.socket.set_nonblocking(false).is_ok() {
            // Blocking sends wait for socket buffer space rather than
            // dropping datagrams the connection already counts as sent.
            self.nonblocking = false;
        }
        let now = Instant::now();
        let Self {
            conns,
            send_buf,
            socket,
            stats,
            ..
        } = self;
        for e in conns.values_mut() {
            loop {
                let (n, to) = e.conn.send_with_addr(send_buf, now);
                let Some(d) = send_buf.get(..n).filter(|_| n > 0) else {
                    break;
                };
                match socket.send_to(d, to.unwrap_or(e.peer)) {
                    Ok(_) => stats.datagrams_sent += 1,
                    Err(_) => stats.send_errors += 1,
                }
            }
            if let Some(a) = e.conn.remote_address() {
                e.peer = a;
            }
        }
        let handles: Vec<ConnectionHandle> = self.conns.keys().copied().collect();
        for h in handles {
            self.sync_routes(h);
        }
    }

    fn send_datagram_to(&mut self, d: &[u8], to: SocketAddr) {
        match self.socket.send_to(d, to) {
            Ok(_) => self.stats.datagrams_sent += 1,
            Err(_) => self.stats.send_errors += 1,
        }
    }
}

fn resolve(addr: impl ToSocketAddrs) -> Result<SocketAddr, EndpointError> {
    let mut it = addr.to_socket_addrs()?;
    it.next()
        .ok_or_else(|| EndpointError::Resolve("no addresses".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_short_long_and_unsupported() {
        let mut short = vec![0x41u8];
        short.extend_from_slice(&[7; 8]);
        short.extend_from_slice(&[0; 20]);
        assert_eq!(classify(&short), Some(Kind::Short { dcid: &[7; 8] }));
        assert_eq!(
            classify(&short[..5]),
            None,
            "short header shorter than a CID"
        );

        // Initial: type bits 00, 20-byte DCID (as quinn clients send).
        let mut initial = vec![0xc0u8, 0, 0, 0, 1, 20];
        initial.extend_from_slice(&[9; 20]);
        initial.extend_from_slice(&[8, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            classify(&initial),
            Some(Kind::Long {
                dcid: &[9; 20],
                initial: true
            })
        );
        let mut handshake = initial.clone();
        handshake[0] = 0xe0;
        assert_eq!(
            classify(&handshake),
            Some(Kind::Long {
                dcid: &[9; 20],
                initial: false
            })
        );
        let mut other = initial.clone();
        other[1..5].copy_from_slice(&0x1a2a_3a4au32.to_be_bytes());
        assert_eq!(
            classify(&other),
            Some(Kind::Unsupported {
                dcid: &[9; 20],
                scid: &[1, 2, 3, 4, 5, 6, 7, 8]
            })
        );
        let mut long_cid = initial.clone();
        long_cid[5] = 21;
        assert_eq!(classify(&long_cid), None, "CID over 20 bytes");
        assert_eq!(classify(&initial[..10]), None, "truncated DCID");
        assert_eq!(classify(&[]), None);
    }
}
