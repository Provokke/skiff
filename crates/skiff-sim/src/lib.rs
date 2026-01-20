//! skiff-sim: a deterministic network simulator for `skiff_quic::Connection`.
//!
//! Two connections (client and server) exchange datagrams over a pair of
//! one-way [`Link`]s in **virtual time**: nothing sleeps, the clock jumps to
//! the next datagram arrival or connection timer. Each link models
//! propagation delay, random loss, reordering (extra random delay),
//! duplication, and a bottleneck with finite bandwidth and a drop-tail
//! queue. Randomness comes from a seeded `rand::rngs::StdRng`, so a seed
//! reproduces the same link behaviour; TLS randoms and connection IDs come
//! from the OS, so runs repeat in timing and loss pattern but not byte for
//! byte.
//!
//! Each side has an address. The server sees the client's current address
//! on every datagram it delivers ([`Connection::recv_from`]), so a test can
//! move the client ([`Sim::client_addr`]) to model NAT rebinding or
//! migration; a server datagram addressed anywhere but the client's
//! current address is dropped ([`Sim::misaddressed`]).
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use skiff_quic::{ApiError, Connection, TransportConfig};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Simulation failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SimError {
    /// Creating the client connection failed.
    #[error(transparent)]
    Setup(#[from] ApiError),
    /// A connection kept producing datagrams without time advancing.
    #[error("livelock at {at:?}: {what}")]
    Livelock {
        /// Virtual time since the start.
        at: Duration,
        /// What looped.
        what: &'static str,
    },
    /// No datagram is in flight and no timer is armed.
    #[error("simulation stalled at {0:?}")]
    Stalled(Duration),
    /// The run's virtual-time budget ran out.
    #[error("not done after {0:?} of virtual time")]
    Timeout(Duration),
}

/// One direction of the network.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// One-way propagation delay.
    pub delay: Duration,
    /// Probability that a datagram is lost.
    pub loss: f64,
    /// Probability that a datagram is delayed by up to `reorder_max` extra,
    /// letting later datagrams overtake it.
    pub reorder: f64,
    /// Largest extra delay of a reordered datagram.
    pub reorder_max: Duration,
    /// Probability that a datagram is delivered twice.
    pub duplicate: f64,
    /// Bottleneck rate in bytes per second (`None`: unlimited).
    pub bandwidth: Option<u64>,
    /// Bytes the bottleneck queue holds before it drops (drop-tail).
    pub queue_limit: usize,
    /// Largest datagram the path carries; larger ones are dropped
    /// (`None`: no limit).
    pub mtu: Option<usize>,
}

impl LinkConfig {
    /// A perfect link with this one-way delay.
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            loss: 0.0,
            reorder: 0.0,
            reorder_max: delay,
            duplicate: 0.0,
            bandwidth: None,
            queue_limit: usize::MAX,
            mtu: None,
        }
    }

    /// Sets the loss probability.
    pub fn loss(mut self, p: f64) -> Self {
        self.loss = p;
        self
    }

    /// Sets the reordering probability (extra delay up to `2 * delay`).
    pub fn reorder(mut self, p: f64) -> Self {
        self.reorder = p;
        self.reorder_max = 2 * self.delay;
        self
    }

    /// Sets the duplication probability.
    pub fn duplicate(mut self, p: f64) -> Self {
        self.duplicate = p;
        self
    }

    /// Sets a bottleneck of `bytes_per_sec` with a `queue` byte buffer.
    pub fn bandwidth(mut self, bytes_per_sec: u64, queue: usize) -> Self {
        self.bandwidth = Some(bytes_per_sec);
        self.queue_limit = queue;
        self
    }

    /// Drops datagrams larger than `bytes`.
    pub fn mtu(mut self, bytes: usize) -> Self {
        self.mtu = Some(bytes);
        self
    }
}

/// Link counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Datagrams offered to the link.
    pub offered: u64,
    /// Datagrams delivered (duplicates included).
    pub delivered: u64,
    /// Bytes delivered.
    pub bytes_delivered: u64,
    /// Datagrams dropped by random loss.
    pub lost: u64,
    /// Datagrams dropped because the bottleneck queue was full.
    pub queue_drops: u64,
    /// Datagrams dropped by [`Link::drop_next`] or [`Link::blackhole`].
    pub forced_drops: u64,
    /// Datagrams dropped for being larger than the link MTU.
    pub too_big: u64,
    /// Extra copies delivered.
    pub duplicated: u64,
    /// Datagrams given extra delay.
    pub reordered: u64,
}

/// A one-way link.
#[derive(Debug)]
pub struct Link {
    cfg: LinkConfig,
    rng: StdRng,
    in_flight: BinaryHeap<Reverse<(Instant, u64, Vec<u8>)>>,
    seq: u64,
    tx_free_at: Option<Instant>,
    /// Drops the next this many offered datagrams (then counts down).
    pub drop_next: u64,
    /// Drops everything while set.
    pub blackhole: bool,
    /// Counters.
    pub stats: LinkStats,
}

impl Link {
    /// A link with its own seeded random stream.
    pub fn new(cfg: LinkConfig, seed: u64) -> Self {
        Self {
            cfg,
            rng: StdRng::seed_from_u64(seed),
            in_flight: BinaryHeap::new(),
            seq: 0,
            tx_free_at: None,
            drop_next: 0,
            blackhole: false,
            stats: LinkStats::default(),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &LinkConfig {
        &self.cfg
    }

    fn chance(&mut self, p: f64) -> bool {
        // Never panics: NaN and out-of-range probabilities just saturate.
        p > 0.0 && self.rng.random::<f64>() < p
    }

    /// Offers a datagram at `now`.
    pub fn push(&mut self, now: Instant, d: &[u8]) {
        self.stats.offered += 1;
        if self.blackhole || self.drop_next > 0 {
            self.drop_next = self.drop_next.saturating_sub(1);
            self.stats.forced_drops += 1;
            return;
        }
        if self.cfg.mtu.is_some_and(|m| d.len() > m) {
            self.stats.too_big += 1;
            return;
        }
        if self.chance(self.cfg.loss) {
            self.stats.lost += 1;
            return;
        }
        let depart = match self.cfg.bandwidth {
            Some(rate) if rate > 0 => {
                let start = self.tx_free_at.map_or(now, |t| t.max(now));
                let backlog = start.saturating_duration_since(now);
                let queued = backlog.as_secs_f64() * rate as f64;
                if queued + d.len() as f64 > self.cfg.queue_limit as f64 {
                    self.stats.queue_drops += 1;
                    return;
                }
                let done = start + Duration::from_secs_f64(d.len() as f64 / rate as f64);
                self.tx_free_at = Some(done);
                done
            }
            _ => now,
        };
        let mut at = depart + self.cfg.delay;
        if self.chance(self.cfg.reorder) {
            self.stats.reordered += 1;
            let max = self.cfg.reorder_max.as_secs_f64();
            at += Duration::from_secs_f64(self.rng.random::<f64>() * max);
        }
        if self.chance(self.cfg.duplicate) {
            self.stats.duplicated += 1;
            self.enqueue(at + Duration::from_micros(500), d.to_vec());
        }
        self.enqueue(at, d.to_vec());
    }

    fn enqueue(&mut self, at: Instant, d: Vec<u8>) {
        self.seq += 1;
        self.in_flight.push(Reverse((at, self.seq, d)));
    }

    /// The next datagram due at or before `now`, earliest first.
    pub fn pop_due(&mut self, now: Instant) -> Option<Vec<u8>> {
        let due = self.in_flight.peek().is_some_and(|Reverse(x)| x.0 <= now);
        if !due {
            return None;
        }
        let Reverse((_, _, d)) = self.in_flight.pop()?;
        self.stats.delivered += 1;
        self.stats.bytes_delivered += d.len() as u64;
        Some(d)
    }

    /// When the next datagram arrives.
    pub fn next_arrival(&self) -> Option<Instant> {
        self.in_flight.peek().map(|Reverse(x)| x.0)
    }
}

/// Everything a simulation needs.
#[derive(Clone)]
pub struct SimConfig {
    /// Client TLS configuration.
    pub client_tls: Arc<rustls::ClientConfig>,
    /// Name the client verifies the server certificate against.
    pub server_name: String,
    /// Server TLS configuration.
    pub server_tls: Arc<rustls::ServerConfig>,
    /// Client transport settings.
    pub client: TransportConfig,
    /// Server transport settings.
    pub server: TransportConfig,
    /// Client-to-server link.
    pub c2s: LinkConfig,
    /// Server-to-client link.
    pub s2c: LinkConfig,
    /// Seed for both links.
    pub seed: u64,
}

/// Datagrams one connection may emit at a single instant before the
/// simulation reports a livelock.
const MAX_BURST: u64 = 100_000;
/// Steps at one instant before the simulation reports a livelock.
const MAX_SAME_INSTANT: u64 = 100_000;

/// A client and a server connection joined by two links.
pub struct Sim {
    /// The client.
    pub client: Connection,
    /// The server, once the client's first Initial arrived.
    pub server: Option<Connection>,
    /// Client-to-server link.
    pub c2s: Link,
    /// Server-to-client link.
    pub s2c: Link,
    /// Current virtual time.
    pub now: Instant,
    /// The client's address as the server sees it; change it to move the
    /// client.
    pub client_addr: SocketAddr,
    /// The server's address.
    pub server_addr: SocketAddr,
    /// Server datagrams dropped because they were sent to an address the
    /// client is no longer at.
    pub misaddressed: u64,
    start: Instant,
    server_tls: Arc<rustls::ServerConfig>,
    server_config: TransportConfig,
    buf: Vec<u8>,
    same_instant: u64,
    /// Steps taken.
    pub steps: u64,
}

impl Sim {
    /// Creates the client connection; the server is created when the
    /// client's first Initial arrives.
    pub fn new(cfg: SimConfig) -> Result<Self, SimError> {
        let start = Instant::now();
        let client = Connection::connect(cfg.client_tls, &cfg.server_name, cfg.client, start)?;
        Ok(Self {
            client,
            server: None,
            c2s: Link::new(cfg.c2s, cfg.seed),
            s2c: Link::new(cfg.s2c, cfg.seed ^ 0x9e37_79b9_7f4a_7c15),
            now: start,
            client_addr: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 5000)),
            server_addr: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
            misaddressed: 0,
            start,
            server_tls: cfg.server_tls,
            server_config: cfg.server,
            buf: vec![0; 65_536],
            same_instant: 0,
            steps: 0,
        })
    }

    /// Virtual time since the start.
    pub fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    fn livelock(&self, what: &'static str) -> SimError {
        SimError::Livelock {
            at: self.elapsed(),
            what,
        }
    }

    /// Sends, delivers and, when nothing else can happen at this instant,
    /// advances the clock to the next event. `Ok(false)` means nothing can
    /// ever happen again (no datagram in flight, no timer armed).
    pub fn step(&mut self) -> Result<bool, SimError> {
        self.step_capped(None)
    }

    /// Like [`Sim::step`], but the clock never moves past `cap`: when the
    /// next event is later, time stops at `cap` (nothing fires).
    fn step_capped(&mut self, cap: Option<Instant>) -> Result<bool, SimError> {
        self.steps += 1;
        let mut progressed = false;
        let mut burst = 0u64;
        loop {
            let (n, _) = self.client.send_with_addr(&mut self.buf, self.now);
            let Some(d) = self.buf.get(..n).filter(|_| n > 0) else {
                break;
            };
            self.c2s.push(self.now, d);
            progressed = true;
            burst += 1;
            if burst > MAX_BURST {
                return Err(self.livelock("client send"));
            }
        }
        if let Some(s) = self.server.as_mut() {
            burst = 0;
            loop {
                let (n, to) = s.send_with_addr(&mut self.buf, self.now);
                let Some(d) = self.buf.get(..n).filter(|_| n > 0) else {
                    break;
                };
                if to.is_some_and(|a| a != self.client_addr) {
                    self.misaddressed += 1;
                } else {
                    self.s2c.push(self.now, d);
                }
                progressed = true;
                burst += 1;
                if burst > MAX_BURST {
                    return Err(self.livelock("server send"));
                }
            }
        }
        while let Some(mut d) = self.c2s.pop_due(self.now) {
            progressed = true;
            if self.server.is_none() {
                if let Ok(s) = Connection::accept(
                    self.server_tls.clone(),
                    self.server_config.clone(),
                    &d,
                    self.now,
                ) {
                    self.server = Some(s);
                }
            }
            if let Some(s) = self.server.as_mut() {
                s.recv_from(&mut d, self.client_addr, self.now);
            }
        }
        while let Some(mut d) = self.s2c.pop_due(self.now) {
            progressed = true;
            self.client.recv_from(&mut d, self.server_addr, self.now);
        }
        if progressed {
            self.same_instant += 1;
            if self.same_instant > MAX_SAME_INSTANT {
                return Err(self.livelock("virtual time stuck"));
            }
            return Ok(true);
        }
        self.same_instant = 0;
        let next = [
            self.c2s.next_arrival(),
            self.s2c.next_arrival(),
            self.client.timeout(),
            self.server.as_ref().and_then(Connection::timeout),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(t) = next else {
            if let Some(c) = cap.filter(|c| *c > self.now) {
                self.now = c;
                return Ok(true);
            }
            return Ok(false);
        };
        if let Some(c) = cap.filter(|c| t > *c && *c > self.now) {
            self.now = c;
            return Ok(true);
        }
        // A timer already in the past fires now; then time moves on.
        self.now = if t > self.now {
            t
        } else {
            self.now + Duration::from_millis(1)
        };
        if self.client.timeout().is_some_and(|x| x <= self.now) {
            self.client.on_timeout(self.now);
        }
        if let Some(s) = self.server.as_mut() {
            if s.timeout().is_some_and(|x| x <= self.now) {
                s.on_timeout(self.now);
            }
        }
        Ok(true)
    }

    /// Lets `d` of virtual time pass, delivering and firing everything due
    /// in it, without jumping past its end (to an idle timeout, say).
    pub fn run_for(&mut self, d: Duration) -> Result<(), SimError> {
        let end = self.now + d;
        while self.now < end {
            if !self.step_capped(Some(end))? {
                break;
            }
        }
        Ok(())
    }

    /// Steps until `done` returns true (it is called before every step and
    /// is where the test's applications run), failing after `budget` of
    /// virtual time or when the simulation stalls.
    pub fn run(
        &mut self,
        budget: Duration,
        mut done: impl FnMut(&mut Self) -> bool,
    ) -> Result<(), SimError> {
        loop {
            if done(self) {
                return Ok(());
            }
            if self.elapsed() > budget {
                return Err(SimError::Timeout(budget));
            }
            if !self.step()? {
                return if done(self) {
                    Ok(())
                } else {
                    Err(SimError::Stalled(self.elapsed()))
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_delay_loss_and_bandwidth() {
        let t0 = Instant::now();
        let mut l = Link::new(LinkConfig::new(Duration::from_millis(10)), 1);
        l.push(t0, &[1; 100]);
        assert_eq!(l.next_arrival(), Some(t0 + Duration::from_millis(10)));
        assert_eq!(l.pop_due(t0 + Duration::from_millis(9)), None);
        assert_eq!(
            l.pop_due(t0 + Duration::from_millis(10)),
            Some(vec![1; 100])
        );

        // 1000 B/s and a 3000-byte queue: 1000-byte datagrams leave 1 s
        // apart; the fourth offered at once overflows the queue.
        let cfg = LinkConfig::new(Duration::ZERO).bandwidth(1000, 3000);
        let mut l = Link::new(cfg, 1);
        for _ in 0..4 {
            l.push(t0, &[0; 1000]);
        }
        assert_eq!(l.stats.queue_drops, 1);
        let mut arrivals = Vec::new();
        while let Some(t) = l.next_arrival() {
            l.pop_due(t);
            arrivals.push(t - t0);
        }
        assert_eq!(
            arrivals,
            [1, 2, 3].map(Duration::from_secs).to_vec(),
            "serialisation delay"
        );

        let mut l = Link::new(LinkConfig::new(Duration::ZERO).loss(0.25), 7);
        for _ in 0..10_000 {
            l.push(t0, &[0]);
        }
        assert!((2200..2800).contains(&l.stats.lost), "{}", l.stats.lost);

        // Same seed, same pattern.
        let run = |seed| {
            let cfg = LinkConfig::new(Duration::from_millis(5))
                .loss(0.3)
                .reorder(0.3);
            let mut l = Link::new(cfg, seed);
            (0..200u8).for_each(|i| l.push(t0, &[i]));
            let mut out = Vec::new();
            while let Some(t) = l.next_arrival() {
                out.extend(l.pop_due(t));
            }
            out
        };
        assert_eq!(run(3), run(3));
        assert_ne!(run(3), run(4));
    }
}
