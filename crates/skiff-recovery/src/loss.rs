//! RFC 9002 Section 6 loss detection and probe timeout, generic over the
//! per-packet payload `T` (e.g. the frames a packet carried).

use crate::{RttEstimator, GRANULARITY};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Packet-reordering threshold (RFC 9002 6.1.1).
pub const PACKET_THRESHOLD: u64 = 3;

/// Packet number space index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Space {
    /// Initial packets.
    Initial = 0,
    /// Handshake packets.
    Handshake = 1,
    /// 0-RTT and 1-RTT packets.
    Data = 2,
}

const SPACES: [Space; 3] = [Space::Initial, Space::Handshake, Space::Data];

/// Metadata about a packet in flight.
#[derive(Debug, Clone)]
pub struct SentPacket<T> {
    /// Time the packet was sent.
    pub time_sent: Instant,
    /// Datagram bytes attributed to the packet.
    pub size: u64,
    /// Whether the packet elicits an ACK.
    pub ack_eliciting: bool,
    /// Caller payload (e.g. retransmittable frames).
    pub payload: T,
}

#[derive(Debug)]
struct SpaceState<T> {
    sent: BTreeMap<u64, SentPacket<T>>,
    largest_acked: Option<u64>,
    loss_time: Option<Instant>,
    last_ack_eliciting: Option<Instant>,
}

impl<T> Default for SpaceState<T> {
    fn default() -> Self {
        Self {
            sent: BTreeMap::new(),
            largest_acked: None,
            loss_time: None,
            last_ack_eliciting: None,
        }
    }
}

/// Outcome of processing an ACK or a timeout.
#[derive(Debug)]
pub struct Outcome<T> {
    /// Newly acknowledged packets.
    pub acked: Vec<(u64, SentPacket<T>)>,
    /// Packets declared lost.
    pub lost: Vec<(u64, SentPacket<T>)>,
}

impl<T> Default for Outcome<T> {
    fn default() -> Self {
        Self {
            acked: Vec::new(),
            lost: Vec::new(),
        }
    }
}

/// What a fired timer asks the caller to do.
#[derive(Debug)]
pub enum TimerAction<T> {
    /// Packets were declared lost by the time threshold.
    Lost(Vec<(u64, SentPacket<T>)>),
    /// Send up to two ack-eliciting probe packets in `Space`.
    Probe(Space),
    /// Nothing to do (timer was stale).
    None,
}

/// Loss detection state for one connection.
#[derive(Debug)]
pub struct LossDetector<T> {
    spaces: [SpaceState<T>; 3],
    /// RTT estimator fed from ACKs.
    pub rtt: RttEstimator,
    pto_count: u32,
    bytes_in_flight: u64,
    max_ack_delay: Duration,
    handshake_confirmed: bool,
    // Client anti-deadlock (RFC 9002 6.2.2.1): the space to probe while the
    // server has not yet validated our address, or `None` once it has.
    anti_deadlock: Option<Space>,
    last_ack_eliciting_any: Option<Instant>,
}

impl<T> LossDetector<T> {
    /// Creates a detector with the peer's max_ack_delay.
    pub fn new(max_ack_delay: Duration) -> Self {
        Self {
            spaces: Default::default(),
            rtt: RttEstimator::default(),
            pto_count: 0,
            bytes_in_flight: 0,
            max_ack_delay,
            handshake_confirmed: false,
            anti_deadlock: None,
            last_ack_eliciting_any: None,
        }
    }

    /// Updates the peer's max_ack_delay (learned from transport parameters).
    pub fn set_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.max_ack_delay = max_ack_delay;
    }

    /// Client anti-deadlock PTO (RFC 9002 6.2.2.1). While `Some(space)`
    /// (the server has not validated our address: no Handshake packet of
    /// ours acknowledged and handshake not confirmed), the PTO stays armed
    /// in `space` even with nothing in flight, so a server blocked by its
    /// anti-amplification limit gets a probe that unblocks it. `space` is
    /// Handshake once Handshake keys exist, else Initial.
    pub fn set_anti_deadlock(&mut self, space: Option<Space>) {
        self.anti_deadlock = space;
    }

    /// Bytes of ack-eliciting packets currently in flight.
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Packets of `space` not yet acknowledged or declared lost, oldest
    /// first (for a PTO probe that sends their data again).
    pub fn in_flight(&self, space: Space) -> impl Iterator<Item = (u64, &SentPacket<T>)> {
        self.spaces[space as usize]
            .sent
            .iter()
            .map(|(pn, p)| (*pn, p))
    }

    /// Consecutive PTO count (backoff exponent).
    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    /// Marks the handshake confirmed (enables Data-space PTO and ack_delay use).
    pub fn set_handshake_confirmed(&mut self) {
        self.handshake_confirmed = true;
    }

    /// Records a sent packet.
    pub fn on_packet_sent(&mut self, space: Space, pn: u64, pkt: SentPacket<T>) {
        if pkt.ack_eliciting {
            self.bytes_in_flight += pkt.size;
            self.spaces[space as usize].last_ack_eliciting = Some(pkt.time_sent);
            self.last_ack_eliciting_any = Some(pkt.time_sent);
        }
        self.spaces[space as usize].sent.insert(pn, pkt);
    }

    /// Discards a space's state (on key discard); its bytes leave flight.
    pub fn discard_space(&mut self, space: Space) {
        let s = &mut self.spaces[space as usize];
        for p in s.sent.values().filter(|p| p.ack_eliciting) {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(p.size);
        }
        *s = SpaceState::default();
        self.pto_count = 0;
    }

    /// Removes and returns a space's sent packets (their bytes leave
    /// flight), e.g. when a Retry means none of them was processed.
    pub fn take_space(&mut self, space: Space) -> Vec<(u64, SentPacket<T>)> {
        let s = core::mem::take(&mut self.spaces[space as usize]);
        for p in s.sent.values().filter(|p| p.ack_eliciting) {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(p.size);
        }
        self.pto_count = 0;
        s.sent.into_iter().collect()
    }

    /// Processes an ACK frame's ranges (inclusive, any order).
    pub fn on_ack_received(
        &mut self,
        space: Space,
        ranges: &[(u64, u64)],
        ack_delay: Duration,
        now: Instant,
    ) -> Outcome<T> {
        let mut out = Outcome::default();
        let Some(largest) = ranges.iter().map(|r| r.1).max() else {
            return out;
        };
        let s = &mut self.spaces[space as usize];
        s.largest_acked = Some(s.largest_acked.map_or(largest, |l| l.max(largest)));
        for &(lo, hi) in ranges {
            let pns: Vec<u64> = s.sent.range(lo..=hi).map(|(pn, _)| *pn).collect();
            for pn in pns {
                if let Some(p) = s.sent.remove(&pn) {
                    out.acked.push((pn, p));
                }
            }
        }
        if out.acked.is_empty() {
            return out;
        }
        out.acked.sort_by_key(|(pn, _)| *pn);
        if let Some((pn, p)) = out.acked.last() {
            if *pn == largest && out.acked.iter().any(|(_, p)| p.ack_eliciting) {
                let delay = if space == Space::Data && self.handshake_confirmed {
                    ack_delay.min(self.max_ack_delay)
                } else {
                    Duration::ZERO
                };
                self.rtt
                    .update(now.saturating_duration_since(p.time_sent), delay);
            }
        }
        for (_, p) in &out.acked {
            if p.ack_eliciting {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(p.size);
            }
        }
        out.lost = self.detect_lost(space, now);
        self.pto_count = 0;
        out
    }

    fn detect_lost(&mut self, space: Space, now: Instant) -> Vec<(u64, SentPacket<T>)> {
        let delay = self.rtt.loss_delay();
        let s = &mut self.spaces[space as usize];
        s.loss_time = None;
        let Some(largest) = s.largest_acked else {
            return Vec::new();
        };
        let lost_before = now.checked_sub(delay);
        let mut lost_pns = Vec::new();
        for (&pn, p) in s.sent.range(..largest) {
            let by_time = lost_before.is_some_and(|t| p.time_sent <= t);
            if by_time || largest >= pn + PACKET_THRESHOLD {
                lost_pns.push(pn);
            } else {
                let t = p.time_sent + delay;
                s.loss_time = Some(s.loss_time.map_or(t, |x| x.min(t)));
            }
        }
        let mut lost = Vec::new();
        for pn in lost_pns {
            if let Some(p) = s.sent.remove(&pn) {
                if p.ack_eliciting {
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(p.size);
                }
                lost.push((pn, p));
            }
        }
        lost
    }

    fn pto_base(&self, space: Space) -> Duration {
        let mad = if space == Space::Data {
            self.max_ack_delay
        } else {
            Duration::ZERO
        };
        let base = self.rtt.smoothed() + (self.rtt.var() * 4).max(GRANULARITY) + mad;
        base * 2u32.saturating_pow(self.pto_count.min(16))
    }

    /// The earliest loss-detection deadline, if any, with its space.
    pub fn timeout(&self) -> Option<(Instant, Space)> {
        if let Some(r) = SPACES
            .iter()
            .filter_map(|&sp| self.spaces[sp as usize].loss_time.map(|t| (t, sp)))
            .min_by_key(|x| x.0)
        {
            return Some(r);
        }
        if self.bytes_in_flight == 0 {
            let space = self.anti_deadlock?;
            let base = self.last_ack_eliciting_any?;
            return Some((base + self.pto_base(space), space));
        }
        // RFC 9002 A.8 (GetPtoTimeAndSpace): the PTO is for a space with
        // ack-eliciting packets in flight. Only if none qualifies (just
        // Application Data in flight before the handshake is confirmed, where
        // A.8 sets no timer) does the last Initial/Handshake send still arm
        // a probe, so a handshake retransmission held back by the congestion
        // window cannot stall the connection.
        let pick = |need_flight: bool| {
            SPACES
                .iter()
                .filter(|&&sp| sp != Space::Data || self.handshake_confirmed)
                .filter(|&&sp| {
                    !need_flight
                        || self.spaces[sp as usize]
                            .sent
                            .values()
                            .any(|p| p.ack_eliciting)
                })
                .filter_map(|&sp| {
                    self.spaces[sp as usize]
                        .last_ack_eliciting
                        .map(|t| (t + self.pto_base(sp), sp))
                })
                .min_by_key(|x| x.0)
        };
        pick(true).or_else(|| pick(false))
    }

    /// Handles the loss-detection timer firing at `now`.
    pub fn on_timeout(&mut self, now: Instant) -> TimerAction<T> {
        let Some((deadline, space)) = self.timeout() else {
            return TimerAction::None;
        };
        if now < deadline {
            return TimerAction::None;
        }
        if self.spaces[space as usize].loss_time.is_some() {
            return TimerAction::Lost(self.detect_lost(space, now));
        }
        self.pto_count += 1;
        if self.bytes_in_flight == 0 {
            // Anti-deadlock probe: re-arm from now (the probe we are asked to
            // send restarts it too, once sent).
            self.last_ack_eliciting_any = Some(now);
        }
        TimerAction::Probe(space)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: once a space's ack-eliciting packets are all acked, its
    /// last send time no longer arms the PTO; the probe goes to the space
    /// that still has data in flight (here the Handshake flight, not the
    /// acked Initial the peer may no longer have keys for).
    #[test]
    fn pto_skips_spaces_with_nothing_in_flight() {
        let t0 = Instant::now();
        let mut ld = LossDetector::new(ms(25));
        ld.on_packet_sent(Space::Initial, 0, pkt(t0));
        ld.on_packet_sent(Space::Handshake, 0, pkt(t0));
        assert_eq!(ld.timeout().map(|x| x.1), Some(Space::Initial));
        ld.on_ack_received(Space::Initial, &[(0, 0)], ms(0), t0 + ms(10));
        let (at, space) = ld.timeout().unwrap();
        assert_eq!(space, Space::Handshake);
        assert!(matches!(
            ld.on_timeout(at),
            TimerAction::Probe(Space::Handshake)
        ));
    }

    fn pkt(t: Instant) -> SentPacket<()> {
        SentPacket {
            time_sent: t,
            size: 1000,
            ack_eliciting: true,
            payload: (),
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn packet_threshold_loss() {
        let t0 = Instant::now();
        let mut ld = LossDetector::new(ms(25));
        for pn in 0..5 {
            ld.on_packet_sent(Space::Data, pn, pkt(t0));
        }
        assert_eq!(ld.bytes_in_flight(), 5000);
        // Ack 3 and 4 only: pn 0 and 1 are >= 3 below largest -> lost; 2 is not.
        let out = ld.on_ack_received(Space::Data, &[(3, 4)], ms(0), t0 + ms(10));
        assert_eq!(out.acked.len(), 2);
        let lost: Vec<u64> = out.lost.iter().map(|x| x.0).collect();
        assert_eq!(lost, vec![0, 1]);
        assert_eq!(ld.bytes_in_flight(), 1000);
        // pn 2 has a time-threshold loss timer armed: 9/8 * 10ms after its send.
        let (deadline, sp) = ld.timeout().unwrap();
        assert_eq!(sp, Space::Data);
        assert_eq!(deadline, t0 + ld.rtt.loss_delay());
        match ld.on_timeout(deadline) {
            TimerAction::Lost(l) => assert_eq!(l[0].0, 2),
            other => panic!("expected loss, got {other:?}"),
        }
        assert_eq!(ld.bytes_in_flight(), 0);
        assert!(ld.timeout().is_none());
    }

    #[test]
    fn rtt_sample_only_from_newly_acked_largest() {
        let t0 = Instant::now();
        let mut ld = LossDetector::<()>::new(ms(25));
        ld.on_packet_sent(Space::Initial, 0, pkt(t0));
        ld.on_ack_received(Space::Initial, &[(0, 0)], ms(5), t0 + ms(40));
        // ack_delay ignored in Initial space.
        assert_eq!(ld.rtt.smoothed(), ms(40));
        // Duplicate ACK changes nothing.
        let out = ld.on_ack_received(Space::Initial, &[(0, 0)], ms(5), t0 + ms(400));
        assert!(out.acked.is_empty());
        assert_eq!(ld.rtt.smoothed(), ms(40));
    }

    #[test]
    fn pto_backoff_and_reset() {
        let t0 = Instant::now();
        let mut ld = LossDetector::<()>::new(ms(25));
        ld.on_packet_sent(Space::Initial, 0, pkt(t0));
        ld.on_ack_received(Space::Initial, &[(0, 0)], ms(0), t0 + ms(100));
        // srtt=100, var=50 -> PTO = 100 + 200 = 300ms (no max_ack_delay in Initial).
        let t1 = t0 + ms(100);
        ld.on_packet_sent(Space::Initial, 1, pkt(t1));
        let (d1, sp) = ld.timeout().unwrap();
        assert_eq!((d1, sp), (t1 + ms(300), Space::Initial));
        assert!(matches!(ld.on_timeout(d1 - ms(1)), TimerAction::None));
        assert!(matches!(
            ld.on_timeout(d1),
            TimerAction::Probe(Space::Initial)
        ));
        assert_eq!(ld.pto_count(), 1);
        assert_eq!(ld.timeout().unwrap().0, t1 + ms(600), "doubles");
        assert!(matches!(ld.on_timeout(t1 + ms(600)), TimerAction::Probe(_)));
        assert_eq!(ld.timeout().unwrap().0, t1 + ms(1200), "doubles again");
        // An ACK resets the backoff.
        ld.on_packet_sent(Space::Initial, 2, pkt(t1 + ms(1200)));
        ld.on_ack_received(Space::Initial, &[(2, 2)], ms(0), t1 + ms(1300));
        assert_eq!(ld.pto_count(), 0);
    }

    #[test]
    fn data_space_pto_waits_for_confirmation() {
        let t0 = Instant::now();
        let mut ld = LossDetector::<()>::new(ms(25));
        ld.on_packet_sent(Space::Data, 0, pkt(t0));
        assert!(ld.timeout().is_none());
        ld.set_handshake_confirmed();
        // Default RTT 333ms, var 166.5ms -> 333 + 666 + 25.
        assert_eq!(ld.timeout().unwrap().0, t0 + ms(333) + ms(666) + ms(25));
    }

    #[test]
    fn client_anti_deadlock_arms_pto_with_nothing_in_flight() {
        let t0 = Instant::now();
        let mut ld = LossDetector::<()>::new(ms(25));
        ld.on_packet_sent(Space::Initial, 0, pkt(t0));
        ld.on_ack_received(Space::Initial, &[(0, 0)], ms(0), t0 + ms(100));
        assert_eq!(ld.bytes_in_flight(), 0);
        assert!(ld.timeout().is_none(), "no timer without anti-deadlock");
        ld.set_anti_deadlock(Some(Space::Handshake));
        // srtt 100, var 50 -> PTO 300ms after the last ack-eliciting send.
        let (d, sp) = ld.timeout().unwrap();
        assert_eq!((d, sp), (t0 + ms(300), Space::Handshake));
        assert!(matches!(
            ld.on_timeout(d),
            TimerAction::Probe(Space::Handshake)
        ));
        // Backed off and re-armed from the firing time.
        assert_eq!(ld.timeout().unwrap().0, d + ms(600));
        ld.set_anti_deadlock(None);
        assert!(ld.timeout().is_none());
    }

    #[test]
    fn discard_space_removes_in_flight() {
        let t0 = Instant::now();
        let mut ld = LossDetector::<()>::new(ms(25));
        ld.on_packet_sent(Space::Initial, 0, pkt(t0));
        ld.on_packet_sent(Space::Handshake, 0, pkt(t0));
        ld.discard_space(Space::Initial);
        assert_eq!(ld.bytes_in_flight(), 1000);
        assert_eq!(ld.timeout().unwrap().1, Space::Handshake);
    }
}
