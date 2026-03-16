//! Couples [`LossDetector`] with a [`CongestionController`]: acknowledged
//! bytes grow the window, losses trigger congestion events, and
//! persistent congestion (RFC 9002 Section 7.6) collapses the window.

use crate::loss::{LossDetector, Outcome, SentPacket, Space};
use crate::{CongestionController, GRANULARITY};
use std::time::{Duration, Instant};

/// RFC 9002 kPersistentCongestionThreshold.
pub const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// Loss detection plus congestion control for one connection path.
pub struct Recovery<T> {
    /// The loss detector (RTT estimator lives inside).
    pub loss: LossDetector<T>,
    cc: Box<dyn CongestionController>,
    max_ack_delay: Duration,
    first_rtt_sample: Option<Instant>,
}

impl<T> Recovery<T> {
    /// Creates recovery state with the given controller.
    pub fn new(cc: Box<dyn CongestionController>, max_ack_delay: Duration) -> Self {
        Self {
            loss: LossDetector::new(max_ack_delay),
            cc,
            max_ack_delay,
            first_rtt_sample: None,
        }
    }

    /// Updates the peer's max_ack_delay (from its transport parameters).
    pub fn set_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.max_ack_delay = max_ack_delay;
        self.loss.set_max_ack_delay(max_ack_delay);
    }

    /// Starts over on a new network path (RFC 9000 9.4): a fresh
    /// congestion controller and RTT estimate. Packets already in flight
    /// stay tracked and are acknowledged or declared lost as usual.
    pub fn reset_for_new_path(&mut self, cc: Box<dyn CongestionController>) {
        self.cc = cc;
        self.loss.rtt = crate::RttEstimator::default();
        self.first_rtt_sample = None;
    }

    /// The datagram size changed (path MTU discovery).
    pub fn set_max_datagram_size(&mut self, bytes: u64) {
        self.cc.set_max_datagram_size(bytes);
    }

    /// Current congestion window.
    pub fn window(&self) -> u64 {
        self.cc.window()
    }

    /// Whether `bytes` more ack-eliciting data may be sent now.
    pub fn can_send(&self, bytes: u64) -> bool {
        self.loss.bytes_in_flight() + bytes <= self.cc.window()
    }

    /// Records a sent packet.
    pub fn on_packet_sent(&mut self, space: Space, pn: u64, pkt: SentPacket<T>) {
        self.loss.on_packet_sent(space, pn, pkt);
    }

    /// Processes an ACK and feeds the controller.
    pub fn on_ack_received(
        &mut self,
        space: Space,
        ranges: &[(u64, u64)],
        ack_delay: Duration,
        now: Instant,
    ) -> Outcome<T> {
        let out = self.loss.on_ack_received(space, ranges, ack_delay, now);
        if !out.acked.is_empty() && self.first_rtt_sample.is_none() {
            self.first_rtt_sample = Some(now);
        }
        for (_, p) in out.acked.iter().filter(|(_, p)| p.ack_eliciting) {
            self.cc.on_ack(p.size, p.time_sent, now, &self.loss.rtt);
        }
        self.on_lost(&out.lost, now);
        out
    }

    /// Feeds packets declared lost (by ACK processing or a timer) to the controller.
    pub fn on_lost(&mut self, lost: &[(u64, SentPacket<T>)], now: Instant) {
        let eliciting: Vec<&(u64, SentPacket<T>)> =
            lost.iter().filter(|(_, p)| p.ack_eliciting).collect();
        let Some(latest) = eliciting.iter().map(|(_, p)| p.time_sent).max() else {
            return;
        };
        self.cc.on_congestion_event(latest, now);
        if self.is_persistent_congestion(&eliciting) {
            self.cc.on_persistent_congestion();
        }
    }

    /// Persistent congestion duration: (srtt + max(4*rttvar, granularity) + max_ack_delay) * 3.
    pub fn persistent_congestion_duration(&self) -> Duration {
        let rtt = &self.loss.rtt;
        (rtt.smoothed() + (rtt.var() * 4).max(GRANULARITY) + self.max_ack_delay)
            * PERSISTENT_CONGESTION_THRESHOLD
    }

    /// Lost ack-eliciting packets with consecutive packet numbers (so none
    /// between them was acknowledged), all sent after the first RTT sample,
    /// spanning longer than the persistent congestion duration.
    fn is_persistent_congestion(&self, lost: &[&(u64, SentPacket<T>)]) -> bool {
        let Some(first_sample) = self.first_rtt_sample else {
            return false;
        };
        let mut run: Vec<&(u64, SentPacket<T>)> = lost
            .iter()
            .copied()
            .filter(|(_, p)| p.time_sent > first_sample)
            .collect();
        run.sort_by_key(|(pn, _)| *pn);
        let threshold = self.persistent_congestion_duration();
        let mut start = 0;
        for i in 0..run.len() {
            if i > 0 && run[i].0 != run[i - 1].0 + 1 {
                start = i;
            }
            if run[i]
                .1
                .time_sent
                .saturating_duration_since(run[start].1.time_sent)
                > threshold
            {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewReno;

    const MSS: u64 = 1200;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn pkt(t: Instant) -> SentPacket<()> {
        SentPacket {
            time_sent: t,
            size: MSS,
            ack_eliciting: true,
            payload: (),
        }
    }

    #[test]
    fn cwnd_through_loss_episode() {
        let t0 = Instant::now();
        let mut r = Recovery::<()>::new(Box::new(NewReno::new(MSS)), ms(25));
        assert_eq!(r.window(), 12_000);
        // Round 1: 10 packets, all acked after 50ms -> slow start doubles.
        for pn in 0..10 {
            r.on_packet_sent(Space::Data, pn, pkt(t0));
        }
        assert!(!r.can_send(MSS + 1), "cwnd full");
        r.on_ack_received(Space::Data, &[(0, 9)], ms(0), t0 + ms(50));
        assert_eq!(r.window(), 24_000);
        assert_eq!(r.loss.bytes_in_flight(), 0);
        // Round 2: 20 packets; pn 10 lost (3+ later packets acked).
        let t1 = t0 + ms(50);
        for pn in 10..30 {
            r.on_packet_sent(Space::Data, pn, pkt(t1));
        }
        let out = r.on_ack_received(Space::Data, &[(11, 29)], ms(0), t1 + ms(50));
        assert_eq!(out.lost.len(), 1);
        // Acks for packets sent before the loss grew the window first (+19*MSS), then halved.
        assert_eq!(r.window(), (24_000 + 19 * MSS) / 2);
        let after_loss = r.window();
        // Packets sent before recovery start that are later acked don't grow it.
        r.on_packet_sent(Space::Data, 30, pkt(t1));
        r.on_ack_received(Space::Data, &[(30, 30)], ms(0), t1 + ms(60));
        assert_eq!(r.window(), after_loss);
        // New packets sent after recovery start grow it in congestion avoidance.
        let t2 = t1 + ms(70);
        for pn in 31..31 + after_loss.div_ceil(MSS) {
            r.on_packet_sent(Space::Data, pn, pkt(t2));
        }
        let last = 30 + after_loss.div_ceil(MSS);
        r.on_ack_received(Space::Data, &[(31, last)], ms(0), t2 + ms(50));
        assert_eq!(r.window(), after_loss + MSS, "one MSS per window in CA");
    }

    #[test]
    fn persistent_congestion_collapses_window() {
        let t0 = Instant::now();
        let mut r = Recovery::<()>::new(Box::new(NewReno::new(MSS)), ms(25));
        r.on_packet_sent(Space::Data, 0, pkt(t0));
        r.on_ack_received(Space::Data, &[(0, 0)], ms(0), t0 + ms(50));
        // srtt 50, var 25 -> duration = (50 + 100 + 25) * 3 = 525ms.
        assert_eq!(r.persistent_congestion_duration(), ms(525));
        // Consecutive packets 1..=8 sent 100ms apart (700ms span) all lost.
        let t1 = t0 + ms(60);
        for pn in 1..=8 {
            r.on_packet_sent(Space::Data, pn, pkt(t1 + ms(100 * (pn - 1))));
        }
        r.on_packet_sent(Space::Data, 20, pkt(t1 + ms(800)));
        r.on_ack_received(Space::Data, &[(20, 20)], ms(0), t1 + ms(850));
        assert_eq!(r.window(), 2 * MSS);
    }

    #[test]
    fn short_loss_span_is_not_persistent() {
        let t0 = Instant::now();
        let mut r = Recovery::<()>::new(Box::new(NewReno::new(MSS)), ms(25));
        r.on_packet_sent(Space::Data, 0, pkt(t0));
        r.on_ack_received(Space::Data, &[(0, 0)], ms(0), t0 + ms(50));
        let w = r.window();
        let t1 = t0 + ms(60);
        for pn in 1..=4 {
            r.on_packet_sent(Space::Data, pn, pkt(t1 + ms(pn)));
        }
        r.on_packet_sent(Space::Data, 10, pkt(t1 + ms(10)));
        r.on_ack_received(Space::Data, &[(10, 10)], ms(0), t1 + ms(60));
        // Halved (with the +MSS from pn 10's ack in slow start first), not collapsed.
        assert_eq!(r.window(), (w + MSS) / 2);
    }
}
