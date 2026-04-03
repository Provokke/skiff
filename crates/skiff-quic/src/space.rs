//! Packet number spaces (RFC 9000 Section 12.3) and ACK range tracking
//! (Section 13.2). This is the first piece of the future `Connection`.

use skiff_wire::frame::{Frame, MAX_ACK_RANGES};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Maximum ranges kept in memory; older (lower) ranges are forgotten so a
/// peer sending sparse packet numbers cannot grow our state unboundedly.
pub const MAX_TRACKED_RANGES: usize = 64;

/// A set of non-overlapping inclusive `u64` ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeSet {
    // start -> end (inclusive)
    map: BTreeMap<u64, u64>,
}

impl RangeSet {
    /// Inserts `v`, merging adjacent ranges. Returns false if already present.
    pub fn insert(&mut self, v: u64) -> bool {
        if self.contains(v) {
            return false;
        }
        let mut start = v;
        let mut end = v;
        if let Some((&s, &e)) = self.map.range(..v).next_back() {
            if e.checked_add(1) == Some(v) {
                start = s;
                self.map.remove(&s);
            }
        }
        if let Some(e) = v.checked_add(1).and_then(|n| self.map.remove(&n)) {
            end = e;
        }
        self.map.insert(start, end);
        while self.map.len() > MAX_TRACKED_RANGES {
            self.map.pop_first();
        }
        true
    }
    /// Whether `v` is in the set.
    pub fn contains(&self, v: u64) -> bool {
        self.map
            .range(..=v)
            .next_back()
            .is_some_and(|(_, &e)| v <= e)
    }
    /// Smallest tracked value (values below were forgotten or never seen).
    pub fn min(&self) -> Option<u64> {
        self.map.keys().next().copied()
    }
    /// Largest value.
    pub fn max(&self) -> Option<u64> {
        self.map.values().next_back().copied()
    }
    /// Ranges, largest first, as `(start, end)`.
    pub fn iter_desc(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.map.iter().rev().map(|(&s, &e)| (s, e))
    }
    /// Number of ranges.
    pub fn len(&self) -> usize {
        self.map.len()
    }
    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Receive/transmit packet-number state for one space.
#[derive(Debug, Default)]
pub struct PacketNumberSpace {
    /// Next packet number to send.
    pub next_pn: u64,
    received: RangeSet,
    largest_rx_time: Option<Instant>,
    ack_eliciting_unacked: u32,
    first_unacked_time: Option<Instant>,
}

impl PacketNumberSpace {
    /// Allocates the next outgoing packet number.
    pub fn take_pn(&mut self) -> u64 {
        let pn = self.next_pn;
        self.next_pn += 1;
        pn
    }

    /// Largest packet number received so far (for PN decoding).
    pub fn largest_received(&self) -> Option<u64> {
        self.received.max()
    }

    /// Whether `pn` is a duplicate (or too old to tell, which is treated as
    /// a duplicate so it is dropped).
    pub fn is_duplicate(&self, pn: u64) -> bool {
        self.received.contains(pn)
            || (self.received.len() >= MAX_TRACKED_RANGES
                && self.received.min().is_some_and(|m| pn < m))
    }

    /// Records a successfully decrypted packet.
    pub fn on_packet_received(&mut self, pn: u64, ack_eliciting: bool, now: Instant) {
        let newest = self.received.max().map_or(true, |m| pn > m);
        if !self.received.insert(pn) {
            return;
        }
        if newest {
            self.largest_rx_time = Some(now);
        }
        if ack_eliciting {
            self.ack_eliciting_unacked += 1;
            self.first_unacked_time.get_or_insert(now);
        }
    }

    /// When an ACK must be sent: immediately after two ack-eliciting packets
    /// (or immediately if `immediate`), otherwise after `max_ack_delay`.
    pub fn ack_deadline(&self, max_ack_delay: Duration, immediate: bool) -> Option<Instant> {
        let first = self.first_unacked_time?;
        if immediate || self.ack_eliciting_unacked >= 2 {
            Some(first)
        } else {
            Some(first + max_ack_delay)
        }
    }

    /// Builds an ACK frame covering everything received (up to
    /// `MAX_ACK_RANGES - 1` ranges) and resets the pending-ack state.
    pub fn build_ack(&mut self, now: Instant, ack_delay_exponent: u32) -> Option<Frame<'static>> {
        let ack = self.ack_frame(now, ack_delay_exponent)?;
        self.on_ack_sent();
        Some(ack)
    }

    /// Like [`PacketNumberSpace::build_ack`] but leaves the pending-ack
    /// state alone; call [`PacketNumberSpace::on_ack_sent`] once the frame
    /// is actually placed in a packet.
    pub fn ack_frame(&self, now: Instant, ack_delay_exponent: u32) -> Option<Frame<'static>> {
        if self.received.is_empty() {
            return None;
        }
        let ranges: Vec<(u64, u64)> = self.received.iter_desc().take(MAX_ACK_RANGES - 1).collect();
        let delay = self
            .largest_rx_time
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
        let delay = (delay.as_micros() as u64) >> ack_delay_exponent.min(20);
        Some(Frame::Ack {
            delay,
            ranges,
            ecn: None,
        })
    }

    /// Clears the pending-ack state after an ACK frame was sent.
    pub fn on_ack_sent(&mut self) {
        self.ack_eliciting_unacked = 0;
        self.first_unacked_time = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use skiff_wire::{Reader, Writer};

    #[test]
    fn rangeset_merges() {
        let mut r = RangeSet::default();
        for v in [5, 7, 6, 1, 2, 10] {
            assert!(r.insert(v));
        }
        assert!(!r.insert(6));
        assert_eq!(
            r.iter_desc().collect::<Vec<_>>(),
            vec![(10, 10), (5, 7), (1, 2)]
        );
        assert!(r.contains(7) && !r.contains(8) && !r.contains(0));
    }

    #[test]
    fn ack_frame_with_gaps_and_delay() {
        let t0 = Instant::now();
        let mut s = PacketNumberSpace::default();
        for pn in [0, 1, 2, 5, 6, 9] {
            s.on_packet_received(pn, true, t0);
        }
        assert!(s.is_duplicate(5) && !s.is_duplicate(7));
        assert_eq!(s.ack_deadline(Duration::from_millis(25), false), Some(t0));
        let ack = s.build_ack(t0 + Duration::from_millis(8), 3).unwrap();
        assert_eq!(
            ack,
            Frame::Ack {
                delay: 1000,
                ranges: vec![(9, 9), (5, 6), (0, 2)],
                ecn: None
            }
        );
        assert_eq!(s.ack_deadline(Duration::from_millis(25), false), None);
        // Encodes and decodes via the wire codec.
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        ack.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(Frame::decode(&mut Reader::new(&buf[..n])).unwrap(), ack);
    }

    #[test]
    fn single_ack_eliciting_waits_for_max_ack_delay() {
        let t0 = Instant::now();
        let mut s = PacketNumberSpace::default();
        s.on_packet_received(0, false, t0);
        assert_eq!(s.ack_deadline(Duration::from_millis(25), false), None);
        s.on_packet_received(1, true, t0);
        assert_eq!(
            s.ack_deadline(Duration::from_millis(25), false),
            Some(t0 + Duration::from_millis(25))
        );
        assert_eq!(s.ack_deadline(Duration::from_millis(25), true), Some(t0));
    }

    #[test]
    fn tracked_ranges_are_bounded() {
        let t0 = Instant::now();
        let mut s = PacketNumberSpace::default();
        for i in 0..1000u64 {
            s.on_packet_received(i * 2, true, t0);
        }
        assert_eq!(s.received.len(), MAX_TRACKED_RANGES);
        assert!(
            s.is_duplicate(0),
            "forgotten old packets are treated as duplicates"
        );
        assert_eq!(s.largest_received(), Some(1998));
    }

    proptest! {
        #[test]
        fn rangeset_matches_model(vals in proptest::collection::vec(0u64..120, 0..300)) {
            let mut r = RangeSet::default();
            // Values < 120 produce at most 60 ranges, so nothing is evicted.
            let mut model = std::collections::BTreeSet::new();
            for v in &vals { prop_assert_eq!(r.insert(*v), model.insert(*v)); }
            for v in 0..120 { prop_assert_eq!(r.contains(v), model.contains(&v)); }
            let ranges: Vec<_> = r.iter_desc().collect();
            for w in ranges.windows(2) { prop_assert!(w[1].1 + 1 < w[0].0); }
        }
    }
}
