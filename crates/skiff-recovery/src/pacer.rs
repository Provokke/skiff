//! Pacing (RFC 9002 7.7): a token bucket that spreads a congestion window
//! over the round trip instead of sending it in one burst. The rate is
//! `N * cwnd / srtt` with N = 1.25; the bucket holds the bytes that rate
//! sends in 2 ms, but at least 10 and at most 256 datagrams, so the first
//! window still leaves at once and a fast path is not slowed down.

use std::time::{Duration, Instant};

/// Pacing gain N = 5/4 (RFC 9002 7.7).
const GAIN_NUM: u128 = 5;
const GAIN_DEN: u128 = 4;
/// The bucket holds what the pacing rate sends in this long...
const BURST_INTERVAL: Duration = Duration::from_millis(2);
/// ...but at least this many datagrams...
const MIN_BURST: u64 = 10;
/// ...and at most this many.
const MAX_BURST: u64 = 256;

/// A token bucket in bytes.
#[derive(Debug, Clone, Default)]
pub struct Pacer {
    tokens: u64,
    last: Option<Instant>,
}

fn sat_u64(x: u128) -> u64 {
    u64::try_from(x).unwrap_or(u64::MAX)
}

impl Pacer {
    /// An empty pacer (full on first use).
    pub fn new() -> Self {
        Self::default()
    }

    /// Bucket size for this window, RTT and datagram size.
    pub fn capacity(cwnd: u64, srtt: Duration, mtu: u64) -> u64 {
        let rtt = srtt.as_nanos().max(1);
        let burst =
            sat_u64(u128::from(cwnd) * GAIN_NUM * BURST_INTERVAL.as_nanos() / (GAIN_DEN * rtt));
        burst.clamp(MIN_BURST * mtu, MAX_BURST * mtu)
    }

    /// When `bytes` may be sent: `None` for now, else the instant the bucket
    /// will hold enough. No pacing without an RTT estimate or a window.
    pub fn delay(
        &mut self,
        now: Instant,
        bytes: u64,
        cwnd: u64,
        srtt: Duration,
        mtu: u64,
    ) -> Option<Instant> {
        if srtt.is_zero() || cwnd == 0 {
            return None;
        }
        let cap = Self::capacity(cwnd, srtt, mtu);
        // Rate in bytes per nanosecond: rate_num / rate_den.
        let rate_num = u128::from(cwnd) * GAIN_NUM;
        let rate_den = GAIN_DEN * srtt.as_nanos();
        match self.last {
            None => {
                self.tokens = cap;
                self.last = Some(now);
            }
            Some(last) => {
                let elapsed = now.saturating_duration_since(last).as_nanos();
                let add = sat_u64(rate_num * elapsed / rate_den);
                self.tokens = self.tokens.saturating_add(add);
                if self.tokens >= cap {
                    self.last = Some(now);
                } else if add > 0 {
                    // Charge only the time the whole bytes took, so the
                    // fraction of a byte is not lost to rounding.
                    let used = u128::from(add) * rate_den / rate_num;
                    self.last = Some(last + Duration::from_nanos(sat_u64(used)));
                }
            }
        }
        self.tokens = self.tokens.min(cap);
        if self.tokens >= bytes {
            return None;
        }
        let need = u128::from(bytes - self.tokens);
        let nanos = (need * rate_den).div_ceil(rate_num);
        let start = self.last.unwrap_or(now);
        let wait = start + Duration::from_nanos(sat_u64(nanos));
        (wait > now).then_some(wait)
    }

    /// Takes `bytes` out of the bucket for a datagram just sent.
    pub fn on_sent(&mut self, bytes: u64) {
        self.tokens = self.tokens.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn burst_then_rate() {
        let t0 = Instant::now();
        let mut p = Pacer::new();
        // cwnd 120,000 B, srtt 100 ms: 1.5 MB/s; 2 ms of that is 3000 B,
        // below the 10-datagram floor, so the bucket holds 12,000 B.
        let (cwnd, rtt, mtu) = (120_000, ms(100), 1200);
        assert_eq!(Pacer::capacity(cwnd, rtt, mtu), 12_000);
        for _ in 0..10 {
            assert_eq!(p.delay(t0, 1200, cwnd, rtt, mtu), None);
            p.on_sent(1200);
        }
        // Empty: the next 1200 B take 1200 / 1.5 MB/s = 800 us.
        let at = p.delay(t0, 1200, cwnd, rtt, mtu).unwrap();
        assert_eq!(at - t0, Duration::from_micros(800));
        assert!(p
            .delay(at - Duration::from_micros(1), 1200, cwnd, rtt, mtu)
            .is_some());
        assert_eq!(p.delay(at, 1200, cwnd, rtt, mtu), None);
        p.on_sent(1200);
        // A long pause refills only up to the capacity.
        let later = at + ms(1000);
        for _ in 0..10 {
            assert_eq!(p.delay(later, 1200, cwnd, rtt, mtu), None);
            p.on_sent(1200);
        }
        assert!(p.delay(later, 1200, cwnd, rtt, mtu).is_some());
    }

    #[test]
    fn rate_follows_window_and_rtt() {
        let t0 = Instant::now();
        let wait = |cwnd: u64, rtt: Duration| {
            let mut p = Pacer::new();
            assert_eq!(p.delay(t0, 0, cwnd, rtt, 1200), None);
            p.on_sent(u64::MAX);
            p.delay(t0, 1200, cwnd, rtt, 1200).unwrap() - t0
        };
        let base = wait(120_000, ms(100));
        assert_eq!(wait(240_000, ms(100)), base / 2, "twice the window");
        assert_eq!(wait(120_000, ms(200)), base * 2, "twice the RTT");
        // The burst grows with the rate, capped at 256 datagrams.
        assert_eq!(Pacer::capacity(12_000_000, ms(10), 1200), 256 * 1200);
        // 1.2 MB / 10 ms * 1.25 * 2 ms = 300,000 B, under the cap.
        assert_eq!(Pacer::capacity(1_200_000, ms(10), 1200), 300_000);
        // No RTT or no window: no pacing.
        let mut p = Pacer::new();
        p.on_sent(u64::MAX);
        assert_eq!(p.delay(t0, 1200, 120_000, Duration::ZERO, 1200), None);
        assert_eq!(p.delay(t0, 1200, 0, ms(100), 1200), None);
    }

    /// Small steps add up: a whole byte's worth of time is never lost to
    /// rounding, so polling often does not slow the rate.
    #[test]
    fn frequent_polling_keeps_the_rate() {
        let t0 = Instant::now();
        let (cwnd, rtt, mtu) = (120_000, ms(100), 1200);
        let mut p = Pacer::new();
        assert_eq!(p.delay(t0, 0, cwnd, rtt, mtu), None);
        p.on_sent(u64::MAX);
        let mut t = t0;
        let mut sent = 0;
        while t < t0 + ms(100) {
            t += Duration::from_nanos(300);
            if p.delay(t, 1200, cwnd, rtt, mtu).is_none() {
                p.on_sent(1200);
                sent += 1;
            }
        }
        // 1.5 MB/s for 100 ms is 150,000 B: 125 datagrams.
        assert!((124..=125).contains(&sent), "{sent}");
    }
}
