//! RFC 9002 building blocks: RTT estimation and congestion control
//! (NewReno and CUBIC, RFC 9438) behind a common trait.
//!
//! [`loss`] implements RFC 9002 Section 6 loss detection and PTO.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod loss;
pub mod pacer;
pub mod recovery;

use std::time::{Duration, Instant};

/// Initial RTT before any sample (RFC 9002 6.2.2).
pub const INITIAL_RTT: Duration = Duration::from_millis(333);
/// Timer granularity.
pub const GRANULARITY: Duration = Duration::from_millis(1);

/// RTT estimator (RFC 9002 Section 5).
#[derive(Debug, Clone)]
pub struct RttEstimator {
    latest: Duration,
    smoothed: Option<Duration>,
    var: Duration,
    min: Duration,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            latest: INITIAL_RTT,
            smoothed: None,
            var: INITIAL_RTT / 2,
            min: Duration::MAX,
        }
    }
}

impl RttEstimator {
    /// Incorporates a sample. `ack_delay` is already capped to max_ack_delay
    /// by the caller once the handshake is confirmed.
    pub fn update(&mut self, latest: Duration, ack_delay: Duration) {
        self.latest = latest;
        self.min = self.min.min(latest);
        match self.smoothed {
            None => {
                self.smoothed = Some(latest);
                self.var = latest / 2;
            }
            Some(srtt) => {
                let adjusted = if latest >= self.min + ack_delay {
                    latest - ack_delay
                } else {
                    latest
                };
                let diff = srtt.abs_diff(adjusted);
                self.var = (self.var * 3 + diff) / 4;
                self.smoothed = Some((srtt * 7 + adjusted) / 8);
            }
        }
    }
    /// Smoothed RTT.
    pub fn smoothed(&self) -> Duration {
        self.smoothed.unwrap_or(INITIAL_RTT)
    }
    /// RTT variance.
    pub fn var(&self) -> Duration {
        self.var
    }
    /// Minimum observed RTT.
    pub fn min(&self) -> Duration {
        if self.min == Duration::MAX {
            self.latest
        } else {
            self.min
        }
    }
    /// Probe timeout base: srtt + max(4*rttvar, granularity) + max_ack_delay.
    pub fn pto(&self, max_ack_delay: Duration) -> Duration {
        self.smoothed() + (self.var * 4).max(GRANULARITY) + max_ack_delay
    }
    /// Loss time threshold: 9/8 * max(srtt, latest).
    pub fn loss_delay(&self) -> Duration {
        (self.smoothed().max(self.latest) * 9 / 8).max(GRANULARITY)
    }
}

/// Congestion controller interface.
pub trait CongestionController: Send {
    /// Current congestion window in bytes.
    fn window(&self) -> u64;
    /// Called when `bytes` sent at `sent` are acknowledged.
    fn on_ack(&mut self, bytes: u64, sent: Instant, now: Instant, rtt: &RttEstimator);
    /// Called on a congestion event (loss or ECN-CE) for a packet sent at `sent`.
    fn on_congestion_event(&mut self, sent: Instant, now: Instant);
    /// Called when persistent congestion is declared.
    fn on_persistent_congestion(&mut self);
    /// Whether the controller is in slow start.
    fn in_slow_start(&self) -> bool;
    /// The maximum datagram size changed (path MTU discovery): window
    /// growth and the minimum window follow the new size (RFC 9002 7.2).
    fn set_max_datagram_size(&mut self, bytes: u64);
}

/// Shared window bookkeeping.
#[derive(Debug, Clone)]
struct Base {
    mss: u64,
    cwnd: u64,
    ssthresh: u64,
    recovery_start: Option<Instant>,
}

impl Base {
    fn new(mss: u64) -> Self {
        Self {
            mss,
            cwnd: (10 * mss).min((2 * mss).max(14720)),
            ssthresh: u64::MAX,
            recovery_start: None,
        }
    }
    fn min_window(&self) -> u64 {
        2 * self.mss
    }
    fn in_recovery(&self, sent: Instant) -> bool {
        self.recovery_start.is_some_and(|r| sent <= r)
    }
}

/// NewReno (RFC 9002 Section 7).
#[derive(Debug, Clone)]
pub struct NewReno {
    b: Base,
    acked_ca: u64,
}

impl NewReno {
    /// Creates a controller for the given max datagram size.
    pub fn new(mss: u64) -> Self {
        Self {
            b: Base::new(mss),
            acked_ca: 0,
        }
    }
}

impl CongestionController for NewReno {
    fn window(&self) -> u64 {
        self.b.cwnd
    }
    fn on_ack(&mut self, bytes: u64, sent: Instant, _now: Instant, _rtt: &RttEstimator) {
        if self.b.in_recovery(sent) {
            return;
        }
        if self.b.cwnd < self.b.ssthresh {
            self.b.cwnd += bytes;
        } else {
            self.acked_ca += bytes;
            if self.acked_ca >= self.b.cwnd {
                self.acked_ca -= self.b.cwnd;
                self.b.cwnd += self.b.mss;
            }
        }
    }
    fn on_congestion_event(&mut self, sent: Instant, now: Instant) {
        if self.b.in_recovery(sent) {
            return;
        }
        self.b.recovery_start = Some(now);
        self.b.ssthresh = (self.b.cwnd / 2).max(self.b.min_window());
        self.b.cwnd = self.b.ssthresh;
        self.acked_ca = 0;
    }
    fn on_persistent_congestion(&mut self) {
        self.b.cwnd = self.b.min_window();
        self.b.recovery_start = None;
    }
    fn set_max_datagram_size(&mut self, bytes: u64) {
        self.b.mss = bytes;
    }

    fn in_slow_start(&self) -> bool {
        self.b.cwnd < self.b.ssthresh
    }
}

/// CUBIC (RFC 9438) with the Reno-friendly region.
#[derive(Debug, Clone)]
pub struct Cubic {
    b: Base,
    w_max: f64,
    k: f64,
    epoch: Option<Instant>,
    w_est: f64,
}

const C: f64 = 0.4;
const BETA: f64 = 0.7;

impl Cubic {
    /// Creates a controller for the given max datagram size.
    pub fn new(mss: u64) -> Self {
        Self {
            b: Base::new(mss),
            w_max: 0.0,
            k: 0.0,
            epoch: None,
            w_est: 0.0,
        }
    }
    /// W_cubic(t) in bytes for `t` seconds since the epoch.
    pub fn w_cubic(&self, t: f64) -> f64 {
        let mss = self.b.mss as f64;
        (C * (t - self.k).powi(3) * mss) + self.w_max
    }
}

impl CongestionController for Cubic {
    fn window(&self) -> u64 {
        self.b.cwnd
    }
    fn on_ack(&mut self, bytes: u64, sent: Instant, now: Instant, rtt: &RttEstimator) {
        if self.b.in_recovery(sent) {
            return;
        }
        if self.b.cwnd < self.b.ssthresh {
            self.b.cwnd += bytes;
            return;
        }
        let mss = self.b.mss as f64;
        let epoch = *self.epoch.get_or_insert(now);
        if self.w_est == 0.0 {
            self.w_est = self.b.cwnd as f64;
        }
        let t = now.saturating_duration_since(epoch).as_secs_f64();
        let target = self.w_cubic(t + rtt.smoothed().as_secs_f64());
        let cwnd = self.b.cwnd as f64;
        // Reno-friendly estimate (RFC 9438 4.3).
        self.w_est += mss * (3.0 * (1.0 - BETA) / (1.0 + BETA)) * (bytes as f64 / cwnd);
        let inc = if target > cwnd {
            ((target - cwnd) / cwnd * mss).min(mss)
        } else {
            0.0
        };
        let next = (cwnd + inc).max(self.w_est);
        self.b.cwnd = (next as u64).max(self.b.min_window());
    }
    fn on_congestion_event(&mut self, sent: Instant, now: Instant) {
        if self.b.in_recovery(sent) {
            return;
        }
        self.b.recovery_start = Some(now);
        let cwnd = self.b.cwnd as f64;
        // Fast convergence.
        self.w_max = if cwnd < self.w_max {
            cwnd * (1.0 + BETA) / 2.0
        } else {
            cwnd
        };
        self.b.ssthresh = ((cwnd * BETA) as u64).max(self.b.min_window());
        self.b.cwnd = self.b.ssthresh;
        self.k = ((self.w_max - self.b.cwnd as f64) / (C * self.b.mss as f64))
            .max(0.0)
            .cbrt();
        self.epoch = Some(now);
        self.w_est = self.b.cwnd as f64;
    }
    fn on_persistent_congestion(&mut self) {
        self.b.cwnd = self.b.min_window();
        self.b.recovery_start = None;
        self.epoch = None;
    }
    fn set_max_datagram_size(&mut self, bytes: u64) {
        self.b.mss = bytes;
    }

    fn in_slow_start(&self) -> bool {
        self.b.cwnd < self.b.ssthresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const MSS: u64 = 1200;

    fn rtt(ms: u64) -> RttEstimator {
        let mut r = RttEstimator::default();
        r.update(Duration::from_millis(ms), Duration::ZERO);
        r
    }

    #[test]
    fn rtt_first_sample_and_smoothing() {
        let mut r = rtt(100);
        assert_eq!(r.smoothed(), Duration::from_millis(100));
        assert_eq!(r.var(), Duration::from_millis(50));
        r.update(Duration::from_millis(200), Duration::from_millis(20));
        // adjusted = 180; srtt = (700 + 180)/8 = 110; var = (150 + 80)/4 = 57.5
        assert_eq!(r.smoothed(), Duration::from_millis(110));
        assert_eq!(r.var(), Duration::from_micros(57_500));
        assert_eq!(r.min(), Duration::from_millis(100));
        assert_eq!(
            r.pto(Duration::from_millis(25)),
            Duration::from_millis(110 + 230 + 25)
        );
    }

    fn slow_start_then_loss(cc: &mut dyn CongestionController, beta: f64) {
        let t0 = Instant::now();
        let r = rtt(50);
        let w0 = cc.window();
        assert_eq!(w0, 12_000);
        assert!(cc.in_slow_start());
        cc.on_ack(w0, t0, t0 + Duration::from_millis(50), &r);
        assert_eq!(cc.window(), 2 * w0, "slow start doubles per RTT");
        let before = cc.window();
        let loss_at = t0 + Duration::from_millis(100);
        cc.on_congestion_event(t0, loss_at);
        assert_eq!(cc.window(), (before as f64 * beta) as u64);
        assert!(!cc.in_slow_start());
        // A second loss of a packet sent before recovery start is ignored.
        let w = cc.window();
        cc.on_congestion_event(
            t0 + Duration::from_millis(90),
            loss_at + Duration::from_millis(1),
        );
        assert_eq!(cc.window(), w);
        // Acks for pre-recovery packets do not grow the window.
        cc.on_ack(5000, t0, loss_at + Duration::from_millis(2), &r);
        assert_eq!(cc.window(), w);
        cc.on_persistent_congestion();
        assert_eq!(cc.window(), 2 * MSS);
    }

    #[test]
    fn newreno_slow_start_and_recovery() {
        slow_start_then_loss(&mut NewReno::new(MSS), 0.5);
    }

    #[test]
    fn cubic_slow_start_and_recovery() {
        slow_start_then_loss(&mut Cubic::new(MSS), 0.7);
    }

    #[test]
    fn newreno_congestion_avoidance_one_mss_per_window() {
        let mut cc = NewReno::new(MSS);
        let t0 = Instant::now();
        let r = rtt(50);
        cc.on_congestion_event(t0, t0);
        let w = cc.window();
        let later = t0 + Duration::from_millis(10);
        cc.on_ack(w, later, later, &r);
        assert_eq!(cc.window(), w + MSS);
    }

    /// After path MTU discovery raises the datagram size, a window of acks
    /// grows the window by one new-sized datagram, for both controllers.
    #[test]
    fn window_growth_follows_the_datagram_size() {
        let t0 = Instant::now();
        let r = rtt(50);
        let mut ccs: [Box<dyn CongestionController>; 2] =
            [Box::new(NewReno::new(MSS)), Box::new(Cubic::new(MSS))];
        for cc in ccs.iter_mut() {
            cc.set_max_datagram_size(1452);
            cc.on_congestion_event(t0, t0);
            let w = cc.window();
            let later = t0 + Duration::from_millis(10);
            cc.on_ack(w, later, later, &r);
            assert!(cc.window() > w && cc.window() <= w + 1452);
        }
        let mut nr = NewReno::new(MSS);
        nr.set_max_datagram_size(1452);
        nr.on_congestion_event(t0, t0);
        let w = nr.window();
        let later = t0 + Duration::from_millis(10);
        nr.on_ack(w, later, later, &r);
        assert_eq!(nr.window(), w + 1452);
    }

    #[test]
    fn cubic_growth_is_concave_then_convex() {
        // Grow a large window, lose, then ack continuously and sample cwnd.
        let mut cc = Cubic::new(MSS);
        let t0 = Instant::now();
        let r = rtt(20);
        cc.on_ack(1_000 * MSS, t0, t0, &r); // leave slow start with a big window
        let w_max = cc.window();
        let loss = t0 + Duration::from_millis(1);
        cc.on_congestion_event(t0, loss);
        assert_eq!(cc.window(), (w_max as f64 * 0.7) as u64);
        let k = cc.k;
        assert!(
            k > 1.0,
            "K = cbrt(W_max*(1-beta)/C) should be several seconds, got {k}"
        );
        let mut samples = Vec::new();
        let mut now = loss;
        for _ in 0..(((k * 2.0) / 0.02) as usize) {
            now += Duration::from_millis(20);
            // One window's worth of acks per RTT.
            let w = cc.window();
            for _ in 0..(w / MSS) {
                cc.on_ack(MSS, now, now, &r);
            }
            samples.push((now.duration_since(loss).as_secs_f64(), cc.window()));
        }
        // Monotonic non-decreasing.
        assert!(samples.windows(2).all(|p| p[1].1 >= p[0].1));
        // Plateau near W_max around t=K: growth in the middle third is slower
        // than in the first and last thirds.
        let n = samples.len() / 3;
        let g = |a: usize, b: usize| samples[b].1 as f64 - samples[a].1 as f64;
        let (first, mid, last) = (g(0, n), g(n, 2 * n), g(2 * n, samples.len() - 1));
        assert!(
            mid < first && mid < last,
            "first={first} mid={mid} last={last}"
        );
        // Window approaches W_max near K and exceeds it after.
        assert!(samples.last().unwrap().1 > w_max);
    }

    proptest! {
        #[test]
        fn rtt_estimates_stay_in_sample_range(samples in proptest::collection::vec(1u64..10_000, 1..50)) {
            let mut r = RttEstimator::default();
            for s in &samples { r.update(Duration::from_millis(*s), Duration::ZERO); }
            let lo = *samples.iter().min().unwrap();
            let hi = *samples.iter().max().unwrap();
            prop_assert!(r.smoothed() >= Duration::from_millis(lo) && r.smoothed() <= Duration::from_millis(hi));
            prop_assert_eq!(r.min(), Duration::from_millis(lo));
        }

        #[test]
        fn window_never_below_minimum(events in proptest::collection::vec((any::<bool>(), 1u64..100_000), 1..100)) {
            let t0 = Instant::now();
            let r = rtt(10);
            let mut ccs: [Box<dyn CongestionController>; 2] = [Box::new(NewReno::new(MSS)), Box::new(Cubic::new(MSS))];
            for cc in ccs.iter_mut() {
                for (i, (loss, bytes)) in events.iter().enumerate() {
                    let now = t0 + Duration::from_millis(i as u64 * 10);
                    if *loss { cc.on_congestion_event(now, now) } else { cc.on_ack(*bytes, now, now, &r) }
                    prop_assert!(cc.window() >= 2 * MSS);
                }
            }
        }
    }
}
