//! Send side of streams: buffering, retransmission of lost ranges and
//! peer flow-control limits with blocked signalling (RFC 9000 Sections 2.2,
//! 4.1, 13.3).

use std::collections::{BTreeMap, VecDeque};

/// Connection-level send credit (peer's MAX_DATA).
#[derive(Debug, Clone)]
pub struct ConnSendFlow {
    max_data: u64,
    sent: u64,
    blocked_signalled: Option<u64>,
}

impl ConnSendFlow {
    /// Starts with the peer's initial_max_data.
    pub fn new(max_data: u64) -> Self {
        Self {
            max_data,
            sent: 0,
            blocked_signalled: None,
        }
    }
    /// Applies a MAX_DATA frame (limits never decrease).
    pub fn on_max_data(&mut self, max: u64) {
        self.max_data = self.max_data.max(max);
    }
    /// Remaining credit.
    pub fn credit(&self) -> u64 {
        self.max_data - self.sent
    }
    /// Returns a DATA_BLOCKED limit to send, once per limit, when out of credit.
    pub fn take_blocked(&mut self) -> Option<u64> {
        if self.credit() == 0 && self.blocked_signalled != Some(self.max_data) {
            self.blocked_signalled = Some(self.max_data);
            Some(self.max_data)
        } else {
            None
        }
    }
}

/// Errors from writing to a send stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The buffer cap is reached; retry after data is acknowledged.
    #[error("send buffer full")]
    WouldBlock,
    /// FIN was already written.
    #[error("stream already finished")]
    Finished,
    /// The stream was reset (locally or via STOP_SENDING).
    #[error("stream reset with code {0}")]
    Reset(u64),
}

/// A STREAM frame's worth of data to transmit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Stream offset.
    pub offset: u64,
    /// Bytes.
    pub data: Vec<u8>,
    /// FIN bit.
    pub fin: bool,
}

/// Send half of a stream.
#[derive(Debug, Clone)]
pub struct SendStream {
    buf: VecDeque<u8>,
    base: u64,
    write_off: u64,
    next_new: u64,
    fin_off: Option<u64>,
    fin_pending: bool,
    fin_acked: bool,
    lost: BTreeMap<u64, u64>,
    acked: BTreeMap<u64, u64>,
    max_data: u64,
    blocked_signalled: Option<u64>,
    max_buffer: usize,
    reset: Option<u64>,
}

impl SendStream {
    /// Creates a stream with the peer's initial MAX_STREAM_DATA.
    pub fn new(max_data: u64) -> Self {
        Self {
            buf: VecDeque::new(),
            base: 0,
            write_off: 0,
            next_new: 0,
            fin_off: None,
            fin_pending: false,
            fin_acked: false,
            lost: BTreeMap::new(),
            acked: BTreeMap::new(),
            max_data,
            blocked_signalled: None,
            max_buffer: usize::MAX,
            reset: None,
        }
    }

    /// Caps the bytes buffered (unacknowledged plus unsent) by this stream.
    pub fn with_buffer_cap(mut self, cap: usize) -> Self {
        self.max_buffer = cap;
        self
    }

    /// Buffers as much of `data` as the buffer cap allows and returns the
    /// number of bytes accepted. FIN is applied only if all of `data` fits.
    pub fn write(&mut self, data: &[u8], fin: bool) -> Result<usize, SendError> {
        if let Some(code) = self.reset {
            return Err(SendError::Reset(code));
        }
        if self.fin_off.is_some() {
            return Err(SendError::Finished);
        }
        let space = self.max_buffer.saturating_sub(self.buf.len());
        if space == 0 && !data.is_empty() {
            return Err(SendError::WouldBlock);
        }
        let n = data.len().min(space);
        self.buf.extend(&data[..n]);
        self.write_off += n as u64;
        if fin && n == data.len() {
            self.fin_off = Some(self.write_off);
            self.fin_pending = true;
        }
        Ok(n)
    }

    /// Abandons the stream (RFC 9000 3.1 "Reset Sent"). Returns the
    /// `(error_code, final_size)` for a RESET_STREAM frame, or `None` if the
    /// stream was already reset or fully acknowledged. The final size is the
    /// highest offset sent, which the peer already counted against flow control.
    pub fn reset(&mut self, error: u64) -> Option<(u64, u64)> {
        if self.reset.is_some() || self.is_complete() {
            return None;
        }
        self.reset = Some(error);
        self.buf.clear();
        self.lost.clear();
        self.acked.clear();
        self.fin_pending = false;
        self.base = self.next_new;
        self.write_off = self.next_new;
        Some((error, self.next_new))
    }

    /// Handles STOP_SENDING from the peer by resetting with its error code.
    pub fn on_stop_sending(&mut self, error: u64) -> Option<(u64, u64)> {
        self.reset(error)
    }

    /// Error code if the stream was reset.
    pub fn reset_code(&self) -> Option<u64> {
        self.reset
    }

    /// Applies a MAX_STREAM_DATA frame.
    pub fn on_max_stream_data(&mut self, max: u64) {
        self.max_data = self.max_data.max(max);
    }

    fn slice(&self, from: u64, to: u64) -> Vec<u8> {
        let a = (from - self.base) as usize;
        let b = (to - self.base) as usize;
        self.buf.range(a..b).copied().collect()
    }

    fn fin_for(&mut self, end: u64) -> bool {
        if self.fin_off == Some(end) && self.fin_pending {
            self.fin_pending = false;
            true
        } else {
            false
        }
    }

    /// Produces the next chunk of at most `max_len` bytes: lost data first,
    /// then new data within stream and connection credit.
    pub fn emit(&mut self, max_len: usize, conn: &mut ConnSendFlow) -> Option<Chunk> {
        if self.reset.is_some() {
            return None;
        }
        while let Some((start, end)) = self.lost.pop_first() {
            let start = start.max(self.base);
            if start >= end {
                continue;
            }
            let stop = end.min(start + max_len as u64);
            if stop < end {
                self.lost.insert(stop, end);
            }
            let data = self.slice(start, stop);
            let fin = self.fin_for(stop);
            return Some(Chunk {
                offset: start,
                data,
                fin,
            });
        }
        let limit = self
            .max_data
            .min(self.next_new + conn.credit())
            .min(self.write_off);
        if limit > self.next_new {
            let stop = limit.min(self.next_new + max_len as u64);
            let start = self.next_new;
            conn.sent += stop - start;
            self.next_new = stop;
            let data = self.slice(start, stop);
            let fin = self.fin_for(stop);
            return Some(Chunk {
                offset: start,
                data,
                fin,
            });
        }
        if self.fin_pending && self.next_new == self.write_off {
            let off = self.write_off;
            self.fin_pending = false;
            return Some(Chunk {
                offset: off,
                data: Vec::new(),
                fin: true,
            });
        }
        None
    }

    /// Returns a STREAM_DATA_BLOCKED limit to send, once per limit, when new
    /// data is waiting only on the peer's stream limit.
    pub fn take_blocked(&mut self) -> Option<u64> {
        if self.write_off > self.next_new
            && self.next_new >= self.max_data
            && self.blocked_signalled != Some(self.max_data)
        {
            self.blocked_signalled = Some(self.max_data);
            Some(self.max_data)
        } else {
            None
        }
    }

    /// A chunk was declared lost: queue it for retransmission.
    pub fn on_lost(&mut self, offset: u64, len: u64, fin: bool) {
        if self.reset.is_some() {
            return;
        }
        let end = offset + len;
        if end > offset {
            let e = self.lost.entry(offset).or_insert(end);
            *e = (*e).max(end);
        }
        if fin && !self.fin_acked {
            self.fin_pending = true;
        }
    }

    /// A chunk was acknowledged: release buffered bytes that are now
    /// contiguously acknowledged.
    pub fn on_ack(&mut self, offset: u64, len: u64, fin: bool) {
        if self.reset.is_some() {
            return;
        }
        if fin {
            self.fin_acked = true;
        }
        let end = offset + len;
        if end <= self.base {
            return;
        }
        let e = self.acked.entry(offset.max(self.base)).or_insert(end);
        *e = (*e).max(end);
        // Advance base over contiguous acked ranges.
        while let Some((&s, &e)) = self.acked.first_key_value() {
            if s > self.base {
                break;
            }
            self.acked.pop_first();
            if e > self.base {
                let n = (e - self.base) as usize;
                self.buf.drain(..n);
                self.base = e;
            }
        }
    }

    /// Whether [`SendStream::emit`] may produce a chunk now (lost data to
    /// retransmit, new data within stream and connection credit, or a FIN).
    pub fn wants_send(&self, conn: &ConnSendFlow) -> bool {
        if self.reset.is_some() {
            return false;
        }
        let new_data =
            self.write_off > self.next_new && self.max_data > self.next_new && conn.credit() > 0;
        !self.lost.is_empty() || new_data || (self.fin_pending && self.next_new == self.write_off)
    }

    /// All data and FIN acknowledged.
    pub fn is_complete(&self) -> bool {
        self.fin_acked && self.fin_off == Some(self.base)
    }

    /// Bytes buffered awaiting acknowledgement.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{ConnFlow, RecvStream};
    use proptest::prelude::*;

    #[test]
    fn respects_limits_and_signals_blocked() {
        let mut conn = ConnSendFlow::new(8);
        let mut s = SendStream::new(5);
        s.write(b"0123456789", true).unwrap();
        let c = s.emit(100, &mut conn).unwrap();
        assert_eq!((c.offset, &c.data[..], c.fin), (0, &b"01234"[..], false));
        assert!(s.emit(100, &mut conn).is_none());
        assert_eq!(s.take_blocked(), Some(5));
        assert_eq!(s.take_blocked(), None, "signalled once per limit");
        s.on_max_stream_data(100);
        let c = s.emit(100, &mut conn).unwrap();
        assert_eq!(&c.data[..], b"567", "connection credit 8");
        assert_eq!(conn.take_blocked(), Some(8));
        conn.on_max_data(100);
        let c = s.emit(100, &mut conn).unwrap();
        assert_eq!((c.offset, &c.data[..], c.fin), (8, &b"89"[..], true));
        assert!(s.emit(100, &mut conn).is_none());
    }

    #[test]
    fn retransmits_lost_and_frees_acked() {
        let mut conn = ConnSendFlow::new(1000);
        let mut s = SendStream::new(1000);
        s.write(b"abcdefghij", true).unwrap();
        let a = s.emit(4, &mut conn).unwrap();
        let b = s.emit(4, &mut conn).unwrap();
        let c = s.emit(4, &mut conn).unwrap();
        assert!(c.fin);
        s.on_ack(b.offset, 4, false);
        assert_eq!(s.buffered(), 10, "gap at front keeps buffer");
        s.on_lost(a.offset, 4, false);
        s.on_lost(c.offset, 2, true);
        let r1 = s.emit(100, &mut conn).unwrap();
        assert_eq!((r1.offset, &r1.data[..]), (0, &b"abcd"[..]));
        let r2 = s.emit(100, &mut conn).unwrap();
        assert_eq!((r2.offset, &r2.data[..], r2.fin), (8, &b"ij"[..], true));
        s.on_ack(0, 4, false);
        assert_eq!(s.buffered(), 2);
        s.on_ack(8, 2, true);
        assert!(s.is_complete());
        assert_eq!(s.buffered(), 0);
    }

    proptest! {
        #[test]
        fn lossy_delivery_reassembles(data in proptest::collection::vec(any::<u8>(), 0..3000),
                                      seed in any::<u64>(), loss_pct in 0u64..60, mtu in 1usize..300) {
            let window = 512u64;
            let mut cflow = ConnSendFlow::new(window * 2);
            let mut s = SendStream::new(window);
            let mut rconn = ConnFlow::new(window * 2);
            let mut r = RecvStream::new(window);
            prop_assert_eq!(s.write(&data, true), Ok(data.len()));
            let mut rng = seed | 1;
            let mut next = || { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; rng };
            let mut out = Vec::new();
            let mut buf = [0u8; 97];
            let mut in_flight: Vec<Chunk> = Vec::new();
            for _ in 0..100_000 {
                if r.is_finished() { break; }
                while let Some(c) = s.emit(mtu, &mut cflow) { in_flight.push(c); if in_flight.len() > 8 { break; } }
                if in_flight.is_empty() { prop_assert!(false, "stalled"); }
                let i = (next() % in_flight.len() as u64) as usize;
                let c = in_flight.swap_remove(i);
                let len = c.data.len() as u64;
                if next() % 100 < loss_pct {
                    s.on_lost(c.offset, len, c.fin);
                } else {
                    r.on_frame(c.offset, &c.data, c.fin, &mut rconn).unwrap();
                    s.on_ack(c.offset, len, c.fin);
                }
                loop { let (n, _) = r.read(&mut buf, &mut rconn); if n == 0 { break; } out.extend_from_slice(&buf[..n]); }
                if let Some(m) = r.take_update() { s.on_max_stream_data(m); }
                if let Some(m) = rconn.take_update() { cflow.on_max_data(m); }
            }
            prop_assert!(r.is_finished());
            prop_assert_eq!(&out, &data);
        }
    }

    #[test]
    fn buffer_cap_would_block_until_acked() {
        let mut conn = ConnSendFlow::new(1000);
        let mut s = SendStream::new(1000).with_buffer_cap(6);
        assert_eq!(s.write(b"abcd", false), Ok(4));
        assert_eq!(
            s.write(b"efgh", true),
            Ok(2),
            "partial write, FIN not applied"
        );
        assert_eq!(s.write(b"gh", true), Err(SendError::WouldBlock));
        let c = s.emit(100, &mut conn).unwrap();
        assert!(!c.fin);
        s.on_ack(0, 6, false);
        assert_eq!(s.write(b"gh", true), Ok(2));
        assert_eq!(s.write(b"x", false), Err(SendError::Finished));
        let c = s.emit(100, &mut conn).unwrap();
        assert_eq!((c.offset, &c.data[..], c.fin), (6, &b"gh"[..], true));
    }

    #[test]
    fn reset_and_stop_sending() {
        let mut conn = ConnSendFlow::new(1000);
        let mut s = SendStream::new(1000);
        s.write(b"0123456789", false).unwrap();
        let c = s.emit(4, &mut conn).unwrap();
        s.on_lost(c.offset, 4, false);
        assert_eq!(
            s.on_stop_sending(7),
            Some((7, 4)),
            "final size = bytes sent"
        );
        assert_eq!(s.reset(9), None, "only once");
        assert_eq!(
            s.emit(100, &mut conn),
            None,
            "no retransmission after reset"
        );
        assert_eq!(s.buffered(), 0);
        assert_eq!(s.write(b"x", false), Err(SendError::Reset(7)));
        assert_eq!(s.reset_code(), Some(7));
        let mut done = SendStream::new(10);
        done.write(b"a", true).unwrap();
        let c = done.emit(10, &mut conn).unwrap();
        done.on_ack(c.offset, 1, true);
        assert_eq!(
            done.reset(1),
            None,
            "fully acknowledged stream cannot be reset"
        );
    }
}
