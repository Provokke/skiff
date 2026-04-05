//! Receive-side stream reassembly and flow control (RFC 9000 Sections 2.2,
//! 4 and 4.5).

use std::collections::BTreeMap;

/// Errors raised while receiving stream data (map to transport error codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    /// Peer exceeded a stream or connection limit (FLOW_CONTROL_ERROR, 0x03).
    #[error("flow control limit exceeded")]
    FlowControl,
    /// Final size changed or data beyond it (FINAL_SIZE_ERROR, 0x06).
    #[error("final size violation")]
    FinalSize,
}

/// Connection-level receive flow control.
#[derive(Debug, Clone)]
pub struct ConnFlow {
    max_data: u64,
    window: u64,
    received: u64,
    consumed: u64,
}

impl ConnFlow {
    /// Creates a controller with an initial/advertised window.
    pub fn new(window: u64) -> Self {
        Self {
            max_data: window,
            window,
            received: 0,
            consumed: 0,
        }
    }
    /// Current advertised limit.
    pub fn max_data(&self) -> u64 {
        self.max_data
    }
    /// Sum of highest offsets received on all streams.
    pub fn received(&self) -> u64 {
        self.received
    }
    fn on_new_bytes(&mut self, n: u64) -> Result<(), StreamError> {
        let r = self
            .received
            .checked_add(n)
            .ok_or(StreamError::FlowControl)?;
        if r > self.max_data {
            return Err(StreamError::FlowControl);
        }
        self.received = r;
        Ok(())
    }
    fn on_consumed(&mut self, n: u64) {
        self.consumed += n;
    }
    /// If the application consumed over half the window, raises the limit and
    /// returns the new value to send in MAX_DATA.
    pub fn take_update(&mut self) -> Option<u64> {
        if self.max_data - self.consumed < self.window / 2 {
            self.max_data = self.consumed + self.window;
            Some(self.max_data)
        } else {
            None
        }
    }
}

/// Receive half of a stream: ordered reassembly with flow control.
#[derive(Debug, Clone)]
pub struct RecvStream {
    chunks: BTreeMap<u64, Vec<u8>>,
    read_off: u64,
    highest: u64,
    fin: Option<u64>,
    max_data: u64,
    window: u64,
    reset: Option<u64>,
    stopped: Option<u64>,
    /// `read` has reported the end of the stream to the application.
    fin_read: bool,
}

impl RecvStream {
    /// Creates a stream with the given initial MAX_STREAM_DATA window.
    pub fn new(window: u64) -> Self {
        Self {
            chunks: BTreeMap::new(),
            read_off: 0,
            highest: 0,
            fin: None,
            max_data: window,
            window,
            reset: None,
            stopped: None,
            fin_read: false,
        }
    }

    /// Handles a STREAM frame. Overlapping and duplicate data are accepted
    /// (the first copy wins); `conn` is charged only for new highest-offset bytes.
    pub fn on_frame(
        &mut self,
        offset: u64,
        data: &[u8],
        fin: bool,
        conn: &mut ConnFlow,
    ) -> Result<(), StreamError> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(StreamError::FlowControl)?;
        if let Some(f) = self.fin {
            if end > f || (fin && end != f) {
                return Err(StreamError::FinalSize);
            }
        }
        if fin && end < self.highest {
            return Err(StreamError::FinalSize);
        }
        if end > self.max_data {
            return Err(StreamError::FlowControl);
        }
        if end > self.highest {
            conn.on_new_bytes(end - self.highest)?;
            self.highest = end;
        }
        if fin {
            self.fin = Some(end);
        }
        if self.reset.is_some() || self.stopped.is_some() {
            // Flow control was accounted above; the bytes are discarded.
            return Ok(());
        }
        // Trim what was already read, then insert only uncovered gaps.
        let mut start = offset.max(self.read_off);
        while start < end {
            // Skip over an existing chunk covering `start`.
            if let Some((&o, c)) = self.chunks.range(..=start).next_back() {
                let cend = o + c.len() as u64;
                if cend > start {
                    start = cend;
                    continue;
                }
            }
            let gap_end = self
                .chunks
                .range(start..)
                .next()
                .map_or(end, |(&o, _)| o.min(end));
            let a = (start - offset) as usize;
            let b = (gap_end - offset) as usize;
            if b > a {
                self.chunks.insert(start, data[a..b].to_vec());
            }
            start = gap_end;
        }
        Ok(())
    }

    /// Copies contiguous data into `buf`; returns `(bytes, fin_reached)`.
    pub fn read(&mut self, buf: &mut [u8], conn: &mut ConnFlow) -> (usize, bool) {
        if self.reset.is_some() {
            return (0, false);
        }
        let mut n = 0;
        while n < buf.len() {
            let Some(mut entry) = self.chunks.first_entry() else {
                break;
            };
            if *entry.key() != self.read_off {
                break;
            }
            let chunk = entry.get_mut();
            let take = chunk.len().min(buf.len() - n);
            buf[n..n + take].copy_from_slice(&chunk[..take]);
            n += take;
            self.read_off += take as u64;
            if take == chunk.len() {
                entry.remove();
            } else {
                let rest = chunk.split_off(take);
                entry.remove();
                self.chunks.insert(self.read_off, rest);
            }
        }
        conn.on_consumed(n as u64);
        let fin = self.is_finished();
        self.fin_read |= fin;
        (n, fin)
    }

    /// Handles RESET_STREAM (RFC 9000 3.2 "Reset Recvd"): validates the final
    /// size, charges connection flow control up to it, discards buffered data
    /// and returns the unread bytes' credit to the connection window.
    pub fn on_reset(
        &mut self,
        error: u64,
        final_size: u64,
        conn: &mut ConnFlow,
    ) -> Result<(), StreamError> {
        if let Some(f) = self.fin {
            if f != final_size {
                return Err(StreamError::FinalSize);
            }
        }
        if final_size < self.highest {
            return Err(StreamError::FinalSize);
        }
        if final_size > self.max_data {
            return Err(StreamError::FlowControl);
        }
        if self.reset.is_some() {
            return Ok(());
        }
        conn.on_new_bytes(final_size - self.highest)?;
        self.highest = final_size;
        self.fin = Some(final_size);
        self.reset = Some(error);
        self.chunks.clear();
        conn.on_consumed(final_size - self.read_off);
        self.read_off = final_size;
        Ok(())
    }

    /// The application no longer wants data. Returns the error code for a
    /// STOP_SENDING frame (once); buffered data is released to the connection window.
    pub fn stop_sending(&mut self, error: u64, conn: &mut ConnFlow) -> Option<u64> {
        if self.stopped.is_some() || self.reset.is_some() || self.is_finished() {
            return None;
        }
        self.stopped = Some(error);
        self.chunks.clear();
        conn.on_consumed(self.highest - self.read_off);
        self.read_off = self.highest;
        Some(error)
    }

    /// The MAX_STREAM_DATA limit currently advertised to the peer.
    pub fn max_stream_data(&self) -> u64 {
        self.max_data
    }

    /// Error code of a received RESET_STREAM.
    pub fn reset_code(&self) -> Option<u64> {
        self.reset
    }

    /// Whether all data up to the final size has been read.
    pub fn is_finished(&self) -> bool {
        self.fin == Some(self.read_off)
    }

    /// Whether `read` has told the application the stream ended. A stream
    /// whose final size equals what was already read (an empty stream, or a
    /// FIN-only frame after all the data was read) is `is_finished` on
    /// arrival, before the application has been told.
    pub fn fin_delivered(&self) -> bool {
        self.fin_read
    }

    /// Whether contiguous data is available to read.
    pub fn is_readable(&self) -> bool {
        self.chunks.contains_key(&self.read_off) || self.is_finished()
    }

    /// New MAX_STREAM_DATA value to advertise, if over half the window was read.
    pub fn take_update(&mut self) -> Option<u64> {
        if self.fin.is_none() && self.max_data - self.read_off < self.window / 2 {
            self.max_data = self.read_off + self.window;
            Some(self.max_data)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn read_all(s: &mut RecvStream, c: &mut ConnFlow) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut buf = [0u8; 7];
        loop {
            let (n, fin) = s.read(&mut buf, c);
            out.extend_from_slice(&buf[..n]);
            if n == 0 || fin {
                return (out, fin);
            }
        }
    }

    #[test]
    fn out_of_order_and_overlap() {
        let mut c = ConnFlow::new(1000);
        let mut s = RecvStream::new(1000);
        s.on_frame(6, b"world", true, &mut c).unwrap();
        assert!(!s.is_readable());
        s.on_frame(0, b"hello ", false, &mut c).unwrap();
        s.on_frame(3, b"lo wo", false, &mut c).unwrap(); // overlap, duplicate
        assert_eq!(read_all(&mut s, &mut c), (b"hello world".to_vec(), true));
        assert_eq!(c.received(), 11);
    }

    #[test]
    fn final_size_errors() {
        let mut c = ConnFlow::new(1000);
        let mut s = RecvStream::new(1000);
        s.on_frame(0, b"abcd", true, &mut c).unwrap();
        assert_eq!(
            s.on_frame(4, b"x", false, &mut c),
            Err(StreamError::FinalSize)
        );
        assert_eq!(
            s.on_frame(0, b"ab", true, &mut c),
            Err(StreamError::FinalSize)
        );
        s.on_frame(0, b"abcd", true, &mut c).unwrap(); // same final size is fine
        let mut s2 = RecvStream::new(1000);
        s2.on_frame(0, b"abcdef", false, &mut c).unwrap();
        assert_eq!(
            s2.on_frame(0, b"abc", true, &mut c),
            Err(StreamError::FinalSize)
        );
    }

    #[test]
    fn stream_and_connection_limits() {
        let mut c = ConnFlow::new(15);
        let mut s = RecvStream::new(10);
        assert_eq!(
            s.on_frame(5, b"123456", false, &mut c),
            Err(StreamError::FlowControl)
        );
        s.on_frame(0, b"0123456789", false, &mut c).unwrap();
        let mut s2 = RecvStream::new(10);
        assert_eq!(
            s2.on_frame(0, b"abcdef", false, &mut c),
            Err(StreamError::FlowControl),
            "conn limit 15"
        );
        // Reading frees credit.
        let mut buf = [0u8; 10];
        assert_eq!(s.read(&mut buf, &mut c), (10, false));
        assert_eq!(s.take_update(), Some(20));
        assert_eq!(c.take_update(), Some(25));
        assert_eq!(c.take_update(), None);
        s2.on_frame(0, b"abcdef", false, &mut c).unwrap();
        s.on_frame(10, b"012345678", false, &mut c).unwrap(); // conn total = 25
        assert_eq!(
            s.on_frame(19, b"9", false, &mut c),
            Err(StreamError::FlowControl)
        );
    }

    #[test]
    fn reset_final_size_and_flow_accounting() {
        let mut c = ConnFlow::new(60);
        let mut s = RecvStream::new(50);
        s.on_frame(10, b"abcde", false, &mut c).unwrap();
        assert_eq!(
            s.on_reset(1, 12, &mut c),
            Err(StreamError::FinalSize),
            "below highest"
        );
        assert_eq!(s.on_reset(1, 60, &mut c), Err(StreamError::FlowControl));
        s.on_reset(1, 40, &mut c).unwrap();
        assert_eq!(c.received(), 40, "charged up to final size");
        assert_eq!(s.reset_code(), Some(1));
        let mut buf = [0u8; 8];
        assert_eq!(s.read(&mut buf, &mut c), (0, false));
        // All 40 bytes count as consumed, so the connection window reopens.
        assert_eq!(c.take_update(), Some(100));
        // Late data must stay within the final size.
        assert_eq!(
            s.on_frame(38, b"xyz", false, &mut c),
            Err(StreamError::FinalSize)
        );
        s.on_frame(0, b"late", false, &mut c).unwrap();
        // A conflicting final size after FIN is an error.
        let mut f = RecvStream::new(50);
        f.on_frame(0, b"abc", true, &mut c).unwrap();
        assert_eq!(f.on_reset(2, 5, &mut c), Err(StreamError::FinalSize));
        f.on_reset(2, 3, &mut c).unwrap();
    }

    #[test]
    fn stop_sending_discards_and_releases_credit() {
        let mut c = ConnFlow::new(20);
        let mut s = RecvStream::new(20);
        s.on_frame(0, b"0123456789ab", false, &mut c).unwrap();
        assert_eq!(s.stop_sending(9, &mut c), Some(9));
        assert_eq!(s.stop_sending(9, &mut c), None, "only once");
        assert_eq!(c.take_update(), Some(32));
        // Further data is still flow-controlled but discarded.
        s.on_frame(10, b"abc", false, &mut c).unwrap();
        assert!(!s.is_readable());
        assert_eq!(
            s.on_frame(10, b"0123456789xyz", false, &mut c),
            Err(StreamError::FlowControl)
        );
    }

    proptest! {
        #[test]
        fn random_chunking_reassembles(data in proptest::collection::vec(any::<u8>(), 1..2000),
                                       cuts in proptest::collection::vec((any::<prop::sample::Index>(), any::<prop::sample::Index>()), 1..60),
                                       order in any::<u64>()) {
            let len = data.len();
            // Random (possibly overlapping) segments plus a full cover so all bytes arrive.
            let mut segs: Vec<(usize, usize)> = cuts.iter().map(|(a, b)| {
                let (x, y) = (a.index(len), b.index(len + 1));
                (x.min(y), x.max(y))
            }).collect();
            let mut i = 0;
            while i < len { let j = (i + 1 + (order as usize + i) % 97).min(len); segs.push((i, j)); i = j; }
            // Duplicate some and shuffle deterministically.
            let dups: Vec<_> = segs.iter().step_by(3).copied().collect();
            segs.extend(dups);
            let mut rng = order | 1;
            for k in (1..segs.len()).rev() {
                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                segs.swap(k, (rng % (k as u64 + 1)) as usize);
            }
            let mut c = ConnFlow::new(1 << 20);
            let mut s = RecvStream::new(1 << 20);
            let mut out = Vec::new();
            let mut buf = [0u8; 64];
            for (a, b) in segs {
                s.on_frame(a as u64, &data[a..b], b == len, &mut c).unwrap();
                loop { let (n, _) = s.read(&mut buf, &mut c); if n == 0 { break; } out.extend_from_slice(&buf[..n]); }
            }
            prop_assert_eq!(&out, &data);
            prop_assert!(s.is_finished());
            prop_assert_eq!(c.received(), len as u64);
        }
    }
}
