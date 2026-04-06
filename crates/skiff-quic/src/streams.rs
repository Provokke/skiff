//! Stream map: ID allocation (RFC 9000 Section 2.1) and MAX_STREAMS
//! limits in both directions (Section 4.6).

use crate::crypto::Side;
use crate::send::SendStream;
use crate::stream::RecvStream;
use std::collections::BTreeMap;

/// Errors from stream bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamsError {
    /// Peer opened a stream beyond our MAX_STREAMS (STREAM_LIMIT_ERROR, 0x04).
    #[error("stream limit exceeded")]
    StreamLimit,
    /// Peer referenced a stream in an invalid state, e.g. a receive-only
    /// stream it cannot send on (STREAM_STATE_ERROR, 0x05).
    #[error("invalid stream state")]
    StreamState,
    /// We cannot open a stream until the peer raises MAX_STREAMS.
    #[error("blocked on peer MAX_STREAMS")]
    Blocked,
}

/// Whether `id` was initiated by `side`.
pub fn is_local(id: u64, side: Side) -> bool {
    (id & 1 == 0) == (side == Side::Client)
}

/// Whether `id` is bidirectional.
pub fn is_bidi(id: u64) -> bool {
    id & 2 == 0
}

/// Both halves of a stream (absent halves for unidirectional streams).
#[derive(Debug)]
pub struct StreamState {
    /// Send half, if we may send.
    pub send: Option<SendStream>,
    /// Receive half, if the peer may send.
    pub recv: Option<RecvStream>,
}

/// Initial flow-control windows used when creating streams.
#[derive(Debug, Clone, Copy)]
pub struct Windows {
    /// Our receive window per stream.
    pub local_recv: u64,
    /// Peer's MAX_STREAM_DATA for streams we open (bidi_remote from their view).
    pub peer_for_local: u64,
    /// Peer's MAX_STREAM_DATA for streams they open (bidi_local from their view).
    pub peer_for_remote: u64,
    /// Peer's MAX_STREAM_DATA for our unidirectional streams.
    pub peer_uni: u64,
}

/// All streams of a connection.
#[derive(Debug)]
pub struct Streams {
    side: Side,
    map: BTreeMap<u64, StreamState>,
    // Streams we have opened / may open, per [bidi, uni].
    opened: [u64; 2],
    peer_limit: [u64; 2],
    // Streams the peer has opened / may open.
    peer_opened: [u64; 2],
    local_limit: [u64; 2],
    windows: Windows,
}

fn kind(bidi: bool) -> usize {
    usize::from(!bidi)
}

impl Streams {
    /// Creates the map. `local_limit` is what we advertise
    /// (initial_max_streams_bidi/uni), `peer_limit` what the peer advertised.
    pub fn new(side: Side, local_limit: [u64; 2], peer_limit: [u64; 2], windows: Windows) -> Self {
        Self {
            side,
            map: BTreeMap::new(),
            opened: [0; 2],
            peer_limit,
            peer_opened: [0; 2],
            local_limit,
            windows,
        }
    }

    fn make_id(&self, index: u64, bidi: bool) -> u64 {
        (index << 2) | (u64::from(!bidi) << 1) | u64::from(self.side == Side::Server)
    }

    /// Opens a new local stream, returning its ID.
    pub fn open(&mut self, bidi: bool) -> Result<u64, StreamsError> {
        let k = kind(bidi);
        if self.opened[k] >= self.peer_limit[k] {
            return Err(StreamsError::Blocked);
        }
        let id = self.make_id(self.opened[k], bidi);
        self.opened[k] += 1;
        let w = self.windows;
        let st = StreamState {
            send: Some(SendStream::new(if bidi {
                w.peer_for_local
            } else {
                w.peer_uni
            })),
            recv: bidi.then(|| RecvStream::new(w.local_recv)),
        };
        self.map.insert(id, st);
        Ok(id)
    }

    /// Looks up (and implicitly opens, with all lower-numbered streams of the
    /// same type) a stream referenced by a peer frame that carries data to us
    /// (STREAM, RESET_STREAM, STREAM_DATA_BLOCKED). `Ok(None)` means the
    /// stream existed and was already retired: the frame is ignored.
    pub fn get_for_recv(&mut self, id: u64) -> Result<Option<&mut StreamState>, StreamsError> {
        if is_local(id, self.side) && !is_bidi(id) {
            return Err(StreamsError::StreamState);
        }
        self.lookup(id)
    }

    /// Looks up a stream referenced by a peer frame about our send half
    /// (MAX_STREAM_DATA, STOP_SENDING). A peer-initiated unidirectional
    /// stream has no send half (STREAM_STATE_ERROR). `Ok(None)`: retired.
    pub fn get_for_send(&mut self, id: u64) -> Result<Option<&mut StreamState>, StreamsError> {
        if !is_local(id, self.side) && !is_bidi(id) {
            return Err(StreamsError::StreamState);
        }
        self.lookup(id)
    }

    fn lookup(&mut self, id: u64) -> Result<Option<&mut StreamState>, StreamsError> {
        let bidi = is_bidi(id);
        let k = kind(bidi);
        if is_local(id, self.side) {
            if (id >> 2) >= self.opened[k] {
                return Err(StreamsError::StreamState);
            }
        } else {
            let index = id >> 2;
            if index >= self.local_limit[k] {
                return Err(StreamsError::StreamLimit);
            }
            while self.peer_opened[k] <= index {
                let new_id = (self.peer_opened[k] << 2) | (id & 3);
                let w = self.windows;
                self.map.insert(
                    new_id,
                    StreamState {
                        send: bidi.then(|| SendStream::new(w.peer_for_remote)),
                        recv: Some(RecvStream::new(w.local_recv)),
                    },
                );
                self.peer_opened[k] += 1;
            }
        }
        // Closed streams were removed; late frames for them are ignored.
        Ok(self.map.get_mut(&id))
    }

    /// A live stream, for application access.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut StreamState> {
        self.map.get_mut(&id)
    }

    /// A live stream, read-only.
    pub fn get(&self, id: u64) -> Option<&StreamState> {
        self.map.get(&id)
    }

    /// IDs of live streams, ascending.
    pub fn ids(&self) -> Vec<u64> {
        self.map.keys().copied().collect()
    }

    /// The MAX_STREAMS limit we currently grant the peer for `bidi` streams.
    pub fn local_limit(&self, bidi: bool) -> u64 {
        self.local_limit[kind(bidi)]
    }

    /// How many `bidi` streams the peer has opened (explicitly or implicitly).
    pub fn peer_opened(&self, bidi: bool) -> u64 {
        self.peer_opened[kind(bidi)]
    }

    /// The peer's current MAX_STREAMS limit for `bidi` streams (for
    /// STREAMS_BLOCKED when [`Streams::open`] fails with `Blocked`).
    pub fn peer_limit(&self, bidi: bool) -> u64 {
        self.peer_limit[kind(bidi)]
    }

    /// Applies a MAX_STREAMS frame from the peer.
    pub fn on_max_streams(&mut self, bidi: bool, max: u64) {
        let k = kind(bidi);
        self.peer_limit[k] = self.peer_limit[k].max(max);
    }

    /// Removes a fully closed stream; if it was peer-initiated, grants one
    /// more stream and returns the new MAX_STREAMS value to advertise.
    pub fn retire(&mut self, id: u64) -> Option<u64> {
        self.map.remove(&id)?;
        if is_local(id, self.side) {
            return None;
        }
        let k = kind(is_bidi(id));
        self.local_limit[k] += 1;
        Some(self.local_limit[k])
    }

    /// Number of live streams.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether there are no live streams.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Windows = Windows {
        local_recv: 100,
        peer_for_local: 100,
        peer_for_remote: 100,
        peer_uni: 100,
    };

    #[test]
    fn id_allocation_per_side_and_type() {
        let mut c = Streams::new(Side::Client, [10, 10], [2, 1], W);
        assert_eq!(c.open(true), Ok(0));
        assert_eq!(c.open(true), Ok(4));
        assert_eq!(c.open(true), Err(StreamsError::Blocked));
        assert_eq!(c.open(false), Ok(2));
        assert_eq!(c.open(false), Err(StreamsError::Blocked));
        c.on_max_streams(true, 3);
        assert_eq!(c.open(true), Ok(8));
        let mut s = Streams::new(Side::Server, [10, 10], [5, 5], W);
        assert_eq!(s.open(true), Ok(1));
        assert_eq!(s.open(false), Ok(3));
        assert!(c.map[&2].recv.is_none(), "local uni is send-only");
    }

    #[test]
    fn peer_streams_limits_and_implicit_open() {
        let mut s = Streams::new(Side::Server, [3, 1], [0, 0], W);
        // Client bidi stream 8 (index 2) implicitly opens 0 and 4.
        assert!(s.get_for_recv(8).unwrap().is_some());
        assert_eq!(s.len(), 3);
        assert_eq!(s.get_for_recv(12).err(), Some(StreamsError::StreamLimit));
        // Client uni 2 ok, 6 over limit.
        assert!(s.get_for_recv(2).unwrap().unwrap().send.is_none());
        assert_eq!(s.get_for_recv(6).err(), Some(StreamsError::StreamLimit));
        // Server-initiated uni stream: peer may not send on it.
        assert_eq!(s.get_for_recv(3).err(), Some(StreamsError::StreamState));
        // Server bidi stream not yet opened.
        assert_eq!(s.get_for_recv(1).err(), Some(StreamsError::StreamState));
        // Retiring a peer stream grants credit.
        assert_eq!(s.retire(0), Some(4));
        assert!(s.get_for_recv(12).unwrap().is_some());
        assert!(s.get_for_recv(0).unwrap().is_none(), "retired: ignored");
        // Frames about our send half: peer uni has none; our uni has one.
        assert_eq!(s.get_for_send(2).err(), Some(StreamsError::StreamState));
        assert_eq!(s.open(false), Err(StreamsError::Blocked));
        let mut c = Streams::new(Side::Client, [1, 1], [1, 1], W);
        let uni = c.open(false).unwrap();
        assert!(c.get_for_send(uni).unwrap().unwrap().send.is_some());
        assert_eq!(c.get_for_recv(uni).err(), Some(StreamsError::StreamState));
        assert_eq!(c.peer_limit(false), 1);
    }
}
