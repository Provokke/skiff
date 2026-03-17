//! Connection IDs (RFC 9000 5.1): the CIDs we issue to the peer and the
//! CIDs the peer issued to us, each with its sequence number and stateless
//! reset token (RFC 9000 10.3).

use std::collections::BTreeMap;

/// Length of a stateless reset token.
pub const RESET_TOKEN_LEN: usize = 16;
/// Smallest stateless reset we send or recognise: 5 bytes that look like a
/// short header plus the token (RFC 9000 10.3).
pub const MIN_RESET_LEN: usize = 21;
/// Largest stateless reset we send.
const MAX_RESET_LEN: usize = 43;

/// Derives stateless reset tokens from connection IDs:
/// `HMAC-SHA256(key, cid)[..16]` (RFC 9000 10.3.2). An endpoint shares one
/// key across its connections so it can compute the token for a CID it no
/// longer has state for and send a stateless reset.
#[derive(Clone)]
pub struct ResetKey(ring::hmac::Key);

impl core::fmt::Debug for ResetKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ResetKey(..)")
    }
}

impl ResetKey {
    /// A key from secret bytes (use at least 32 random bytes).
    pub fn new(secret: &[u8]) -> Self {
        Self(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret))
    }

    /// A key from 32 bytes of system randomness; `None` if the system RNG
    /// fails.
    pub fn random() -> Option<Self> {
        let mut secret = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut secret).ok()?;
        Some(Self::new(&secret))
    }

    /// A stateless reset (RFC 9000 10.3) answering a `trigger_len`-byte
    /// datagram sent to `cid`: a short-header-looking first byte, random
    /// bytes, then the token. It is one byte shorter than the trigger (so two
    /// endpoints cannot keep resetting each other) and at most 43 bytes;
    /// `None` when that would be under 21 bytes or the RNG fails.
    pub fn stateless_reset(&self, cid: &[u8], trigger_len: usize) -> Option<Vec<u8>> {
        let len = trigger_len.checked_sub(1)?.min(MAX_RESET_LEN);
        if len < MIN_RESET_LEN {
            return None;
        }
        let mut out = vec![0u8; len];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut out).ok()?;
        let split = len - RESET_TOKEN_LEN;
        let first = out.first_mut()?;
        *first = (*first & 0x3f) | 0x40;
        out.get_mut(split..)?.copy_from_slice(&self.token(cid));
        Some(out)
    }

    /// The stateless reset token for `cid`.
    pub fn token(&self, cid: &[u8]) -> [u8; RESET_TOKEN_LEN] {
        let tag = ring::hmac::sign(&self.0, cid);
        let mut t = [0u8; RESET_TOKEN_LEN];
        for (d, s) in t.iter_mut().zip(tag.as_ref()) {
            *d = *s;
        }
        t
    }
}

/// A CID we issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalCid {
    pub seq: u64,
    pub cid: Vec<u8>,
    pub token: [u8; RESET_TOKEN_LEN],
}

/// The CIDs we issued and the peer has not retired.
#[derive(Debug)]
pub(crate) struct LocalCids {
    active: Vec<LocalCid>,
    next_seq: u64,
    /// Bumped whenever the active set changes (endpoints re-route then).
    generation: u64,
}

/// A RETIRE_CONNECTION_ID for a sequence number we never issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnissuedSeq;

impl LocalCids {
    /// Starts with the handshake CID (sequence number 0).
    pub fn new(cid: Vec<u8>, token: [u8; RESET_TOKEN_LEN]) -> Self {
        Self {
            active: vec![LocalCid { seq: 0, cid, token }],
            next_seq: 1,
            generation: 0,
        }
    }

    pub fn seq_of(&self, cid: &[u8]) -> Option<u64> {
        self.active.iter().find(|c| c.cid == cid).map(|c| c.seq)
    }

    pub fn get(&self, seq: u64) -> Option<&LocalCid> {
        self.active.iter().find(|c| c.seq == seq)
    }

    pub fn len(&self) -> usize {
        self.active.len()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn cids(&self) -> impl Iterator<Item = &[u8]> {
        self.active.iter().map(|c| c.cid.as_slice())
    }

    /// Issues a new CID; returns its sequence number.
    pub fn issue(&mut self, cid: Vec<u8>, token: [u8; RESET_TOKEN_LEN]) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.active.push(LocalCid { seq, cid, token });
        self.generation += 1;
        seq
    }

    /// The peer retired `seq`: `Ok(true)` if it was active, `Ok(false)` if
    /// it was retired before, an error if we never issued it.
    pub fn retire(&mut self, seq: u64) -> Result<bool, UnissuedSeq> {
        if seq >= self.next_seq {
            return Err(UnissuedSeq);
        }
        let before = self.active.len();
        self.active.retain(|c| c.seq != seq);
        let was = self.active.len() != before;
        if was {
            self.generation += 1;
        }
        Ok(was)
    }
}

/// Why a NEW_CONNECTION_ID frame is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewCidError {
    /// A known sequence number with a different CID or token
    /// (PROTOCOL_VIOLATION).
    Conflict,
    /// More active CIDs than our active_connection_id_limit
    /// (CONNECTION_ID_LIMIT_ERROR).
    Limit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteCid {
    cid: Vec<u8>,
    token: Option<[u8; RESET_TOKEN_LEN]>,
}

/// The CIDs the peer issued to us. Exactly one is in use; the others are
/// spares for migration.
#[derive(Debug)]
pub(crate) struct RemoteCids {
    entries: BTreeMap<u64, RemoteCid>,
    /// Sequence numbers we used and retired (never used again).
    used: Vec<u64>,
    current: u64,
    retire_prior_to: u64,
    limit: u64,
}

impl RemoteCids {
    /// Starts with the peer's handshake CID (sequence number 0); `limit` is
    /// the active_connection_id_limit we advertise.
    pub fn new(cid: Vec<u8>, limit: u64) -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(0, RemoteCid { cid, token: None });
        Self {
            entries,
            used: Vec::new(),
            current: 0,
            retire_prior_to: 0,
            limit,
        }
    }

    /// The CID packets are sent with.
    pub fn current(&self) -> &[u8] {
        self.entries
            .get(&self.current)
            .map_or(&[][..], |c| c.cid.as_slice())
    }

    /// Replaces the handshake CID (a client learns the server's from its
    /// first Initial).
    pub fn set_handshake_cid(&mut self, cid: Vec<u8>) {
        if let Some(c) = self.entries.get_mut(&0) {
            c.cid = cid;
        }
    }

    /// Sets the stateless reset token of the handshake CID (from the
    /// server's transport parameters).
    pub fn set_handshake_token(&mut self, token: [u8; RESET_TOKEN_LEN]) {
        if let Some(c) = self.entries.get_mut(&0) {
            c.token = Some(token);
        }
    }

    /// The stateless reset token of the CID in use. Only it is checked:
    /// RFC 9000 10.3.1 forbids checking tokens of CIDs not yet used, and
    /// used ones are retired when we switch.
    pub fn current_token(&self) -> Option<&[u8; RESET_TOKEN_LEN]> {
        self.entries.get(&self.current)?.token.as_ref()
    }

    /// Number of unused CIDs available for a switch.
    pub fn spares(&self) -> usize {
        self.entries
            .keys()
            .filter(|s| **s != self.current && !self.used.contains(s))
            .count()
    }

    /// Handles NEW_CONNECTION_ID (RFC 9000 19.15, 5.1.2). Returns the
    /// sequence numbers that must now be retired with
    /// RETIRE_CONNECTION_ID.
    pub fn on_new(
        &mut self,
        seq: u64,
        retire_prior_to: u64,
        cid: &[u8],
        token: [u8; RESET_TOKEN_LEN],
    ) -> Result<Vec<u64>, NewCidError> {
        let entry = RemoteCid {
            cid: cid.to_vec(),
            token: Some(token),
        };
        if let Some(known) = self.entries.get(&seq) {
            // The handshake CID has no token in the table for a client
            // until the parameters arrive; a peer never re-sends seq 0.
            return if *known == entry {
                Ok(Vec::new())
            } else {
                Err(NewCidError::Conflict)
            };
        }
        if self
            .entries
            .iter()
            .any(|(s, c)| *s != seq && c.cid == entry.cid)
        {
            return Err(NewCidError::Conflict);
        }
        let mut retire = Vec::new();
        if seq < self.retire_prior_to || self.used.contains(&seq) {
            // Already covered by an earlier Retire Prior To: retire at once.
            retire.push(seq);
        } else {
            self.entries.insert(seq, entry);
        }
        if retire_prior_to > self.retire_prior_to {
            self.retire_prior_to = retire_prior_to;
            let old: Vec<u64> = self
                .entries
                .keys()
                .copied()
                .filter(|s| *s < retire_prior_to)
                .collect();
            for s in old {
                self.entries.remove(&s);
                retire.push(s);
            }
            if !self.entries.contains_key(&self.current) {
                // The CID in use was retired: move to the lowest spare (the
                // frame itself carries one at or above Retire Prior To).
                if let Some(next) = self
                    .entries
                    .keys()
                    .copied()
                    .find(|s| !self.used.contains(s))
                {
                    self.current = next;
                }
            }
        }
        if self.entries.len() as u64 > self.limit {
            return Err(NewCidError::Limit);
        }
        Ok(retire)
    }

    /// Switches to an unused spare CID; returns the sequence number of the
    /// CID that was in use (to retire), or `None` if there is no spare.
    pub fn switch(&mut self) -> Option<u64> {
        let next = self
            .entries
            .keys()
            .copied()
            .find(|s| *s != self.current && !self.used.contains(s))?;
        let old = self.current;
        self.entries.remove(&old);
        self.used.push(old);
        self.current = next;
        Some(old)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_tokens_are_keyed_and_deterministic() {
        let a = ResetKey::new(&[1; 32]);
        let b = ResetKey::new(&[2; 32]);
        assert_eq!(a.token(b"cid-1"), a.clone().token(b"cid-1"));
        assert_ne!(a.token(b"cid-1"), a.token(b"cid-2"));
        assert_ne!(a.token(b"cid-1"), b.token(b"cid-1"));
        assert_eq!(format!("{a:?}"), "ResetKey(..)");
        assert!(ResetKey::random().is_some());
    }

    #[test]
    fn local_issue_and_retire() {
        let mut l = LocalCids::new(vec![0; 8], [0; 16]);
        assert_eq!(l.issue(vec![1; 8], [1; 16]), 1);
        assert_eq!(l.issue(vec![2; 8], [2; 16]), 2);
        let g = l.generation();
        assert_eq!(l.seq_of(&[2; 8]), Some(2));
        assert_eq!(l.retire(1), Ok(true));
        assert!(l.generation() > g);
        assert_eq!(l.retire(1), Ok(false));
        assert_eq!(l.retire(3), Err(UnissuedSeq));
        assert_eq!(l.seq_of(&[1; 8]), None);
        assert_eq!(l.len(), 2);
        assert_eq!(l.get(2).map(|c| c.token), Some([2; 16]));
    }

    #[test]
    fn remote_new_retire_prior_to_and_limit() {
        let mut r = RemoteCids::new(vec![0; 8], 3);
        assert_eq!(r.on_new(1, 0, &[1; 8], [1; 16]), Ok(vec![]));
        // Duplicate is fine, a conflicting one is not.
        assert_eq!(r.on_new(1, 0, &[1; 8], [1; 16]), Ok(vec![]));
        assert_eq!(r.on_new(1, 0, &[9; 8], [1; 16]), Err(NewCidError::Conflict));
        assert_eq!(
            r.on_new(5, 0, &[1; 8], [5; 16]),
            Err(NewCidError::Conflict),
            "same CID under two sequence numbers"
        );
        assert_eq!(r.spares(), 1);
        // Retire Prior To 2 retires 0 (in use) and 1; we move to 2.
        let mut got = r.on_new(2, 2, &[2; 8], [2; 16]).unwrap();
        got.sort_unstable();
        assert_eq!(got, vec![0, 1]);
        assert_eq!(r.current(), &[2; 8]);
        // A late frame below Retire Prior To is retired immediately.
        assert_eq!(r.on_new(1, 0, &[1; 8], [1; 16]), Ok(vec![1]));
        assert_eq!(r.on_new(3, 2, &[3; 8], [3; 16]), Ok(vec![]));
        assert_eq!(r.on_new(4, 2, &[4; 8], [4; 16]), Ok(vec![]));
        assert_eq!(r.on_new(6, 2, &[6; 8], [6; 16]), Err(NewCidError::Limit));
        assert_eq!(r.current_token(), Some(&[2; 16]), "token of the CID in use");
    }

    #[test]
    fn remote_switch_uses_each_cid_once() {
        let mut r = RemoteCids::new(vec![0; 8], 4);
        assert_eq!(r.switch(), None);
        r.on_new(1, 0, &[1; 8], [1; 16]).unwrap();
        r.on_new(2, 0, &[2; 8], [2; 16]).unwrap();
        assert_eq!(r.switch(), Some(0));
        assert_eq!(r.current(), &[1; 8]);
        assert_eq!(r.switch(), Some(1));
        assert_eq!(r.current(), &[2; 8]);
        assert_eq!(r.switch(), None);
        // A retired sequence number re-announced is retired again.
        assert_eq!(r.on_new(0, 0, &[0; 8], [0; 16]), Ok(vec![0]));
        assert_eq!(r.spares(), 0);
    }
}
