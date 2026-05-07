//! The QPACK encoder (RFC 9204 2.1, 4.3, 4.4, 4.5).
//!
//! Policy: static-table matches first; then dynamic-table matches; fields
//! that fit in half the table are inserted (with a static or dynamic name
//! reference when one exists) and referenced if the section may block,
//! otherwise sent as literals. Entries are only evicted once their insert
//! is acknowledged and no unacknowledged field section references them,
//! and at most the peer's
//! SETTINGS_QPACK_BLOCKED_STREAMS streams may wait on unacknowledged
//! inserts. Every dynamic reference is relative to Base = Required Insert
//! Count, so the encoder never needs post-base forms (the decoder accepts
//! them).

use super::prefix::{decode_int, encode_int, encode_str, PrimitiveError};
use super::table::{static_find, DynamicTable, Match};
use super::{section_size, Field, QpackError, ENTRY_OVERHEAD};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone)]
struct Section {
    ric: u64,
    refs: Vec<u64>,
}

enum Rep<'a> {
    Static(u64),
    Dynamic(u64),
    StaticName(u64, &'a Field),
    DynamicName(u64, &'a Field),
    Literal(&'a Field),
}

/// A QPACK encoder for one connection.
#[derive(Debug, Clone)]
pub struct Encoder {
    table: DynamicTable,
    /// Capacity this side is willing to use (an upper bound).
    local_capacity: u64,
    peer_max_capacity: u64,
    peer_max_blocked: u64,
    peer_max_section: u64,
    settings_applied: bool,
    known_received: u64,
    refs: BTreeMap<u64, u32>,
    outstanding: BTreeMap<u64, VecDeque<Section>>,
    out: Vec<u8>,
    pending: Vec<u8>,
}

impl Encoder {
    /// An encoder that will use a dynamic table of at most `capacity`
    /// bytes once the peer's settings allow it (0 disables the dynamic
    /// table). Until [`Encoder::apply_peer_settings`], only the static
    /// table and literals are used.
    pub fn new(capacity: u64) -> Self {
        Self {
            table: DynamicTable::new(),
            local_capacity: capacity,
            peer_max_capacity: 0,
            peer_max_blocked: 0,
            peer_max_section: u64::MAX,
            settings_applied: false,
            known_received: 0,
            refs: BTreeMap::new(),
            outstanding: BTreeMap::new(),
            out: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// Applies the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    /// SETTINGS_QPACK_BLOCKED_STREAMS and SETTINGS_MAX_FIELD_SECTION_SIZE
    /// (once; later calls are ignored). Emits Set Dynamic Table Capacity if
    /// the table is enabled.
    pub fn apply_peer_settings(
        &mut self,
        max_table_capacity: u64,
        blocked_streams: u64,
        max_field_section_size: u64,
    ) {
        if self.settings_applied {
            return;
        }
        self.settings_applied = true;
        self.peer_max_capacity = max_table_capacity;
        self.peer_max_blocked = blocked_streams;
        self.peer_max_section = max_field_section_size;
        let cap = self.local_capacity.min(max_table_capacity);
        if cap > 0 {
            self.table
                .set_capacity(usize::try_from(cap).unwrap_or(usize::MAX));
            encode_int(&mut self.out, 0x20, 5, cap);
        }
    }

    /// The dynamic table.
    pub fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// Inserts the decoder is known to have received.
    pub fn known_received_count(&self) -> u64 {
        self.known_received
    }

    /// Streams with field sections that wait on unacknowledged inserts.
    pub fn blocked_streams(&self) -> usize {
        self.outstanding
            .values()
            .filter(|q| q.iter().any(|s| s.ric > self.known_received))
            .count()
    }

    /// Field sections not yet acknowledged.
    pub fn unacknowledged_sections(&self) -> usize {
        self.outstanding.values().map(VecDeque::len).sum()
    }

    /// Encoder-stream bytes to send to the peer's decoder (drained). Must be
    /// sent before (or with) any field section that references them.
    pub fn take_instructions(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    fn add_ref(&mut self, abs: u64, refs: &mut Vec<u64>) {
        *self.refs.entry(abs).or_insert(0) += 1;
        refs.push(abs);
    }

    fn release(&mut self, s: &Section) {
        for abs in &s.refs {
            if let Some(n) = self.refs.get_mut(abs) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.refs.remove(abs);
                }
            }
        }
    }

    /// Inserts `f` if room can be made without evicting a referenced entry;
    /// returns its absolute index.
    fn try_insert(&mut self, f: &Field, static_name: Option<u64>) -> Option<u64> {
        let size = f.name.len() + f.value.len() + ENTRY_OVERHEAD;
        if size > self.table.capacity() / 2 {
            return None;
        }
        let evict = self.table.evictions_for(size)?;
        // Only evictable entries may go: acknowledged (below the Known
        // Received Count) and referenced by no unacknowledged section
        // (RFC 9204 2.1.1).
        let first = self.table.first_index();
        let end = first + evict as u64;
        if evict > 0
            && (end > self.known_received || (first..end).any(|abs| self.refs.contains_key(&abs)))
        {
            return None;
        }
        let count = self.table.insert_count();
        // The name reference is resolved before the insertion (which may
        // evict the referenced entry; the decoder copies the name first).
        let mut ins = Vec::new();
        if let Some(i) = static_name {
            encode_int(&mut ins, 0xc0, 6, i);
        } else if let Some(Match::Name(abs) | Match::Full(abs)) =
            self.table.find(&f.name, &[], count)
        {
            encode_int(&mut ins, 0x80, 6, count - 1 - abs);
        } else {
            encode_str(&mut ins, 0x40, 5, &f.name);
        }
        encode_str(&mut ins, 0x00, 7, &f.value);
        if !self.table.insert(f.name.clone(), f.value.clone()) {
            return None;
        }
        self.out.extend_from_slice(&ins);
        Some(count)
    }

    /// Encodes a field section for a HEADERS frame on `stream_id`. Any
    /// encoder-stream instructions it needs are queued for
    /// [`Encoder::take_instructions`].
    pub fn encode(&mut self, stream_id: u64, fields: &[Field]) -> Result<Vec<u8>, QpackError> {
        let size = section_size(fields);
        if size > self.peer_max_section {
            return Err(QpackError::FieldSectionTooLarge {
                size,
                limit: self.peer_max_section,
            });
        }
        let krc = self.known_received;
        let stream_blocked = self
            .outstanding
            .get(&stream_id)
            .is_some_and(|q| q.iter().any(|s| s.ric > krc));
        let may_block = stream_blocked || (self.blocked_streams() as u64) < self.peer_max_blocked;
        let mut refs = Vec::new();
        let mut reps = Vec::with_capacity(fields.len());
        for f in fields {
            let st = static_find(&f.name, &f.value);
            // A never-indexed field is always sent as a literal, even when
            // the static table holds it (RFC 9204 4.5.4).
            if let (Some(Match::Full(i)), false) = (st, f.never_index) {
                reps.push(Rep::Static(i));
                continue;
            }
            let static_name = match st {
                Some(Match::Name(i) | Match::Full(i)) => Some(i),
                None => None,
            };
            let limit = if may_block {
                self.table.insert_count()
            } else {
                krc
            };
            if !f.never_index {
                let count = self.table.insert_count();
                match self.table.find(&f.name, &f.value, count) {
                    Some(Match::Full(abs)) if abs < limit => {
                        self.add_ref(abs, &mut refs);
                        reps.push(Rep::Dynamic(abs));
                        continue;
                    }
                    // Present but not yet usable without blocking: do not
                    // insert a second copy.
                    Some(Match::Full(_)) => {}
                    _ => {
                        if let Some(abs) = self.try_insert(f, static_name) {
                            if may_block {
                                self.add_ref(abs, &mut refs);
                                reps.push(Rep::Dynamic(abs));
                                continue;
                            }
                        }
                    }
                }
            }
            if let Some(i) = static_name {
                reps.push(Rep::StaticName(i, f));
            } else if let Some(Match::Name(abs) | Match::Full(abs)) =
                self.table.find(&f.name, &[], limit)
            {
                self.add_ref(abs, &mut refs);
                reps.push(Rep::DynamicName(abs, f));
            } else {
                reps.push(Rep::Literal(f));
            }
        }
        let ric = refs.iter().max().map_or(0, |m| m + 1);
        let max_entries = self.peer_max_capacity / ENTRY_OVERHEAD as u64;
        let mut out = Vec::new();
        let encoded = match ric.checked_rem(2 * max_entries) {
            Some(r) if ric > 0 => r + 1,
            _ => 0,
        };
        encode_int(&mut out, 0x00, 8, encoded);
        encode_int(&mut out, 0x00, 7, 0); // Base = Required Insert Count
        let base = ric;
        let n = |never: bool, bit: u8| if never { bit } else { 0 };
        for r in &reps {
            match r {
                Rep::Static(i) => encode_int(&mut out, 0xc0, 6, *i),
                Rep::Dynamic(abs) => encode_int(&mut out, 0x80, 6, base - 1 - abs),
                Rep::StaticName(i, f) => {
                    encode_int(&mut out, 0x50 | n(f.never_index, 0x20), 4, *i);
                    encode_str(&mut out, 0x00, 7, &f.value);
                }
                Rep::DynamicName(abs, f) => {
                    encode_int(&mut out, 0x40 | n(f.never_index, 0x20), 4, base - 1 - abs);
                    encode_str(&mut out, 0x00, 7, &f.value);
                }
                Rep::Literal(f) => {
                    encode_str(&mut out, 0x20 | n(f.never_index, 0x10), 3, &f.name);
                    encode_str(&mut out, 0x00, 7, &f.value);
                }
            }
        }
        if ric > 0 {
            self.outstanding
                .entry(stream_id)
                .or_default()
                .push_back(Section { ric, refs });
        }
        Ok(out)
    }

    /// Consumes decoder-stream bytes (instructions may be split across
    /// calls).
    pub fn on_decoder_stream(&mut self, data: &[u8]) -> Result<(), QpackError> {
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(data);
        let mut pos = 0;
        let res = loop {
            match self.instruction(buf.get(pos..).unwrap_or_default()) {
                Ok(n) => pos += n,
                Err(PrimitiveError::Incomplete) => break Ok(()),
                Err(PrimitiveError::Invalid(r)) => break Err(QpackError::DecoderStream(r)),
            }
        };
        buf.drain(..pos.min(buf.len()));
        self.pending = buf;
        res
    }

    fn instruction(&mut self, buf: &[u8]) -> Result<usize, PrimitiveError> {
        let first = *buf.first().ok_or(PrimitiveError::Incomplete)?;
        if first & 0x80 != 0 {
            // Section Acknowledgment (4.4.1).
            let (id, n) = decode_int(buf, 7)?;
            let q = self
                .outstanding
                .get_mut(&id)
                .ok_or(PrimitiveError::Invalid(
                    "Section Acknowledgment for no section",
                ))?;
            let s = q.pop_front().ok_or(PrimitiveError::Invalid(
                "Section Acknowledgment for no section",
            ))?;
            if q.is_empty() {
                self.outstanding.remove(&id);
            }
            self.release(&s);
            self.known_received = self.known_received.max(s.ric);
            Ok(n)
        } else if first & 0x40 != 0 {
            // Stream Cancellation (4.4.2).
            let (id, n) = decode_int(buf, 6)?;
            for s in self.outstanding.remove(&id).unwrap_or_default() {
                self.release(&s);
            }
            Ok(n)
        } else {
            // Insert Count Increment (4.4.3).
            let (inc, n) = decode_int(buf, 6)?;
            let krc = self
                .known_received
                .checked_add(inc)
                .filter(|k| inc > 0 && *k <= self.table.insert_count())
                .ok_or(PrimitiveError::Invalid("invalid Insert Count Increment"))?;
            self.known_received = krc;
            Ok(n)
        }
    }
}
