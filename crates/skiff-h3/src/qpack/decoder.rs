//! The QPACK decoder (RFC 9204 2.2, 4.3, 4.4, 4.5): applies encoder-stream
//! instructions to its dynamic table, decodes field sections (reporting
//! sections that need inserts not yet received as blocked) and produces
//! decoder-stream instructions.

use super::prefix::{decode_int, decode_str, encode_int, PrimitiveError};
use super::table::{static_entry, DynamicTable};
use super::{Field, QpackError, ENTRY_OVERHEAD};
use std::collections::BTreeSet;

/// Outcome of [`Decoder::decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// The decoded field lines.
    Fields(Vec<Field>),
    /// The section needs dynamic table inserts that have not arrived; call
    /// [`Decoder::decode`] again with the same bytes once
    /// [`Decoder::insert_count`] has grown.
    Blocked {
        /// The Insert Count the section requires.
        required_insert_count: u64,
    },
}

/// A QPACK decoder for one connection.
#[derive(Debug, Clone)]
pub struct Decoder {
    table: DynamicTable,
    max_capacity: u64,
    max_blocked: u64,
    max_section_size: u64,
    pending: Vec<u8>,
    out: Vec<u8>,
    /// Insert Count the encoder knows we have received.
    acked: u64,
    blocked: BTreeSet<u64>,
}

fn dec_err(e: PrimitiveError) -> QpackError {
    QpackError::DecompressionFailed(match e {
        PrimitiveError::Incomplete => "truncated field section",
        PrimitiveError::Invalid(r) => r,
    })
}

impl Decoder {
    /// A decoder that advertises `max_table_capacity`
    /// (SETTINGS_QPACK_MAX_TABLE_CAPACITY), `max_blocked_streams`
    /// (SETTINGS_QPACK_BLOCKED_STREAMS) and accepts field sections up to
    /// `max_field_section_size` (SETTINGS_MAX_FIELD_SECTION_SIZE).
    pub fn new(
        max_table_capacity: u64,
        max_blocked_streams: u64,
        max_field_section_size: u64,
    ) -> Self {
        Self {
            table: DynamicTable::new(),
            max_capacity: max_table_capacity,
            max_blocked: max_blocked_streams,
            max_section_size: max_field_section_size,
            pending: Vec::new(),
            out: Vec::new(),
            acked: 0,
            blocked: BTreeSet::new(),
        }
    }

    /// The dynamic table.
    pub fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// Insertions received so far.
    pub fn insert_count(&self) -> u64 {
        self.table.insert_count()
    }

    /// Streams currently blocked on dynamic table inserts.
    pub fn blocked_streams(&self) -> usize {
        self.blocked.len()
    }

    /// Decoder-stream bytes to send to the peer's encoder (drained): Section
    /// Acknowledgments and Stream Cancellations queued so far, then an
    /// Insert Count Increment for inserts no acknowledgment covered.
    pub fn take_instructions(&mut self) -> Vec<u8> {
        let count = self.table.insert_count();
        if count > self.acked {
            encode_int(&mut self.out, 0x00, 6, count - self.acked);
            self.acked = count;
        }
        std::mem::take(&mut self.out)
    }

    /// Consumes encoder-stream bytes; instructions may be split across
    /// calls.
    pub fn on_encoder_stream(&mut self, data: &[u8]) -> Result<(), QpackError> {
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(data);
        let mut pos = 0;
        let res = loop {
            match self.instruction(buf.get(pos..).unwrap_or_default()) {
                Ok(n) => pos += n,
                Err(PrimitiveError::Incomplete) => break Ok(()),
                Err(PrimitiveError::Invalid(r)) => break Err(QpackError::EncoderStream(r)),
            }
        };
        buf.drain(..pos.min(buf.len()));
        self.pending = buf;
        res
    }

    fn max_str(&self) -> usize {
        // An entry's name and value must fit in the table together.
        usize::try_from(self.max_capacity).unwrap_or(usize::MAX)
    }

    /// Applies one encoder instruction; returns its length.
    fn instruction(&mut self, buf: &[u8]) -> Result<usize, PrimitiveError> {
        let first = *buf.first().ok_or(PrimitiveError::Incomplete)?;
        let max = self.max_str();
        let (name, value, len) = if first & 0x80 != 0 {
            // Insert With Name Reference (4.3.2).
            let (idx, n) = decode_int(buf, 6)?;
            let (value, m) = decode_str(buf.get(n..).unwrap_or_default(), 7, max)?;
            let name = if first & 0x40 != 0 {
                static_entry(idx)
                    .ok_or(PrimitiveError::Invalid("invalid static table index"))?
                    .0
                    .to_vec()
            } else {
                self.relative(idx)?.0
            };
            (name, value, n + m)
        } else if first & 0x40 != 0 {
            // Insert With Literal Name (4.3.3).
            let (name, n) = decode_str(buf, 5, max)?;
            let (value, m) = decode_str(buf.get(n..).unwrap_or_default(), 7, max)?;
            (name, value, n + m)
        } else if first & 0x20 != 0 {
            // Set Dynamic Table Capacity (4.3.1).
            let (cap, n) = decode_int(buf, 5)?;
            if cap > self.max_capacity {
                return Err(PrimitiveError::Invalid("capacity exceeds the maximum"));
            }
            self.table
                .set_capacity(usize::try_from(cap).unwrap_or(usize::MAX));
            return Ok(n);
        } else {
            // Duplicate (4.3.4).
            let (idx, n) = decode_int(buf, 5)?;
            let (name, value) = self.relative(idx)?;
            (name, value, n)
        };
        if !self.table.insert(name, value) {
            return Err(PrimitiveError::Invalid(
                "entry larger than the table capacity",
            ));
        }
        Ok(len)
    }

    /// The entry at encoder-stream relative index `idx` (relative to the
    /// Insert Count).
    fn relative(&self, idx: u64) -> Result<(Vec<u8>, Vec<u8>), PrimitiveError> {
        let e = self
            .table
            .insert_count()
            .checked_sub(idx)
            .and_then(|x| x.checked_sub(1))
            .and_then(|abs| self.table.get(abs))
            .ok_or(PrimitiveError::Invalid("invalid dynamic table reference"))?;
        Ok((e.name.clone(), e.value.clone()))
    }

    /// Reconstructs the Required Insert Count (RFC 9204 4.5.1.1).
    fn required_insert_count(&self, encoded: u64) -> Result<u64, QpackError> {
        if encoded == 0 {
            return Ok(0);
        }
        let bad = QpackError::DecompressionFailed("invalid Required Insert Count");
        let max_entries = self.max_capacity / ENTRY_OVERHEAD as u64;
        let full_range = 2 * max_entries;
        if encoded > full_range {
            return Err(bad);
        }
        let max_value = self.table.insert_count() + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut ric = max_wrapped + encoded - 1;
        if ric > max_value {
            if ric <= full_range {
                return Err(bad);
            }
            ric -= full_range;
        }
        if ric == 0 {
            return Err(bad);
        }
        Ok(ric)
    }

    /// Decodes the field section of a HEADERS frame on `stream_id`. A
    /// section that references inserts not yet received is
    /// [`Decoded::Blocked`] (counted against the blocked-streams limit until
    /// it decodes or [`Decoder::cancel_stream`] is called). A section that
    /// used the dynamic table is acknowledged on the decoder stream.
    pub fn decode(&mut self, stream_id: u64, block: &[u8]) -> Result<Decoded, QpackError> {
        let (encoded, n) = decode_int(block, 8).map_err(dec_err)?;
        let ric = self.required_insert_count(encoded)?;
        let rest = block.get(n..).unwrap_or_default();
        let sign = rest
            .first()
            .ok_or_else(|| dec_err(PrimitiveError::Incomplete))?
            & 0x80
            != 0;
        let (delta, m) = decode_int(rest, 7).map_err(dec_err)?;
        let base = if sign {
            ric.checked_sub(delta).and_then(|x| x.checked_sub(1))
        } else {
            ric.checked_add(delta)
        }
        .ok_or(QpackError::DecompressionFailed("invalid Base"))?;
        if ric > self.table.insert_count() {
            if !self.blocked.contains(&stream_id) {
                if self.blocked.len() as u64 >= self.max_blocked {
                    return Err(QpackError::DecompressionFailed("too many blocked streams"));
                }
                self.blocked.insert(stream_id);
            }
            return Ok(Decoded::Blocked {
                required_insert_count: ric,
            });
        }
        self.blocked.remove(&stream_id);
        let fields = self.lines(rest.get(m..).unwrap_or_default(), ric, base)?;
        if ric > 0 {
            // Section Acknowledgment (4.4.1).
            encode_int(&mut self.out, 0x80, 7, stream_id);
            self.acked = self.acked.max(ric);
        }
        Ok(Decoded::Fields(fields))
    }

    fn dynamic(&self, abs: Option<u64>, ric: u64) -> Result<(Vec<u8>, Vec<u8>), QpackError> {
        let e = abs
            .filter(|a| *a < ric)
            .and_then(|a| self.table.get(a))
            .ok_or(QpackError::DecompressionFailed(
                "invalid dynamic table reference",
            ))?;
        Ok((e.name.clone(), e.value.clone()))
    }

    fn lines(&self, mut buf: &[u8], ric: u64, base: u64) -> Result<Vec<Field>, QpackError> {
        let max = usize::try_from(self.max_section_size).unwrap_or(usize::MAX);
        let mut fields = Vec::new();
        let mut size = 0u64;
        while let Some(&b) = buf.first() {
            let stat = |idx: u64| {
                static_entry(idx)
                    .map(|(n, v)| (n.to_vec(), v.to_vec()))
                    .ok_or(QpackError::DecompressionFailed(
                        "invalid static table index",
                    ))
            };
            let rel = |idx: u64| base.checked_sub(idx).and_then(|x| x.checked_sub(1));
            let (name, value, never, used) = if b & 0x80 != 0 {
                // Indexed Field Line (4.5.2).
                let (idx, n) = decode_int(buf, 6).map_err(dec_err)?;
                let (name, value) = if b & 0x40 != 0 {
                    stat(idx)?
                } else {
                    self.dynamic(rel(idx), ric)?
                };
                (name, value, false, n)
            } else if b & 0x40 != 0 {
                // Literal Field Line with Name Reference (4.5.4).
                let (idx, n) = decode_int(buf, 4).map_err(dec_err)?;
                let name = if b & 0x10 != 0 {
                    stat(idx)?.0
                } else {
                    self.dynamic(rel(idx), ric)?.0
                };
                let (value, m) =
                    decode_str(buf.get(n..).unwrap_or_default(), 7, max).map_err(dec_err)?;
                (name, value, b & 0x20 != 0, n + m)
            } else if b & 0x20 != 0 {
                // Literal Field Line with Literal Name (4.5.6).
                let (name, n) = decode_str(buf, 3, max).map_err(dec_err)?;
                let (value, m) =
                    decode_str(buf.get(n..).unwrap_or_default(), 7, max).map_err(dec_err)?;
                (name, value, b & 0x10 != 0, n + m)
            } else if b & 0x10 != 0 {
                // Indexed Field Line with Post-Base Index (4.5.3).
                let (idx, n) = decode_int(buf, 4).map_err(dec_err)?;
                let (name, value) = self.dynamic(base.checked_add(idx), ric)?;
                (name, value, false, n)
            } else {
                // Literal Field Line with Post-Base Name Reference (4.5.5).
                let (idx, n) = decode_int(buf, 3).map_err(dec_err)?;
                let name = self.dynamic(base.checked_add(idx), ric)?.0;
                let (value, m) =
                    decode_str(buf.get(n..).unwrap_or_default(), 7, max).map_err(dec_err)?;
                (name, value, b & 0x08 != 0, n + m)
            };
            let f = Field {
                name,
                value,
                never_index: never,
            };
            size += f.size();
            if size > self.max_section_size {
                return Err(QpackError::FieldSectionTooLarge {
                    size,
                    limit: self.max_section_size,
                });
            }
            fields.push(f);
            buf = buf.get(used..).unwrap_or_default();
        }
        Ok(fields)
    }

    /// The stream was reset or abandoned before its field sections were
    /// decoded: forget it as blocked and, if the dynamic table is enabled,
    /// tell the encoder (Stream Cancellation, 4.4.2).
    pub fn cancel_stream(&mut self, stream_id: u64) {
        self.blocked.remove(&stream_id);
        if self.max_capacity > 0 {
            encode_int(&mut self.out, 0x40, 6, stream_id);
        }
    }
}
