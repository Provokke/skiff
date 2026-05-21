//! QPACK: field compression for HTTP/3 (RFC 9204).
//!
//! - [`prefix`]: prefixed integers and string literals (RFC 7541 5.1, 5.2).
//! - [`huffman`]: the static Huffman code (RFC 7541 Appendix B).
//! - [`table`]: the static table (RFC 9204 Appendix A) and the dynamic table.
//! - [`Encoder`]: encodes field sections, writes encoder-stream instructions
//!   and consumes decoder-stream instructions.
//! - [`Decoder`]: consumes encoder-stream instructions, decodes field
//!   sections (blocking on missing inserts), writes decoder-stream
//!   instructions.

pub mod decoder;
pub mod encoder;
pub mod huffman;
mod huffman_code;
pub mod prefix;
mod static_table;
pub mod table;

pub use decoder::{Decoded, Decoder};
pub use encoder::Encoder;

/// Bytes added to `name.len() + value.len()` for an entry's size (RFC 9204 3.2.1).
pub const ENTRY_OVERHEAD: usize = 32;

/// QPACK_DECOMPRESSION_FAILED (RFC 9204 6).
pub const DECOMPRESSION_FAILED: u64 = 0x200;
/// QPACK_ENCODER_STREAM_ERROR (RFC 9204 6).
pub const ENCODER_STREAM_ERROR: u64 = 0x201;
/// QPACK_DECODER_STREAM_ERROR (RFC 9204 6).
pub const DECODER_STREAM_ERROR: u64 = 0x202;

/// QPACK failures. The first three are HTTP/3 connection errors with the
/// code from [`QpackError::code`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QpackError {
    /// An encoded field section could not be decoded.
    #[error("QPACK decompression failed: {0}")]
    DecompressionFailed(&'static str),
    /// An encoder-stream instruction was invalid.
    #[error("QPACK encoder stream error: {0}")]
    EncoderStream(&'static str),
    /// A decoder-stream instruction was invalid.
    #[error("QPACK decoder stream error: {0}")]
    DecoderStream(&'static str),
    /// A field section to encode exceeds the peer's
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (a local error, nothing was sent).
    #[error("field section of {size} bytes exceeds the peer limit of {limit}")]
    FieldSectionTooLarge {
        /// Size of the section (RFC 9114 4.2.2).
        size: u64,
        /// The peer's limit.
        limit: u64,
    },
}

impl QpackError {
    /// The HTTP/3 error code for this error.
    pub fn code(&self) -> u64 {
        match self {
            Self::DecompressionFailed(_) | Self::FieldSectionTooLarge { .. } => {
                DECOMPRESSION_FAILED
            }
            Self::EncoderStream(_) => ENCODER_STREAM_ERROR,
            Self::DecoderStream(_) => DECODER_STREAM_ERROR,
        }
    }
}

/// One field line (a header or trailer).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Field {
    /// Field name (lowercase in HTTP/3).
    pub name: Vec<u8>,
    /// Field value.
    pub value: Vec<u8>,
    /// Never insert into the dynamic table and mark intermediaries must
    /// not either (the `N` bit, RFC 9204 4.5.4).
    pub never_index: bool,
}

impl Field {
    /// A field that may be indexed.
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            never_index: false,
        }
    }

    /// The field's size for table accounting and
    /// SETTINGS_MAX_FIELD_SECTION_SIZE: name + value + 32.
    pub fn size(&self) -> u64 {
        (self.name.len() + self.value.len() + ENTRY_OVERHEAD) as u64
    }
}

/// Sum of [`Field::size`] over a field section.
pub fn section_size(fields: &[Field]) -> u64 {
    fields.iter().map(Field::size).sum()
}
