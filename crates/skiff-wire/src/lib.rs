//! QUIC wire-format codecs (RFC 9000): variable-length integers, packet
//! number encoding, long/short packet headers, frames and transport
//! parameters. All decoders borrow from the input buffer (zero copy) and
//! never panic on malformed input.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod codec;
pub mod frame;
pub mod header;
pub mod params;
pub mod pn;

pub use codec::{Reader, Writer};

/// Errors produced by the wire codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The input ended before a complete value could be read.
    #[error("buffer too short")]
    BufferTooShort,
    /// The output buffer has no room for the value being written.
    #[error("output buffer full")]
    BufferFull,
    /// A value exceeds the 2^62-1 range of a QUIC varint.
    #[error("varint out of range")]
    VarintRange,
    /// A frame was malformed (RFC 9000 FRAME_ENCODING_ERROR).
    #[error("malformed frame of type {0:#x}")]
    InvalidFrame(u64),
    /// A packet header was malformed.
    #[error("malformed packet header")]
    InvalidHeader,
    /// A transport parameter was malformed or duplicated.
    #[error("malformed transport parameter {0:#x}")]
    InvalidParam(u64),
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, WireError>;

/// Largest value representable as a QUIC varint.
pub const MAX_VARINT: u64 = (1 << 62) - 1;

