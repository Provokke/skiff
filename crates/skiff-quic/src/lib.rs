//! skiff-quic: QUIC transport building blocks.
//!
//! The sans-I/O [`conn::Connection`] state machine (handshake via
//! `rustls::quic`, streams, flow control, loss recovery, close/idle) built
//! on the RFC 9001 packet-protection layer ([`crypto`], [`packet`], [`tls`]),
//! packet-number spaces ([`space`]) and stream state ([`stream`], [`send`],
//! [`streams`]). See `HANDOFF.md` at the repository root for what is missing.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod cid;
pub mod conn;
pub mod crypto;
pub mod packet;
pub mod retry;
pub mod send;
pub mod space;
pub mod stream;
pub mod streams;
pub mod tls;

pub use cid::ResetKey;
pub use conn::{ApiError, CloseReason, Connection, Event, TransportConfig};
pub use retry::TokenKey;

/// Errors produced by skiff-quic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// AEAD authentication failed or a key could not be constructed.
    #[error("packet protection failure")]
    Crypto,
    /// The packet is too short to sample for header protection.
    #[error("packet too short for header protection")]
    ShortPacket,
    /// Wire-format error.
    #[error(transparent)]
    Wire(#[from] skiff_wire::WireError),
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, Error>;

