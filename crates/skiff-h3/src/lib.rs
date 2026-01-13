//! skiff-h3: HTTP/3 (RFC 9114) and QPACK (RFC 9204) over a skiff-quic
//! [`skiff_quic::Connection`].
//!
//! [`qpack`] holds the static table (RFC 9204 Appendix A), the Huffman code
//! (RFC 7541 Appendix B), prefixed integers and string literals, the dynamic
//! table, and a QPACK [`qpack::Encoder`] / [`qpack::Decoder`] pair that
//! exchange encoder- and decoder-stream instructions. [`frame`] parses and
//! writes HTTP/3 frames and SETTINGS; [`H3Connection`] runs the control and
//! QPACK unidirectional streams and the request/response streams on top of
//! a QUIC connection, sans-I/O. See `HANDOFF.md` at the repository root for
//! what is missing.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod conn;
pub mod frame;
pub mod qpack;

pub use conn::{H3Config, H3Connection, H3Error, H3Event};
