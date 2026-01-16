//! skiff: a blocking UDP [`endpoint::Endpoint`] that multiplexes
//! sans-I/O [`skiff_quic::Connection`]s over one `std::net::UdpSocket` by
//! destination connection ID, TLS configuration helpers ([`tls`]), and the
//! two applications the `skiff-server` and `skiff-client` binaries run:
//! stream echo ([`echo`]) and HTTP/3 GET serving and fetching ([`http3`]).
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod echo;
pub mod endpoint;
pub mod http3;
pub mod tls;

pub use endpoint::{ConnectionHandle, Endpoint, EndpointError, EndpointStats};

