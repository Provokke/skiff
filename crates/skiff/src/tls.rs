//! rustls configuration helpers: self-signed certificates, server and
//! client configs restricted to TLS 1.3 on the `ring` provider, and an
//! `--insecure` client verifier that skips the certificate chain but still
//! checks the handshake signature.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;

/// Errors building TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Certificate generation failed.
    #[error("certificate generation: {0}")]
    Generate(String),
    /// rustls rejected the configuration.
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    /// A certificate or key file could not be read or parsed.
    #[error("{0}")]
    File(String),
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Generates a self-signed certificate for `names` and its PKCS#8 key.
pub fn self_signed(
    names: &[&str],
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), TlsError> {
    let names: Vec<String> = names.iter().map(|s| (*s).to_string()).collect();
    let ck =
        rcgen::generate_simple_self_signed(names).map_err(|e| TlsError::Generate(e.to_string()))?;
    let key = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
    Ok((ck.cert.der().clone(), key.into()))
}

/// A TLS 1.3 server config with the given chain, key and ALPN protocols.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn: &[&[u8]],
) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// A TLS 1.3 client config trusting exactly `roots`.
pub fn client_config(
    roots: Vec<CertificateDer<'static>>,
    alpn: &[&[u8]],
) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let mut store = rustls::RootCertStore::empty();
    for r in roots {
        store.add(r)?;
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(store)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// A TLS 1.3 client config that accepts any server certificate (it still
/// verifies the CertificateVerify signature against the presented key).
/// For testing against self-signed servers only.
pub fn insecure_client_config(alpn: &[&[u8]]) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let p = provider();
    let verifier = Arc::new(AcceptAnyCert(p.clone()));
    let mut cfg = rustls::ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // QUIC is TLS 1.3 only.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Reads a DER certificate file.
pub fn read_cert_der(path: &std::path::Path) -> Result<CertificateDer<'static>, TlsError> {
    std::fs::read(path)
        .map(CertificateDer::from)
        .map_err(|e| TlsError::File(format!("{}: {e}", path.display())))
}

/// Reads a DER PKCS#8 private key file.
pub fn read_key_der(path: &std::path::Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    std::fs::read(path)
        .map(|k| PrivatePkcs8KeyDer::from(k).into())
        .map_err(|e| TlsError::File(format!("{}: {e}", path.display())))
}
