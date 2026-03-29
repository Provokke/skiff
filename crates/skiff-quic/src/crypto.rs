//! RFC 9001 key schedule and packet protection primitives (ring-backed).

use crate::{Error, Result};
use ring::{aead, hkdf};

/// RFC 9001 Section 5.2 initial salt for QUIC v1.
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// AEAD tag length for all QUIC v1 cipher suites.
pub const TAG_LEN: usize = 16;
/// Header protection sample length.
pub const SAMPLE_LEN: usize = 16;

/// Supported AEAD algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// TLS_AES_128_GCM_SHA256.
    Aes128Gcm,
    /// TLS_CHACHA20_POLY1305_SHA256.
    ChaCha20Poly1305,
}

impl Suite {
    fn aead(self) -> &'static aead::Algorithm {
        match self {
            Suite::Aes128Gcm => &aead::AES_128_GCM,
            Suite::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
    fn hp(self) -> &'static aead::quic::Algorithm {
        match self {
            Suite::Aes128Gcm => &aead::quic::AES_128,
            Suite::ChaCha20Poly1305 => &aead::quic::CHACHA20,
        }
    }
    fn key_len(self) -> usize {
        match self {
            Suite::Aes128Gcm => 16,
            Suite::ChaCha20Poly1305 => 32,
        }
    }
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand-Label (RFC 8446 Section 7.1) with an empty context.
pub fn expand_label(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> Result<()> {
    let len = u16::try_from(out.len())
        .map_err(|_| Error::Crypto)?
        .to_be_bytes();
    let full_len = [(6 + label.len()) as u8];
    let info: [&[u8]; 5] = [&len, &full_len, b"tls13 ", label, &[0]];
    prk.expand(&info, Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| Error::Crypto)
}

/// The raw traffic secrets for both Initial directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialSecrets {
    /// client_initial_secret.
    pub client: [u8; 32],
    /// server_initial_secret.
    pub server: [u8; 32],
}

/// Derives the Initial secrets from the client's first Destination CID.
pub fn initial_secrets(dcid: &[u8]) -> Result<InitialSecrets> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &INITIAL_SALT_V1);
    let initial = salt.extract(dcid);
    let mut s = InitialSecrets {
        client: [0; 32],
        server: [0; 32],
    };
    expand_label(&initial, b"client in", &mut s.client)?;
    expand_label(&initial, b"server in", &mut s.server)?;
    Ok(s)
}

/// Raw key material for one direction (exposed for tests and benchmarks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMaterial {
    /// AEAD key.
    pub key: Vec<u8>,
    /// AEAD IV.
    pub iv: [u8; 12],
    /// Header protection key.
    pub hp: Vec<u8>,
}

impl KeyMaterial {
    /// Derives key/iv/hp from a traffic secret ("quic key", "quic iv", "quic hp").
    pub fn from_secret(suite: Suite, secret: &[u8]) -> Result<Self> {
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
        let mut key = vec![0u8; suite.key_len()];
        let mut iv = [0u8; 12];
        let mut hp = vec![0u8; suite.key_len()];
        expand_label(&prk, b"quic key", &mut key)?;
        expand_label(&prk, b"quic iv", &mut iv)?;
        expand_label(&prk, b"quic hp", &mut hp)?;
        Ok(Self { key, iv, hp })
    }
}

/// Packet protection keys for one direction of one encryption level.
pub struct DirectionalKeys {
    aead: aead::LessSafeKey,
    iv: [u8; 12],
    hp: aead::quic::HeaderProtectionKey,
}

impl core::fmt::Debug for DirectionalKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DirectionalKeys { .. }")
    }
}

impl DirectionalKeys {
    /// Builds keys from raw material.
    pub fn new(suite: Suite, m: &KeyMaterial) -> Result<Self> {
        let unbound = aead::UnboundKey::new(suite.aead(), &m.key).map_err(|_| Error::Crypto)?;
        let hp =
            aead::quic::HeaderProtectionKey::new(suite.hp(), &m.hp).map_err(|_| Error::Crypto)?;
        Ok(Self {
            aead: aead::LessSafeKey::new(unbound),
            iv: m.iv,
            hp,
        })
    }

    /// Builds keys from a traffic secret.
    pub fn from_secret(suite: Suite, secret: &[u8]) -> Result<Self> {
        Self::new(suite, &KeyMaterial::from_secret(suite, secret)?)
    }

    fn nonce(&self, pn: u64) -> aead::Nonce {
        let mut n = self.iv;
        for (i, b) in pn.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        aead::Nonce::assume_unique_for_key(n)
    }

    /// Encrypts `payload` in place and returns the authentication tag.
    pub fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let tag = self
            .aead
            .seal_in_place_separate_tag(self.nonce(pn), aead::Aad::from(header), payload)
            .map_err(|_| Error::Crypto)?;
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    /// Decrypts `payload_and_tag` in place, returning the plaintext prefix.
    pub fn open<'a>(
        &self,
        pn: u64,
        header: &[u8],
        payload_and_tag: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        self.aead
            .open_in_place(self.nonce(pn), aead::Aad::from(header), payload_and_tag)
            .map_err(|_| Error::Crypto)
    }

    /// Computes the 5-byte header protection mask for `sample`.
    pub fn hp_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        self.hp.new_mask(sample).map_err(|_| Error::Crypto)
    }
}

/// Packet protection for one direction of one encryption level, abstracted
/// so our own Initial keys and the Handshake/1-RTT keys produced by
/// `rustls::quic` (see [`crate::tls`]) drive the same `protect`/`unprotect`.
pub trait PacketProtection: Send + Sync {
    /// Encrypts `payload` in place and returns the authentication tag.
    fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<[u8; TAG_LEN]>;
    /// Decrypts `payload_and_tag` in place, returning the plaintext length.
    fn open_in_place(&self, pn: u64, header: &[u8], payload_and_tag: &mut [u8]) -> Result<usize>;
    /// Computes the header protection mask for a `SAMPLE_LEN` sample. Only
    /// the low five bits of byte 0 are significant.
    fn hp_mask(&self, sample: &[u8]) -> Result<[u8; 5]>;
}

impl PacketProtection for DirectionalKeys {
    fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        DirectionalKeys::seal(self, pn, header, payload)
    }
    fn open_in_place(&self, pn: u64, header: &[u8], payload_and_tag: &mut [u8]) -> Result<usize> {
        self.open(pn, header, payload_and_tag).map(|p| p.len())
    }
    fn hp_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        DirectionalKeys::hp_mask(self, sample)
    }
}

/// Both directions of one encryption level.
#[derive(Debug)]
pub struct Keys {
    /// Keys used to protect packets we send.
    pub local: DirectionalKeys,
    /// Keys used to remove protection from packets we receive.
    pub remote: DirectionalKeys,
}

/// Which endpoint we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Connection initiator.
    Client,
    /// Connection acceptor.
    Server,
}

impl Keys {
    /// Initial keys for `side`, derived from the client's original DCID.
    pub fn initial(dcid: &[u8], side: Side) -> Result<Self> {
        let s = initial_secrets(dcid)?;
        let c = DirectionalKeys::from_secret(Suite::Aes128Gcm, &s.client)?;
        let sv = DirectionalKeys::from_secret(Suite::Aes128Gcm, &s.server)?;
        Ok(match side {
            Side::Client => Keys {
                local: c,
                remote: sv,
            },
            Side::Server => Keys {
                local: sv,
                remote: c,
            },
        })
    }
}
