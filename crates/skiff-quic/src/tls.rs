//! Adapter from `rustls::quic` packet keys (Handshake and 1-RTT levels) to
//! [`PacketProtection`], so packets at every level go through the same
//! [`crate::packet::protect`] / [`crate::packet::unprotect`].

use crate::crypto::{PacketProtection, TAG_LEN};
use crate::{Error, Result};

/// One direction of rustls-derived packet protection keys.
pub struct TlsKeys(pub rustls::quic::DirectionalKeys);

impl core::fmt::Debug for TlsKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TlsKeys { .. }")
    }
}

fn seal(
    key: &dyn rustls::quic::PacketKey,
    pn: u64,
    header: &[u8],
    payload: &mut [u8],
) -> Result<[u8; TAG_LEN]> {
    let tag = key
        .encrypt_in_place(pn, header, payload)
        .map_err(|_| Error::Crypto)?;
    let tag = tag.as_ref();
    if tag.len() != TAG_LEN {
        return Err(Error::Crypto);
    }
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(tag);
    Ok(out)
}

fn open(
    key: &dyn rustls::quic::PacketKey,
    pn: u64,
    header: &[u8],
    payload_and_tag: &mut [u8],
) -> Result<usize> {
    key.decrypt_in_place(pn, header, payload_and_tag)
        .map(<[u8]>::len)
        .map_err(|_| Error::Crypto)
}

fn hp_mask(key: &dyn rustls::quic::HeaderProtectionKey, sample: &[u8]) -> Result<[u8; 5]> {
    // rustls only applies the mask. Apply it to a short-header first
    // byte whose PN-length bits say 4 bytes (0x03) and to an all-zero
    // PN: the XOR result is then the mask itself (low 5 bits of byte 0,
    // which is all header protection ever uses).
    let mut first = 0x03u8;
    let mut pn = [0u8; 4];
    key.encrypt_in_place(sample, &mut first, &mut pn)
        .map_err(|_| Error::Crypto)?;
    Ok([first ^ 0x03, pn[0], pn[1], pn[2], pn[3]])
}

impl PacketProtection for TlsKeys {
    fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        seal(self.0.packet.as_ref(), pn, header, payload)
    }

    fn open_in_place(&self, pn: u64, header: &[u8], payload_and_tag: &mut [u8]) -> Result<usize> {
        open(self.0.packet.as_ref(), pn, header, payload_and_tag)
    }

    fn hp_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        hp_mask(self.0.header.as_ref(), sample)
    }
}

/// Header protection alone. 1-RTT header protection keys survive key
/// updates (RFC 9001 6), so they are kept apart from the packet keys;
/// `seal`/`open_in_place` always fail.
pub struct HeaderOnly(pub Box<dyn rustls::quic::HeaderProtectionKey>);

impl core::fmt::Debug for HeaderOnly {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HeaderOnly { .. }")
    }
}

impl PacketProtection for HeaderOnly {
    fn seal(&self, _: u64, _: &[u8], _: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        Err(Error::Crypto)
    }

    fn open_in_place(&self, _: u64, _: &[u8], _: &mut [u8]) -> Result<usize> {
        Err(Error::Crypto)
    }

    fn hp_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        hp_mask(self.0.as_ref(), sample)
    }
}

/// One generation of 1-RTT packet (AEAD) keys; `hp_mask` always fails.
pub struct PacketOnly(pub Box<dyn rustls::quic::PacketKey>);

impl core::fmt::Debug for PacketOnly {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PacketOnly { .. }")
    }
}

impl PacketProtection for PacketOnly {
    fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        seal(self.0.as_ref(), pn, header, payload)
    }

    fn open_in_place(&self, pn: u64, header: &[u8], payload_and_tag: &mut [u8]) -> Result<usize> {
        open(self.0.as_ref(), pn, header, payload_and_tag)
    }

    fn hp_mask(&self, _: &[u8]) -> Result<[u8; 5]> {
        Err(Error::Crypto)
    }
}

/// Header protection from one key and AEAD from another: how 1-RTT
/// packets are protected after a key update.
pub struct Split<'a> {
    /// Supplies `hp_mask`.
    pub hp: &'a dyn PacketProtection,
    /// Supplies `seal` / `open_in_place`.
    pub aead: &'a dyn PacketProtection,
}

impl PacketProtection for Split<'_> {
    fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        self.aead.seal(pn, header, payload)
    }

    fn open_in_place(&self, pn: u64, header: &[u8], payload_and_tag: &mut [u8]) -> Result<usize> {
        self.aead.open_in_place(pn, header, payload_and_tag)
    }

    fn hp_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        self.hp.hp_mask(sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Keys, Side};
    use crate::packet::{protect, unprotect};

    fn rustls_initial(dcid: &[u8], side: rustls::Side) -> rustls::quic::Keys {
        let provider = rustls::crypto::ring::default_provider();
        let suite = provider
            .cipher_suites
            .iter()
            .find_map(|s| match s {
                rustls::SupportedCipherSuite::Tls13(t)
                    if t.common.suite == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 =>
                {
                    Some(*t)
                }
                _ => None,
            })
            .unwrap();
        suite
            .quic_suite()
            .unwrap()
            .keys(dcid, side, rustls::quic::Version::V1)
    }

    /// rustls's Initial keys and ours must interoperate in both directions,
    /// which proves the adapter's seal/open and mask extraction.
    #[test]
    fn adapter_matches_own_initial_keys() {
        let dcid = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08";
        let ours = Keys::initial(dcid, Side::Client).unwrap();
        let theirs = rustls_initial(dcid, rustls::Side::Server);
        let remote = TlsKeys(theirs.remote);
        let sample = [0x5au8; 16];
        assert_eq!(
            remote.hp_mask(&sample).unwrap()[1..],
            ours.local.hp_mask(&sample).unwrap()[1..]
        );
        assert_eq!(
            remote.hp_mask(&sample).unwrap()[0] & 0x1f,
            ours.local.hp_mask(&sample).unwrap()[0] & 0x1f
        );
        for (first, pn_off) in [(0xc3u8, 18usize), (0x43u8, 9usize)] {
            let mut pkt = vec![0u8; 80];
            pkt[0] = first;
            pkt[pn_off..pn_off + 4].copy_from_slice(&[0, 0, 0, 7]);
            for (i, b) in pkt[pn_off + 4..64].iter_mut().enumerate() {
                *b = i as u8;
            }
            let plain = pkt.clone();
            // Ours protects, rustls-backed adapter opens.
            let n = protect(&ours.local, &mut pkt, pn_off, 7, 64).unwrap();
            let opened = unprotect(&remote, &mut pkt[..n], pn_off, Some(6)).unwrap();
            assert_eq!(opened.pn, 7);
            assert_eq!(&pkt[..64], &plain[..64]);
            // Adapter protects, ours opens.
            let local = TlsKeys(rustls_initial(dcid, rustls::Side::Client).local);
            let mut pkt2 = plain.clone();
            let n = protect(&local, &mut pkt2, pn_off, 7, 64).unwrap();
            let server = Keys::initial(dcid, Side::Server).unwrap();
            let o = unprotect(&server.remote, &mut pkt2[..n], pn_off, Some(6)).unwrap();
            assert_eq!((o.pn, &pkt2[..64]), (7, &plain[..64]));
        }
    }
}
