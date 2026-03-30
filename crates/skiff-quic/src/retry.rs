//! Retry (RFC 9000 8.1.2, 17.2.5): the Retry packet with its integrity tag
//! (RFC 9001 5.8) and the address validation tokens a server puts in it.

use ring::aead;
use ring::hmac;
use skiff_wire::header::VERSION_1;
use std::net::SocketAddr;

/// Length of the Retry Integrity Tag.
pub const RETRY_TAG_LEN: usize = 16;
/// Fixed AES-128-GCM key for the Retry Integrity Tag (RFC 9001 5.8, v1).
const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
/// Fixed nonce for the Retry Integrity Tag (RFC 9001 5.8, v1).
const RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
/// Length of the MAC that ends a token.
const TOKEN_MAC_LEN: usize = 16;
/// Token format version (first byte), so the format can change later.
const TOKEN_FORMAT: u8 = 1;

/// The Retry Integrity Tag of `packet` (a Retry packet without its tag),
/// sent in answer to an Initial whose Destination CID was `odcid`: the
/// AES-128-GCM tag over the Retry pseudo-packet, with empty plaintext.
pub fn integrity_tag(odcid: &[u8], packet: &[u8]) -> Option<[u8; RETRY_TAG_LEN]> {
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_KEY).ok()?);
    let mut pseudo = Vec::with_capacity(1 + odcid.len() + packet.len());
    pseudo.push(u8::try_from(odcid.len()).ok()?);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(packet);
    let tag = key
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(RETRY_NONCE),
            aead::Aad::from(pseudo),
            &mut [],
        )
        .ok()?;
    tag.as_ref().try_into().ok()
}

/// Builds a Retry packet: to the client's `dcid` (its Source CID), from our
/// new `scid`, carrying `token`, with the integrity tag for `odcid` (the
/// Destination CID of the client's Initial).
pub fn retry_packet(dcid: &[u8], scid: &[u8], odcid: &[u8], token: &[u8]) -> Option<Vec<u8>> {
    let mut p = Vec::with_capacity(7 + dcid.len() + scid.len() + token.len() + RETRY_TAG_LEN);
    p.push(0xf0); // long header, fixed bit, type 3 (Retry), unused bits 0
    p.extend_from_slice(&VERSION_1.to_be_bytes());
    p.push(u8::try_from(dcid.len()).ok()?);
    p.extend_from_slice(dcid);
    p.push(u8::try_from(scid.len()).ok()?);
    p.extend_from_slice(scid);
    p.extend_from_slice(token);
    let tag = integrity_tag(odcid, &p)?;
    p.extend_from_slice(&tag);
    Some(p)
}

/// Whether `packet` (a whole Retry packet) carries a valid integrity tag
/// for `odcid` (compared in constant time).
pub fn verify_retry(odcid: &[u8], packet: &[u8]) -> bool {
    let Some(split) = packet.len().checked_sub(RETRY_TAG_LEN) else {
        return false;
    };
    let (body, tag) = packet.split_at(split);
    let Some(want) = integrity_tag(odcid, body) else {
        return false;
    };
    want.iter().zip(tag).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
}

/// A fresh random connection ID of our length (for a Retry's Source CID);
/// `None` if the system RNG fails.
pub fn new_cid() -> Option<Vec<u8>> {
    let mut cid = vec![0u8; crate::conn::LOCAL_CID_LEN];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut cid).ok()?;
    Some(cid)
}

/// Mints and checks the address validation tokens a server sends in Retry
/// packets. A token binds the client address, the CID the client must use
/// next (the Retry's Source CID), the client's original Destination CID
/// and the time it was issued, under an HMAC-SHA256 key:
/// `format || issued (u64 BE seconds) || odcid len || odcid || mac[..16]`.
/// The original CID is in the clear: it carries nothing secret.
#[derive(Clone)]
pub struct TokenKey(hmac::Key);

impl core::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TokenKey(..)")
    }
}

fn addr_bytes(a: SocketAddr) -> Vec<u8> {
    let mut v = match a.ip() {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    v.extend_from_slice(&a.port().to_be_bytes());
    v
}

impl TokenKey {
    /// A key from secret bytes (use at least 32 random bytes).
    pub fn new(secret: &[u8]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, secret))
    }

    /// A key from 32 bytes of system randomness; `None` if the RNG fails.
    pub fn random() -> Option<Self> {
        let mut secret = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut secret).ok()?;
        Some(Self::new(&secret))
    }

    fn mac(&self, peer: SocketAddr, retry_scid: &[u8], body: &[u8]) -> hmac::Tag {
        let mut ctx = hmac::Context::with_key(&self.0);
        ctx.update(&addr_bytes(peer));
        ctx.update(&[u8::try_from(retry_scid.len()).unwrap_or(u8::MAX)]);
        ctx.update(retry_scid);
        ctx.update(body);
        ctx.sign()
    }

    /// A token for a Retry to `peer`, whose next Initial must go to
    /// `retry_scid`; `odcid` is the Destination CID of its first Initial and
    /// `now_secs` the current time in seconds (any fixed epoch).
    pub fn retry_token(
        &self,
        peer: SocketAddr,
        odcid: &[u8],
        retry_scid: &[u8],
        now_secs: u64,
    ) -> Option<Vec<u8>> {
        let mut t = vec![TOKEN_FORMAT];
        t.extend_from_slice(&now_secs.to_be_bytes());
        t.push(u8::try_from(odcid.len()).ok()?);
        t.extend_from_slice(odcid);
        let mac = self.mac(peer, retry_scid, &t);
        t.extend_from_slice(mac.as_ref().get(..TOKEN_MAC_LEN)?);
        Some(t)
    }

    /// Checks a token from an Initial that `peer` sent to `dcid`: it must be
    /// ours, for this address and this CID, and at most `lifetime_secs` old
    /// (and not from the future). Returns the original Destination CID.
    pub fn validate(
        &self,
        token: &[u8],
        peer: SocketAddr,
        dcid: &[u8],
        now_secs: u64,
        lifetime_secs: u64,
    ) -> Option<Vec<u8>> {
        let split = token.len().checked_sub(TOKEN_MAC_LEN)?;
        let (body, mac) = token.split_at(split);
        let want = self.mac(peer, dcid, body);
        let diff = want
            .as_ref()
            .iter()
            .zip(mac)
            .fold(0u8, |a, (x, y)| a | (x ^ y));
        if diff != 0 || *body.first()? != TOKEN_FORMAT {
            return None;
        }
        let issued = u64::from_be_bytes(body.get(1..9)?.try_into().ok()?);
        if issued > now_secs || now_secs - issued > lifetime_secs {
            return None;
        }
        let len = usize::from(*body.get(9)?);
        let odcid = body.get(10..)?;
        (odcid.len() == len).then(|| odcid.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.4: the Retry packet, byte for byte.
    #[test]
    fn rfc9001_a4_retry_vector() {
        let odcid = hex("8394c8f03e515708");
        let pkt = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        assert!(verify_retry(&odcid, &pkt));
        let (body, tag) = pkt.split_at(pkt.len() - 16);
        assert_eq!(integrity_tag(&odcid, body).unwrap().as_slice(), tag);
        // Any other original CID, or a flipped bit, fails.
        assert!(!verify_retry(&hex("8394c8f03e515709"), &pkt));
        for i in 0..pkt.len() {
            let mut bad = pkt.clone();
            bad[i] ^= 0x01;
            assert!(!verify_retry(&odcid, &bad), "byte {i}");
        }
        assert!(!verify_retry(&odcid, &pkt[..15]));
        // Our builder, with the same fields and first byte, agrees.
        let mut ours = retry_packet(&[], &hex("f067a5502a4262b5"), &odcid, b"token").unwrap();
        assert_eq!(ours[0], 0xf0);
        ours[0] = 0xff;
        let n = ours.len() - 16;
        let t = integrity_tag(&odcid, &ours[..n]).unwrap();
        ours[n..].copy_from_slice(&t);
        assert_eq!(ours, pkt);
    }

    #[test]
    fn tokens_bind_address_cid_and_age() {
        let k = TokenKey::new(&[9; 32]);
        let a: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        let odcid = [1u8; 8];
        let scid = [2u8; 8];
        let t = k.retry_token(a, &odcid, &scid, 1000).unwrap();
        assert_eq!(k.validate(&t, a, &scid, 1000, 10), Some(odcid.to_vec()));
        assert_eq!(k.validate(&t, a, &scid, 1010, 10), Some(odcid.to_vec()));
        assert_eq!(k.validate(&t, a, &scid, 1011, 10), None, "expired");
        assert_eq!(k.validate(&t, a, &scid, 999, 10), None, "from the future");
        let other: SocketAddr = "192.0.2.1:4434".parse().unwrap();
        assert_eq!(k.validate(&t, other, &scid, 1000, 10), None, "other port");
        assert_eq!(k.validate(&t, a, &odcid, 1000, 10), None, "other CID");
        assert_eq!(
            TokenKey::new(&[8; 32]).validate(&t, a, &scid, 1000, 10),
            None
        );
        for i in 0..t.len() {
            let mut bad = t.clone();
            bad[i] ^= 0x80;
            assert_eq!(k.validate(&bad, a, &scid, 1000, 10), None, "byte {i}");
        }
        assert_eq!(k.validate(&t[..10], a, &scid, 1000, 10), None);
        assert_eq!(k.validate(&[], a, &scid, 1000, 10), None);
    }
}
