//! RFC 9001 Appendix A test vectors.

use skiff_quic::crypto::{
    initial_secrets, DirectionalKeys, KeyMaterial, Keys, Side, Suite, TAG_LEN,
};
use skiff_quic::packet::{protect, unprotect};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const DCID: &str = "8394c8f03e515708";

#[test]
fn a1_initial_keys() {
    let s = initial_secrets(&hex(DCID)).unwrap();
    assert_eq!(
        s.client.to_vec(),
        hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    );
    assert_eq!(
        s.server.to_vec(),
        hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
    );
    let c = KeyMaterial::from_secret(Suite::Aes128Gcm, &s.client).unwrap();
    assert_eq!(c.key, hex("1f369613dd76d5467730efcbe3b1a22d"));
    assert_eq!(c.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(c.hp, hex("9f50449e04a0e810283a1e9933adedd2"));
    let sv = KeyMaterial::from_secret(Suite::Aes128Gcm, &s.server).unwrap();
    assert_eq!(sv.key, hex("cf3a5331653c364c88f0f379b6067e37"));
    assert_eq!(sv.iv.to_vec(), hex("0ac1493ca1905853b0bba03e"));
    assert_eq!(sv.hp, hex("c206b8d9b9f0f37644430b490eeaa314"));
}

#[test]
fn a2_client_initial_header_protection_mask() {
    let keys = Keys::initial(&hex(DCID), Side::Client).unwrap();
    let mask = keys
        .local
        .hp_mask(&hex("d1b1c98dd7689fb8ec11d242b123dc9b"))
        .unwrap();
    assert_eq!(mask.to_vec(), hex("437b9aec36"));
}

#[test]
fn a3_server_initial_full_packet() {
    let header = hex("c1000000010008f067a5502a4262b50040750001");
    let payload = hex(
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a04
         5a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32b
         b9da1a002b00020304",
    );
    let expected = hex(
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554
         780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b
         562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee",
    );
    let keys = Keys::initial(&hex(DCID), Side::Server).unwrap();
    let mut buf = header.clone();
    buf.extend_from_slice(&payload);
    let len = buf.len();
    buf.resize(len + TAG_LEN, 0);
    let pn_offset = header.len() - 2;
    let n = protect(&keys.local, &mut buf, pn_offset, 1, len).unwrap();
    assert_eq!(&buf[..n], &expected[..], "byte-for-byte RFC 9001 A.3");

    // And the client can open it.
    let client = Keys::initial(&hex(DCID), Side::Client).unwrap();
    let opened = unprotect(&client.remote, &mut buf, pn_offset, None).unwrap();
    assert_eq!(opened.pn, 1);
    assert_eq!(
        &buf[opened.payload_offset..opened.payload_offset + opened.payload_len],
        &payload[..]
    );
}

#[test]
fn a5_chacha20_short_header() {
    let secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let keys = DirectionalKeys::from_secret(Suite::ChaCha20Poly1305, &secret).unwrap();
    let mut buf = hex("4200bff401");
    buf.resize(5 + TAG_LEN, 0);
    let n = protect(&keys, &mut buf, 1, 654_360_564, 5).unwrap();
    assert_eq!(
        &buf[..n],
        &hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")[..]
    );
    let opened = unprotect(&keys, &mut buf, 1, Some(654_360_563)).unwrap();
    assert_eq!(opened.pn, 654_360_564);
    assert_eq!(
        &buf[opened.payload_offset..opened.payload_offset + 1],
        &[0x01]
    );
}

#[test]
fn tampered_packet_rejected() {
    let keys = Keys::initial(b"abcdefgh", Side::Client).unwrap();
    let peer = Keys::initial(b"abcdefgh", Side::Server).unwrap();
    let mut buf = vec![0xc3, 0, 0, 0, 1, 0, 0, 0x40, 0x30, 0, 0, 0, 7];
    buf.extend_from_slice(&[0x01; 40]);
    let len = buf.len();
    buf.resize(len + TAG_LEN, 0);
    protect(&keys.local, &mut buf, 9, 7, len).unwrap();
    let mut bad = buf.clone();
    bad[20] ^= 1;
    assert!(unprotect(&peer.remote, &mut bad, 9, None).is_err());
    assert_eq!(unprotect(&peer.remote, &mut buf, 9, None).unwrap().pn, 7);
}
