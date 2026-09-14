#![no_main]
//! A real client/server handshake with fuzzer-chosen datagrams injected
//! into the server: raw datagrams (header parsing, routing, AEAD failure
//! paths) and well-formed client Initial packets whose *plaintext* payload
//! is fuzz input (frame parsing, CRYPTO reassembly into rustls, ACK
//! validation and frame-per-space rules at the Initial level), plus clock
//! jumps that fire timers. Any panic is a bug.
//!
//! Input: records of `[kind: u8][len: u16 LE][len bytes]`.
use libfuzzer_sys::fuzz_target;
use rustls::pki_types::PrivatePkcs8KeyDer;
use skiff_quic::crypto::{Keys, Side, TAG_LEN};
use skiff_quic::{Connection, TransportConfig};
use skiff_wire::header::{write_long, PacketType, VERSION_1};
use skiff_wire::Writer;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const ALPN: &[u8] = b"fuzz";

fn configs() -> &'static (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    static CFG: OnceLock<(Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>)> = OnceLock::new();
    CFG.get_or_init(|| {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        server.alpn_protocols = vec![ALPN.to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![ALPN.to_vec()];
        (Arc::new(client), Arc::new(server))
    })
}

/// A client Initial packet (padded to 1200 bytes) carrying `payload` as
/// its plaintext frames, protected with the client's Initial keys.
fn initial(keys: &Keys, dcid: &[u8], scid: &[u8], pn: u64, payload: &[u8]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 1300 + payload.len()];
    let (len_off, hdr) = {
        let mut w = Writer::new(&mut buf);
        let len_off = write_long(&mut w, PacketType::Initial, VERSION_1, dcid, scid, &[], pn, 4).ok()?;
        (len_off, w.position())
    };
    let body = payload.len().max(1200usize.saturating_sub(hdr + TAG_LEN));
    buf.get_mut(hdr..hdr + payload.len())?.copy_from_slice(payload);
    let field = u16::try_from(4 + body + TAG_LEN).ok().filter(|f| *f < 0x4000)?;
    buf.get_mut(len_off..len_off + 2)?.copy_from_slice(&(0x4000 | field).to_be_bytes());
    let total = skiff_quic::packet::protect(&keys.local, &mut buf, hdr - 4, pn, hdr + body).ok()?;
    buf.truncate(total);
    Some(buf)
}

fn exchange(client: &mut Connection, server: &mut Connection, now: Instant) {
    let mut buf = [0u8; 1500];
    for _ in 0..32 {
        let n = client.send(&mut buf, now);
        if n == 0 {
            break;
        }
        server.recv(&mut buf[..n], now);
    }
    for _ in 0..32 {
        let n = server.send(&mut buf, now);
        if n == 0 {
            break;
        }
        client.recv(&mut buf[..n], now);
    }
}

fuzz_target!(|data: &[u8]| {
    let (ctls, stls) = configs();
    let mut now = Instant::now();
    let Ok(mut client) = Connection::connect(ctls.clone(), "localhost", TransportConfig::default(), now) else {
        return;
    };
    let mut first = [0u8; 1500];
    let n = client.send(&mut first, now);
    let Ok(mut server) = Connection::accept(stls.clone(), TransportConfig::default(), &first[..n], now) else {
        return;
    };
    server.recv(&mut first[..n], now);
    let odcid = server.original_dcid().to_vec();
    let scid = client.local_cid().to_vec();
    let Ok(keys) = Keys::initial(&odcid, Side::Client) else {
        return;
    };
    // Packet numbers well above the client's own so they are not duplicates.
    let mut pn = 1000u64;
    let mut rest = data;
    while rest.len() >= 3 {
        let kind = rest[0];
        let len = usize::from(u16::from_le_bytes([rest[1], rest[2]])).min(rest.len() - 3);
        let body = &rest[3..3 + len];
        rest = &rest[3 + len..];
        match kind % 4 {
            0 => server.recv(&mut body.to_vec(), now),
            1 => {
                pn += 1;
                if let Some(mut p) = initial(&keys, &odcid, &scid, pn, body) {
                    server.recv(&mut p, now);
                }
            }
            2 => {
                now += Duration::from_millis(u64::from(body.first().copied().unwrap_or(1)) * 10);
                client.on_timeout(now);
                server.on_timeout(now);
            }
            _ => exchange(&mut client, &mut server, now),
        }
        while server.poll_event().is_some() {}
        let _ = server.timeout();
    }
    exchange(&mut client, &mut server, now);
});
