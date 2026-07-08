//! Retry (RFC 9000 8.1.2, 17.2.5; RFC 9001 5.8) between two in-memory
//! connections: the server side is played by the test with
//! `skiff_quic::retry` and `Connection::accept_retried`, as an endpoint
//! would.

use rustls::pki_types::PrivatePkcs8KeyDer;
use skiff_quic::conn::{CloseReason, Connection, TransportConfig};
use skiff_quic::retry::{retry_packet, TokenKey};
use skiff_wire::header::{Header, PacketType};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const ALPN: &[u8] = b"skiff-test";

fn tls() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
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
    .clone()
}

const CLIENT: &str = "198.51.100.7:5000";
const LCID: usize = skiff_quic::conn::LOCAL_CID_LEN;

struct Initial {
    dcid: Vec<u8>,
    scid: Vec<u8>,
    token: Vec<u8>,
    datagram: Vec<u8>,
}

fn next_initial(c: &mut Connection, now: Instant) -> Initial {
    let mut buf = vec![0u8; 2048];
    let n = c.send(&mut buf, now);
    assert!(n >= 1200, "a padded client Initial, got {n}");
    let h = Header::parse(&buf[..n], LCID).unwrap();
    assert_eq!(h.ty, PacketType::Initial);
    Initial {
        dcid: h.dcid.to_vec(),
        scid: h.scid.to_vec(),
        token: h.token.to_vec(),
        datagram: buf[..n].to_vec(),
    }
}

/// Plays the server endpoint's part: a Retry for `first` with a token.
fn retry_for(first: &Initial, key: &TokenKey, new_scid: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let addr: SocketAddr = CLIENT.parse().unwrap();
    let token = key.retry_token(addr, &first.dcid, new_scid, 100).unwrap();
    let pkt = retry_packet(&first.scid, new_scid, &first.dcid, &token).unwrap();
    (pkt, token)
}

/// A server certificate of about 6 KB (many names): more than three times
/// a 1200-byte client Initial, and more than one datagram of handshake.
fn big_cert_tls() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    static CFG: OnceLock<(Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>)> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut names: Vec<String> = (0..200)
            .map(|i| format!("host-{i:04}.example-long-domain-name.test"))
            .collect();
        names.push("localhost".to_string());
        let ck = rcgen::generate_simple_self_signed(names).unwrap();
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
    .clone()
}

/// Bytes a server sends in answer to one client Initial, before hearing
/// anything else from the client.
fn first_flight(s: &mut Connection, now: Instant) -> usize {
    let mut buf = vec![0u8; 2048];
    let mut total = 0;
    loop {
        let n = s.send(&mut buf, now);
        if n == 0 {
            return total;
        }
        total += n;
    }
}

/// RFC 9000 8.1: a valid Retry token proves the client's address, so the
/// retried server sends its whole first flight (a 6 KB certificate); a
/// server without one stops at three times the 1200 bytes it received.
#[test]
fn retried_server_is_not_amplification_limited() {
    let (ct, st) = big_cert_tls();
    let now = Instant::now();
    let mut c =
        Connection::connect(ct.clone(), "localhost", TransportConfig::default(), now).unwrap();
    let first = next_initial(&mut c, now);
    let mut s =
        Connection::accept(st.clone(), TransportConfig::default(), &first.datagram, now).unwrap();
    let mut d = first.datagram.clone();
    s.recv(&mut d, now);
    let plain = first_flight(&mut s, now);
    assert!(plain > 0 && plain <= 3 * 1200, "{plain}");

    let mut c = Connection::connect(ct, "localhost", TransportConfig::default(), now).unwrap();
    let first = next_initial(&mut c, now);
    let key = TokenKey::new(&[5; 32]);
    let (mut retry, _) = retry_for(&first, &key, &[0x66; LCID]);
    c.recv(&mut retry, now);
    let second = next_initial(&mut c, now);
    let mut s = Connection::accept_retried(
        st,
        TransportConfig::default(),
        &second.datagram,
        &first.dcid,
        now,
    )
    .unwrap();
    let mut d = second.datagram.clone();
    s.recv(&mut d, now);
    let retried = first_flight(&mut s, now);
    assert!(retried > 3 * 1200, "{retried} (unretried: {plain})");
}

/// Runs both sides with immediate delivery until `done` or `budget` of
/// virtual time.
fn run(
    c: &mut Connection,
    s: &mut Connection,
    now: &mut Instant,
    budget: Duration,
    done: impl Fn(&Connection, &Connection) -> bool,
) {
    let end = *now + budget;
    let mut buf = vec![0u8; 2048];
    while !done(c, s) && *now < end {
        let mut moved = false;
        loop {
            let n = c.send(&mut buf, *now);
            if n == 0 {
                break;
            }
            s.recv(&mut buf[..n], *now);
            moved = true;
        }
        loop {
            let n = s.send(&mut buf, *now);
            if n == 0 {
                break;
            }
            c.recv(&mut buf[..n], *now);
            moved = true;
        }
        if !moved {
            let t = [c.timeout(), s.timeout()].into_iter().flatten().min();
            *now = t
                .map_or(*now + Duration::from_millis(1), |t| t.max(*now))
                .min(end);
            for x in [&mut *c, &mut *s] {
                if x.timeout().is_some_and(|t| t <= *now) {
                    x.on_timeout(*now);
                }
            }
        }
    }
}

fn confirmed(c: &Connection, s: &Connection) -> bool {
    c.is_handshake_confirmed() && s.is_handshake_confirmed()
}

/// The full exchange: the client's first Initial gets a Retry; its next
/// Initial goes to the Retry's Source CID with the token, under keys from
/// that CID, with a higher packet number; the server accepts it with
/// `accept_retried`; both sides check each other's CIDs and the handshake
/// and a stream complete. The server's address counts as validated, so
/// it is not amplification-limited.
#[test]
fn retry_then_handshake() {
    let (ct, st) = tls();
    let mut now = Instant::now();
    let mut c = Connection::connect(ct, "localhost", TransportConfig::default(), now).unwrap();
    let first = next_initial(&mut c, now);
    assert!(first.token.is_empty());
    let key = TokenKey::new(&[5; 32]);
    let new_scid = vec![0x77; LCID];
    let (mut retry, token) = retry_for(&first, &key, &new_scid);
    c.recv(&mut retry, now);
    assert!(c.retried());
    let second = next_initial(&mut c, now);
    assert_eq!(second.dcid, new_scid, "Initials now go to the Retry's SCID");
    assert_eq!(second.scid, first.scid);
    assert_eq!(second.token, token, "and carry the token");
    // The server endpoint validates the token and recovers the original CID.
    let addr: SocketAddr = CLIENT.parse().unwrap();
    let odcid = key
        .validate(&second.token, addr, &second.dcid, 101, 10)
        .unwrap();
    assert_eq!(odcid, first.dcid);
    let mut s = Connection::accept_retried(
        st,
        TransportConfig::default(),
        &second.datagram,
        &odcid,
        now,
    )
    .unwrap();
    assert!(s.retried());
    assert_eq!(s.original_dcid(), &first.dcid[..]);
    assert_eq!(s.initial_dcid(), &new_scid[..]);
    let mut d = second.datagram.clone();
    s.recv(&mut d, now);
    assert!(
        s.stats().packets_received > 0,
        "decrypted under the new Initial keys"
    );
    let start = now;
    run(&mut c, &mut s, &mut now, Duration::from_secs(10), confirmed);
    assert!(
        confirmed(&c, &s),
        "{:?} {:?}",
        c.close_reason(),
        s.close_reason()
    );
    // With instant delivery and nothing lost, no timer was needed: the
    // ClientHello was resent at once and the server was never blocked by
    // the amplification limit.
    assert_eq!(now, start, "handshake waited on a timer");
    let id = c.open_stream(true).unwrap();
    c.stream_write(id, b"after retry", true).unwrap();
    run(
        &mut c,
        &mut s,
        &mut now,
        Duration::from_millis(100),
        |_, _| false,
    );
    let mut got = [0u8; 64];
    assert_eq!(s.stream_read(id, &mut got).unwrap(), (11, true));
    assert_eq!(&got[..11], b"after retry");
}

/// What the client must ignore (RFC 9000 17.2.5.2): a Retry with a bad
/// integrity tag, for another original CID, with an empty token or from
/// the original DCID; a second Retry; a Retry once a server packet was
/// processed (even from the server's own CID). And what it
/// must refuse in the server's transport parameters (RFC 9000 7.3): after
/// a Retry, no retry_source_connection_id or a wrong original CID.
#[test]
fn retry_rules() {
    let (ct, st) = tls();
    let now = Instant::now();
    let key = TokenKey::new(&[5; 32]);
    let scid = vec![0x77; LCID];

    let mut c =
        Connection::connect(ct.clone(), "localhost", TransportConfig::default(), now).unwrap();
    let first = next_initial(&mut c, now);
    let (good, _) = retry_for(&first, &key, &scid);
    let mut bad_tag = good.clone();
    *bad_tag.last_mut().unwrap() ^= 1;
    let other = Initial {
        dcid: vec![1; 8],
        scid: first.scid.clone(),
        token: Vec::new(),
        datagram: Vec::new(),
    };
    let (wrong_odcid, _) = retry_for(&other, &key, &scid);
    let empty_token = retry_packet(&first.scid, &scid, &first.dcid, &[]).unwrap();
    let (same_cid, _) = retry_for(&first, &key, &first.dcid);
    for (what, mut d) in [
        ("tag", bad_tag),
        ("odcid", wrong_odcid),
        ("token", empty_token),
        ("SCID equal to the original DCID", same_cid),
    ] {
        c.recv(&mut d, now);
        assert!(!c.retried(), "{what}");
    }
    let mut d = good.clone();
    c.recv(&mut d, now);
    assert!(c.retried());
    let (mut second_retry, _) = retry_for(&first, &key, &[0x55; LCID]);
    c.recv(&mut second_retry, now);
    let pkt = next_initial(&mut c, now);
    assert_eq!(pkt.dcid, scid, "a second Retry is ignored");

    // A server that ignores the token: no retry_source_connection_id in
    // its parameters, so the client closes with TRANSPORT_PARAMETER_ERROR.
    let mut s =
        Connection::accept(st.clone(), TransportConfig::default(), &pkt.datagram, now).unwrap();
    let mut d = pkt.datagram.clone();
    s.recv(&mut d, now);
    let mut t = now;
    run(&mut c, &mut s, &mut t, Duration::from_secs(10), |c, _| {
        c.is_closing() || c.is_handshake_complete()
    });
    assert!(
        matches!(
            c.close_reason(),
            Some(CloseReason::LocalTransport { code: 0x08, .. })
        ),
        "{:?}",
        c.close_reason()
    );

    // A retried server that names the wrong original CID.
    let mut c =
        Connection::connect(ct.clone(), "localhost", TransportConfig::default(), now).unwrap();
    let first = next_initial(&mut c, now);
    let (mut r, _) = retry_for(&first, &key, &scid);
    c.recv(&mut r, now);
    let pkt = next_initial(&mut c, now);
    let mut s = Connection::accept_retried(
        st.clone(),
        TransportConfig::default(),
        &pkt.datagram,
        &[9; 8],
        now,
    )
    .unwrap();
    let mut d = pkt.datagram.clone();
    s.recv(&mut d, now);
    let mut t = now;
    run(&mut c, &mut s, &mut t, Duration::from_secs(10), |c, _| {
        c.is_closing() || c.is_handshake_complete()
    });
    assert!(
        matches!(
            c.close_reason(),
            Some(CloseReason::LocalTransport { code: 0x08, .. })
        ),
        "{:?}",
        c.close_reason()
    );

    // No Retry once the server's Initial was processed. The large
    // certificate keeps the client mid-handshake after that first datagram,
    // so only that rule stops the Retry.
    let (ct, st) = big_cert_tls();
    let mut c = Connection::connect(ct, "localhost", TransportConfig::default(), now).unwrap();
    let first = next_initial(&mut c, now);
    let mut s = Connection::accept(st, TransportConfig::default(), &first.datagram, now).unwrap();
    let mut d = first.datagram.clone();
    s.recv(&mut d, now);
    let mut buf = vec![0u8; 2048];
    let n = s.send(&mut buf, now);
    c.recv(&mut buf[..n], now);
    assert!(!c.is_handshake_complete());
    let server_cid = s.local_cid().to_vec();
    let (mut late, _) = retry_for(&first, &key, &server_cid);
    c.recv(&mut late, now);
    assert!(!c.retried(), "Retry after a server packet");
    let mut t = now;
    run(&mut c, &mut s, &mut t, Duration::from_secs(10), confirmed);
    assert!(confirmed(&c, &s));
    assert!(!s.retried());
}
