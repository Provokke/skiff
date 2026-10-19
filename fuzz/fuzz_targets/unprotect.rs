#![no_main]
use libfuzzer_sys::fuzz_target;
use skiff_quic::crypto::{Keys, Side};
fuzz_target!(|data: &[u8]| {
    // Arbitrary datagram through header parse + HP removal + AEAD open.
    let mut buf = data.to_vec();
    if let Ok(h) = skiff_wire::header::Header::parse(data, 8) {
        if let Ok(keys) = Keys::initial(h.dcid, Side::Server) {
            let end = h.packet_len.min(buf.len());
            let _ = skiff_quic::packet::unprotect(&keys.remote, &mut buf[..end], h.pn_offset, None);
        }
    }
});
