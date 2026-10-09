#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(p) = skiff_wire::params::TransportParams::decode(data) {
        let mut out = Vec::new();
        let _ = p.encode(&mut out);
    }
});
