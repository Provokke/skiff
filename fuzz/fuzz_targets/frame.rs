#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut buf = vec![0u8; 4096];
    for f in skiff_wire::frame::parse_all(data).flatten() {
        // Anything we decode must re-encode without panicking.
        let _ = f.encode(&mut skiff_wire::Writer::new(&mut buf));
    }
});
