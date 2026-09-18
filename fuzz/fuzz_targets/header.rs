#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Some((&l, rest)) = data.split_first() {
        let _ = skiff_wire::header::Header::parse(rest, usize::from(l % 21));
    }
});
