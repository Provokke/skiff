#![no_main]
use libfuzzer_sys::fuzz_target;
use skiff_quic::stream::{ConnFlow, RecvStream};
// Interprets input as a sequence of (offset u16, len u8, fin bit) frames over
// a reference byte pattern; whatever is readable must match the pattern.
fuzz_target!(|data: &[u8]| {
    let pattern: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
    let mut conn = ConnFlow::new(1 << 16);
    let mut s = RecvStream::new(1 << 16);
    let mut read = 0usize;
    let mut buf = [0u8; 300];
    for f in data.chunks_exact(4) {
        let off = usize::from(u16::from_be_bytes([f[0], f[1]]));
        let len = usize::from(f[2]);
        let fin = f[3] & 1 == 1;
        let _ = s.on_frame(off as u64, &pattern[off..off + len], fin, &mut conn);
        if f[3] & 2 == 2 {
            let (n, _) = s.read(&mut buf, &mut conn);
            assert_eq!(&buf[..n], &pattern[read..read + n]);
            read += n;
        }
    }
});
