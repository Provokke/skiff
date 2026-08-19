//! Frame encode/decode micro-benchmarks.
use criterion::{criterion_group, criterion_main, Criterion};
use skiff_wire::frame::Frame;
use skiff_wire::{Reader, Writer};

fn bench(c: &mut Criterion) {
    let data = vec![7u8; 1100];
    let stream = Frame::Stream {
        id: 4,
        offset: 1 << 20,
        data: &data,
        fin: false,
    };
    let ack = Frame::Ack {
        delay: 10,
        ranges: (0..32)
            .map(|i| (1000 - i * 10 - 5, 1000 - i * 10))
            .collect(),
        ecn: None,
    };
    let mut buf = vec![0u8; 2048];
    for (name, f) in [("stream_1100", &stream), ("ack_32_ranges", &ack)] {
        c.bench_function(&format!("encode_{name}"), |b| {
            b.iter(|| {
                let mut w = Writer::new(&mut buf);
                f.encode(&mut w).unwrap();
                w.position()
            })
        });
        let mut w = Writer::new(&mut buf);
        f.encode(&mut w).unwrap();
        let n = w.position();
        let enc = buf[..n].to_vec();
        c.bench_function(&format!("decode_{name}"), |b| {
            b.iter(|| Frame::decode(&mut Reader::new(&enc)).unwrap())
        });
    }
}
criterion_group!(benches, bench);
criterion_main!(benches);
