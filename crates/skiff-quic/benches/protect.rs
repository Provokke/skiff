//! Packet protect/unprotect throughput (1200-byte packets, AES-128-GCM).
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use skiff_quic::crypto::{Keys, Side, TAG_LEN};
use skiff_quic::packet::{protect, unprotect};

fn bench(c: &mut Criterion) {
    let client = Keys::initial(b"benchcid", Side::Client).unwrap();
    let server = Keys::initial(b"benchcid", Side::Server).unwrap();
    let mut g = c.benchmark_group("packet");
    g.throughput(Throughput::Bytes(1200));
    let mut template = vec![0x41u8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 42];
    template.resize(1200 - TAG_LEN, 0xab);
    let len = template.len();
    template.resize(1200, 0);
    g.bench_function("protect_1200", |b| {
        let mut buf = template.clone();
        b.iter(|| protect(&client.local, &mut buf, 9, 42, len).unwrap())
    });
    let mut sealed = template.clone();
    protect(&client.local, &mut sealed, 9, 42, len).unwrap();
    g.bench_function("unprotect_1200", |b| {
        b.iter(|| {
            let mut buf = sealed.clone();
            unprotect(&server.remote, &mut buf, 9, Some(41)).unwrap().pn
        })
    });
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
