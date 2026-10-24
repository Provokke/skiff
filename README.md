<div align="center">

# skiff

A from-scratch QUIC implementation (RFC 9000, 9001, 9002) in Rust, built as a sans-I/O stack, with QPACK and HTTP/3 on top.

![License](https://img.shields.io/badge/LICENSE-MIT-blue?style=for-the-badge)  ![Language](https://img.shields.io/badge/RUST-dea584?style=for-the-badge&logo=rust&logoColor=white)  ![Tests](https://img.shields.io/badge/TESTS-180-brightgreen?style=for-the-badge)

Refer to [LICENSE](LICENSE) for the legal bits.

</div>

## 🏗️ Architecture

```
  skiff-server / skiff-client -> skiff::Endpoint (UDP) -> skiff-quic::Connection (+ rustls)
  skiff-h3 (QPACK + HTTP/3) ---------------------------^
                                                         |
               skiff-quic::{crypto, packet}  <-----------+----> skiff-recovery
                         |                                      (RTT, NewReno, CUBIC, pacer)
                     skiff-wire  (varint, pn, header, frame, params)
```

- `skiff-wire`: varints, packet number encoding, long/short/Version Negotiation/Retry headers, every RFC 9000 frame type (borrowed, zero-copy) and transport parameters.
- `skiff-recovery`: RFC 9002 RTT estimation, loss detection and PTO, persistent congestion, NewReno and CUBIC behind a `CongestionController` trait, and a token-bucket pacer.
- `skiff-quic`: the connection state machine. Packet protection and header protection, packet number spaces and ACK generation, stream reassembly and send buffering, flow control, stream limits, connection IDs and migration with path validation, stateless reset, Retry, key updates, path MTU discovery, idle timeout and closing/draining.
- `skiff-h3`: QPACK (static and dynamic tables, Huffman, blocked streams) and a sans-I/O HTTP/3 client and server over a `Connection`. The static table and Huffman code are generated from the RFC text by `crates/skiff-h3/tools/gen_tables.py`.
- `skiff`: `Endpoint` on a blocking `std::net::UdpSocket`, which demultiplexes by every connection ID a connection has issued, answers Version Negotiation, sends rate-limited stateless resets and can require Retry. Also the `skiff-server` and `skiff-client` binaries (stream echo, or HTTP/3 GET/HEAD with `--h3`).
- `skiff-sim`: a seeded, virtual-time network simulator (loss, reordering, duplication, delay, a bottleneck with a drop-tail queue) that drives two `Connection`s.
- `skiff-interop` (unpublished): interop tests against quinn 0.11 and h3 0.0.8 / h3-quinn 0.0.10.

## 🚀 Quick start

```
cargo build --workspace --locked
cargo test --workspace --locked        # includes the quinn and h3 interop tests
cargo test -p skiff-sim --release      # simulator, including 50 MB bulk transfers

cargo run -p skiff --bin skiff-server -- --listen 127.0.0.1:4433 --cert-out /tmp/skiff.der
cargo run -p skiff --bin skiff-client -- --connect 127.0.0.1:4433 --ca /tmp/skiff.der --streams 4 --bytes 100000

cargo run -p skiff --bin skiff-server -- --h3 --root ./site --cert-out /tmp/skiff.der
cargo run -p skiff --bin skiff-client -- --h3 --ca /tmp/skiff.der --path /index.html --out /tmp/index.html
```

The toolchain is pinned in `rust-toolchain.toml`. Fuzzing and Miri need nightly.

## 🧪 Testing

There are 180 tests across the workspace, plus 8 fuzz targets.

- Wire: unit tests and proptest round-trips for every codec, plus never-panic properties on arbitrary input.
- Packet protection: RFC 9001 Appendix A.1, A.2, A.3 and A.5 vectors match byte for byte, and the A.4 Retry integrity tag vector passes.
- Recovery: RTT maths, loss and PTO behaviour and cwnd through loss, all on a fake clock.
- Connection: handshake, streams, flow control, close and idle, key updates in both directions, connection ID rotation, migration and NAT rebinding, Retry, stateless reset, PMTUD and pacing, driven through an in-memory network.
- Simulator: bulk transfers checked by SHA-256 at 0%, 5% and 20% loss, reordering, duplication and bottleneck queues.
- Loopback: both binaries over real UDP on localhost.
- Interop: skiff client against a quinn server and quinn client against a skiff server, plus HTTP/3 against h3 in both directions.
- QPACK and HTTP/3: RFC 7541 Huffman vectors, RFC 9204 table behaviour, blocked streams and error handling.

I also ran a round of mutation checks: break a specific rule in the implementation (an off-by-one on the connection ID limit, skipping the amplification limit, not comparing the reset token, and so on) and confirm some test fails. Where a mutant survived I added a test for it.

The fuzz targets are `header`, `frame`, `params`, `unprotect`, `reassembly`, `connection_recv`, `qpack_decode` and `h3_frame`. `connection_recv` runs a real handshake and then feeds fuzzed datagrams. Each target has had a 60 second run on the current tree with no crashes. Miri has been run over `skiff-wire` only (no UB reported).

## ⏱️ Benchmarks

Criterion on a shared 4-core VM, `--measurement-time 2`:

| bench | time |
|---|---|
| encode STREAM frame (1100 B) | 28.2 ns |
| decode STREAM frame (1100 B) | 15.2 ns |
| encode ACK, 32 ranges | 358 ns |
| decode ACK, 32 ranges | 242 ns |
| protect 1200 B packet (AES-128-GCM + HP) | 198 ns |
| unprotect 1200 B packet | 228 ns |

There are no loopback throughput, handshake latency or quinn comparison benchmarks yet, so I make no performance claims beyond the codec and packet protection numbers above.

## ⚠️ Honest limits

- No 0-RTT and no NEW_TOKEN.
- No ECN. `std::net::UdpSocket` can't set or read the ECN bits, so this would need a different socket layer.
- No path MTU black-hole detection. PMTUD probes upwards and bisects after lost probes, but doesn't back off if a previously working size starts failing.
- Key updates work, but nothing triggers one automatically before the AEAD confidentiality or integrity limit is reached.
- HTTP/3 has no server push, no priorities and no WebTransport.
- Only tested against quinn and h3/h3-quinn, over loopback. Not tested against curl, quiche or browsers. h3 0.0.8 only uses stateless QPACK, so the dynamic table is only exercised skiff to skiff.
- The endpoint is a simple blocking loop, with no GSO or recvmmsg.
- Miri covers `skiff-wire` only, and there's been no ASan run.

## Licence

MIT OR Apache-2.0.
