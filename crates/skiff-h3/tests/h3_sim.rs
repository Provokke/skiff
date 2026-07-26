//! HTTP/3 through the skiff-sim network simulator: many concurrent
//! requests with mixed body sizes under loss, reordering and duplication
//! (QPACK encoder-stream data may arrive after the request that needs it,
//! so streams can block and unblock), checked byte for byte.

mod common;

use common::*;
use skiff_h3::{H3Config, H3Connection};
use skiff_quic::TransportConfig;
use skiff_sim::{LinkConfig, Sim, SimConfig};
use std::collections::BTreeMap;
use std::time::Duration;

fn sim(link: LinkConfig, seed: u64) -> Sim {
    let (c, s) = tls();
    Sim::new(SimConfig {
        client_tls: c,
        server_name: "localhost".into(),
        server_tls: s,
        client: TransportConfig::default(),
        server: TransportConfig::default(),
        c2s: link.clone(),
        s2c: link,
        seed,
    })
    .unwrap()
}

/// Runs one warm-up GET (so the client knows the server's SETTINGS and
/// may use the dynamic table), then GETs of `/size/N` for every size, to
/// completion, and verifies them.
fn exchange(link: LinkConfig, seed: u64, sizes: &[usize]) -> (H3Connection, H3Connection) {
    let mut s = sim(link, seed);
    let mut ch = H3Connection::new(H3Config::default());
    let mut sh = H3Connection::new(H3Config::default());
    let mut client = Client::default();
    let mut server = Server::default();
    client.get("/size/0");
    let mut queued = false;
    s.run(Duration::from_secs(600), |s| {
        client.poll(&mut ch, &mut s.client, s.now);
        if let Some(c) = s.server.as_mut() {
            server.poll(&mut sh, c, s.now);
        }
        if !queued && client.finished() == 1 {
            queued = true;
            for n in sizes {
                client.get(&format!("/size/{n}"));
            }
            client.poll(&mut ch, &mut s.client, s.now);
        }
        client.finished() == sizes.len() + 1
    })
    .unwrap();
    assert!(ch.peer_settings().is_some());
    let paths: BTreeMap<u64, String> = client.sent[1..]
        .iter()
        .zip(sizes)
        .map(|(id, n)| (*id, format!("/size/{n}")))
        .collect();
    client.verify_sizes(&paths);
    assert!(client.responses.values().all(|r| r.reset.is_none()));
    (ch, sh)
}

fn sizes(count: usize, seed: u64) -> Vec<usize> {
    (0..count as u64)
        .map(|i| {
            let x = (i ^ seed).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 40;
            [0, 10, 1200, 5000, 40_000][(x % 5) as usize] + (x % 97) as usize
        })
        .collect()
}

#[test]
fn many_requests_clean_path() {
    let link = LinkConfig::new(Duration::from_millis(20));
    let (ch, sh) = exchange(link, 1, &sizes(100, 1));
    assert!(ch.qpack_encoder().table().insert_count() > 0);
    assert!(sh.qpack_encoder().table().insert_count() > 0);
}

#[test]
fn many_requests_under_loss_reorder_duplication() {
    for seed in 1..=3 {
        let link = LinkConfig::new(Duration::from_millis(15))
            .loss(0.05)
            .reorder(0.1)
            .duplicate(0.01);
        exchange(link, seed, &sizes(100, seed));
    }
}

#[test]
fn large_download_at_heavy_loss() {
    let link = LinkConfig::new(Duration::from_millis(10)).loss(0.15);
    exchange(link, 7, &[1_000_000, 3, 70_000]);
}
