/// Parallel verification of a 2**42 SHA-256 random beacon.
///
/// Usage: `cargo run --release --bin verify < 1024.txt`
///
/// Input should be 1025 lines, i.e. 1024 overlapping pairs, each line being 256 bits, hex-encoded
/// (64 hex characters).
extern crate hex;
extern crate itertools;
extern crate rayon;
extern crate verify_beacon;

use itertools::Itertools;
use rayon::prelude::*;
use std::io::{self, BufRead};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use verify_beacon::sha256;

fn main() {
    let stdin = io::stdin();
    let handle = stdin.lock();
    let pairs = handle
        .lines()
        .map(decode_hex)
        .tuple_windows()
        .collect::<Vec<([u8; 32], [u8; 32])>>();
    let count = pairs.len();
    let iterations = (1 << 42) / count;
    let remaining = Arc::new(AtomicUsize::new(count));
    pairs.par_iter().for_each(|(a, b)| {
        verify(&a, &b, iterations);
        println!(
            "remaining={}/{}",
            remaining.fetch_sub(1, Ordering::Relaxed) - 1,
            count
        );
    });
}

fn verify(a: &[u8; 32], b: &[u8; 32], iterations: usize) {
    unsafe {
        let result = sha256::iterated_sha256(a, iterations);
        assert_eq!(b, &result);
    }
}

fn decode_hex(s: Result<String, io::Error>) -> [u8; 32] {
    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(&hex::decode(s.unwrap()).unwrap());
    buffer
}
