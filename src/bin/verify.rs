/// Parallel verification of a 2**42 SHA-256 random beacon.
///
/// Usage: `cargo run --release --bin verify < 1024.txt`
///
/// Input should be 1025 lines, i.e. 1024 overlapping pairs, each line being 256 bits, hex-encoded
/// (64 hex characters).
///
/// This only checks that the input is a valid chain of 2**42 iterations; the printed start and end
/// hashes must be compared against the published seed and beacon values.
use rayon::prelude::*;
use std::io::{self, BufRead};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use verify_beacon::sha256;

const TOTAL_ITERATIONS: usize = 1 << 42;

fn main() {
    let stdin = io::stdin();
    let handle = stdin.lock();
    let hashes = handle.lines().map(decode_hex).collect::<Vec<[u8; 32]>>();
    if hashes.len() < 2 {
        eprintln!(
            "error: expected at least 2 lines of input, got {}",
            hashes.len()
        );
        process::exit(1);
    }
    let count = hashes.len() - 1;
    if !TOTAL_ITERATIONS.is_multiple_of(count) {
        eprintln!(
            "error: number of pairs ({}) must divide 2^42 exactly",
            count
        );
        process::exit(1);
    }
    let iterations = TOTAL_ITERATIONS / count;
    println!("start={}", hex::encode(hashes[0]));
    println!("end={}", hex::encode(hashes[count]));
    let remaining = Arc::new(AtomicUsize::new(count));
    hashes.par_windows(2).enumerate().for_each(|(i, pair)| {
        let (a, b) = (&pair[0], &pair[1]);
        let result = sha256::iterated_sha256(a, iterations);
        if &result != b {
            eprintln!(
                "error: pair {} failed: {} -> {}, expected {}",
                i,
                hex::encode(a),
                hex::encode(result),
                hex::encode(b)
            );
            process::exit(1);
        }
        println!(
            "remaining={}/{}",
            remaining.fetch_sub(1, Ordering::Relaxed) - 1,
            count
        );
    });
    println!("OK: verified 2^42 iterations from start to end");
}

fn decode_hex(s: Result<String, io::Error>) -> [u8; 32] {
    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(&hex::decode(s.unwrap()).unwrap());
    buffer
}
