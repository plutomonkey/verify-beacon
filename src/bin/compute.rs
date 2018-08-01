/// Computes 2**42 iterations of SHA-256 for a given 256-bit input, hex-encoded (64 hex
/// characters).
///
/// Usage: `cargo run --release --bin compute < hex.txt`
extern crate hex;
extern crate verify_beacon;

use std::io::{self, BufRead};
use verify_beacon::sha256;

fn main() {
    let stdin = io::stdin();
    let handle = stdin.lock();
    let count = 1024;
    let iterations = (1 << 42) / count;
    let mut seed = decode_hex(handle.lines().next().unwrap());
    println!("{}", hex::encode(&seed));
    for _ in 0..count {
        let next = unsafe { sha256::iterated_sha256(&seed, iterations) };
        println!("{}", hex::encode(&next));
        seed = next;
    }
}

fn decode_hex(s: Result<String, io::Error>) -> [u8; 32] {
    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(&hex::decode(s.unwrap()).unwrap());
    buffer
}
