verify-beacon
=============

This is for computing and verifying the [randomness beacon][beacon] used in the
[Powers of Tau][ceremony] and Sapling MPC ceremonies, using hardware
acceleration if available.

The beacon is computed using 2^42 iterations of SHA-256.

The files `powersoftau.txt` and `sapling.txt` each contain 1025 hashes (1024
sequential pairs), allowing the beacon to be verified more quickly in parallel.

Two hardware-accelerated implementations are available, along with a
non-accelerated fallback.  Currently, [Intel SHA extensions][intel] (e.g. AMD
Ryzen) and ARMv8 cryptographic extensions are supported.

Usage
-----

*Important:* binaries _must_ be compiled with `RUSTFLAGS='-C
target-cpu=native'` to enable hardware-acceleration.

* `cargo run --release --bin compute > pairs.txt`
* `cargo run --release --bin verify < pairs.txt`

Benchmarks
----------

The time taken is around 130 cycles per iteration on AMD Ryzen, which is ~1h45m
to verify on on 24 cores running at 3.8GHz.

[beacon]: https://lists.z.cash.foundation/pipermail/zapps-wg/2018/000267.html
[ceremony]: https://z.cash.foundation/blog/powers-of-tau/
[intel]: https://en.wikipedia.org/wiki/Intel_SHA_extensions
