verify-beacon
=============

This is primarily for verifying the [randomness beacon][beacon] used in the
[Powers of Tau ceremony][ceremony].  The file `1024.txt` contains 1024 hashes
plus the final hash; these are verified in a pairwise fashion in parallel for a
total of 2^42 iterations (2^32 per pair).

Two hardware-accelerated implementations are available, along with a
non-accelerated fallback.

The `verify-beacon` binary will panic if any of the pairs are invalid.

# Intel SHA Extensions

For example, this should work on AMD Ryzen CPUs:

```sh
RUSTFLAGS='-C target-cpu=native' cargo run --release --bin verify-beacon < 1024.txt
```

The time taken is around 130 cycles per iteration, which is ~1h45m on 24 Ryzen
cores running at 3.8GHz.

# ARM NEON

```sh
RUSTFLAGS='-C target-feature=+crypto,+neon' cargo run --release --bin verify-beacon < 1024.txt
```

The time taken is a bit over double the number of cycles compared with Ryzen,
e.g. ~2h20m on 96 Cavium ThunderX cores.  There may be some room to optimise
here.

[beacon]: https://lists.z.cash.foundation/pipermail/zapps-wg/2018/000267.html
[ceremony]: https://z.cash.foundation/blog/powers-of-tau/
