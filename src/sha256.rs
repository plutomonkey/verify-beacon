#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[allow(unused_imports)]
use crunchy::unroll;

const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[allow(dead_code)]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Reads a 256-bit input as eight big-endian words, followed by the SHA-256 padding for a 256-bit
/// message.
#[allow(dead_code)]
fn load_block(input: &[u8]) -> [u32; 16] {
    assert_eq!(input.len(), 32);
    let mut data = [0u32; 16];
    for (word, bytes) in data.iter_mut().zip(input.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    data[8] = 0x8000_0000;
    data[15] = 0x100;
    data
}

fn store_digest(words: &[u32; 8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    for (bytes, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *bytes = word.to_be_bytes();
    }
    digest
}

/// Packs four words into a vector with `a` in lane 0, matching the word order used by the SHA
/// extensions.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "sse2")]
fn to_m128i(a: u32, b: u32, c: u32, d: u32) -> __m128i {
    _mm_setr_epi32(a as i32, b as i32, c as i32, d as i32)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn has_x86_sha() -> bool {
    is_x86_feature_detected!("sha")
        && is_x86_feature_detected!("sse2")
        && is_x86_feature_detected!("ssse3")
        && is_x86_feature_detected!("sse4.1")
}

#[cfg(target_arch = "aarch64")]
fn has_aarch64_sha() -> bool {
    use std::arch::is_aarch64_feature_detected;
    is_aarch64_feature_detected!("sha2") && is_aarch64_feature_detected!("neon")
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
// `unroll!` substitutes a constant for `i`, so comparisons such as `0 > 0` are expected.
#[allow(clippy::absurd_extreme_comparisons)]
fn iterated_sha256_x86(input: &[u8], iterations: usize) -> [u8; 32] {
    let data = load_block(input);

    let mut msg = [
        to_m128i(data[0], data[1], data[2], data[3]),
        to_m128i(data[4], data[5], data[6], data[7]),
        to_m128i(data[8], data[9], data[10], data[11]),
        to_m128i(data[12], data[13], data[14], data[15]),
    ];

    let tmp = to_m128i(H[0], H[1], H[2], H[3]);
    let state1 = to_m128i(H[4], H[5], H[6], H[7]);

    let tmp = _mm_shuffle_epi32(tmp, 0xb1);
    let state1 = _mm_shuffle_epi32(state1, 0x1b);
    let state0 = _mm_alignr_epi8(tmp, state1, 8);
    let state1 = _mm_blend_epi16(state1, tmp, 0xf0);

    let abef_save = state0;
    let cdgh_save = state1;
    let msg2_save = msg[2];
    let msg3_save = msg[3];

    for _ in 0..iterations {
        let mut state0 = abef_save;
        let mut state1 = cdgh_save;

        msg[2] = msg2_save;
        msg[3] = msg3_save;

        unroll! {
            for i in 0..16 {
                let m = i % 4;
                let m_next = (i + 1) % 4;
                let m_prev = (i + 3) % 4;
                {
                    let tmp = _mm_add_epi32(msg[m], to_m128i(K[i*4], K[i*4+1], K[i*4+2], K[i*4+3]));
                    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
                    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp, 0x0e));
                }
                if i > 2 {
                    let tmp = _mm_alignr_epi8(msg[m], msg[m_prev], 4);
                    msg[m_next] = _mm_add_epi32(msg[m_next], tmp);
                    msg[m_next] = _mm_sha256msg2_epu32(msg[m_next], msg[m]);
                }
                if i > 0 {
                    msg[m_prev] = _mm_sha256msg1_epu32(msg[m_prev], msg[m]);
                }
            }
        }

        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);

        {
            let tmp = _mm_shuffle_epi32(state0, 0x1b);
            state1 = _mm_shuffle_epi32(state1, 0xb1);
            msg[0] = _mm_blend_epi16(tmp, state1, 0xf0);
            msg[1] = _mm_alignr_epi8(state1, tmp, 8);
        }
    }

    let mut words = [0u32; 8];
    // SAFETY: each store writes four words within `words`.
    unsafe {
        _mm_storeu_si128(words[0..4].as_mut_ptr().cast(), msg[0]);
        _mm_storeu_si128(words[4..8].as_mut_ptr().cast(), msg[1]);
    }

    store_digest(&words)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2,neon")]
fn iterated_sha256_aarch64(input: &[u8], iterations: usize) -> [u8; 32] {
    let data = load_block(input);

    // SAFETY: each load reads four words within `data` or `H`.
    let mut msg = unsafe {
        [
            vld1q_u32(data[0..4].as_ptr()),
            vld1q_u32(data[4..8].as_ptr()),
            vld1q_u32(data[8..12].as_ptr()),
            vld1q_u32(data[12..16].as_ptr()),
        ]
    };

    let state0 = unsafe { vld1q_u32(H[0..4].as_ptr()) };
    let state1 = unsafe { vld1q_u32(H[4..8].as_ptr()) };

    let abef_save = state0;
    let cdgh_save = state1;
    let msg2_save = msg[2];
    let msg3_save = msg[3];

    for _ in 0..iterations {
        let mut state0 = abef_save;
        let mut state1 = cdgh_save;

        msg[2] = msg2_save;
        msg[3] = msg3_save;

        unroll! {
            for i in 0..16 {
                let m = i % 4;
                let m_next = (i + 1) % 4;
                // SAFETY: reads four words within `K`.
                let k = unsafe { vld1q_u32(K[i*4..i*4+4].as_ptr()) };
                let tmp = vaddq_u32(msg[m], k);
                msg[m] = vsha256su0q_u32(msg[m], msg[m_next]);
                let old_state0 = state0;
                state0 = vsha256hq_u32(state0, state1, tmp);
                state1 = vsha256h2q_u32(state1, old_state0, tmp);
                msg[m] = vsha256su1q_u32(msg[m], msg[(i + 2) % 4], msg[(i + 3) % 4]);
            }
        }

        msg[0] = vaddq_u32(state0, abef_save);
        msg[1] = vaddq_u32(state1, cdgh_save);
    }

    let mut words = [0u32; 8];
    // SAFETY: each store writes four words within `words`.
    unsafe {
        vst1q_u32(words[0..4].as_mut_ptr(), msg[0]);
        vst1q_u32(words[4..8].as_mut_ptr(), msg[1]);
    }

    store_digest(&words)
}

fn iterated_sha256_fallback(input: &[u8], iterations: usize) -> [u8; 32] {
    use core::slice;
    use sha2::block_api::compress256;

    let mut block = [0u8; 64];
    block[..32].copy_from_slice(input);
    block[32] = 0x80;
    block[62] = 0x01;

    for _ in 0..iterations {
        let mut state = H;
        compress256(&mut state, slice::from_ref(&block));
        block[..32].copy_from_slice(&store_digest(&state));
    }
    block[..32].try_into().unwrap()
}

/// Computes `iterations` iterations of SHA-256 for a 256-bit input, using hardware acceleration if
/// available.
///
/// # Panics
///
/// Panics if `input` is not 32 bytes long.
pub fn iterated_sha256(input: &[u8], iterations: usize) -> [u8; 32] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if has_x86_sha() {
            // SAFETY: the required CPU features were detected above.
            return unsafe { iterated_sha256_x86(input, iterations) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if has_aarch64_sha() {
            // SAFETY: the required CPU features were detected above.
            return unsafe { iterated_sha256_aarch64(input, iterations) };
        }
    }

    iterated_sha256_fallback(input, iterations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;
    use std::time::Instant;

    /// Checks each hardware backend available on this machine against the portable fallback, so
    /// that a broken backend is caught even when the dispatcher would not select it by default.
    #[test]
    fn test_backends_match_fallback() {
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(
            &hex::decode("00000000000000000034b33e842ac1c50456abe5fa92b60f6b3dfc5d247f7b58")
                .unwrap(),
        );
        assert_eq!(
            hex::encode(iterated_sha256_fallback(&buffer, 2)),
            "10220216300ab35b89a72f8fee8c998b4aeec7ef25379864d7f0e5fbfa9e7a32"
        );
        for &iterations in &[0, 1, 2, 3, 1000] {
            #[allow(unused_variables)]
            let expected = iterated_sha256_fallback(&buffer, iterations);

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                if has_x86_sha() {
                    let actual = unsafe { iterated_sha256_x86(&buffer, iterations) };
                    assert_eq!(actual, expected, "x86, iterations={}", iterations);
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                if has_aarch64_sha() {
                    let actual = unsafe { iterated_sha256_aarch64(&buffer, iterations) };
                    assert_eq!(actual, expected, "aarch64, iterations={}", iterations);
                }
            }
        }
    }

    fn time(name: &str, iterations: usize, f: impl FnOnce() -> [u8; 32]) {
        let start = Instant::now();
        black_box(f());
        let ns = start.elapsed().as_nanos() as f64 / iterations as f64;
        println!("{name}: {ns:.2} ns/iteration");
    }

    /// Times each backend available on this machine.
    ///
    /// Run with `cargo test --release -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_backends() {
        let buffer = [0u8; 32];
        let iterations = 1 << 24;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if has_x86_sha() {
                time("x86", iterations, || unsafe {
                    iterated_sha256_x86(black_box(&buffer), iterations)
                });
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if has_aarch64_sha() {
                time("aarch64", iterations, || unsafe {
                    iterated_sha256_aarch64(black_box(&buffer), iterations)
                });
            }
        }

        time("fallback", iterations, || {
            iterated_sha256_fallback(black_box(&buffer), iterations)
        });
    }

    #[test]
    fn test_iterated_sha256() {
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(
            &hex::decode("00000000000000000034b33e842ac1c50456abe5fa92b60f6b3dfc5d247f7b58")
                .unwrap(),
        );
        let one_iteration = iterated_sha256(&buffer, 1);
        assert_eq!(
            hex::encode(one_iteration),
            "6b0ae522ab1c83ab6d75dad82bb5369840d48ad1b2b245284ab1bcf00135e458"
        );
        let two_iterations = iterated_sha256(&buffer, 2);
        assert_eq!(
            hex::encode(two_iterations),
            "10220216300ab35b89a72f8fee8c998b4aeec7ef25379864d7f0e5fbfa9e7a32"
        );
    }
}
