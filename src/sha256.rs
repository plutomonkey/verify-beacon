use byteorder::{BigEndian, ByteOrder};

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use packed_simd::*;

#[allow(dead_code)]
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

unsafe fn iterated_sha256_x86(input: &[u8], iterations: usize) -> [u8; 32] {
    let mut digest = [0u8; 32];

    let mut data = [0u32; 16];
    BigEndian::read_u32_into(input, &mut data[..8]);
    data[8] = 0x8000_0000;
    data[15] = 0x100;

    let mut msg = [
        u32x4::new(data[0], data[1], data[2], data[3]).into_bits(),
        u32x4::new(data[4], data[5], data[6], data[7]).into_bits(),
        u32x4::new(data[8], data[9], data[10], data[11]).into_bits(),
        u32x4::new(data[12], data[13], data[14], data[15]).into_bits(),
    ];

    let tmp = u32x4::new(H[0], H[1], H[2], H[3]).into_bits();
    let state1 = u32x4::new(H[4], H[5], H[6], H[7]).into_bits();

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
                    let tmp = _mm_add_epi32(msg[m], i32x4::new(K[i*4] as i32, K[i*4+1] as i32, K[i*4+2] as i32, K[i*4+3] as i32).into_bits());
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

    let msg0: u32x4 = msg[0].into_bits();
    let msg1: u32x4 = msg[1].into_bits();

    let mut words = [0u32; 8];
    msg0.write_to_slice_unaligned(&mut words[..4]);
    msg1.write_to_slice_unaligned(&mut words[4..]);

    BigEndian::write_u32_into(&words, &mut digest);

    digest
}

#[cfg(target_arch = "aarch64")]
unsafe fn iterated_sha256_aarch64(input: &[u8], iterations: usize) -> [u8; 32] {
    let mut digest = [0u8; 32];

    let mut data = [0u32; 16];
    BigEndian::read_u32_into(input, &mut data[..8]);
    data[8] = 0x8000_0000;
    data[15] = 0x100;

    let mut msg = [
        u32x4::new(data[0], data[1], data[2], data[3]).into_bits(),
        u32x4::new(data[4], data[5], data[6], data[7]).into_bits(),
        u32x4::new(data[8], data[9], data[10], data[11]).into_bits(),
        u32x4::new(data[12], data[13], data[14], data[15]).into_bits(),
    ];

    let state0 = u32x4::new(H[0], H[1], H[2], H[3]).into_bits();
    let state1 = u32x4::new(H[4], H[5], H[6], H[7]).into_bits();

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
                let tmp = vaddq_u32(msg[m], u32x4::new(K[i*4], K[i*4+1], K[i*4+2], K[i*4+3]).into_bits());
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

    let msg0: u32x4 = msg[0].into_bits();
    let msg1: u32x4 = msg[1].into_bits();

    let mut words = [0u32; 8];
    msg0.store_unaligned(&mut words[..4]);
    msg1.store_unaligned(&mut words[4..]);

    BigEndian::write_u32_into(&words, &mut digest);
    digest
}

pub unsafe fn iterated_sha256(input: &[u8], iterations: usize) -> [u8; 32] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("sha")
            && is_x86_feature_detected!("sse2")
            && is_x86_feature_detected!("ssse3")
            && is_x86_feature_detected!("sse4.1")
        {
            return iterated_sha256_x86(input, iterations);
        }
    }

    #[cfg(all(target_arch = "aarch64"))]
    {
        if is_aarch64_feature_detected("crypto") && is_aarch64_feature_detected("neon") {
            return iterated_sha256_aarch64(input, iterations);
        }
    }

    {
        use crypto::sha2::sha256_digest_block;

        let mut data = [0u8; 64];
        data[..32].copy_from_slice(input);
        data[32] = 0x80;
        data[62] = 0x01;

        for _ in 0..iterations {
            let mut state = H;
            sha256_digest_block(&mut state, &data);
            BigEndian::write_u32_into(&state, &mut data[..32]);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[..32]);
        digest
    }
}

#[cfg(test)]
mod tests {

    extern crate hex;
    extern crate test;
    use self::test::Bencher;
    use super::iterated_sha256;

    #[test]
    fn test_iterated_sha256() {
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(
            &hex::decode("00000000000000000034b33e842ac1c50456abe5fa92b60f6b3dfc5d247f7b58")
                .unwrap(),
        );
        unsafe {
            let one_iteration = iterated_sha256(&buffer, 1);
            assert_eq!(
                hex::encode(&one_iteration),
                "6b0ae522ab1c83ab6d75dad82bb5369840d48ad1b2b245284ab1bcf00135e458"
            );
            let two_iterations = iterated_sha256(&buffer, 2);
            assert_eq!(
                hex::encode(&two_iterations),
                "10220216300ab35b89a72f8fee8c998b4aeec7ef25379864d7f0e5fbfa9e7a32"
            );
        }
    }

    #[bench]
    fn bench_iterated_sha256(b: &mut Bencher) {
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(
            &hex::decode("00000000000000000034b33e842ac1c50456abe5fa92b60f6b3dfc5d247f7b58")
                .unwrap(),
        );
        unsafe {
            b.iter(|| iterated_sha256(&buffer, 1 << 12));
        }
    }
}
