#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use super::{KeccakState, SHAKE256x4};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

// ========================================================================
// SHAKE256x4 with AVX2 Optimizations
// ========================================================================

// This AVX2-specific implementation uses AVX2 opcodes to perform four
// Keccak functions in parallel.
// These function change the memory layout, in that the four Keccak states
// are interleaved (on a 64-bit word granularity).

// Assuming that the provided states contains only zeros, inject the
// seed bytes + ID byte + padding into each of the four states.
pub(crate) unsafe fn init_seed(sh: &mut SHAKE256x4, seed: &[u8]) {
    let mut i = 0;
    let mut jh = 0;
    let mut jl = 0;
    loop {
        let (x0, x1, x2, x3);
        let mut quit = false;
        if (i + 8) <= seed.len() {
            // At least 8 seed bytes to inject.
            x0 = u64::from_le_bytes(
                *<&[u8; 8]>::try_from(&seed[i..(i + 8)]).unwrap());
            x1 = x0;
            x2 = x0;
            x3 = x0;
            i += 8;
        } else if (i + 7) == seed.len() {
            // 7 seed bytes to inject + ID byte.
            let n = seed.len() - i;
            let mut x = 0;
            for k in 0..n {
                x |= (seed[i + k] as u64) << (k << 3);
            }
            x0 = x;
            x1 = x | (1u64 << (n << 3));
            x2 = x | (2u64 << (n << 3));
            x3 = x | (3u64 << (n << 3));
            i += 8;
        } else if i <= seed.len() {
            // 0-6 seed bytes to inject + ID byte + padding byte.
            let n = seed.len() - i;
            let mut x = 0;
            for k in 0..n {
                x |= (seed[i + k] as u64) << (k << 3);
            }
            x0 = x | (0x1F00u64 << (n << 3));
            x1 = x | (0x1F01u64 << (n << 3));
            x2 = x | (0x1F02u64 << (n << 3));
            x3 = x | (0x1F03u64 << (n << 3));
            quit = true;
        } else {
            // Only the padding byte to inject.
            x0 = 0x1F;
            x1 = 0x1F;
            x2 = 0x1F;
            x3 = 0x1F;
            quit = true;
        }
        match jl {
            22 => {
                sh.state[jh].0[jl + 0] ^= x0;
                sh.state[jh].0[jl + 1] ^= x1;
                sh.state[jh].0[jl + 2] ^= x2;
                sh.state[jh + 1].0[0] ^= x3;
                jh += 1;
                jl = 1;
            },
            23 => {
                sh.state[jh].0[jl + 0] ^= x0;
                sh.state[jh].0[jl + 1] ^= x1;
                sh.state[jh + 1].0[0] ^= x2;
                sh.state[jh + 1].0[1] ^= x3;
                jh += 1;
                jl = 2;
            },
            24 => {
                sh.state[jh].0[jl + 0] ^= x0;
                sh.state[jh + 1].0[0] ^= x1;
                sh.state[jh + 1].0[1] ^= x2;
                sh.state[jh + 1].0[2] ^= x3;
                jh += 1;
                jl = 3;
            },
            _ => {
                sh.state[jh].0[jl + 0] ^= x0;
                sh.state[jh].0[jl + 1] ^= x1;
                sh.state[jh].0[jl + 2] ^= x2;
                sh.state[jh].0[jl + 3] ^= x3;
                jl += 4;
                if jl == 25 {
                    jh += 1;
                    jl = 0;
                }
            },
        }
        // We exit the loop when we have injected the padding bytes (0x1F).
        // We do _not_ run the Keccak function in that case, even if the
        // state is full, because that is delayed until output is requested.
        if quit {
            break;
        }
        if jh == 2 && jl == 18 {
            // We filled 68 words, i.e. 136 bytes per state.
            keccak_x4(&mut sh.state);
            jh = 0;
            jl = 0;
        }
    }

    // Since we put the padding bytes, we must have a complete padding.
    sh.state[2].0[14] ^= 0x80 << 56;
    sh.state[2].0[15] ^= 0x80 << 56;
    sh.state[2].0[16] ^= 0x80 << 56;
    sh.state[2].0[17] ^= 0x80 << 56;
}

// Refill the PRNG buffer. This function does not reset sh.ptr.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn refill(sh: &mut SHAKE256x4) {
    keccak_x4(&mut sh.state);
    let s: *const __m256i = core::mem::transmute((&sh.state).as_ptr());
    let d: *mut __m256i = core::mem::transmute((&mut sh.buf).as_ptr());
    for i in 0..17 {
        let x = _mm256_loadu_si256(s.wrapping_add(i));
        _mm256_storeu_si256(d.wrapping_add(i), x);
    }
}

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
];

// Run four parallel Keccak functions. The provided array has room for
// four Keccak states but they are internally interleaved.
#[target_feature(enable = "avx2")]
unsafe fn keccak_x4(state: &mut [KeccakState; 4]) {
    let s: *const __m256i = core::mem::transmute(state.as_ptr());
    let mut ya = [_mm256_setzero_si256(); 25];
    for i in 0..25 {
        ya[i] = _mm256_loadu_si256(s.wrapping_add(i));
    }

    // Invert some words (alternate internal representation, which
    // saves some operations).
    let yones = _mm256_set1_epi32(-1);
    ya[ 1] = _mm256_xor_si256(ya[ 1], yones);
    ya[ 2] = _mm256_xor_si256(ya[ 2], yones);
    ya[ 8] = _mm256_xor_si256(ya[ 8], yones);
    ya[12] = _mm256_xor_si256(ya[12], yones);
    ya[17] = _mm256_xor_si256(ya[17], yones);
    ya[20] = _mm256_xor_si256(ya[20], yones);

    // Compute the 24 rounds. This loop is partially unrolled (each
    // iteration computes two rounds).
    for hj in 0..12 {

        #[target_feature(enable = "avx2")]
        #[inline]
        unsafe fn yCOMB1(y0: __m256i, y1: __m256i, y2: __m256i, y3: __m256i,
            y4: __m256i, y5: __m256i, y6: __m256i, y7: __m256i,
            y8: __m256i, y9: __m256i) -> __m256i
        {
            let ytt0 = _mm256_xor_si256(y0, y1);
            let ytt1 = _mm256_xor_si256(y2, y3);
            let ytt0 = _mm256_xor_si256(ytt0, _mm256_xor_si256(y4, ytt1));
            let ytt0 = _mm256_or_si256(
                _mm256_slli_epi64(ytt0, 1), _mm256_srli_epi64(ytt0, 63));
            let ytt2 = _mm256_xor_si256(y5, y6);
            let ytt3 = _mm256_xor_si256(y7, y8);
            let ytt0 = _mm256_xor_si256(ytt0, y9);
            let ytt2 = _mm256_xor_si256(ytt2, ytt3);
            _mm256_xor_si256(ytt0, ytt2)
        }

        #[target_feature(enable = "avx2")]
        #[inline]
        unsafe fn yCOMB2_1(ya: &mut [__m256i; 25],
            i0: usize, i1: usize, i2: usize, i3: usize, i4: usize)
        {
            let ykt = _mm256_or_si256(ya[i1], ya[i2]);
            let yc0 = _mm256_xor_si256(ykt, ya[i0]);
            let ykt = _mm256_or_si256(
                _mm256_xor_si256(ya[i2], _mm256_set1_epi32(-1)), ya[i3]);
            let yc1 = _mm256_xor_si256(ykt, ya[i1]);
            let ykt = _mm256_and_si256(ya[i3], ya[i4]);
            let yc2 = _mm256_xor_si256(ykt, ya[i2]);
            let ykt = _mm256_or_si256(ya[i4], ya[i0]);
            let yc3 = _mm256_xor_si256(ykt, ya[i3]);
            let ykt = _mm256_and_si256(ya[i0], ya[i1]);
            let yc4 = _mm256_xor_si256(ykt, ya[i4]);
            ya[i0] = yc0;
            ya[i1] = yc1;
            ya[i2] = yc2;
            ya[i3] = yc3;
            ya[i4] = yc4;
        }

        #[target_feature(enable = "avx2")]
        #[inline]
        unsafe fn yCOMB2_2(ya: &mut [__m256i; 25],
            i0: usize, i1: usize, i2: usize, i3: usize, i4: usize)
        {
            let ykt = _mm256_or_si256(ya[i1], ya[i2]);
            let yc0 = _mm256_xor_si256(ykt, ya[i0]);
            let ykt = _mm256_and_si256(ya[i2], ya[i3]);
            let yc1 = _mm256_xor_si256(ykt, ya[i1]);
            let ykt = _mm256_or_si256(ya[i3],
                _mm256_xor_si256(ya[i4], _mm256_set1_epi32(-1)));
            let yc2 = _mm256_xor_si256(ykt, ya[i2]);
            let ykt = _mm256_or_si256(ya[i4], ya[i0]);
            let yc3 = _mm256_xor_si256(ykt, ya[i3]);
            let ykt = _mm256_and_si256(ya[i0], ya[i1]);
            let yc4 = _mm256_xor_si256(ykt, ya[i4]);
            ya[i0] = yc0;
            ya[i1] = yc1;
            ya[i2] = yc2;
            ya[i3] = yc3;
            ya[i4] = yc4;
        }

        #[target_feature(enable = "avx2")]
        #[inline]
        unsafe fn yCOMB2_3(ya: &mut [__m256i; 25],
            i0: usize, i1: usize, i2: usize, i3: usize, i4: usize)
        {
            let ykt = _mm256_or_si256(ya[i1], ya[i2]);
            let yc0 = _mm256_xor_si256(ykt, ya[i0]);
            let ykt = _mm256_andnot_si256(ya[i3], ya[i2]);
            let yc1 = _mm256_xor_si256(ykt, ya[i1]);
            let ykt = _mm256_and_si256(ya[i3], ya[i4]);
            let yc2 = _mm256_xor_si256(ykt, ya[i2]);
            let ykt = _mm256_or_si256(ya[i4], ya[i0]);
            let yc3 = _mm256_xor_si256(ykt, ya[i3]);
            let ykt = _mm256_and_si256(ya[i0], ya[i1]);
            let yc4 = _mm256_xor_si256(ykt, ya[i4]);
            ya[i0] = yc0;
            ya[i1] = yc1;
            ya[i2] = yc2;
            ya[i3] = yc3;
            ya[i4] = yc4;
        }

        #[target_feature(enable = "avx2")]
        #[inline]
        unsafe fn yCOMB2_4(ya: &mut [__m256i; 25],
            i0: usize, i1: usize, i2: usize, i3: usize, i4: usize)
        {
            let ykt = _mm256_and_si256(ya[i1], ya[i2]);
            let yc0 = _mm256_xor_si256(ykt, ya[i0]);
            let ykt = _mm256_or_si256(ya[i2],
                _mm256_xor_si256(ya[i3], _mm256_set1_epi32(-1)));
            let yc1 = _mm256_xor_si256(ykt, ya[i1]);
            let ykt = _mm256_or_si256(ya[i3], ya[i4]);
            let yc2 = _mm256_xor_si256(ykt, ya[i2]);
            let ykt = _mm256_and_si256(ya[i4], ya[i0]);
            let yc3 = _mm256_xor_si256(ykt, ya[i3]);
            let ykt = _mm256_or_si256(ya[i0], ya[i1]);
            let yc4 = _mm256_xor_si256(ykt, ya[i4]);
            ya[i0] = yc0;
            ya[i1] = yc1;
            ya[i2] = yc2;
            ya[i3] = yc3;
            ya[i4] = yc4;
        }

        #[target_feature(enable = "avx2")]
        #[inline]
        unsafe fn yCOMB2_5(ya: &mut [__m256i; 25],
            i0: usize, i1: usize, i2: usize, i3: usize, i4: usize)
        {
            let ykt = _mm256_and_si256(ya[i1], ya[i2]);
            let yc0 = _mm256_xor_si256(ykt, ya[i0]);
            let ykt = _mm256_or_si256(ya[i2], ya[i3]);
            let yc1 = _mm256_xor_si256(ykt, ya[i1]);
            let ykt = _mm256_and_si256(ya[i3], ya[i4]);
            let yc2 = _mm256_xor_si256(ykt, ya[i2]);
            let ykt = _mm256_or_si256(ya[i4], ya[i0]);
            let yc3 = _mm256_xor_si256(ykt, ya[i3]);
            let ykt = _mm256_andnot_si256(ya[i1], ya[i0]);
            let yc4 = _mm256_xor_si256(ykt, ya[i4]);
            ya[i0] = yc0;
            ya[i1] = yc1;
            ya[i2] = yc2;
            ya[i3] = yc3;
            ya[i4] = yc4;
        }

        // ===== Round j =====

        let yt0 = yCOMB1(ya[1], ya[6], ya[11], ya[16],
            ya[21], ya[4], ya[9], ya[14], ya[19], ya[24]);
        let yt1 = yCOMB1(ya[2], ya[7], ya[12], ya[17],
            ya[22], ya[0], ya[5], ya[10], ya[15], ya[20]);
        let yt2 = yCOMB1(ya[3], ya[8], ya[13], ya[18],
            ya[23], ya[1], ya[6], ya[11], ya[16], ya[21]);
        let yt3 = yCOMB1(ya[4], ya[9], ya[14], ya[19],
            ya[24], ya[2], ya[7], ya[12], ya[17], ya[22]);
        let yt4 = yCOMB1(ya[0], ya[5], ya[10], ya[15],
            ya[20], ya[3], ya[8], ya[13], ya[18], ya[23]);

        ya[ 0] = _mm256_xor_si256(ya[ 0], yt0);
        ya[ 5] = _mm256_xor_si256(ya[ 5], yt0);
        ya[10] = _mm256_xor_si256(ya[10], yt0);
        ya[15] = _mm256_xor_si256(ya[15], yt0);
        ya[20] = _mm256_xor_si256(ya[20], yt0);
        ya[ 1] = _mm256_xor_si256(ya[ 1], yt1);
        ya[ 6] = _mm256_xor_si256(ya[ 6], yt1);
        ya[11] = _mm256_xor_si256(ya[11], yt1);
        ya[16] = _mm256_xor_si256(ya[16], yt1);
        ya[21] = _mm256_xor_si256(ya[21], yt1);
        ya[ 2] = _mm256_xor_si256(ya[ 2], yt2);
        ya[ 7] = _mm256_xor_si256(ya[ 7], yt2);
        ya[12] = _mm256_xor_si256(ya[12], yt2);
        ya[17] = _mm256_xor_si256(ya[17], yt2);
        ya[22] = _mm256_xor_si256(ya[22], yt2);
        ya[ 3] = _mm256_xor_si256(ya[ 3], yt3);
        ya[ 8] = _mm256_xor_si256(ya[ 8], yt3);
        ya[13] = _mm256_xor_si256(ya[13], yt3);
        ya[18] = _mm256_xor_si256(ya[18], yt3);
        ya[23] = _mm256_xor_si256(ya[23], yt3);
        ya[ 4] = _mm256_xor_si256(ya[ 4], yt4);
        ya[ 9] = _mm256_xor_si256(ya[ 9], yt4);
        ya[14] = _mm256_xor_si256(ya[14], yt4);
        ya[19] = _mm256_xor_si256(ya[19], yt4);
        ya[24] = _mm256_xor_si256(ya[24], yt4);
        ya[ 5] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 5], 36), _mm256_srli_epi64(ya[ 5], 64 - 36));
        ya[10] = _mm256_or_si256(
            _mm256_slli_epi64(ya[10],  3), _mm256_srli_epi64(ya[10], 64 -  3));
        ya[15] = _mm256_or_si256(
            _mm256_slli_epi64(ya[15], 41), _mm256_srli_epi64(ya[15], 64 - 41));
        ya[20] = _mm256_or_si256(
            _mm256_slli_epi64(ya[20], 18), _mm256_srli_epi64(ya[20], 64 - 18));
        ya[ 1] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 1],  1), _mm256_srli_epi64(ya[ 1], 64 -  1));
        ya[ 6] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 6], 44), _mm256_srli_epi64(ya[ 6], 64 - 44));
        ya[11] = _mm256_or_si256(
            _mm256_slli_epi64(ya[11], 10), _mm256_srli_epi64(ya[11], 64 - 10));
        ya[16] = _mm256_or_si256(
            _mm256_slli_epi64(ya[16], 45), _mm256_srli_epi64(ya[16], 64 - 45));
        ya[21] = _mm256_or_si256(
            _mm256_slli_epi64(ya[21],  2), _mm256_srli_epi64(ya[21], 64 -  2));
        ya[ 2] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 2], 62), _mm256_srli_epi64(ya[ 2], 64 - 62));
        ya[ 7] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 7],  6), _mm256_srli_epi64(ya[ 7], 64 -  6));
        ya[12] = _mm256_or_si256(
            _mm256_slli_epi64(ya[12], 43), _mm256_srli_epi64(ya[12], 64 - 43));
        ya[17] = _mm256_or_si256(
            _mm256_slli_epi64(ya[17], 15), _mm256_srli_epi64(ya[17], 64 - 15));
        ya[22] = _mm256_or_si256(
            _mm256_slli_epi64(ya[22], 61), _mm256_srli_epi64(ya[22], 64 - 61));
        ya[ 3] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 3], 28), _mm256_srli_epi64(ya[ 3], 64 - 28));
        ya[ 8] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 8], 55), _mm256_srli_epi64(ya[ 8], 64 - 55));
        ya[13] = _mm256_or_si256(
            _mm256_slli_epi64(ya[13], 25), _mm256_srli_epi64(ya[13], 64 - 25));
        ya[18] = _mm256_or_si256(
            _mm256_slli_epi64(ya[18], 21), _mm256_srli_epi64(ya[18], 64 - 21));
        ya[23] = _mm256_or_si256(
            _mm256_slli_epi64(ya[23], 56), _mm256_srli_epi64(ya[23], 64 - 56));
        ya[ 4] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 4], 27), _mm256_srli_epi64(ya[ 4], 64 - 27));
        ya[ 9] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 9], 20), _mm256_srli_epi64(ya[ 9], 64 - 20));
        ya[14] = _mm256_or_si256(
            _mm256_slli_epi64(ya[14], 39), _mm256_srli_epi64(ya[14], 64 - 39));
        ya[19] = _mm256_or_si256(
            _mm256_slli_epi64(ya[19],  8), _mm256_srli_epi64(ya[19], 64 -  8));
        ya[24] = _mm256_or_si256(
            _mm256_slli_epi64(ya[24], 14), _mm256_srli_epi64(ya[24], 64 - 14));

        yCOMB2_1(&mut ya, 0, 6, 12, 18, 24);
        yCOMB2_2(&mut ya, 3, 9, 10, 16, 22);
        ya[19] = _mm256_xor_si256(ya[19], yones);
        yCOMB2_3(&mut ya, 1, 7, 13, 19, 20);
        ya[17] = _mm256_xor_si256(ya[17], yones);
        yCOMB2_4(&mut ya, 4, 5, 11, 17, 23);
        ya[8] = _mm256_xor_si256(ya[8], yones);
        yCOMB2_5(&mut ya, 2, 8, 14, 15, 21);

        ya[0] = _mm256_xor_si256(ya[0],
            _mm256_set1_epi64x(RC[(hj << 1) + 0] as i64));

        // ===== Round j + 1 =====

        let yt0 = yCOMB1(ya[6], ya[9], ya[7], ya[5],
            ya[8], ya[24], ya[22], ya[20], ya[23], ya[21]);
        let yt1 = yCOMB1(ya[12], ya[10], ya[13], ya[11],
            ya[14], ya[0], ya[3], ya[1], ya[4], ya[2]);
        let yt2 = yCOMB1(ya[18], ya[16], ya[19], ya[17],
            ya[15], ya[6], ya[9], ya[7], ya[5], ya[8]);
        let yt3 = yCOMB1(ya[24], ya[22], ya[20], ya[23],
            ya[21], ya[12], ya[10], ya[13], ya[11], ya[14]);
        let yt4 = yCOMB1(ya[0], ya[3], ya[1], ya[4],
            ya[2], ya[18], ya[16], ya[19], ya[17], ya[15]);

        ya[ 0] = _mm256_xor_si256(ya[ 0], yt0);
        ya[ 3] = _mm256_xor_si256(ya[ 3], yt0);
        ya[ 1] = _mm256_xor_si256(ya[ 1], yt0);
        ya[ 4] = _mm256_xor_si256(ya[ 4], yt0);
        ya[ 2] = _mm256_xor_si256(ya[ 2], yt0);
        ya[ 6] = _mm256_xor_si256(ya[ 6], yt1);
        ya[ 9] = _mm256_xor_si256(ya[ 9], yt1);
        ya[ 7] = _mm256_xor_si256(ya[ 7], yt1);
        ya[ 5] = _mm256_xor_si256(ya[ 5], yt1);
        ya[ 8] = _mm256_xor_si256(ya[ 8], yt1);
        ya[12] = _mm256_xor_si256(ya[12], yt2);
        ya[10] = _mm256_xor_si256(ya[10], yt2);
        ya[13] = _mm256_xor_si256(ya[13], yt2);
        ya[11] = _mm256_xor_si256(ya[11], yt2);
        ya[14] = _mm256_xor_si256(ya[14], yt2);
        ya[18] = _mm256_xor_si256(ya[18], yt3);
        ya[16] = _mm256_xor_si256(ya[16], yt3);
        ya[19] = _mm256_xor_si256(ya[19], yt3);
        ya[17] = _mm256_xor_si256(ya[17], yt3);
        ya[15] = _mm256_xor_si256(ya[15], yt3);
        ya[24] = _mm256_xor_si256(ya[24], yt4);
        ya[22] = _mm256_xor_si256(ya[22], yt4);
        ya[20] = _mm256_xor_si256(ya[20], yt4);
        ya[23] = _mm256_xor_si256(ya[23], yt4);
        ya[21] = _mm256_xor_si256(ya[21], yt4);
        ya[ 3] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 3], 36), _mm256_srli_epi64(ya[ 3], 64 - 36));
        ya[ 1] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 1],  3), _mm256_srli_epi64(ya[ 1], 64 -  3));
        ya[ 4] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 4], 41), _mm256_srli_epi64(ya[ 4], 64 - 41));
        ya[ 2] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 2], 18), _mm256_srli_epi64(ya[ 2], 64 - 18));
        ya[ 6] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 6],  1), _mm256_srli_epi64(ya[ 6], 64 -  1));
        ya[ 9] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 9], 44), _mm256_srli_epi64(ya[ 9], 64 - 44));
        ya[ 7] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 7], 10), _mm256_srli_epi64(ya[ 7], 64 - 10));
        ya[ 5] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 5], 45), _mm256_srli_epi64(ya[ 5], 64 - 45));
        ya[ 8] = _mm256_or_si256(
            _mm256_slli_epi64(ya[ 8],  2), _mm256_srli_epi64(ya[ 8], 64 -  2));
        ya[12] = _mm256_or_si256(
            _mm256_slli_epi64(ya[12], 62), _mm256_srli_epi64(ya[12], 64 - 62));
        ya[10] = _mm256_or_si256(
            _mm256_slli_epi64(ya[10],  6), _mm256_srli_epi64(ya[10], 64 -  6));
        ya[13] = _mm256_or_si256(
            _mm256_slli_epi64(ya[13], 43), _mm256_srli_epi64(ya[13], 64 - 43));
        ya[11] = _mm256_or_si256(
            _mm256_slli_epi64(ya[11], 15), _mm256_srli_epi64(ya[11], 64 - 15));
        ya[14] = _mm256_or_si256(
            _mm256_slli_epi64(ya[14], 61), _mm256_srli_epi64(ya[14], 64 - 61));
        ya[18] = _mm256_or_si256(
            _mm256_slli_epi64(ya[18], 28), _mm256_srli_epi64(ya[18], 64 - 28));
        ya[16] = _mm256_or_si256(
            _mm256_slli_epi64(ya[16], 55), _mm256_srli_epi64(ya[16], 64 - 55));
        ya[19] = _mm256_or_si256(
            _mm256_slli_epi64(ya[19], 25), _mm256_srli_epi64(ya[19], 64 - 25));
        ya[17] = _mm256_or_si256(
            _mm256_slli_epi64(ya[17], 21), _mm256_srli_epi64(ya[17], 64 - 21));
        ya[15] = _mm256_or_si256(
            _mm256_slli_epi64(ya[15], 56), _mm256_srli_epi64(ya[15], 64 - 56));
        ya[24] = _mm256_or_si256(
            _mm256_slli_epi64(ya[24], 27), _mm256_srli_epi64(ya[24], 64 - 27));
        ya[22] = _mm256_or_si256(
            _mm256_slli_epi64(ya[22], 20), _mm256_srli_epi64(ya[22], 64 - 20));
        ya[20] = _mm256_or_si256(
            _mm256_slli_epi64(ya[20], 39), _mm256_srli_epi64(ya[20], 64 - 39));
        ya[23] = _mm256_or_si256(
            _mm256_slli_epi64(ya[23],  8), _mm256_srli_epi64(ya[23], 64 -  8));
        ya[21] = _mm256_or_si256(
            _mm256_slli_epi64(ya[21], 14), _mm256_srli_epi64(ya[21], 64 - 14));

        yCOMB2_1(&mut ya, 0, 9, 13, 17, 21);
        yCOMB2_2(&mut ya, 18, 22, 1, 5, 14);
        ya[23] = _mm256_xor_si256(ya[23], yones);
        yCOMB2_3(&mut ya, 6, 10, 19, 23, 2);
        ya[11] = _mm256_xor_si256(ya[11], yones);
        yCOMB2_4(&mut ya, 24, 3, 7, 11, 15);
        ya[16] = _mm256_xor_si256(ya[16], yones);
        yCOMB2_5(&mut ya, 12, 16, 20, 4, 8);

        ya[0] = _mm256_xor_si256(ya[0],
            _mm256_set1_epi64x(RC[(hj << 1) + 1] as i64));

        // Apply combined permutation for next round.

        let yt = ya[ 5];
        ya[ 5] = ya[18];
        ya[18] = ya[11];
        ya[11] = ya[10];
        ya[10] = ya[ 6];
        ya[ 6] = ya[22];
        ya[22] = ya[20];
        ya[20] = ya[12];
        ya[12] = ya[19];
        ya[19] = ya[15];
        ya[15] = ya[24];
        ya[24] = ya[ 8];
        ya[ 8] = yt;
        let yt = ya[ 1];
        ya[ 1] = ya[ 9];
        ya[ 9] = ya[14];
        ya[14] = ya[ 2];
        ya[ 2] = ya[13];
        ya[13] = ya[23];
        ya[23] = ya[ 4];
        ya[ 4] = ya[21];
        ya[21] = ya[16];
        ya[16] = ya[ 3];
        ya[ 3] = ya[17];
        ya[17] = ya[ 7];
        ya[ 7] = yt;
    }

    // Invert some words back to normal representation.
    ya[ 1] = _mm256_xor_si256(ya[ 1], yones);
    ya[ 2] = _mm256_xor_si256(ya[ 2], yones);
    ya[ 8] = _mm256_xor_si256(ya[ 8], yones);
    ya[12] = _mm256_xor_si256(ya[12], yones);
    ya[17] = _mm256_xor_si256(ya[17], yones);
    ya[20] = _mm256_xor_si256(ya[20], yones);

    // Write back state words.
    let d: *mut __m256i = core::mem::transmute(state.as_ptr());
    for i in 0..25 {
        _mm256_storeu_si256(d.wrapping_add(i), ya[i]);
    }
}
