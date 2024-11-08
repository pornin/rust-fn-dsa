#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//! # Computations modulo q = 12289 (with AVX2 optimizations)
//!
//! This module implements the same API as the [mq] module, but
//! leveraging AVX2 opcodes. As such, all functions are tagged "unsafe"
//! and the caller is responsible for checking that AVX2 is supported
//! in the current CPU before calling them.
//!
//! [mq]: ../mq/

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use core::mem::transmute;

/// Check whether the provided polynomial with small coefficient is
/// invertible modulo `X^n+1` and modulo q.
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_small_is_invertible(logn: u32,
    f: &[i8], tmp: &mut [u16]) -> bool
{
    let n = 1usize << logn;
    mqpoly_small_to_int(logn, f, tmp);
    mqpoly_int_to_NTT(logn, tmp);
    if logn >= 4 {
        let tp: *const __m256i = transmute(tmp.as_ptr());
        let mut yr = _mm256_set1_epi16(-1);
        let qq = _mm256_set1_epi16(Q as i16);
        for i in 0..(1usize << (logn - 4)) {
            let y = _mm256_loadu_si256(tp.wrapping_add(i));
            yr = _mm256_and_si256(yr, _mm256_sub_epi16(y, qq));
        }
        let r = _mm256_movemask_epi8(yr) as u32;
        return (r & 0xAAAAAAAA) == 0xAAAAAAAA;
    } else {
        let mut r = 0xFFFFFFFF;
        for i in 0..n {
            r &= (tmp[i] as u32).wrapping_sub(Q);
        }
        return (r >> 16) != 0;
    }
}

/// Compute `h = g/f mod X^n+1 mod q`.
///
/// This function assumes that `f` is invertible. Output is in external
/// representation (coefficients are in `[0,q-1]`).
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_div_small(logn: u32,
    f: &[i8], g: &[i8], h: &mut [u16], tmp: &mut [u16])
{
    let n = 1usize << logn;
    mqpoly_small_to_int(logn, f, tmp);
    mqpoly_small_to_int(logn, g, h);
    mqpoly_int_to_NTT(logn, tmp);
    mqpoly_int_to_NTT(logn, h);
    if logn >= 4 {
        let hp: *mut __m256i = transmute(h.as_mut_ptr());
        let tp: *const __m256i = transmute(tmp.as_ptr());
        for i in 0..(1usize << (logn - 4)) {
            let yh = _mm256_loadu_si256(hp.wrapping_add(i));
            let tp = _mm256_loadu_si256(tp.wrapping_add(i));
            let yh = mq_div_x16(yh, tp);
            _mm256_storeu_si256(hp.wrapping_add(i), yh);
        }
    } else {
        for i in 0..n {
            h[i] = mq_div(h[i] as u32, tmp[i] as u32) as u16;
        }
    }
    mqpoly_NTT_to_int(logn, h);
    mqpoly_int_to_ext(logn, h);
}

// Maximum squared norm for "small" vectors (floor(beta^2)).
// (re-exported from mq.rs)
pub use super::mq::SQBETA;

const Q: u32 = 12289;

// -1/q mod 2^32
const Q1I: u32 = 4143984639;

// 2^64 mod q
const R2: u32 = 5664;

/// Convert a polynomial with signed coefficients into a polynomial modulo q
/// (external representation).
///
/// The source values are assumed to be in the `[-q/2,+q/2]` range.
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_signed_to_ext(logn: u32, v: &[i16], d: &mut [u16]) {
    if logn >= 4 {
        let vp: *const __m256i = transmute(v.as_ptr());
        let dp: *mut __m256i = transmute(d.as_mut_ptr());
        let qq = _mm256_set1_epi16(Q as i16);
        for i in 0..(1usize << (logn - 4)) {
            let y = _mm256_loadu_si256(vp.wrapping_add(i));
            let y = _mm256_add_epi16(y,
                _mm256_and_si256(qq, _mm256_srai_epi16(y, 15)));
            _mm256_storeu_si256(dp.wrapping_add(i), y);
        }
    } else {
        for i in 0..(1usize << logn) {
            let x = (v[i] as i32) as u32;
            d[i] = x.wrapping_add((x >> 16) & Q) as u16;
        }
    }
}

// Addition modulo q (internal representation).
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_add(x: u32, y: u32) -> u32 {
    // a = q - (x + y)
    // -q <= a <= q - 2  (represented as u32)
    let a = Q.wrapping_sub(x + y);

    // If a < 0, add q.
    // b = -(x + y) mod q
    // 0 <= b <= q - 1
    let b = a.wrapping_add(Q & (a >> 16));

    // q - b = x + y mod q
    // 1 <= q - b <= q
    Q - b
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_add_x16(x: __m256i, y: __m256i) -> __m256i {
    let qq = _mm256_set1_epi16(Q as i16);
    let a = _mm256_sub_epi16(qq, _mm256_add_epi16(x, y));
    let b = _mm256_add_epi16(a,
        _mm256_and_si256(qq, _mm256_srai_epi16(a, 15)));
    _mm256_sub_epi16(qq, b)
}

// Subtraction modulo q (internal representation).
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_sub(x: u32, y: u32) -> u32 {
    // -(q - 1) <= a <= q - 1
    let a = y.wrapping_sub(x);
    // 0 <= b <= q - 1
    let b = a.wrapping_add(Q & (a >> 16));
    Q - b
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_sub_x16(x: __m256i, y: __m256i) -> __m256i {
    let qq = _mm256_set1_epi16(Q as i16);
    let a = _mm256_sub_epi16(y, x);
    let b = _mm256_add_epi16(a,
        _mm256_and_si256(qq, _mm256_srai_epi16(a, 15)));
    _mm256_sub_epi16(qq, b)
}

// Negation modulo q (internal representation).
#[allow(dead_code)]
#[inline]
unsafe fn mq_neg(x: u32) -> u32 {
    let a = Q - x;
    let b = a.wrapping_add(Q & (a >> 16));
    Q - b
}

#[target_feature(enable = "avx2")]
#[allow(dead_code)]
#[inline]
unsafe fn mq_neg_x16(x: __m256i) -> __m256i {
    let qq = _mm256_set1_epi16(Q as i16);
    let a = _mm256_sub_epi16(qq, x);
    let b = _mm256_add_epi16(a,
        _mm256_and_si256(qq, _mm256_srai_epi16(a, 15)));
    _mm256_sub_epi16(qq, b)
}

// Halving modulo q (internal representation).
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_half(x: u32) -> u32 {
    (x + ((x & 1).wrapping_neg() & Q)) >> 1
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_half_x16(x: __m256i) -> __m256i {
    let qq = _mm256_set1_epi16(Q as i16);
    let y = _mm256_and_si256(x, _mm256_set1_epi16(1));
    let y = _mm256_sub_epi16(_mm256_setzero_si256(), y);
    let y = _mm256_and_si256(y, qq);
    let y = _mm256_add_epi16(x, y);
    _mm256_srli_epi16(y, 1)
}

// mq_mred(x) computes x/2^32 mod q, without output in the [1,q] range.
// Input must be such that 1 <= x <= 3489673216. Note that this means
// that we can add up to 23 products together, and mutualize their
// reduction.
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_mred(x: u32) -> u32 {
    let b = x.wrapping_mul(Q1I);
    let c = (b >> 16) * Q;
    (c >> 16) + 1
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_mred_x16(lo: __m256i, hi: __m256i) -> __m256i {
    let qx16 = _mm256_set1_epi16(Q as i16);
    let q1ilox16 = _mm256_set1_epi16(Q1I as i16);
    let q1ihix16 = _mm256_set1_epi16((Q1I >> 16) as i16);

    // x <- (x * Q1I) >> 16
    // 32-bit input is split into its low and high halves. Q1I is
    // itself a 32-bit constant. Product is computed modulo 2^32,
    // and we are interested only in its high 16 bits.
    let x = _mm256_add_epi16(
        _mm256_add_epi16(
            _mm256_mulhi_epu16(lo, q1ilox16),
            _mm256_mullo_epi16(lo, q1ihix16)),
        _mm256_mullo_epi16(hi, q1ilox16));

    // x <- (x * Q) >> 16
    // x and Q both fit on 16 bits each.
    let x = _mm256_mulhi_epu16(x, qx16);

    // Result is x + 1.
    _mm256_add_epi16(x, _mm256_set1_epi16(1))
}

// Montgomery multiplication modulo q (internal representation).
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_mmul(x: u32, y: u32) -> u32 {
    mq_mred(x * y)
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn mq_mmul_x16(x: __m256i, y: __m256i) -> __m256i {
    mq_mred_x16(_mm256_mullo_epi16(x, y), _mm256_mulhi_epu16(x, y))
}

// Division modulo q (internal representation). If the divisor is zero
// (represented by q), then the result is zero.
#[target_feature(enable = "avx2")]
unsafe fn mq_div(x: u32, y: u32) -> u32 {
    // Convert y to Montgomery representation.
    let y = mq_mmul(y, R2);

    // 1/y = y^(q-2), with a custom addition chain.
    let y2 = mq_mmul(y, y);
    let y3 = mq_mmul(y2, y);
    let y5 = mq_mmul(y3, y2);
    let y10 = mq_mmul(y5, y5);
    let y20 = mq_mmul(y10, y10);
    let y40 = mq_mmul(y20, y20);
    let y80 = mq_mmul(y40, y40);
    let y160 = mq_mmul(y80, y80);
    let y163 = mq_mmul(y160, y3);
    let y323 = mq_mmul(y163, y160);
    let y646 = mq_mmul(y323, y323);
    let y1292 = mq_mmul(y646, y646);
    let y1455 = mq_mmul(y1292, y163);
    let y2910 = mq_mmul(y1455, y1455);
    let y5820 = mq_mmul(y2910, y2910);
    let y6143 = mq_mmul(y5820, y323);
    let y12286 = mq_mmul(y6143, y6143);
    let iy = mq_mmul(y12286, y);

    // Multiply by x to get x/y. 1/y is in Montgomery representation but
    // x is not, so the product is in normal (internal) representation.
    mq_mmul(x, iy)
}

#[target_feature(enable = "avx2")]
unsafe fn mq_div_x16(x: __m256i, y: __m256i) -> __m256i {
    // Convert y to Montgomery representation.
    let yr2 = _mm256_set1_epi16(R2 as i16);
    let y = mq_mmul_x16(y, yr2);

    // 1/y = y^(q-2), with a custom addition chain.
    let y2 = mq_mmul_x16(y, y);
    let y3 = mq_mmul_x16(y2, y);
    let y5 = mq_mmul_x16(y3, y2);
    let y10 = mq_mmul_x16(y5, y5);
    let y20 = mq_mmul_x16(y10, y10);
    let y40 = mq_mmul_x16(y20, y20);
    let y80 = mq_mmul_x16(y40, y40);
    let y160 = mq_mmul_x16(y80, y80);
    let y163 = mq_mmul_x16(y160, y3);
    let y323 = mq_mmul_x16(y163, y160);
    let y646 = mq_mmul_x16(y323, y323);
    let y1292 = mq_mmul_x16(y646, y646);
    let y1455 = mq_mmul_x16(y1292, y163);
    let y2910 = mq_mmul_x16(y1455, y1455);
    let y5820 = mq_mmul_x16(y2910, y2910);
    let y6143 = mq_mmul_x16(y5820, y323);
    let y12286 = mq_mmul_x16(y6143, y6143);
    let iy = mq_mmul_x16(y12286, y);

    // Multiply by x to get x/y. 1/y is in Montgomery representation but
    // x is not, so the product is in normal (internal) representation.
    mq_mmul_x16(x, iy)
}

/// Given a polynomial with small coefficients, convert it to internal
/// representation.
///
/// Converted polynomial is written into `d`.
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_small_to_int(logn: u32, f: &[i8], d: &mut [u16]) {
    if logn >= 4 {
        let fp: *const __m128i = transmute(f.as_ptr());
        let dp: *mut __m128i = transmute(d.as_mut_ptr());
        let qq = _mm_set1_epi16(Q as i16);
        for i in 0..(1usize << (logn - 4)) {
            let x = _mm_loadu_si128(fp.wrapping_add(i));
            let x = _mm_sub_epi8(_mm_setzero_si128(), x);
            let x0 = _mm_cvtepi8_epi16(x);
            let x1 = _mm_cvtepi8_epi16(_mm_bsrli_si128(x, 8));
            let x0 = _mm_add_epi16(x0,
                _mm_and_si128(_mm_srai_epi16(x0, 15), qq));
            let x1 = _mm_add_epi16(x1,
                _mm_and_si128(_mm_srai_epi16(x1, 15), qq));
            let x0 = _mm_sub_epi16(qq, x0);
            let x1 = _mm_sub_epi16(qq, x1);
            _mm_storeu_si128(dp.wrapping_add((i << 1) + 0), x0);
            _mm_storeu_si128(dp.wrapping_add((i << 1) + 1), x1);
        }
    } else {
        for i in 0..(1usize << logn) {
            let x = (-(f[i] as i32)) as u32;
            d[i] = (Q - x.wrapping_add((x >> 16) & Q)) as u16;
        }
    }
}

/// Given a polynomial in internal representation, convert it to small
/// coefficients.
///
/// Converted polynomial is written into `f`. If all coefficients, when
/// converted to minimal signed representation, are in `[-127,+127]`,
/// then the function succeeds and returns `true`. Otherwise, the
/// function fails and returns `false`; values obtained for out-of-range
/// coefficients are unspecified.
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_int_to_small(logn: u32, d: &[u16], f: &mut [i8]) -> bool {
    // Internal representation is in [1,q]. If the value is in the
    // correct range, then adding 128 will yield a value in the [1,255]
    // range; otherwise, we get a value in [256, q].
    if logn >= 4 {
        let dp: *const __m256i = transmute(d.as_ptr());
        let fp: *mut __m128i = transmute(f.as_mut_ptr());
        let y128 = _mm256_set1_epi16(128);
        let sm = _mm256_setr_epi8(
            0, 2, 4, 6, 8, 10, 12, 14, -1, -1, -1, -1, -1, -1, -1, -1,
            0, 2, 4, 6, 8, 10, 12, 14, -1, -1, -1, -1, -1, -1, -1, -1);
        let mut ov = _mm256_setzero_si256();
        for i in 0..(1usize << (logn - 4)) {
            let y = _mm256_loadu_si256(dp.wrapping_add(i));
            let y = mq_add_x16(y, y128);
            ov = _mm256_or_si256(ov, y);
            let y = _mm256_sub_epi16(y, y128);
            let y = _mm256_shuffle_epi8(y, sm);
            let y = _mm256_permute4x64_epi64(y, 0x88);
            _mm_storeu_si128(fp.wrapping_add(i), _mm256_castsi256_si128(y));
        }
        let ov = _mm256_movemask_epi8(ov) as u32;
        return (ov & 0xAAAAAAAA) == 0;
    } else {
        let mut ov = 0;
        for i in 0..(1usize << logn) {
            let x = mq_add(d[i] as u32, 128);
            ov |= x >> 8;
            f[i] = x.wrapping_sub(128) as i8;
        }
        return ov == 0;
    }
}

/// Given a polynomial in external representation, convert it to internal
/// representation (in-place).
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_ext_to_int(logn: u32, a: &mut [u16]) {
    // Internal representation is the same as external, except that
    // zero is represented by q instead of 0.
    if logn >= 4 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let qq = _mm256_set1_epi16(Q as i16);
        for i in 0..(1usize << (logn - 4)) {
            let y = _mm256_loadu_si256(ap.wrapping_add(i));
            let y = _mm256_add_epi16(
                y, _mm256_and_si256(qq,
                    _mm256_cmpeq_epi16(y, _mm256_setzero_si256())));
            _mm256_storeu_si256(ap.wrapping_add(i), y);
        }
    } else {
        for i in 0..(1usize << logn) {
            let x = a[i] as u32;
            a[i] = (x + (Q & (x.wrapping_sub(1) >> 16))) as u16;
        }
    }
}

/// Given a polynomial in internal representation, convert it to external
/// representation (in-place).
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_int_to_ext(logn: u32, a: &mut [u16]) {
    // External representation is the same as internal, except that
    // zero is represented by 0 instead of q.
    if logn >= 4 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let qq = _mm256_set1_epi16(Q as i16);
        for i in 0..(1usize << (logn - 4)) {
            let y = _mm256_loadu_si256(ap.wrapping_add(i));
            let y = _mm256_andnot_si256(_mm256_cmpeq_epi16(y, qq), y);
            _mm256_storeu_si256(ap.wrapping_add(i), y);
        }
    } else {
        for i in 0..(1usize << logn) {
            let x = (a[i] as u32).wrapping_sub(Q);
            a[i] = x.wrapping_add(Q & (x >> 16)) as u16;
        }
    }
}

#[target_feature(enable = "avx2")]
unsafe fn NTT32(ya0: __m256i, ya1: __m256i, k: usize) -> (__m256i, __m256i) {
    // t = 32, m = 1
    let yt1 = ya0;
    let yt2 = mq_mmul_x16(ya1, _mm256_set1_epi16(GM[k] as i16));
    let ya0 = mq_add_x16(yt1, yt2);
    let ya1 = mq_sub_x16(yt1, yt2);

    // ya0:  0  1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
    // ya1: 16 17 18 19 20 21 22 23 | 24 25 26 27 28 29 30 31

    // t = 16, m = 2
    let yt1 = _mm256_permute2x128_si256(ya0, ya1, 0x20);
    let yt2 = _mm256_permute2x128_si256(ya0, ya1, 0x31);
    let g1_0 = GM[(k << 1) + 0] as i16;
    let g1_1 = GM[(k << 1) + 1] as i16;
    let yg1 = _mm256_setr_epi16(
        g1_0, g1_0, g1_0, g1_0, g1_0, g1_0, g1_0, g1_0,
        g1_1, g1_1, g1_1, g1_1, g1_1, g1_1, g1_1, g1_1);
    let yt2 = mq_mmul_x16(yt2, yg1);
    let ya0 = mq_add_x16(yt1, yt2);
    let ya1 = mq_sub_x16(yt1, yt2);

    // ya0:  0  1  2  3  4  5  6  7 | 16 17 18 19 20 21 22 23
    // ya1:  8  9 10 11 12 13 14 15 | 24 25 26 27 28 29 30 31

    // t = 8, m = 4
    let yt1 = _mm256_unpacklo_epi64(ya0, ya1);
    let yt2 = _mm256_unpackhi_epi64(ya0, ya1);
    let yg2 = _mm256_setr_epi64x(
        GM[(k << 2) + 0] as i64, GM[(k << 2) + 1] as i64,
        GM[(k << 2) + 2] as i64, GM[(k << 2) + 3] as i64);
    let yg2 = _mm256_or_si256(yg2, _mm256_slli_epi64(yg2, 32));
    let yg2 = _mm256_or_si256(yg2, _mm256_slli_epi32(yg2, 16));
    let yt2 = mq_mmul_x16(yt2, yg2);
    let ya0 = mq_add_x16(yt1, yt2);
    let ya1 = mq_sub_x16(yt1, yt2);

    // ya0:  0  1  2  3  8  9 10 11 | 16 17 18 19 24 25 26 27
    // ya1:  4  5  6  7 12 13 14 15 | 20 21 22 23 28 29 30 31

    // t = 4, m = 8
    let yt3 = _mm256_shuffle_epi32(ya0, 0xD8);
    let yt4 = _mm256_shuffle_epi32(ya1, 0xD8);
    let yt1 = _mm256_unpacklo_epi32(yt3, yt4);
    let yt2 = _mm256_unpackhi_epi32(yt3, yt4);
    let gp: *const __m128i = transmute((&GM).as_ptr());
    let yg3 = _mm256_cvtepi16_epi32(_mm_loadu_si128(gp.wrapping_add(k)));
    let yg3 = _mm256_or_si256(yg3, _mm256_slli_epi32(yg3, 16));
    let yt2 = mq_mmul_x16(yt2, yg3);
    let ya0 = mq_add_x16(yt1, yt2);
    let ya1 = mq_sub_x16(yt1, yt2);

    // ya0:  0  1  4  5  8  9 12 13 | 16 17 20 21 24 25 28 29
    // ya1:  2  3  6  7 10 11 14 15 | 18 19 22 23 26 27 30 31

    // t = 2, m = 16
    let ysk = _mm256_setr_epi8(
        0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15,
        0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15);
    let yt3 = _mm256_shuffle_epi8(ya0, ysk);
    let yt4 = _mm256_shuffle_epi8(ya1, ysk);
    let yt1 = _mm256_unpacklo_epi16(yt3, yt4);
    let yt2 = _mm256_unpackhi_epi16(yt3, yt4);
    let gp: *const __m256i = transmute((&GM).as_ptr());
    let yt2 = mq_mmul_x16(yt2, _mm256_loadu_si256(gp.wrapping_add(k)));
    let ya0 = mq_add_x16(yt1, yt2);
    let ya1 = mq_sub_x16(yt1, yt2);

    // ya0:  0  2  4  6  8 10 12 14 | 16 18 20 22 24 26 28 30
    // ya1:  1  3  5  7  9 11 13 15 | 17 19 21 23 25 27 29 31
    let yt1 = _mm256_unpacklo_epi16(ya0, ya1);
    let yt2 = _mm256_unpackhi_epi16(ya0, ya1);
    let ya0 = _mm256_permute2x128_si256(yt1, yt2, 0x20);
    let ya1 = _mm256_permute2x128_si256(yt1, yt2, 0x31);
    (ya0, ya1)
}

/// Convert a polynomial from internal representation to NTT (in-place).
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_int_to_NTT(logn: u32, a: &mut [u16]) {
    if logn == 0 {
        return;
    }
    if logn >= 5 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let n = 1usize << logn;
        let mut t = n >> 4;
        for lm in 0..(logn - 5) {
            let m = 1usize << lm;
            let ht = t >> 1;
            let mut j0 = 0;
            for i in 0..m {
                let ys = _mm256_set1_epi16(GM[i + m] as i16);
                for j in 0..ht {
                    let j1 = j0 + j;
                    let j2 = j1 + ht;
                    let y1 = _mm256_loadu_si256(ap.wrapping_add(j1));
                    let y2 = _mm256_loadu_si256(ap.wrapping_add(j2));
                    let y2 = mq_mmul_x16(y2, ys);
                    _mm256_storeu_si256(ap.wrapping_add(j1),
                        mq_add_x16(y1, y2));
                    _mm256_storeu_si256(ap.wrapping_add(j2),
                        mq_sub_x16(y1, y2));
                }
                j0 += t;
            }
            t = ht;
        }
        let m = n >> 5;
        for i in 0..m {
            let ya0 = _mm256_loadu_si256(ap.wrapping_add((i << 1) + 0));
            let ya1 = _mm256_loadu_si256(ap.wrapping_add((i << 1) + 1));
            let (ya0, ya1) = NTT32(ya0, ya1, i + m);
            _mm256_storeu_si256(ap.wrapping_add((i << 1) + 0), ya0);
            _mm256_storeu_si256(ap.wrapping_add((i << 1) + 1), ya1);
        }
    } else {
        let mut t = 1usize << logn;
        for lm in 0..logn {
            let m = 1 << lm;
            let ht = t >> 1;
            let mut j0 = 0;
            for i in 0..m {
                let s = GM[i + m] as u32;
                for j in 0..ht {
                    let j1 = j0 + j;
                    let j2 = j1 + ht;
                    let x1 = a[j1] as u32;
                    let x2 = mq_mmul(a[j2] as u32, s);
                    a[j1] = mq_add(x1, x2) as u16;
                    a[j2] = mq_sub(x1, x2) as u16;
                }
                j0 += t;
            }
            t = ht;
        }
    }
}

#[target_feature(enable = "avx2")]
unsafe fn iNTT32(ya0: __m256i, ya1: __m256i, k: usize) -> (__m256i, __m256i) {
    // ya0:  0  1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
    // ya1: 16 17 18 19 20 21 22 23 | 24 25 26 27 28 29 30 31

    let yt1 = _mm256_permute2x128_si256(ya0, ya1, 0x20);
    let yt2 = _mm256_permute2x128_si256(ya0, ya1, 0x31);

    // yt1:  0  1  2  3  4  5  6  7 | 16 17 18 19 20 21 22 23
    // yt2:  8  9 10 11 12 13 14 15 | 24 25 26 27 28 29 30 31

    let ysk = _mm256_setr_epi8(
        0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15,
        0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15);
    let yt3 = _mm256_shuffle_epi8(yt1, ysk);
    let yt4 = _mm256_shuffle_epi8(yt2, ysk);

    // yt3:  0  2  4  6  1  3  5  7 | 16 18 20 22 17 19 21 23
    // yt4:  8 10 12 14  9 11 13 15 | 24 26 28 30 25 27 29 31

    let yt1 = _mm256_unpacklo_epi64(yt3, yt4);
    let yt2 = _mm256_unpackhi_epi64(yt3, yt4);
    let ya0 = mq_half_x16(mq_add_x16(yt1, yt2));
    let igp: *const __m256i = transmute((&iGM).as_ptr());
    let ya1 = mq_mmul_x16(mq_sub_x16(yt1, yt2),
            _mm256_loadu_si256(igp.wrapping_add(k)));

    // ya0:  0  2  4  6  8 10 12 14 | 16 18 20 22 24 26 28 30
    // ya1:  1  3  5  7  9 11 13 15 | 17 19 21 23 25 27 29 31

    let yt1 = _mm256_blend_epi16(ya0, _mm256_slli_epi32(ya1, 16), 0xAA);
    let yt2 = _mm256_blend_epi16(_mm256_srli_epi32(ya0, 16), ya1, 0xAA);
    let igp: *const __m128i = transmute((&iGM).as_ptr());
    let yig3 = _mm256_cvtepi16_epi32(_mm_loadu_si128(igp.wrapping_add(k)));
    let yig3 = _mm256_or_si256(yig3, _mm256_slli_epi32(yig3, 16));
    let ya0 = mq_half_x16(mq_add_x16(yt1, yt2));
    let ya1 = mq_mmul_x16(mq_sub_x16(yt1, yt2), yig3);

    // ya0:  0  1  4  5  8  9 12 13 | 16 17 20 21 24 25 28 29
    // ya1:  2  3  6  7 10 11 14 15 | 18 19 22 23 26 27 30 31

    let yt1 = _mm256_blend_epi16(ya0, _mm256_slli_epi64(ya1, 32), 0xCC);
    let yt2 = _mm256_blend_epi16(_mm256_srli_epi64(ya0, 32), ya1, 0xCC);
    let yig2 = _mm256_setr_epi64x(
        iGM[(k << 2) + 0] as i64, iGM[(k << 2) + 1] as i64,
        iGM[(k << 2) + 2] as i64, iGM[(k << 2) + 3] as i64);
    let yig2 = _mm256_or_si256(yig2, _mm256_slli_epi64(yig2, 32));
    let yig2 = _mm256_or_si256(yig2, _mm256_slli_epi32(yig2, 16));
    let ya0 = mq_half_x16(mq_add_x16(yt1, yt2));
    let ya1 = mq_mmul_x16(mq_sub_x16(yt1, yt2), yig2);

    // ya0:  0  1  2  3  8  9 10 11 | 16 17 18 19 24 25 26 27
    // ya1:  4  5  6  7 12 13 14 15 | 20 21 22 23 28 29 30 31

    let yt1 = _mm256_unpacklo_epi64(ya0, ya1);
    let yt2 = _mm256_unpackhi_epi64(ya0, ya1);
    let ig1_0 = iGM[(k << 1) + 0] as i16;
    let ig1_1 = iGM[(k << 1) + 1] as i16;
    let yig1 = _mm256_setr_epi16(
        ig1_0, ig1_0, ig1_0, ig1_0, ig1_0, ig1_0, ig1_0, ig1_0,
        ig1_1, ig1_1, ig1_1, ig1_1, ig1_1, ig1_1, ig1_1, ig1_1);
    let ya0 = mq_half_x16(mq_add_x16(yt1, yt2));
    let ya1 = mq_mmul_x16(mq_sub_x16(yt1, yt2), yig1);

    // ya0:  0  1  2  3  4  5  6  7 | 16 17 18 19 20 21 22 23
    // ya1:  8  9 10 11 12 13 14 15 | 24 25 26 27 28 29 30 31

    let yt1 = _mm256_permute2x128_si256(ya0, ya1, 0x20);
    let yt2 = _mm256_permute2x128_si256(ya0, ya1, 0x31);
    let yig0 = _mm256_set1_epi16(iGM[k] as i16);
    let ya0 = mq_half_x16(mq_add_x16(yt1, yt2));
    let ya1 = mq_mmul_x16(mq_sub_x16(yt1, yt2), yig0);

    // ya0:  0  1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
    // ya1: 16 17 18 19 20 21 22 23 | 24 25 26 27 28 29 30 31

    (ya0, ya1)
}

/// Convert a polynomial from NTT to internal representation (in-place).
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_NTT_to_int(logn: u32, a: &mut [u16]) {
    if logn == 0 {
        return;
    }
    if logn >= 5 {
        let ap: *mut __m256i = transmute(a.as_ptr());
        let n = 1usize << logn;
        let m = n >> 5;
        for i in 0..m {
            let ya0 = _mm256_loadu_si256(ap.wrapping_add((i << 1) + 0));
            let ya1 = _mm256_loadu_si256(ap.wrapping_add((i << 1) + 1));
            let (ya0, ya1) = iNTT32(ya0, ya1, i + m);
            _mm256_storeu_si256(ap.wrapping_add((i << 1) + 0), ya0);
            _mm256_storeu_si256(ap.wrapping_add((i << 1) + 1), ya1);
        }
        let mut t = 2;
        for lm in 5..logn {
            let hm = 1usize << (logn - 1 - lm);
            let dt = t << 1;
            let mut j0 = 0;
            for i in 0..hm {
                let ys = _mm256_set1_epi16(iGM[i + hm] as i16);
                for j in 0..t {
                    let j1 = j0 + j;
                    let j2 = j1 + t;
                    let y1 = _mm256_loadu_si256(ap.wrapping_add(j1));
                    let y2 = _mm256_loadu_si256(ap.wrapping_add(j2));
                    _mm256_storeu_si256(ap.wrapping_add(j1),
                        mq_half_x16(mq_add_x16(y1, y2)));
                    _mm256_storeu_si256(ap.wrapping_add(j2),
                        mq_mmul_x16(ys, mq_sub_x16(y1, y2)));
                }
                j0 += dt;
            }
            t = dt;
        }
    } else {
        let mut t = 1;
        for lm in 0..logn {
            let hm = 1 << (logn - 1 - lm);
            let dt = t << 1;
            let mut j0 = 0;
            for i in 0..hm {
                let s = iGM[i + hm] as u32;
                for j in 0..t {
                    let j1 = j0 + j;
                    let j2 = j1 + t;
                    let x1 = a[j1] as u32;
                    let x2 = a[j2] as u32;
                    a[j1] = mq_half(mq_add(x1, x2)) as u16;
                    a[j2] = mq_mmul(mq_sub(x1, x2), s) as u16;
                }
                j0 += dt;
            }
            t = dt;
        }
    }
}

/// Multiply polynomial `a` by polynomial `b`; both must be in NTT
/// representation.
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_mul_ntt(logn: u32, a: &mut [u16], b: &[u16]) {
    if logn >= 4 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let bp: *const __m256i = transmute(b.as_ptr());
        let yr2 = _mm256_set1_epi16(R2 as i16);
        for i in 0..(1usize << (logn - 4)) {
            let ya = _mm256_loadu_si256(ap.wrapping_add(i));
            let yb = _mm256_loadu_si256(bp.wrapping_add(i));
            let yc = mq_mmul_x16(mq_mmul_x16(ya, yb), yr2);
            _mm256_storeu_si256(ap.wrapping_add(i), yc);
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] = mq_mmul(mq_mmul(a[i] as u32, b[i] as u32), R2) as u16;
        }
    }
}

/// Divide polynomial `a` by polynomial `b`; both must be in NTT
/// representation.
///
/// If `b` is invertible (none of its NTT coefficients are zero), then
/// this returns `true`; otherwise, this returns false and the impacted
/// result coefficients are set to the internal representation of zero.
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_div_ntt(logn: u32, a: &mut [u16], b: &[u16]) -> bool {
    if logn >= 4 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let bp: *const __m256i = transmute(b.as_ptr());
        let qq = _mm256_set1_epi16(Q as i16);
        let mut ov = _mm256_set1_epi16(-1);
        for i in 0..(1usize << (logn - 4)) {
            let ya = _mm256_loadu_si256(ap.wrapping_add(i));
            let yb = _mm256_loadu_si256(bp.wrapping_add(i));
            let yc = mq_div_x16(ya, yb);
            _mm256_storeu_si256(ap.wrapping_add(i), yc);
            ov = _mm256_and_si256(ov, _mm256_sub_epi16(yb, qq));
        }
        let r = _mm256_movemask_epi8(ov) as u32;
        return (r & 0xAAAAAAAA) == 0xAAAAAAAA;
    } else {
        let mut r = 0xFFFFFFFF;
        for i in 0..(1usize << logn) {
            let x = b[i] as u32;
            r &= x.wrapping_sub(Q);
            a[i] = mq_div(a[i] as u32, x) as u16;
        }
        return (r >> 16) != 0;
    }
}

/// Subtract polynomial `b` from polynomial `a`; both must be in internal
/// representation, or both must be in NTT representation.
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_sub_int(logn: u32, a: &mut [u16], b: &[u16]) {
    if logn >= 4 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let bp: *const __m256i = transmute(b.as_ptr());
        for i in 0..(1usize << (logn - 4)) {
            let ya = _mm256_loadu_si256(ap.wrapping_add(i));
            let yb = _mm256_loadu_si256(bp.wrapping_add(i));
            let yc = mq_sub_x16(ya, yb);
            _mm256_storeu_si256(ap.wrapping_add(i), yc);
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] = mq_sub(a[i] as u32, b[i] as u32) as u16;
        }
    }
}

/// Get the squared norm of a polynomial modulo q (assuming normalization
/// of coefficients in `[-q/2,+q/2]`).
///
/// The polynomial must be in external representation. If the squared norm
/// exceeds `2^31-1` then `2^32-1` is returned.
#[target_feature(enable = "avx2")]
pub unsafe fn mqpoly_sqnorm(logn: u32, a: &[u16]) -> u32 {
    if logn >= 4 {
        let ap: *const __m256i = transmute(a.as_ptr());
        let mut ys = _mm256_setzero_si256();
        let mut ysat = _mm256_setzero_si256();
        let qq = _mm256_set1_epi16(Q as i16);
        let hq = _mm256_set1_epi16(((Q - 1) >> 1) as i16);
        for i in 0..(1usize << (logn - 4)) {
            let y = _mm256_loadu_si256(ap.wrapping_add(i));

            // Normalize to [-q/2,+q/2].
            let ym = _mm256_cmpgt_epi16(y, hq);
            let y = _mm256_sub_epi16(y, _mm256_and_si256(ym, qq));

            // Compute and add coefficient squares.
            let ylo = _mm256_mullo_epi16(y, y);
            let yhi = _mm256_mulhi_epi16(y, y);
            let y0 = _mm256_blend_epi16(ylo, _mm256_bslli_epi128(yhi, 2), 0xAA);
            let y1 = _mm256_blend_epi16(_mm256_bsrli_epi128(ylo, 2), yhi, 0xAA);
            ys = _mm256_add_epi32(ys, _mm256_add_epi32(y0, y1));

            // Since normalized values are at most floor(q/2) = 6144, the
            // addition above added at most 2*6144^2 = 75497472, which is
            // lower than 2^31. If an overflow occurs at some point, then
            // the corresponding slot in ys must first go through a value
            // with its high bit set.
            ysat = _mm256_or_si256(ysat, ys);
        }

        // Finish the addition.
        // Saturate to 2^32-1 if any of the overflow bits was set.
        ys = _mm256_add_epi32(ys, _mm256_srli_epi64(ys, 32));
        ysat = _mm256_or_si256(ysat, ys);
        ys = _mm256_add_epi32(ys, _mm256_bsrli_epi128(ys, 8));
        ysat = _mm256_or_si256(ysat, ys);
        let xs = _mm_add_epi32(
            _mm256_castsi256_si128(ys),
            _mm256_extracti128_si256(ys, 1));
        let r = _mm_cvtsi128_si32(xs) as u32;
        let sat = ((_mm256_movemask_epi8(ysat) as u32) & 0x88888888)
            | (r & 0x80000000);
        return r | ((((sat | sat.wrapping_neg()) as i32) >> 31) as u32);
    } else {
        let mut s = 0u32;
        let mut sat = 0;
        for i in 0..(1usize << logn) {
            let x = a[i] as u32;
            let m = ((Q - 1) >> 1).wrapping_sub(x) >> 16;
            let y = x.wrapping_sub(m & Q) as i32;
            s = s.wrapping_add((y * y) as u32);
            sat |= s;
        }
        return s | (sat >> 31).wrapping_neg();
    }
}

/// Get the square norm of a polynomial with signed integer coefficients.
///
/// This function assumes that the squared norm fits on 32 bits (this is
/// guaranteed if `logn <= 10` and all coefficients are in `[-2047,+2047]`).
#[target_feature(enable = "avx2")]
pub unsafe fn signed_poly_sqnorm(logn: u32, a: &[i16]) -> u32 {
    if logn >= 4 {
        let ap: *const __m256i = transmute(a.as_ptr());
        let mut ys = _mm256_setzero_si256();
        for i in 0..(1usize << (logn - 4)) {
            let y = _mm256_loadu_si256(ap.wrapping_add(i));
            let ylo = _mm256_mullo_epi16(y, y);
            let yhi = _mm256_mulhi_epi16(y, y);
            let y0 = _mm256_blend_epi16(ylo, _mm256_bslli_epi128(yhi, 2), 0xAA);
            let y1 = _mm256_blend_epi16(_mm256_bsrli_epi128(ylo, 2), yhi, 0xAA);
            ys = _mm256_add_epi32(ys, _mm256_add_epi32(y0, y1));
        }
        ys = _mm256_add_epi32(ys, _mm256_srli_epi64(ys, 32));
        ys = _mm256_add_epi32(ys, _mm256_bsrli_epi128(ys, 8));
        let xs = _mm_add_epi32(
            _mm256_castsi256_si128(ys),
            _mm256_extracti128_si256(ys, 1));
        return _mm_cvtsi128_si32(xs) as u32;
    } else {
        let mut s = 0;
        for i in 0..(1usize << logn) {
            let x = a[i] as i32;
            s += (x * x) as u32;
        }
        return s;
    }
}

// NTT factors: already defined in mq.rs.
use super::mq::{GM, iGM};

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn qadd(a: u32, b: u32) -> u32 {
        let c = a + b;
        if c >= 12289 { c - 12289 } else { c }
    }

    #[inline]
    fn qsub(a: u32, b: u32) -> u32 {
        if a >= b { a - b } else { (a + 12289) - b }
    }

    #[inline]
    fn qmul(a: u32, b: u32) -> u32 {
        (a * b) % 12289
    }

    unsafe fn inner_NTT(logn: u32, seed: u32) {
        let mut tmp = [0u16; 5 * 1024];
        let n = 1 << logn;
        let (t1, tx) = tmp.split_at_mut(n);
        let (t2, tx) = tx.split_at_mut(n);
        let (w3, tx) = tx.split_at_mut(2 * n);
        let (t5, _) = tx.split_at_mut(n);

        // Generate random polynomials in t1 and t2.
        let mut sh = crate::shake::SHAKE256::new();
        for i in 0..n {
            sh.reset();
            sh.inject(&seed.to_le_bytes());
            sh.inject(&(i as u16).to_le_bytes());
            sh.flip();
            let mut hv = [0u8; 16];
            sh.extract(&mut hv);
            t1[i] = (u64::from_le_bytes(*<&[u8; 8]>::try_from(&hv[0..8]).unwrap()) % 12289) as u16;
            t2[i] = (u64::from_le_bytes(*<&[u8; 8]>::try_from(&hv[8..16]).unwrap()) % 12289) as u16;
        }

        // Compute the product t1*t2 into w3 "manually", then reduce it
        // modulo X^n+1.
        for i in 0..(2 * n) {
            w3[i] = 0;
        }
        for i in 0..n {
            for j in 0..n {
                let z = qmul(t1[i] as u32, t2[j] as u32);
                let z = qadd(z, w3[i + j] as u32);
                w3[i + j] = z as u16;
            }
        }
        for i in 0..n {
            let x = w3[i] as u32;
            let y = w3[i + n] as u32;
            t5[i] = qsub(x, y) as u16;
        }

        // Convert t1 and t2 to the NTT domain, do the multiplication
        // in that domain, then convert back. This should yield the same
        // result as the "manual" process.
        mqpoly_ext_to_int(logn, t1);
        mqpoly_ext_to_int(logn, t2);
        mqpoly_int_to_NTT(logn, t1);
        mqpoly_int_to_NTT(logn, t2);
        for i in 0..n {
            t1[i] = mq_mmul(mq_mmul(t1[i] as u32, t2[i] as u32), R2) as u16;
        }
        mqpoly_NTT_to_int(logn, t1);
        mqpoly_int_to_ext(logn, t1);
        assert!(t1 == t5);
    }

    #[test]
    fn NTT() {
        if crate::has_avx2() {
            unsafe {
                for logn in 1..11 {
                    for j in 0..10 {
                        inner_NTT(logn, j);
                    }
                }
            }
        }
    }

    #[test]
    fn div() {
        if crate::has_avx2() {
            unsafe {
                for x in 1..10 {
                    for y in 1..12289 {
                        let z = mq_div(x, y);
                        assert!((y * z) % 12289 == x);
                    }
                    assert!(mq_div(x, 12289) == 12289);
                }

                #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                if crate::has_avx2() {
                    for x in 1..10 {
                        for y in 1..12289 {
                            let zz = mq_div_x16(
                                _mm256_set1_epi16(x), _mm256_set1_epi16(y));
                            let zb: [i16; 16] = core::mem::transmute(zz);
                            let r = mq_div(x as u32, y as u32) as i16;
                            assert!(zb == [r; 16]);
                        }

                        let zz = mq_div_x16(
                            _mm256_set1_epi16(x), _mm256_set1_epi16(12289));
                        let zb: [i16; 16] = core::mem::transmute(zz);
                        assert!(zb == [12289i16; 16]);
                    }
                }
            }
        }
    }

    #[test]
    fn sqnorm_sat() {
        if crate::has_avx2() {
            unsafe {
                // We generate random vectors with signed coefficients.
                // We choose integers randomly in [0, 5039]; for a degree 256,
                // this ensures that the squared norm will be above 2^31 about
                // half of the time. The signs are also randomized.
                let mut a = [0u16; 256];
                let mut sh = crate::shake::SHAKE256::new();
                sh.inject(&b"sqnorm_sat"[..]);
                sh.flip();
                for _ in 0..100 {
                    let mut rs = 0;
                    for i in 0..256 {
                        // x <- absolute value of next coefficient.
                        let mut buf = [0u8; 4];
                        sh.extract(&mut buf);
                        let x = u32::from_le_bytes(buf) % 5040;
                        rs += (x * x) as u64;

                        // v <- x with random sign and normalized in [1,q].
                        let v = if buf[3] >= 0x80 {
                            Q - x
                        } else if x == 0 {
                            Q
                        } else {
                            x
                        };

                        a[i] = v as u16;
                    }
                    let s = mqpoly_sqnorm(8, &a);
                    if rs > 0x7FFFFFFF {
                        assert!(s == 0xFFFFFFFF);
                    } else {
                        assert!(s == (rs as u32));
                    }
                }
            }
        }
    }
}
