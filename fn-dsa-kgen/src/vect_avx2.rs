#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use super::fxp::{FXR, FXC, GM_TAB};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use core::mem::transmute;

// ======================================================================== 
// Fixed-point vector operations (with AVX2 optimizations)
// ======================================================================== 

// ------------------------------------------------------------------------
// Parallel operations on FXR values (x4).

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn fxr_mul_x4(ya: __m256i, yb: __m256i) -> __m256i {
    let ya_hi = _mm256_srli_epi64(ya, 32);
    let yb_hi = _mm256_srli_epi64(yb, 32);
    let y1 = _mm256_mul_epu32(ya, yb);
    let y2 = _mm256_mul_epu32(ya, yb_hi);
    let y3 = _mm256_mul_epu32(ya_hi, yb);
    let y4 = _mm256_mul_epu32(ya_hi, yb_hi);
    let y1 = _mm256_srli_epi64(y1, 32);
    let y4 = _mm256_slli_epi64(y4, 32);
    let y5 = _mm256_add_epi64(
        _mm256_add_epi64(y1, y2),
        _mm256_add_epi64(y3, y4));
    let yna = _mm256_srai_epi32(ya, 31);
    let ynb = _mm256_srai_epi32(yb, 31);
    _mm256_sub_epi64(y5, _mm256_add_epi64(
        _mm256_and_si256(_mm256_slli_epi64(yb, 32), yna),
        _mm256_and_si256(_mm256_slli_epi64(ya, 32), ynb)))
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn fxr_sqr_x4(ya: __m256i) -> __m256i {
    let ya_hi = _mm256_srli_epi64(ya, 32);
    let y1 = _mm256_mul_epu32(ya, ya);
    let y2 = _mm256_mul_epu32(ya, ya_hi);
    let y3 = _mm256_mul_epu32(ya_hi, ya_hi);
    let y1 = _mm256_srli_epi64(y1, 32);
    let y2 = _mm256_add_epi64(y2, y2);
    let y3 = _mm256_slli_epi64(y3, 32);
    let y4 = _mm256_add_epi64(_mm256_add_epi64(y1, y2), y3);
    _mm256_sub_epi64(y4,
        _mm256_and_si256(_mm256_slli_epi64(ya, 33),
        _mm256_srai_epi32(ya, 31)))
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn fxr_half_x4(ya: __m256i) -> __m256i {
    let y1 = _mm256_set1_epi64x(1);
    let yh = _mm256_set1_epi64x((1u64 << 63) as i64);
    let ya = _mm256_add_epi64(ya, y1);
    _mm256_or_si256(
        _mm256_srli_epi64(ya, 1),
        _mm256_and_si256(ya, yh))
}

#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn fxr_div_x4(yn: __m256i, yd: __m256i) -> __m256i {
    // Get absolute values and signs. From now on, we can suppose
    // that n and d fit on 63 bits (we ignore edge conditions).
    let ysn = _mm256_sub_epi64(_mm256_setzero_si256(),
        _mm256_srli_epi64(yn, 63));
    let ysd = _mm256_sub_epi64(_mm256_setzero_si256(),
        _mm256_srli_epi64(yd, 63));
    let mut yn = _mm256_sub_epi64(_mm256_xor_si256(yn, ysn), ysn);
    let yd = _mm256_sub_epi64(_mm256_xor_si256(yd, ysd), ysd);

    // Do a bit by bit division, assuming that the quotient fits.
    // The numerator starts at n*2^31, and is shifted one bit a time.
    let mut yq = _mm256_setzero_si256();
    let mut ynum = _mm256_srli_epi64(yn, 31);
    let y1 = _mm256_set1_epi64x(1);
    // bits 63 to 33
    for _ in 33..64 {
        let yb = _mm256_srli_epi64(_mm256_sub_epi64(ynum, yd), 63);
        let yc = _mm256_sub_epi64(yb, y1);
        yq = _mm256_add_epi64(yq, yq);
        yq = _mm256_sub_epi64(yq, yc);
        ynum = _mm256_sub_epi64(ynum, _mm256_and_si256(yc, yd));
        ynum = _mm256_add_epi64(ynum, ynum);
        ynum = _mm256_or_si256(ynum,
            _mm256_and_si256(_mm256_srli_epi64(yn, 30), y1));
        yn = _mm256_add_epi64(yn, yn);
    }
    // bits 32 to 0
    for _ in 0..33 {
        let yb = _mm256_srli_epi64(_mm256_sub_epi64(ynum, yd), 63);
        let yc = _mm256_sub_epi64(yb, y1);
        yq = _mm256_add_epi64(yq, yq);
        yq = _mm256_sub_epi64(yq, yc);
        ynum = _mm256_sub_epi64(ynum, _mm256_and_si256(yc, yd));
        ynum = _mm256_add_epi64(ynum, ynum);
    }

    // Rounding: if the remainder is at least d/2 (scaled), we add
    // 2^(-32) to the quotient.
    let yb0 = _mm256_srli_epi64(_mm256_sub_epi64(ynum, yd), 63);
    yq = _mm256_add_epi64(_mm256_xor_si256(y1, yb0), yq);

    // Sign management: if the original yn and yd had different signs,
    // then we must negate the quotient.
    let ysn = _mm256_xor_si256(ysn, ysd);
    yq = _mm256_sub_epi64(_mm256_xor_si256(yq, ysn), ysn);

    yq
}

// ------------------------------------------------------------------------
// Parallel operations on FXC values (x4).

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn fxc_mul_x4(ya_re: __m256i, ya_im: __m256i,
    yb_re: __m256i, yb_im: __m256i) -> (__m256i, __m256i)
{
    let y0 = fxr_mul_x4(ya_re, yb_re);
    let y1 = fxr_mul_x4(ya_im, yb_im);
    let y2 = fxr_mul_x4(
        _mm256_add_epi64(ya_re, ya_im),
        _mm256_add_epi64(yb_re, yb_im));
    let yd_re = _mm256_sub_epi64(y0, y1);
    let yd_im = _mm256_sub_epi64(y2, _mm256_add_epi64(y0, y1));
    (yd_re, yd_im)
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn FFT4(yv0_re: __m256i, yv1_re: __m256i,
    yv0_im: __m256i, yv1_im: __m256i, k: usize)
    -> (__m256i, __m256i, __m256i, __m256i)
{
    // yv0: 0:1:2:3
    // yv1: 4:5:6:7
    // combine 0/2 and 1/3 with gm[k+0]
    // combine 4/6 and 5/7 with gm[k+1]

    // yt0 <- 0:1:4:5
    // yt1 <- 2:3:6:7
    let yt0_re = _mm256_permute2x128_si256(yv0_re, yv1_re, 0x20);
    let yt0_im = _mm256_permute2x128_si256(yv0_im, yv1_im, 0x20);
    let yt1_re = _mm256_permute2x128_si256(yv0_re, yv1_re, 0x31);
    let yt1_im = _mm256_permute2x128_si256(yv0_im, yv1_im, 0x31);

    // yg0 <- gm0:gm0:gm1:gm1
    let gp: *const __m256i = transmute((&GM_TAB).as_ptr());
    let yg0 = _mm256_loadu_si256(gp.wrapping_add(k >> 1));
    let yg0_re = _mm256_shuffle_epi32(yg0, 0x44);
    let yg0_im = _mm256_shuffle_epi32(yg0, 0xEE);

    let (yt1_re, yt1_im) = fxc_mul_x4(yt1_re, yt1_im, yg0_re, yg0_im);

    let yv0_re = _mm256_add_epi64(yt0_re, yt1_re);
    let yv0_im = _mm256_add_epi64(yt0_im, yt1_im);
    let yv1_re = _mm256_sub_epi64(yt0_re, yt1_re);
    let yv1_im = _mm256_sub_epi64(yt0_im, yt1_im);

    // v0: 0:1:4:5
    // v1: 2:3:6:7
    // combine 0/1 with gm[2*k+0], 2/3 with gm[2*k+1]
    // combine 4/5 with gm[2*k+2], 6/7 with gm[2*k+3]

    // yt0 <- 0:2:4:6
    // yt1 <- 1:3:5:7
    let yt0_re = _mm256_unpacklo_epi64(yv0_re, yv1_re);
    let yt0_im = _mm256_unpacklo_epi64(yv0_im, yv1_im);
    let yt1_re = _mm256_unpackhi_epi64(yv0_re, yv1_re);
    let yt1_im = _mm256_unpackhi_epi64(yv0_im, yv1_im);

    // yg1 <- gm4:gm5:gm6:gm7
    let yg1_re = _mm256_setr_epi64x(
        GM_TAB[(k << 1) + 0].re.0 as i64,
        GM_TAB[(k << 1) + 1].re.0 as i64,
        GM_TAB[(k << 1) + 2].re.0 as i64,
        GM_TAB[(k << 1) + 3].re.0 as i64);
    let yg1_im = _mm256_setr_epi64x(
        GM_TAB[(k << 1) + 0].im.0 as i64,
        GM_TAB[(k << 1) + 1].im.0 as i64,
        GM_TAB[(k << 1) + 2].im.0 as i64,
        GM_TAB[(k << 1) + 3].im.0 as i64);

    let (yt1_re, yt1_im) = fxc_mul_x4(yt1_re, yt1_im, yg1_re, yg1_im);

    let yv0_re = _mm256_add_epi64(yt0_re, yt1_re);
    let yv0_im = _mm256_add_epi64(yt0_im, yt1_im);
    let yv1_re = _mm256_sub_epi64(yt0_re, yt1_re);
    let yv1_im = _mm256_sub_epi64(yt0_im, yt1_im);

    // Reorder into 0:1:2:3 and 4:5:6:7
    let yt0_re = _mm256_unpacklo_epi64(yv0_re, yv1_re);
    let yt0_im = _mm256_unpacklo_epi64(yv0_im, yv1_im);
    let yt1_re = _mm256_unpackhi_epi64(yv0_re, yv1_re);
    let yt1_im = _mm256_unpackhi_epi64(yv0_im, yv1_im);
    let yv0_re = _mm256_permute2x128_si256(yt0_re, yt1_re, 0x20);
    let yv0_im = _mm256_permute2x128_si256(yt0_im, yt1_im, 0x20);
    let yv1_re = _mm256_permute2x128_si256(yt0_re, yt1_re, 0x31);
    let yv1_im = _mm256_permute2x128_si256(yt0_im, yt1_im, 0x31);

    (yv0_re, yv1_re, yv0_im, yv1_im)
}

// Convert a (real) vector to its FFT representation.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_FFT(logn: u32, f: &mut [FXR]) {
    if logn >= 4 {
        let fp: *mut __m256i = transmute(f.as_mut_ptr());
        let hn = 1usize << (logn - 3);
        let mut t = hn;
        for lm in 1..(logn - 2) {
            let m = 1usize << lm;
            let ht = t >> 1;
            let mut j0 = 0;
            let hm = m >> 1;
            for i in 0..hm {
                let s = GM_TAB[m + i];
                let ys_re = _mm256_set1_epi64x(s.re.0 as i64);
                let ys_im = _mm256_set1_epi64x(s.im.0 as i64);
                for j in 0..ht {
                    let j1_re = j0 + j;
                    let j1_im = j0 + j + hn;
                    let j2_re = j0 + j + ht;
                    let j2_im = j0 + j + ht + hn;
                    let ya_re = _mm256_loadu_si256(fp.wrapping_add(j1_re));
                    let ya_im = _mm256_loadu_si256(fp.wrapping_add(j1_im));
                    let yb_re = _mm256_loadu_si256(fp.wrapping_add(j2_re));
                    let yb_im = _mm256_loadu_si256(fp.wrapping_add(j2_im));
                    let (yb_re, yb_im) = fxc_mul_x4(yb_re, yb_im, ys_re, ys_im);
                    let yc_re = _mm256_add_epi64(ya_re, yb_re);
                    let yc_im = _mm256_add_epi64(ya_im, yb_im);
                    let yd_re = _mm256_sub_epi64(ya_re, yb_re);
                    let yd_im = _mm256_sub_epi64(ya_im, yb_im);
                    _mm256_storeu_si256(fp.wrapping_add(j1_re), yc_re);
                    _mm256_storeu_si256(fp.wrapping_add(j1_im), yc_im);
                    _mm256_storeu_si256(fp.wrapping_add(j2_re), yd_re);
                    _mm256_storeu_si256(fp.wrapping_add(j2_im), yd_im);
                }
                j0 += t;
            }
            t = ht;
        }

        let m = hn << 1;
        let hm = m >> 1;
        for i in 0..(hm >> 1) {
            let j0_re = (i << 1) + 0;
            let j1_re = (i << 1) + 1;
            let j0_im = (i << 1) + 0 + hn;
            let j1_im = (i << 1) + 1 + hn;
            let ya0_re = _mm256_loadu_si256(fp.wrapping_add(j0_re));
            let ya1_re = _mm256_loadu_si256(fp.wrapping_add(j1_re));
            let ya0_im = _mm256_loadu_si256(fp.wrapping_add(j0_im));
            let ya1_im = _mm256_loadu_si256(fp.wrapping_add(j1_im));
            let (ya0_re, ya1_re, ya0_im, ya1_im) =
                FFT4(ya0_re, ya1_re, ya0_im, ya1_im, m + (i << 1));
            _mm256_storeu_si256(fp.wrapping_add(j0_re), ya0_re);
            _mm256_storeu_si256(fp.wrapping_add(j1_re), ya1_re);
            _mm256_storeu_si256(fp.wrapping_add(j0_im), ya0_im);
            _mm256_storeu_si256(fp.wrapping_add(j1_im), ya1_im);
        }
    } else {
        let hn = 1usize << (logn - 1);
        let mut t = hn;
        for lm in 1..logn {
            let m = 1usize << lm;
            let ht = t >> 1;
            let mut j0 = 0;
            for i in 0..(m >> 1) {
                let s = GM_TAB[m + i];
                for j in j0..(j0 + ht) {
                    let x = FXC { re: f[j], im: f[j + hn] };
                    let y = FXC { re: f[j + ht], im: f[j + ht + hn] };
                    let z = s * y;
                    let w1 = x + z;
                    f[j] = w1.re;
                    f[j + hn] = w1.im;
                    let w2 = x - z;
                    f[j + ht] = w2.re;
                    f[j + ht + hn] = w2.im;
                }
                j0 += t;
            }
            t = ht;
        }
    }
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn iFFT4(yv0_re: __m256i, yv1_re: __m256i,
    yv0_im: __m256i, yv1_im: __m256i, k: usize)
    -> (__m256i, __m256i, __m256i, __m256i)
{
    // v0: 0:1:2:3
    // v1: 4:5:6:7
    // combine 0/1 with gm[2*k+0], 2/3 with gm[2*k+1]
    // combine 4/5 with gm[2*k+2], 6/7 with gm[2*k+3]

    // yt0 <- 0:4:2:6
    // yt1 <- 1:5:3:7
    let yt0_re = _mm256_unpacklo_epi64(yv0_re, yv1_re);
    let yt0_im = _mm256_unpacklo_epi64(yv0_im, yv1_im);
    let yt1_re = _mm256_unpackhi_epi64(yv0_re, yv1_re);
    let yt1_im = _mm256_unpackhi_epi64(yv0_im, yv1_im);

    // yg1 <- gm4:gm6:gm5:gm7
    let yg1_re = _mm256_setr_epi64x(
        GM_TAB[(k << 1) + 0].re.0 as i64,
        GM_TAB[(k << 1) + 2].re.0 as i64,
        GM_TAB[(k << 1) + 1].re.0 as i64,
        GM_TAB[(k << 1) + 3].re.0 as i64);
    let yg1_im = _mm256_setr_epi64x(
        GM_TAB[(k << 1) + 0].im.0 as i64,
        GM_TAB[(k << 1) + 2].im.0 as i64,
        GM_TAB[(k << 1) + 1].im.0 as i64,
        GM_TAB[(k << 1) + 3].im.0 as i64);
    let yg1_im = _mm256_sub_epi64(_mm256_setzero_si256(), yg1_im);

    let yv0_re = fxr_half_x4(_mm256_add_epi64(yt0_re, yt1_re));
    let yv0_im = fxr_half_x4(_mm256_add_epi64(yt0_im, yt1_im));
    let yv1_re = fxr_half_x4(_mm256_sub_epi64(yt0_re, yt1_re));
    let yv1_im = fxr_half_x4(_mm256_sub_epi64(yt0_im, yt1_im));
    let (yv1_re, yv1_im) = fxc_mul_x4(yv1_re, yv1_im, yg1_re, yg1_im);

    // v0: 0:4:2:6
    // v1: 1:5:3:7
    // combine 0/2 and 1/3 with gm[k+0]
    // combine 4/6 and 5/7 with gm[k+1]

    // yt0 <- 0:4:1:5
    // yt1 <- 2:6:3:7
    let yt0_re = _mm256_permute2x128_si256(yv0_re, yv1_re, 0x20);
    let yt0_im = _mm256_permute2x128_si256(yv0_im, yv1_im, 0x20);
    let yt1_re = _mm256_permute2x128_si256(yv0_re, yv1_re, 0x31);
    let yt1_im = _mm256_permute2x128_si256(yv0_im, yv1_im, 0x31);

    // yg0 <- gm0:gm1:gm0:gm1
    let gp: *const __m256i = transmute((&GM_TAB).as_ptr());
    let yg0 = _mm256_loadu_si256(gp.wrapping_add(k >> 1));
    let yg0_re = _mm256_permute4x64_epi64(yg0, 0x88);
    let yg0_im = _mm256_permute4x64_epi64(yg0, 0xDD);
    let yg0_im = _mm256_sub_epi64(_mm256_setzero_si256(), yg0_im);

    let yv0_re = fxr_half_x4(_mm256_add_epi64(yt0_re, yt1_re));
    let yv0_im = fxr_half_x4(_mm256_add_epi64(yt0_im, yt1_im));
    let yv1_re = fxr_half_x4(_mm256_sub_epi64(yt0_re, yt1_re));
    let yv1_im = fxr_half_x4(_mm256_sub_epi64(yt0_im, yt1_im));
    let (yv1_re, yv1_im) = fxc_mul_x4(yv1_re, yv1_im, yg0_re, yg0_im);

    // Reorder into 0:1:2:3 and 4:5:6:7
    let yt0_re = _mm256_unpacklo_epi64(yv0_re, yv1_re);
    let yt0_im = _mm256_unpacklo_epi64(yv0_im, yv1_im);
    let yt1_re = _mm256_unpackhi_epi64(yv0_re, yv1_re);
    let yt1_im = _mm256_unpackhi_epi64(yv0_im, yv1_im);
    let yv0_re = _mm256_permute4x64_epi64(yt0_re, 0xD8);
    let yv0_im = _mm256_permute4x64_epi64(yt0_im, 0xD8);
    let yv1_re = _mm256_permute4x64_epi64(yt1_re, 0xD8);
    let yv1_im = _mm256_permute4x64_epi64(yt1_im, 0xD8);

    (yv0_re, yv1_re, yv0_im, yv1_im)
}

// Convert back from FFT representation into a real vector.
//
// Note: in the final outer iteration:
//
//  - f[j] and f[j+hn] are set to the half of a complex number. Fixed point
//    values are held in integers in the [-2^63..+2^63-1] range (in signed
//    interpretation) and halving is done by adding 1 and then an
//    arithmetic right shift, thus with an output necessarily in the
//    [-2^62..+2^62-1] range (addition of 1 to 2^63-1 "wraps around" in that
//    +2^63 is interpreted as -2^63 instead).
//
//  - f[j+ht] and f[j+ht+hn] are set to the product of the half of a
//    complex number, and the complex sqrt(2)-i*sqrt(2). Value sqrt(2)
//    is represented by the fixed point 3037000500. Following the steps
//    in fxc_mul():
//       r1, i1:           -2^62 .. +2^62-1
//       r2:               +3037000500
//       i2:               -3037000500
//       t0:               -3260954456358912000 .. +3260954456358911999
//       t1:               -3260954456358912000 .. +3260954456358912000
//       fxr_add(r1, i1):  -2^63 .. +2^63-2
//       fxr_add(r2, i2):  always zero
//       t2:               always zero
//       fxr_sub(t0, t1):  -6521908912717824000 .. +6521908912717823999
//       fxr_add(t0, t1):  -6521908912717824000 .. +6521908912717823999
//    Thus, the obtained output values must be in the
//    [-6521908912717824000..+6521908912717824000] range.
//
// If the output of vect_iFFT() is then rounded to integers, then the
// maximum range for any output value after rounding is
// [-1518500250..+1518500250], regardless of the contents of the source
// vector. In particular, this is a smaller range than signed 32-bit integers
// in general, and it avoids the troublesome values such as -2^31.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_iFFT(logn: u32, f: &mut [FXR]) {
    if logn >= 4 {
        let fp: *mut __m256i = transmute(f.as_mut_ptr());
        let hn = 1usize << (logn - 3);
        let m1 = hn << 1;
        let hm1 = m1 >> 1;
        for i in 0..(hm1 >> 1) {
            let j0_re = (i << 1) + 0;
            let j1_re = (i << 1) + 1;
            let j0_im = (i << 1) + 0 + hn;
            let j1_im = (i << 1) + 1 + hn;
            let ya0_re = _mm256_loadu_si256(fp.wrapping_add(j0_re));
            let ya1_re = _mm256_loadu_si256(fp.wrapping_add(j1_re));
            let ya0_im = _mm256_loadu_si256(fp.wrapping_add(j0_im));
            let ya1_im = _mm256_loadu_si256(fp.wrapping_add(j1_im));
            let (ya0_re, ya1_re, ya0_im, ya1_im) =
                iFFT4(ya0_re, ya1_re, ya0_im, ya1_im, m1 + (i << 1));
            _mm256_storeu_si256(fp.wrapping_add(j0_re), ya0_re);
            _mm256_storeu_si256(fp.wrapping_add(j1_re), ya1_re);
            _mm256_storeu_si256(fp.wrapping_add(j0_im), ya0_im);
            _mm256_storeu_si256(fp.wrapping_add(j1_im), ya1_im);
        }

        let mut ht = 1;
        for lm in (1..=(logn - 3)).rev() {
            let m = 1usize << lm;
            let t = ht << 1;
            let mut j0 = 0;
            let hm = m >> 1;
            for i in 0..hm {
                let s = GM_TAB[m + i];
                let ys_re = _mm256_set1_epi64x(s.re.0 as i64);
                let ys_im = _mm256_set1_epi64x(-(s.im.0 as i64));
                for j in 0..ht {
                    let j0_re = j0 + j;
                    let j0_im = j0 + j + hn;
                    let j1_re = j0 + j + ht;
                    let j1_im = j0 + j + ht + hn;
                    let ya_re = _mm256_loadu_si256(fp.wrapping_add(j0_re));
                    let ya_im = _mm256_loadu_si256(fp.wrapping_add(j0_im));
                    let yb_re = _mm256_loadu_si256(fp.wrapping_add(j1_re));
                    let yb_im = _mm256_loadu_si256(fp.wrapping_add(j1_im));
                    let yc_re = fxr_half_x4(_mm256_add_epi64(ya_re, yb_re));
                    let yc_im = fxr_half_x4(_mm256_add_epi64(ya_im, yb_im));
                    let yd_re = fxr_half_x4(_mm256_sub_epi64(ya_re, yb_re));
                    let yd_im = fxr_half_x4(_mm256_sub_epi64(ya_im, yb_im));
                    let (yd_re, yd_im) = fxc_mul_x4(yd_re, yd_im, ys_re, ys_im);
                    _mm256_storeu_si256(fp.wrapping_add(j0_re), yc_re);
                    _mm256_storeu_si256(fp.wrapping_add(j0_im), yc_im);
                    _mm256_storeu_si256(fp.wrapping_add(j1_re), yd_re);
                    _mm256_storeu_si256(fp.wrapping_add(j1_im), yd_im);
                }
                j0 += t;
            }
            ht = t;
        }
    } else {
        let hn = 1usize << (logn - 1);
        let mut ht = 1;
        for lm in (1..logn).rev() {
            let m = 1usize << lm;
            let t = ht << 1;
            let mut j0 = 0;
            for i in 0..(m >> 1) {
                let s = GM_TAB[m + i].conj();
                for j in j0..(j0 + ht) {
                    let x = FXC { re: f[j], im: f[j + hn] };
                    let y = FXC { re: f[j + ht], im: f[j + ht + hn] };
                    let z1 = (x + y).half();
                    f[j] = z1.re;
                    f[j + hn] = z1.im;
                    let z2 = s * (x - y).half();
                    f[j + ht] = z2.re;
                    f[j + ht + hn] = z2.im;
                }
                j0 += t;
            }
            ht = t;
        }
    }
}

// Set vector d to the value of polynomial f.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_to_fxr(logn: u32, d: &mut [FXR], f: &[i8]) {
    if logn >= 4 {
        let fp: *const __m128i = transmute(f.as_ptr());
        let dp: *mut __m256i = transmute(d.as_mut_ptr());
        for i in 0..(1usize << (logn - 4)) {
            let xf = _mm_loadu_si128(fp.wrapping_add(i));
            let ya0 = _mm256_cvtepi8_epi64(xf);
            let ya1 = _mm256_cvtepi8_epi64(_mm_bsrli_si128(xf, 4));
            let ya2 = _mm256_cvtepi8_epi64(_mm_bsrli_si128(xf, 8));
            let ya3 = _mm256_cvtepi8_epi64(_mm_bsrli_si128(xf, 12));
            let ya0 = _mm256_slli_epi64(ya0, 32);
            let ya1 = _mm256_slli_epi64(ya1, 32);
            let ya2 = _mm256_slli_epi64(ya2, 32);
            let ya3 = _mm256_slli_epi64(ya3, 32);
            _mm256_storeu_si256(dp.wrapping_add((i << 2) + 0), ya0);
            _mm256_storeu_si256(dp.wrapping_add((i << 2) + 1), ya1);
            _mm256_storeu_si256(dp.wrapping_add((i << 2) + 2), ya2);
            _mm256_storeu_si256(dp.wrapping_add((i << 2) + 3), ya3);
        }
    } else {
        for i in 0..(1usize << logn) {
            d[i] = FXR::from_i32(f[i] as i32);
        }
    }
}

// Add vector b to vector a. This works in both real and FFT representations.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_add(logn: u32, a: &mut [FXR], b: &[FXR]) {
    if logn >= 2 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let bp: *const __m256i = transmute(b.as_ptr());
        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_si256(ap.wrapping_add(i));
            let yb = _mm256_loadu_si256(bp.wrapping_add(i));
            let yd = _mm256_add_epi64(ya, yb);
            _mm256_storeu_si256(ap.wrapping_add(i), yd);
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] += b[i];
        }
    }
}

// Multiply vector a by constant c. This works in both real and FFT
// representations.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_mul_realconst(logn: u32, a: &mut [FXR], c: FXR) {
    if logn >= 2 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let yc = _mm256_set1_epi64x(c.0 as i64);
        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_si256(ap.wrapping_add(i));
            let yd = fxr_mul_x4(ya, yc);
            _mm256_storeu_si256(ap.wrapping_add(i), yd);
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] *= c;
        }
    }
}

// Multiply vector a by 2^e. Exponent e should be in the [0,30] range.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_mul2e(logn: u32, a: &mut [FXR], e: u32) {
    if logn >= 2 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let ye = _mm256_set1_epi64x(e as i64);
        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_si256(ap.wrapping_add(i));
            let yd = _mm256_sllv_epi64(ya, ye);
            _mm256_storeu_si256(ap.wrapping_add(i), yd);
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i].set_mul2e(e);
        }
    }
}

// Multiply vector a by vector b. The vectors must be in FFT representation,
// and the result is in FFT representation.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_mul_fft(logn: u32, a: &mut [FXR], b: &[FXR]) {
    if logn >= 3 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let bp: *const __m256i = transmute(b.as_ptr());
        let hn = 1usize << (logn - 3);
        for i in 0..hn {
            let ya_re = _mm256_loadu_si256(ap.wrapping_add(i));
            let ya_im = _mm256_loadu_si256(ap.wrapping_add(i + hn));
            let yb_re = _mm256_loadu_si256(bp.wrapping_add(i));
            let yb_im = _mm256_loadu_si256(bp.wrapping_add(i + hn));
            let (yd_re, yd_im) = fxc_mul_x4(ya_re, ya_im, yb_re, yb_im);
            _mm256_storeu_si256(ap.wrapping_add(i), yd_re);
            _mm256_storeu_si256(ap.wrapping_add(i + hn), yd_im);
        }
    } else {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            let x = FXC { re: a[i], im: a[i + hn] };
            let y = FXC { re: b[i], im: b[i + hn] };
            let z = x * y;
            a[i] = z.re;
            a[i + hn] = z.im;
        }
    }
}

// Convert a vector into its Hermitian adjoint (in FFT representation).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_adj_fft(logn: u32, a: &mut [FXR]) {
    if logn >= 3 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let hn = 1usize << (logn - 3);
        for i in hn..(hn << 1) {
            let ya_im = _mm256_loadu_si256(ap.wrapping_add(i));
            let yd_im = _mm256_sub_epi64(_mm256_setzero_si256(), ya_im);
            _mm256_storeu_si256(ap.wrapping_add(i), yd_im);
        }
    } else {
        for i in (1usize << (logn - 1))..(1usize << logn) {
            a[i].set_neg();
        }
    }
}

// Multiply vector a by the self-adjoint vector b. Both vectors are in FFT
// representation. Since the FFT representation of a self-adjoint vector
// contains only real numbers, the second half of b contains only zeros and
// thus is not accessed (the slice may be half length).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_mul_selfadj_fft(logn: u32, a: &mut [FXR], b: &[FXR]) {
    if logn >= 3 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let bp: *const __m256i = transmute(b.as_ptr());
        let hn = 1usize << (logn - 3);
        for i in 0..hn {
            let ya_re = _mm256_loadu_si256(ap.wrapping_add(i));
            let ya_im = _mm256_loadu_si256(ap.wrapping_add(i + hn));
            let yb_re = _mm256_loadu_si256(bp.wrapping_add(i));
            let yd_re = fxr_mul_x4(ya_re, yb_re);
            let yd_im = fxr_mul_x4(ya_im, yb_re);
            _mm256_storeu_si256(ap.wrapping_add(i), yd_re);
            _mm256_storeu_si256(ap.wrapping_add(i + hn), yd_im);
        }
    } else {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            let c = b[i];
            a[i] *= c;
            a[i + hn] *= c;
        }
    }
}

// Divide vector a by the self-adjoint vector b. Both vectors are in FFT
// representation. Since the FFT representation of a self-adjoint vector
// contains only real numbers, the second half of b contains only zeros and
// thus is not accessed (the slice may be half length).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_div_selfadj_fft(logn: u32, a: &mut [FXR], b: &[FXR]) {
    if logn >= 3 {
        let ap: *mut __m256i = transmute(a.as_mut_ptr());
        let bp: *const __m256i = transmute(b.as_ptr());
        let hn = 1usize << (logn - 3);
        for i in 0..hn {
            let ya_re = _mm256_loadu_si256(ap.wrapping_add(i));
            let ya_im = _mm256_loadu_si256(ap.wrapping_add(i + hn));
            let yb_re = _mm256_loadu_si256(bp.wrapping_add(i));
            let yd_re = fxr_div_x4(ya_re, yb_re);
            let yd_im = fxr_div_x4(ya_im, yb_re);
            _mm256_storeu_si256(ap.wrapping_add(i), yd_re);
            _mm256_storeu_si256(ap.wrapping_add(i + hn), yd_im);
        }
    } else {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            // We do not compute 1/c separately because that would deviate
            // from the specification, and lose too much precision; we need
            // to perform the two divisions.
            let c = b[i];
            a[i] /= c;
            a[i + hn] /= c;
        }
    }
}

// Compute d = a*adj(a) + b*adj(b). Polynomials are in FFT representation.
// Since d is self-adjoint, it is half-size (only the low half is set, the
// high half is implicitly zero).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_norm_fft(logn: u32,
    d: &mut [FXR], a: &[FXR], b: &[FXR])
{
    if logn >= 3 {
        let dp: *mut __m256i = transmute(d.as_mut_ptr());
        let ap: *const __m256i = transmute(a.as_ptr());
        let bp: *const __m256i = transmute(b.as_ptr());
        let hn = 1usize << (logn - 3);
        for i in 0..hn {
            let ya_re = _mm256_loadu_si256(ap.wrapping_add(i));
            let ya_im = _mm256_loadu_si256(ap.wrapping_add(i + hn));
            let yb_re = _mm256_loadu_si256(bp.wrapping_add(i));
            let yb_im = _mm256_loadu_si256(bp.wrapping_add(i + hn));
            let y0 = fxr_sqr_x4(ya_re);
            let y1 = fxr_sqr_x4(ya_im);
            let y2 = fxr_sqr_x4(yb_re);
            let y3 = fxr_sqr_x4(yb_im);
            let yd = _mm256_add_epi64(
                _mm256_add_epi64(y0, y1),
                _mm256_add_epi64(y2, y3));
            _mm256_storeu_si256(dp.wrapping_add(i), yd);
        }
    } else {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            d[i] = a[i].sqr() + a[i + hn].sqr() + b[i].sqr() + b[i + hn].sqr();
        }
    }
}

// Compute d = (2^e)/(a*adj(a) + b*adj(b)). Polynomials are in FFT
// representation. Since d is self-adjoint, it is half-size (only the
// low half is set, the high half is implicitly zero).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn vect_invnorm_fft(logn: u32, d: &mut [FXR],
    a: &[FXR], b: &[FXR], e: u32)
{
    if logn >= 3 {
        let dp: *mut __m256i = transmute(d.as_mut_ptr());
        let ap: *const __m256i = transmute(a.as_ptr());
        let bp: *const __m256i = transmute(b.as_ptr());
        let hn = 1usize << (logn - 3);
        let r = FXR::from_i32(1i32 << e);
        let yfe = _mm256_set1_epi64x(r.0 as i64);
        for i in 0..hn {
            let ya_re = _mm256_loadu_si256(ap.wrapping_add(i));
            let ya_im = _mm256_loadu_si256(ap.wrapping_add(i + hn));
            let yb_re = _mm256_loadu_si256(bp.wrapping_add(i));
            let yb_im = _mm256_loadu_si256(bp.wrapping_add(i + hn));
            let y0 = fxr_sqr_x4(ya_re);
            let y1 = fxr_sqr_x4(ya_im);
            let y2 = fxr_sqr_x4(yb_re);
            let y3 = fxr_sqr_x4(yb_im);
            let yd = _mm256_add_epi64(
                _mm256_add_epi64(y0, y1),
                _mm256_add_epi64(y2, y3));
            let yd = fxr_div_x4(yfe, yd);
            _mm256_storeu_si256(dp.wrapping_add(i), yd);
        }
    } else {
        let hn = 1usize << (logn - 1);
        let r = FXR::from_i32(1i32 << e);
        for i in 0..hn {
            let z1 = a[i].sqr() + a[i + hn].sqr();
            let z2 = b[i].sqr() + b[i + hn].sqr();
            d[i] = r / (z1 + z2);
        }
    }
}

// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    fn rndvect(logn: u32, f: &mut [FXR], seed: u64) {
        let mut sh = Sha256::new();
        let mut buf = [0u8; 32];
        for i in 0..(1usize << logn) {
            if (i & 31) == 0 {
                sh.update(seed.to_le_bytes());
                sh.update((i as u64).to_le_bytes());
                buf[..].copy_from_slice(&sh.finalize_reset());
            }
            f[i] = FXR::from_i32((buf[i & 31] as i8) as i32);
        }
    }

    fn mulvect(logn: u32, d: &mut [FXR], a: &[FXR], b: &[FXR]) {
        let n = 1usize << logn;
        for i in 0..n {
            d[i] = FXR::ZERO;
        }
        for i in 0..n {
            for j in 0..n {
                let z = a[i] * b[j];
                let k = i + j;
                if k < n {
                    d[k] += z;
                } else {
                    d[k - n] -= z;
                }
            }
        }
    }

    #[test]
    fn test_FFT() {
        if fn_dsa_comm::has_avx2() {
            unsafe {
                let mut a = [FXR::ZERO; 1024];
                let mut b = [FXR::ZERO; 1024];
                let mut c = [FXR::ZERO; 1024];
                let mut d = [FXR::ZERO; 1024];
                for logn in 1u32..10u32 {
                    let n = 1usize << logn;
                    for i in 0u32..10u32 {
                        rndvect(logn, &mut a,
                            (0 | (logn << 8) | (i << 12)) as u64);
                        rndvect(logn, &mut b,
                            (1 | (logn << 8) | (i << 12)) as u64);
                        c[..n].copy_from_slice(&a[..n]);
                        let mut c2 = c;
                        vect_FFT(logn, &mut c);
                        crate::vect::vect_FFT(logn, &mut c2);
                        assert!(c == c2);
                        vect_iFFT(logn, &mut c);
                        crate::vect::vect_iFFT(logn, &mut c2);
                        assert!(c == c2);
                        for j in 0..n {
                            assert!(a[j].round() == c[j].round());
                        }

                        c[..n].copy_from_slice(&a[..n]);
                        vect_FFT(logn, &mut c);
                        d[..n].copy_from_slice(&b[..n]);
                        vect_FFT(logn, &mut d);
                        vect_mul_fft(logn, &mut c, &d);
                        vect_iFFT(logn, &mut c);
                        mulvect(logn, &mut d, &a, &b);
                        for j in 0..n {
                            assert!(c[j].round() == d[j].round());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_fxr_x4()
    {
        if fn_dsa_comm::has_avx2() {
            unsafe {
                let mut sh = Sha256::new();
                let mut buf = [0u8; 32];
                for i in 0..1000u32 {
                    let mut f = [FXR::ZERO; 4];
                    let mut g = [FXR::ZERO; 4];
                    sh.update((2 * i + 0).to_le_bytes());
                    buf[..].copy_from_slice(&sh.finalize_reset());
                    for j in 0..4 {
                        f[j] = FXR(u64::from_le_bytes(*<&[u8; 8]>::try_from(
                            &buf[8 * j..8 * j + 8]).unwrap()));
                    }
                    sh.update((2 * i + 1).to_le_bytes());
                    buf[..].copy_from_slice(&sh.finalize_reset());
                    for j in 0..4 {
                        g[j] = FXR(u64::from_le_bytes(*<&[u8; 8]>::try_from(
                            &buf[8 * j..8 * j + 8]).unwrap()));
                    }

                    let mut h = [FXR::ZERO; 4];
                    let fp: *const __m256i = transmute((&f).as_ptr());
                    let gp: *const __m256i = transmute((&g).as_ptr());
                    let hp: *mut __m256i = transmute((&mut h).as_mut_ptr());
                    let yf = _mm256_loadu_si256(fp);
                    let yg = _mm256_loadu_si256(gp);

                    let yh = fxr_mul_x4(yf, yg);
                    _mm256_storeu_si256(hp, yh);
                    for j in 0..4 {
                        assert!(h[j] == f[j] * g[j]);
                    }

                    let yh = fxr_sqr_x4(yf);
                    _mm256_storeu_si256(hp, yh);
                    for j in 0..4 {
                        assert!(h[j] == f[j].sqr());
                    }

                    let yh = fxr_half_x4(yf);
                    _mm256_storeu_si256(hp, yh);
                    for j in 0..4 {
                        assert!(h[j] == f[j].half());
                    }

                    let yh = fxr_div_x4(yf, yg);
                    _mm256_storeu_si256(hp, yh);
                    for j in 0..4 {
                        assert!(h[j] == f[j] / g[j]);
                    }
                }
            }
        }
    }
}
