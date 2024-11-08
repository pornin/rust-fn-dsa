#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use super::fxp::*;
use super::mp31::*;
use super::zint31_avx2::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use core::mem::transmute;

// ======================================================================== 
// Operations on polynomials modulo X^n+1 (with AVX2 optimizations)
// ======================================================================== 

// ------------------------------------------------------------------------
// Parallel versions of mp31 primitives (x8).

#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn mp_set_x8(yv: __m256i, yp: __m256i) -> __m256i {
    _mm256_add_epi32(yv, _mm256_and_si256(yp, _mm256_srai_epi32(yv, 31)))
}

#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn mp_norm_x8(yv: __m256i, yp: __m256i, yhp: __m256i)
    -> __m256i
{
    _mm256_sub_epi32(yv, _mm256_and_si256(yp, _mm256_cmpgt_epi32(yv, yhp)))
}

#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn mp_add_x8(ya: __m256i, yb: __m256i, yp: __m256i)
    -> __m256i
{
    let yd = _mm256_sub_epi32(_mm256_add_epi32(ya, yb), yp);
    _mm256_add_epi32(yd, _mm256_and_si256(yp, _mm256_srai_epi32(yd, 31)))
}

#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn mp_sub_x8(ya: __m256i, yb: __m256i, yp: __m256i)
    -> __m256i
{
    let yd = _mm256_sub_epi32(ya, yb);
    _mm256_add_epi32(yd, _mm256_and_si256(yp, _mm256_srai_epi32(yd, 31)))
}

#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn mp_half_x8(ya: __m256i, yp: __m256i) -> __m256i {
    _mm256_srli_epi32(
        _mm256_add_epi32(ya, _mm256_and_si256(yp,
            _mm256_sub_epi32(_mm256_setzero_si256(),
                _mm256_and_si256(ya, _mm256_set1_epi32(1))))), 1)
}

// Input:
//    ya = a0 : XX : a1 : XX : a2 : XX : a3 : XX
//    yb = b0 : XX : b1 : XX : b2 : XX : b3 : XX
// Output:
//    mm(a0,b0) : 00 : mm(a1,b1) : 00 : mm(a2,b2) : 00 : mm(a3,b3) : 00
#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn mp_mmul_x4(
    ya: __m256i, yb: __m256i, yp: __m256i, yp0i: __m256i) -> __m256i
{
    let yd = _mm256_mul_epu32(ya, yb);
    let ye = _mm256_mul_epu32(yd, yp0i);
    let ye = _mm256_mul_epu32(ye, yp);
    let yd = _mm256_srli_epi64(_mm256_add_epi64(yd, ye), 32);
    let yd = _mm256_sub_epi32(yd, yp);
    _mm256_add_epi32(yd, _mm256_and_si256(yp, _mm256_srai_epi32(yd, 31)))
}

#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn mp_mmul_x8(
    ya: __m256i, yb: __m256i, yp: __m256i, yp0i: __m256i) -> __m256i
{
    // yd0 <- a0*b0 : a2*b2 (+high lane)
    let yd0 = _mm256_mul_epu32(ya, yb);
    // yd1 <- a1*b1 : a3*b3 (+high lane)
    let yd1 = _mm256_mul_epu32(
        _mm256_srli_epi64(ya, 32),
        _mm256_srli_epi64(yb, 32));

    let ye0 = _mm256_mul_epu32(yd0, yp0i);
    let ye1 = _mm256_mul_epu32(yd1, yp0i);
    let ye0 = _mm256_mul_epu32(ye0, yp);
    let ye1 = _mm256_mul_epu32(ye1, yp);
    let yd0 = _mm256_add_epi64(yd0, ye0);
    let yd1 = _mm256_add_epi64(yd1, ye1);

    // yf0 <- lo(d0) : lo(d1) : hi(d0) : hi(d1) (+high lane)
    let yf0 = _mm256_unpacklo_epi32(yd0, yd1);
    // yf1 <- lo(d2) : lo(d3) : hi(d2) : hi(d3) (+high lane)
    let yf1 = _mm256_unpackhi_epi32(yd0, yd1);
    // yg <- hi(d0) : hi(d1) : hi(d2) : hi(d3) (+high lane)
    let yg = _mm256_unpackhi_epi64(yf0, yf1);
    // Alternate version (instead of the three unpack above) but it
    // seems to be slightly slower.
    // let yg = _mm256_blend_epi32(_mm256_srli_epi64(yd0, 32), yd1, 0xAA);

    let yg = _mm256_sub_epi32(yg, yp);
    _mm256_add_epi32(yg, _mm256_and_si256(yp, _mm256_srai_epi32(yg, 31)))
}

// ------------------------------------------------------------------------

// Compute the roots for NTT and inverse NTT.
// Inputs:
//    logn   wanted degree (logarithmic, 0 to 10)
//    g      primitive 2048-th root of 1 modulo p (Montgomery representation)
//    ig     inverse of g modulo p (Montgomery representation)
//    p      modulus
//    p0i    -1/p mod 2^32
// Outputs are written into gm[] and igm[]; in both slices, exactly
// n = 2^logn values are written. Output values are in Montgomery
// representation.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn mp_mkgmigm(logn: u32, g: u32, ig: u32, p: u32, p0i: u32,
    gm: &mut [u32], igm: &mut [u32])
{
    // We want a primitive 2n-th root of 1; we have a primitive 2048-th root
    // of 1, so we must square it a few times if logn < 10.
    let mut g = g;
    let mut ig = ig;
    for _ in logn..10 {
        g = mp_mmul(g, g, p, p0i);
        ig = mp_mmul(ig, ig, p, p0i);
    }

    if logn >= 3 {
        // If i % 8 == 0, then gm[i + j] = gm[i]*(gx^v) for v = 1..7,
        // with gx = g^(1024/8) mod p.
        // (Idem for igm[] and igx = ig^(1024/8) mod p)
        let mut gx = g;
        for _ in 3..logn {
            gx = mp_mmul(gx, gx, p, p0i);
        }
        let a0 = mp_R(p);
        let a4 = gx;
        let a2 = mp_mmul(a4, gx, p, p0i);
        let a6 = mp_mmul(a2, gx, p, p0i);
        let a1 = mp_mmul(a6, gx, p, p0i);
        let a5 = mp_mmul(a1, gx, p, p0i);
        let a3 = mp_mmul(a5, gx, p, p0i);
        let a7 = mp_mmul(a3, gx, p, p0i);
        let mut ya = _mm256_setr_epi32(
            a0 as i32, a1 as i32, a2 as i32, a3 as i32,
            a4 as i32, a5 as i32, a6 as i32, a7 as i32);
        let yg = _mm256_set1_epi32(g as i32);

        let mut igx = ig;
        for _ in 3..logn {
            igx = mp_mmul(igx, igx, p, p0i);
        }
        let b0 = mp_hR(p);
        let b4 = mp_half(igx, p);
        let b2 = mp_mmul(b4, igx, p, p0i);
        let b6 = mp_mmul(b2, igx, p, p0i);
        let b1 = mp_mmul(b6, igx, p, p0i);
        let b5 = mp_mmul(b1, igx, p, p0i);
        let b3 = mp_mmul(b5, igx, p, p0i);
        let b7 = mp_mmul(b3, igx, p, p0i);
        let mut yb = _mm256_setr_epi32(
            b0 as i32, b1 as i32, b2 as i32, b3 as i32,
            b4 as i32, b5 as i32, b6 as i32, b7 as i32);
        let yig = _mm256_set1_epi32(ig as i32);

        let k = 10 - logn;
        let gmp: *mut __m256i = transmute(gm.as_mut_ptr());
        let igmp: *mut __m256i = transmute(igm.as_mut_ptr());
        let yp = _mm256_set1_epi32(p as i32);
        let yp0i = _mm256_set1_epi32(p0i as i32);
        for i in 0..(1usize << (logn - 3)) {
            let j = (REV10[i << k] as usize) >> 3;
            _mm256_storeu_si256(gmp.wrapping_add(j), ya);
            _mm256_storeu_si256(igmp.wrapping_add(j), yb);
            ya = mp_mmul_x8(ya, yg, yp, yp0i);
            yb = mp_mmul_x8(yb, yig, yp, yp0i);
        }
    } else {
        let k = 10 - logn;
        let mut x1 = mp_R(p);
        let mut x2 = mp_hR(p);
        for i in 0..(1usize << logn) {
            let v = REV10[i << k] as usize;
            gm[v] = x1;
            igm[v] = x2;
            x1 = mp_mmul(x1, g, p, p0i);
            x2 = mp_mmul(x2, ig, p, p0i);
        }
    }
}

// Specialized version of mp_mkgmigm() when only the forward values (gm[])
// are needed.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn mp_mkgm(logn: u32, g: u32, p: u32, p0i: u32, gm: &mut [u32]) {
    let mut g = g;
    for _ in logn..10 {
        g = mp_mmul(g, g, p, p0i);
    }

    if logn >= 3 {
        let mut gx = g;
        for _ in 3..logn {
            gx = mp_mmul(gx, gx, p, p0i);
        }
        let a0 = mp_R(p);
        let a4 = gx;
        let a2 = mp_mmul(a4, gx, p, p0i);
        let a6 = mp_mmul(a2, gx, p, p0i);
        let a1 = mp_mmul(a6, gx, p, p0i);
        let a5 = mp_mmul(a1, gx, p, p0i);
        let a3 = mp_mmul(a5, gx, p, p0i);
        let a7 = mp_mmul(a3, gx, p, p0i);
        let mut ya = _mm256_setr_epi32(
            a0 as i32, a1 as i32, a2 as i32, a3 as i32,
            a4 as i32, a5 as i32, a6 as i32, a7 as i32);
        let yg = _mm256_set1_epi32(g as i32);

        let k = 10 - logn;
        let gmp: *mut __m256i = transmute(gm.as_mut_ptr());
        let yp = _mm256_set1_epi32(p as i32);
        let yp0i = _mm256_set1_epi32(p0i as i32);
        for i in 0..(1usize << (logn - 3)) {
            let j = (REV10[i << k] as usize) >> 3;
            _mm256_storeu_si256(gmp.wrapping_add(j), ya);
            ya = mp_mmul_x8(ya, yg, yp, yp0i);
        }
    } else {
        let k = 10 - logn;
        let mut x1 = mp_R(p);
        for i in 0..(1 << logn) {
            let v = REV10[i << k] as usize;
            gm[v] = x1;
            x1 = mp_mmul(x1, g, p, p0i);
        }
    }
}

// Specialized version of mp_mkgmigm() when only the reverse values (igm[])
// are needed.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn mp_mkigm(logn: u32, ig: u32, p: u32, p0i: u32, igm: &mut [u32]) {
    let mut ig = ig;
    for _ in logn..10 {
        ig = mp_mmul(ig, ig, p, p0i);
    }

    if logn >= 3 {
        let mut igx = ig;
        for _ in 3..logn {
            igx = mp_mmul(igx, igx, p, p0i);
        }
        let b0 = mp_hR(p);
        let b4 = mp_half(igx, p);
        let b2 = mp_mmul(b4, igx, p, p0i);
        let b6 = mp_mmul(b2, igx, p, p0i);
        let b1 = mp_mmul(b6, igx, p, p0i);
        let b5 = mp_mmul(b1, igx, p, p0i);
        let b3 = mp_mmul(b5, igx, p, p0i);
        let b7 = mp_mmul(b3, igx, p, p0i);
        let mut yb = _mm256_setr_epi32(
            b0 as i32, b1 as i32, b2 as i32, b3 as i32,
            b4 as i32, b5 as i32, b6 as i32, b7 as i32);
        let yig = _mm256_set1_epi32(ig as i32);

        let k = 10 - logn;
        let igmp: *mut __m256i = transmute(igm.as_mut_ptr());
        let yp = _mm256_set1_epi32(p as i32);
        let yp0i = _mm256_set1_epi32(p0i as i32);
        for i in 0..(1usize << (logn - 3)) {
            let j = (REV10[i << k] as usize) >> 3;
            _mm256_storeu_si256(igmp.wrapping_add(j), yb);
            yb = mp_mmul_x8(yb, yig, yp, yp0i);
        }
    } else {
        let k = 10 - logn;
        let mut x2 = mp_hR(p);
        for i in 0..(1 << logn) {
            let v = REV10[i << k] as usize;
            igm[v] = x2;
            x2 = mp_mmul(x2, ig, p, p0i);
        }
    }
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn NTT8(ya: __m256i, gm: &[u32], k: usize, yp: __m256i, yp0i: __m256i)
    -> __m256i
{
    // 0/4, 1/5, 2/6, 3/7 with gm[1]
    // ya <- a0:a1:a4:a5:a2:a3:a6:a7
    let ya = _mm256_permute4x64_epi64(ya, 0xD8);
    // yt1 <- a0:a4:a1:a5:a2:a6:a3:a7
    let yt1 = _mm256_shuffle_epi32(ya, 0xD8);
    // yt2 <- a4:a0:a5:a1:a6:a2:a7:a3
    let yt2 = _mm256_shuffle_epi32(ya, 0x72);
    // yg0 <- g1:g1:g1:g1:g1:g1:g1:g1
    let yg0 = _mm256_set1_epi32(gm[k] as i32);
    let yt2 = mp_mmul_x4(yt2, yg0, yp, yp0i);
    let ya0 = mp_add_x8(yt1, yt2, yp);
    let ya1 = mp_sub_x8(yt1, yt2, yp);

    // ya0 = a0:--:a1:--:a2:--:a3:--
    // ya1 = a4:--:a5:--:a6:--:a7:--

    // 0/2, 1/3 with gm[2]; 4/6, 5/7 with gm[3]
    // yt1 <- a0:--:a1:--:a4:--:a5:--
    // yt2 <- a2:--:a3:--:a6:--:a7:--
    let yt1 = _mm256_permute2x128_si256(ya0, ya1, 0x20);
    let yt2 = _mm256_permute2x128_si256(ya0, ya1, 0x31);
    let yg1 = _mm256_setr_epi32(
        gm[(k << 1) + 0] as i32, gm[(k << 1) + 0] as i32,
        gm[(k << 1) + 0] as i32, gm[(k << 1) + 0] as i32,
        gm[(k << 1) + 1] as i32, gm[(k << 1) + 1] as i32,
        gm[(k << 1) + 1] as i32, gm[(k << 1) + 1] as i32);
    let yt2 = mp_mmul_x4(yt2, yg1, yp, yp0i);
    let ya0 = mp_add_x8(yt1, yt2, yp);
    let ya1 = mp_sub_x8(yt1, yt2, yp);

    // ya0 = a0:--:a1:--:a4:--:a5:--
    // ya1 = a2:--:a3:--:a6:--:a7:--

    // 0/1 with gm[4], 2/3 with gm[5], 4/5 with gm[6], 6/7 with gm[7]
    // yt1 <- a0:--:a2:--:a4:--:a6:--
    // yt2 <- a1:--:a3:--:a5:--:a7:--
    let yt1 = _mm256_unpacklo_epi64(ya0, ya1);
    let yt2 = _mm256_unpackhi_epi64(ya0, ya1);
    let yg2 = _mm256_setr_epi32(
        gm[(k << 2) + 0] as i32, gm[(k << 2) + 0] as i32,
        gm[(k << 2) + 1] as i32, gm[(k << 2) + 1] as i32,
        gm[(k << 2) + 2] as i32, gm[(k << 2) + 2] as i32,
        gm[(k << 2) + 3] as i32, gm[(k << 2) + 3] as i32);
    let yt2 = mp_mmul_x4(yt2, yg2, yp, yp0i);
    let ya0 = mp_add_x8(yt1, yt2, yp);
    let ya1 = mp_sub_x8(yt1, yt2, yp);

    // ya0 = a0:--:a2:--:a4:--:a6:--
    // ya1 = a1:--:a3:--:a5:--:a7:--
    let ya = _mm256_blend_epi32(ya0, _mm256_slli_epi64(ya1, 32), 0xAA);
    ya
}

// Apply NTT over a polynomial in GF(p)[X]/(X^n+1). Input coefficients are
// expected in unsigned representation. The polynomial is modified in place.
// The number of coefficients is n = 2^logn, with 0 <= logn <= 10. The gm[]
// table must have been initialized with mp_mkgm() (or mp_mkgmigm()) with
// at least n elements.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn mp_NTT(logn: u32,
    a: &mut [u32], gm: &[u32], p: u32, p0i: u32)
{
    match logn {
        0 => { }
        1 => {
            let x1 = a[0];
            let x2 = mp_mmul(a[1], gm[1], p, p0i);
            a[0] = mp_add(x1, x2, p);
            a[1] = mp_sub(x1, x2, p);
        }
        2 => {
            let s = gm[1];
            let x1 = a[0];
            let x2 = mp_mmul(a[2], s, p, p0i);
            let a0 = mp_add(x1, x2, p);
            let a2 = mp_sub(x1, x2, p);
            let x1 = a[1];
            let x2 = mp_mmul(a[3], s, p, p0i);
            let a1 = mp_add(x1, x2, p);
            let a3 = mp_sub(x1, x2, p);
            let x1 = a0;
            let x2 = mp_mmul(a1, gm[2], p, p0i);
            a[0] = mp_add(x1, x2, p);
            a[1] = mp_sub(x1, x2, p);
            let x1 = a2;
            let x2 = mp_mmul(a3, gm[3], p, p0i);
            a[2] = mp_add(x1, x2, p);
            a[3] = mp_sub(x1, x2, p);
        }
        _ => {
            let ap: *mut __m256i = transmute(a.as_mut_ptr());
            let yp = _mm256_set1_epi32(p as i32);
            let yp0i = _mm256_set1_epi32(p0i as i32);
            let n = 1usize << logn;
            let mut t = n >> 3;
            for lm in 0..(logn - 3) {
                let m = 1usize << lm;
                let ht = t >> 1;
                let mut j0 = 0;
                for i in 0..m {
                    let ys = _mm256_set1_epi32(gm[i + m] as i32);
                    for j in 0..ht {
                        let j1 = j0 + j;
                        let j2 = j1 + ht;
                        let y1 = _mm256_loadu_si256(ap.wrapping_add(j1));
                        let y2 = _mm256_loadu_si256(ap.wrapping_add(j2));
                        let y2 = mp_mmul_x8(y2, ys, yp, yp0i);
                        _mm256_storeu_si256(ap.wrapping_add(j1),
                                mp_add_x8(y1, y2, yp));
                        _mm256_storeu_si256(ap.wrapping_add(j2),
                                mp_sub_x8(y1, y2, yp));
                    }
                    j0 += t;
                }
                t = ht;
            }
            let m = n >> 3;
            for i in 0..m {
                let ya = _mm256_loadu_si256(ap.wrapping_add(i));
                let ya = NTT8(ya, gm, i + m, yp, yp0i);
                _mm256_storeu_si256(ap.wrapping_add(i), ya);
            }
        }
    }
}

#[target_feature(enable = "avx2")]
#[inline]
unsafe fn iNTT8(ya: __m256i, igm: &[u32], k: usize, yp: __m256i, yp0i: __m256i)
    -> __m256i
{
    // yt1 <- a0:--:a2:--:a4:--:a6:--
    // yt2 <- a1:--:a3:--:a5:--:a7:--
    let yt1 = ya;
    let yt2 = _mm256_srli_epi64(ya, 32);
    let yg2 = _mm256_setr_epi32(
        igm[(k << 2) + 0] as i32, igm[(k << 2) + 0] as i32,
        igm[(k << 2) + 1] as i32, igm[(k << 2) + 1] as i32,
        igm[(k << 2) + 2] as i32, igm[(k << 2) + 2] as i32,
        igm[(k << 2) + 3] as i32, igm[(k << 2) + 3] as i32);
    let ya0 = mp_half_x8(mp_add_x8(yt1, yt2, yp), yp);
    let ya1 = mp_mmul_x4(mp_sub_x8(yt1, yt2, yp), yg2, yp, yp0i);

    // yt1 <- a0:--:a1:--:a4:--:a5:--
    // yt2 <- a2:--:a3:--:a6:--:a7:--
    let yt1 = _mm256_unpacklo_epi64(ya0, ya1);
    let yt2 = _mm256_unpackhi_epi64(ya0, ya1);
    let yg1 = _mm256_setr_epi32(
        igm[(k << 1) + 0] as i32, igm[(k << 1) + 0] as i32,
        igm[(k << 1) + 0] as i32, igm[(k << 1) + 0] as i32,
        igm[(k << 1) + 1] as i32, igm[(k << 1) + 1] as i32,
        igm[(k << 1) + 1] as i32, igm[(k << 1) + 1] as i32);
    let ya0 = mp_half_x8(mp_add_x8(yt1, yt2, yp), yp);
    let ya1 = mp_mmul_x4(mp_sub_x8(yt1, yt2, yp), yg1, yp, yp0i);

    // yt1 <- a0:--:a1:--:a2:--:a3:--
    // yt2 <- a4:--:a5:--:a6:--:a7:--
    let yt1 = _mm256_permute2x128_si256(ya0, ya1, 0x20);
    let yt2 = _mm256_permute2x128_si256(ya0, ya1, 0x31);
    let yg0 = _mm256_set1_epi32(igm[k] as i32);
    let ya0 = mp_half_x8(mp_add_x8(yt1, yt2, yp), yp);
    let ya1 = mp_mmul_x4(mp_sub_x8(yt1, yt2, yp), yg0, yp, yp0i);

    // yt1 <- a0:--:a1:--:a4:--:a5:--
    // yt2 <- a2:--:a3:--:a6:--:a7:--
    let yt1 = _mm256_permute2x128_si256(ya0, ya1, 0x20);
    let yt2 = _mm256_permute2x128_si256(ya0, ya1, 0x31);
    // yt1 <- a0:a2:a1:a3:a4:a6:a5:a7
    let yt1 = _mm256_blend_epi32(yt1, _mm256_slli_epi64(yt2, 32), 0xAA);
    let ya = _mm256_shuffle_epi32(yt1, 0xD8);
    ya
}

// Apply inverse NTT over a polynomial in GF(p)[X]/(X^n+1). Input
// coefficients are expected in unsigned representation. The polynomial is
// modified in place. The number of coefficients is n = 2^logn, with
// 0 <= logn <= 10. The igm[] table must have been initialized with
// mp_mkigm() (or mp_mkgmigm()) with at least n elements.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn mp_iNTT(logn: u32,
    a: &mut [u32], igm: &[u32], p: u32, p0i: u32)
{
    match logn {
        0 => { }
        1 => {
            let x1 = a[0];
            let x2 = a[1];
            a[0] = mp_half(mp_add(x1, x2, p), p);
            a[1] = mp_mmul(mp_sub(x1, x2, p), igm[1], p, p0i);
        }
        2 => {
            let x1 = a[0];
            let x2 = a[1];
            let a0 = mp_half(mp_add(x1, x2, p), p);
            let a1 = mp_mmul(mp_sub(x1, x2, p), igm[2], p, p0i);
            let x1 = a[2];
            let x2 = a[3];
            let a2 = mp_half(mp_add(x1, x2, p), p);
            let a3 = mp_mmul(mp_sub(x1, x2, p), igm[3], p, p0i);
            let s = igm[1];
            let x1 = a0;
            let x2 = a2;
            a[0] = mp_half(mp_add(x1, x2, p), p);
            a[2] = mp_mmul(mp_sub(x1, x2, p), s, p, p0i);
            let x1 = a1;
            let x2 = a3;
            a[1] = mp_half(mp_add(x1, x2, p), p);
            a[3] = mp_mmul(mp_sub(x1, x2, p), s, p, p0i);
        }
        _ => {
            let ap: *mut __m256i = transmute(a.as_mut_ptr());
            let yp = _mm256_set1_epi32(p as i32);
            let yp0i = _mm256_set1_epi32(p0i as i32);
            let n = 1usize << logn;
            let m = n >> 3;
            for i in 0..m {
                let ya = _mm256_loadu_si256(ap.wrapping_add(i));
                let ya = iNTT8(ya, igm, i + m, yp, yp0i);
                _mm256_storeu_si256(ap.wrapping_add(i), ya);
            }
            let mut t = 1;
            for lm in 3..logn {
                let hm = 1usize << (logn - 1 - lm);
                let dt = t << 1;
                let mut j0 = 0;
                for i in 0..hm {
                    let ys = _mm256_set1_epi32(igm[i + hm] as i32);
                    for j in 0..t {
                        let j1 = j0 + j;
                        let j2 = j1 + t;
                        let y1 = _mm256_loadu_si256(ap.wrapping_add(j1));
                        let y2 = _mm256_loadu_si256(ap.wrapping_add(j2));
                        _mm256_storeu_si256(ap.wrapping_add(j1),
                            mp_half_x8(mp_add_x8(y1, y2, yp), yp));
                        _mm256_storeu_si256(ap.wrapping_add(j2),
                            mp_mmul_x8(mp_sub_x8(y1, y2, yp), ys, yp, yp0i));
                    }
                    j0 += dt;
                }
                t = dt;
            }
        }
    }
}

// Set polynomial d to the RNS representation (modulo p) of the polynomial
// with small coefficients f.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_mp_set_small(logn: u32, f: &[i8], p: u32, d: &mut [u32]) {
    if logn >= 4 {
        let fp: *const __m128i = transmute(f.as_ptr());
        let dp: *mut __m256i = transmute(d.as_mut_ptr());
        let yp = _mm256_set1_epi32(p as i32);
        for i in 0..(1usize << (logn - 4)) {
            let xf = _mm_loadu_si128(fp.wrapping_add(i));
            let y0 = _mm256_cvtepi8_epi32(xf);
            let y1 = _mm256_cvtepi8_epi32(_mm_bsrli_si128(xf, 8));
            let yd0 = mp_set_x8(y0, yp);
            let yd1 = mp_set_x8(y1, yp);
            _mm256_storeu_si256(dp.wrapping_add((i << 1) + 0), yd0);
            _mm256_storeu_si256(dp.wrapping_add((i << 1) + 1), yd1);
        }
    } else {
        for i in 0..(1usize << logn) {
            d[i] = mp_set(f[i] as i32, p);
        }
    }
}

// Set polynomial f to its RNS representation (modulo p); the converted
// value overwrites the source. The source is assumed to use signed
// representation.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_mp_set(logn: u32, f: &mut [u32], p: u32) {
    if logn >= 3 {
        let fp: *mut __m256i = transmute(f.as_mut_ptr());
        let yps = _mm256_set1_epi32((p + 0x80000000) as i32);
        let yt = _mm256_set1_epi32(0x3FFFFFFF);
        for i in 0..(1usize << (logn - 3)) {
            let yf = _mm256_loadu_si256(fp.wrapping_add(i));
            let yf = _mm256_add_epi32(yf,
                _mm256_and_si256(yps, _mm256_cmpgt_epi32(yf, yt)));
            _mm256_storeu_si256(fp.wrapping_add(i), yf);
        }
    } else {
        for i in 0..(1usize << logn) {
            let x = f[i];
            f[i] = mp_set((x | ((x & 0x40000000) << 1)) as i32, p);
        }
    }
}

// Convert a polynomial from RNS to plain, signed representation, 1 word
// per coefficient. Note: the returned 32-bit values are NOT truncated to
// 31 bits; they are full-size signed 32-bit values, cast to u32 type.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_mp_norm(logn: u32, f: &mut [u32], p: u32) {
    if logn >= 3 {
        let fp: *mut __m256i = transmute(f.as_mut_ptr());
        let yp = _mm256_set1_epi32(p as i32);
        let yhp = _mm256_srli_epi32(yp, 1);
        for i in 0..(1usize << (logn - 3)) {
            let yf = _mm256_loadu_si256(fp.wrapping_add(i));
            let yf = mp_norm_x8(yf, yp, yhp);
            _mm256_storeu_si256(fp.wrapping_add(i), yf);
        }
    } else {
        for i in 0..(1usize << logn) {
            f[i] = mp_norm(f[i], p) as u32;
        }
    }
}

// Get the maximum bitlength of the coefficients of the provided polynomial
// (degree 2^logn, coefficients in plain representation, xlen words per
// coefficient).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_max_bitlength(logn: u32, x: &[u32], xlen: usize) -> u32 {
    let n = 1usize << logn;
    let mut t = 0u32;
    let mut tk = 0u32;
    for i in 0..n {
        // Extend sign bit into a 31-bit mask.
        let m = (x[i + ((xlen - 1) << logn)] >> 30).wrapping_neg() & 0x7FFFFFFF;

        // Get top non-zero sign-adjusted word, with index.
        //   c    top non-zero word
        //   ck   index at which c was found
        let mut c = 0u32;
        let mut ck = 0u32;
        for j in 0..xlen {
            // Sign-adjust the word.
            let w = x[i + (j << logn)] ^ m;

            // If the word is non-zero, then update c and ck.
            let nz = (w.wrapping_sub(1) >> 31).wrapping_sub(1);
            c ^= nz & (c ^ w);
            ck ^= nz & (ck ^ (j as u32));
        }

        // If ck > tk, or ck == tk but c > t, then (c,ck) must replace
        // (t,tk) as current candidate.
        let nz1 = tk.wrapping_sub(ck);
        let nz2 = (tk ^ ck).wrapping_sub(1) & t.wrapping_sub(c);
        let nz = tbmask(nz1 | nz2);
        t ^= nz & (t ^ c);
        tk ^= nz & (tk ^ ck);
    }

    31 * tk + bitlength(t)
}

// Return (q, r) where q = x / 31 and r = x % 31. This function works for
// any integer x up to 63487 (inclusive).
#[inline(always)]
pub(crate) const fn divrem31(x: u32) -> (u32, u32) {
    let q = x.wrapping_mul(67651) >> 21;
    let r = x - 31 * q;
    (q, r)
}

// Convert a polynomial to a fixed-point approximation, with scaling.
// Source coefficients of f have length flen words. For each coefficient x,
// the computed approximation is x/2^sc.
//
// This function assumes that |x| < 2^(30+sc). The length of each
// coefficient must be less than 2^16 words.
//
// This function is constant-time with regard to both the coefficient
// contents and the scaling factor sc.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_big_to_fixed(logn: u32,
    f: &[u32], flen: usize, sc: u32, d: &mut [FXR])
{
    let n = 1usize << logn;

    if flen == 0 {
        for i in 0..n {
            d[i] = FXR::ZERO;
        }
        return;
    }

    // We split sc into sch and scl such that:
    //   sc = 31*sch + scl
    // We also want scl in the 1..31 range, not 0..30. If sc == 0, then
    // this will imply that sch "wraps around" to 2^32-1, which is harmless.
    let (mut sch, mut scl) = divrem31(sc);
    let t = scl.wrapping_sub(1) >> 5;
    sch = sch.wrapping_sub(t & 1);
    scl |= t & 31;

    // For each coefficient, we want three words, each with a given left
    // shift (negative for a right shift):
    //    sch-1   1 - scl
    //    sch     32 - scl
    //    sch+1   63 - scl
    let t0 = sch.wrapping_sub(1) & 0xFFFF;
    let t1 = sch & 0xFFFF;
    let t2 = sch.wrapping_add(1) & 0xFFFF;
    for i in 0..n {
        // Get the relevant upper words.
        let mut w0 = 0u32;
        let mut w1 = 0u32;
        let mut w2 = 0u32;
        for j in 0..flen {
            let w = f[i + (j << logn)];
            let t = j as u32;
            w0 |= w & ((((t ^ t0).wrapping_sub(1) as i32) >> 16) as u32);
            w1 |= w & ((((t ^ t1).wrapping_sub(1) as i32) >> 16) as u32);
            w2 |= w & ((((t ^ t2).wrapping_sub(1) as i32) >> 16) as u32);
        }

        // If there are not enough words for the requested scaling, then
        // we must supply copies with the proper sign.
        let ws = (f[i + ((flen - 1) << logn)] >> 30).wrapping_neg() >> 1;
        let ff = (flen as u32).wrapping_sub(sch) as i32;
        w0 |= ws & ((ff >> 31) as u32);
        w1 |= ws & ((ff.wrapping_sub(1) >> 31) as u32);
        w2 |= ws & ((ff.wrapping_sub(2) >> 31) as u32);

        // Assemble the 64-bit value with the shifts. We assume that
        // shifts on 32-bit values are constant-time with regard to
        // the shift count (the last notable architecture on which this
        // was not true was the Willamette and Northwood cores in the
        // Pentium IV).
        w2 |= (w2 & 0x40000000) << 1;
        let xl = (w0 >> (scl - 1)) | (w1 << (32 - scl));
        let xh = (w1 >> scl) | (w2 << (31 - scl));
        d[i] = FXR::from_u64_scaled32((xl as u64) | ((xh as u64) << 32));
    }
}

// Subtract f*k*2^scale_k from F. Coefficients of F and f use Flen and flen
// words, respectively, and are in plain signed representation. Coefficients
// from k are signed 32-bit integers (provided in u32 slots).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_sub_scaled(logn: u32, F: &mut [u32], Flen: usize,
    f: &[u32], flen: usize, k: &[u32], sc: u32)
{
    if flen == 0 {
        return;
    }
    let (sch, scl) = divrem31(sc);
    if (sch as usize) >= Flen {
        return;
    }
    let Flen2 = Flen - (sch as usize);
    let flen = core::cmp::min(flen, Flen2);

    match logn {
        1 => {
            let Foff = (sch as usize) << logn;
            let Flen = Flen2;
            let mut t0 = 0u32;
            let mut t1 = 0u32;
            let signf0 = (f[(flen << 1) - 2] >> 30).wrapping_neg() >> 1;
            let signf1 = (f[(flen << 1) - 1] >> 30).wrapping_neg() >> 1;
            let k0 = k[0] as i32;
            let k1 = k[1] as i32;
            let mut cc0 = 0i64;
            let mut cc1 = 0i64;
            for i in 0..Flen {
                // Next word, shifted.
                let (f0, f1);
                if i < flen {
                    f0 = f[(i << 1) + 0];
                    f1 = f[(i << 1) + 1];
                } else {
                    f0 = signf0;
                    f1 = signf1;
                }
                let fs0 = ((f0 << scl) & 0x7FFFFFFF) | t0;
                let fs1 = ((f1 << scl) & 0x7FFFFFFF) | t1;
                t0 = f0 >> (31 - scl);
                t1 = f1 >> (31 - scl);

                let F0 = F[Foff + (i << 1) + 0];
                let F1 = F[Foff + (i << 1) + 1];
                let z0 = (F0 as i64) + cc0
                    - (fs0 as i64) * (k0 as i64)
                    + (fs1 as i64) * (k1 as i64);
                let z1 = (F1 as i64) + cc1
                    - (fs0 as i64) * (k1 as i64)
                    - (fs1 as i64) * (k0 as i64);
                F[Foff + (i << 1) + 0] = (z0 as u32) & 0x7FFFFFFF;
                F[Foff + (i << 1) + 1] = (z1 as u32) & 0x7FFFFFFF;
                cc0 = z0 >> 31;
                cc1 = z1 >> 31;
            }
        }

        2 => {
            let Flen = Flen2;
            let fp: *const __m128i = transmute(f.as_ptr());
            let Fp: *mut __m128i = transmute(F.as_mut_ptr());
            let Fp = Fp.wrapping_add(sch as usize);

            let mut xt = _mm_setzero_si128();
            let xsignf = _mm_loadu_si128(fp.wrapping_add(flen - 1));
            let xsignf = _mm_srli_epi32(
                _mm_srai_epi32(_mm_slli_epi32(xsignf, 1), 31), 1);
            let k0 = k[0] as i32;
            let k1 = k[1] as i32;
            let k2 = k[2] as i32;
            let k3 = k[3] as i32;
            let nk0 = k0.wrapping_neg();
            let nk1 = k1.wrapping_neg();
            let nk2 = k2.wrapping_neg();
            let nk3 = k3.wrapping_neg();
            let yk0 = _mm256_setr_epi32(nk0, 0, nk1, 0, nk2, 0, nk3, 0);
            let yk1 = _mm256_setr_epi32( k3, 0, nk0, 0, nk1, 0, nk2, 0);
            let yk2 = _mm256_setr_epi32( k2, 0,  k3, 0, nk0, 0, nk1, 0);
            let yk3 = _mm256_setr_epi32( k1, 0,  k2, 0,  k3, 0, nk0, 0);
            let xscl = _mm_cvtsi32_si128(scl as i32);
            let xnscl = _mm_cvtsi32_si128(31 - (scl as i32));
            let mut ycc = _mm256_setzero_si256();
            let x31 = _mm_set1_epi32(0x7FFFFFFF);
            let y31 = _mm256_set1_epi32(0x7FFFFFFF);
            let y31lo = _mm256_set1_epi64x(0x7FFFFFFF);
            for i in 0..Flen {
                // Next word, shifted.
                let xf;
                if i < flen {
                    xf = _mm_loadu_si128(fp.wrapping_add(i));
                } else {
                    xf = xsignf;
                }
                let xfs = _mm_or_si128(xt,
                    _mm_and_si128(_mm_sll_epi32(xf, xscl), x31));
                xt = _mm_srl_epi32(xf, xnscl);

                let yfs0 = _mm256_broadcastd_epi32(xfs);
                let yfs1 = _mm256_broadcastd_epi32(_mm_bsrli_si128(xfs, 4));
                let yfs2 = _mm256_broadcastd_epi32(_mm_bsrli_si128(xfs, 8));
                let yfs3 = _mm256_broadcastd_epi32(_mm_bsrli_si128(xfs, 12));

                let yF = _mm256_castsi128_si256(
                    _mm_loadu_si128(Fp.wrapping_add(i)));
                let yF = _mm256_shuffle_epi32(
                    _mm256_permute4x64_epi64(yF, 0x10), 0x10);
                let yF = _mm256_and_si256(yF, y31lo);

                let yv0 = _mm256_mul_epi32(yfs0, yk0);
                let yv1 = _mm256_mul_epi32(yfs1, yk1);
                let yv2 = _mm256_mul_epi32(yfs2, yk2);
                let yv3 = _mm256_mul_epi32(yfs3, yk3);
                let yz = _mm256_add_epi64(
                    _mm256_add_epi64(
                        _mm256_add_epi64(yv0, yv1),
                        _mm256_add_epi64(yv2, yv3)),
                    _mm256_add_epi64(ycc, yF));
                ycc = _mm256_blend_epi32(
                    _mm256_srli_epi64(yz, 31),
                    _mm256_srai_epi32(yz, 31), 0xAA);
                let yz = _mm256_shuffle_epi32(
                    _mm256_and_si256(yz, y31), 0x88);
                let yz = _mm256_permute4x64_epi64(yz, 0x88);
                let xF = _mm256_castsi256_si128(yz);
                _mm_storeu_si128(Fp.wrapping_add(i), xF);
            }
        }

        3 => {
            let Flen = Flen2;
            let fp: *const __m256i = transmute(f.as_ptr());
            let Fp: *mut __m256i = transmute(F.as_mut_ptr());
            let Fp = Fp.wrapping_add(sch as usize);

            let mut yt = _mm256_setzero_si256();
            let ysignf = _mm256_loadu_si256(fp.wrapping_add(flen - 1));
            let ysignf = _mm256_srli_epi32(
                _mm256_srai_epi32(_mm256_slli_epi32(ysignf, 1), 31), 1);

            let k0 = k[0] as i32;
            let k1 = k[1] as i32;
            let k2 = k[2] as i32;
            let k3 = k[3] as i32;
            let k4 = k[4] as i32;
            let k5 = k[5] as i32;
            let k6 = k[6] as i32;
            let k7 = k[7] as i32;
            let nk0 = k0.wrapping_neg();
            let nk1 = k1.wrapping_neg();
            let nk2 = k2.wrapping_neg();
            let nk3 = k3.wrapping_neg();
            let nk4 = k4.wrapping_neg();
            let nk5 = k5.wrapping_neg();
            let nk6 = k6.wrapping_neg();
            let nk7 = k7.wrapping_neg();
            let yk0l = _mm256_setr_epi32(
                nk0, nk1, nk2, nk3, nk4, nk5, nk6, nk7);
            let yk1l = _mm256_setr_epi32(
                 k7, nk0, nk1, nk2, nk3, nk4, nk5, nk6);
            let yk2l = _mm256_setr_epi32(
                 k6,  k7, nk0, nk1, nk2, nk3, nk4, nk5);
            let yk3l = _mm256_setr_epi32(
                 k5,  k6,  k7, nk0, nk1, nk2, nk3, nk4);
            let yk4l = _mm256_setr_epi32(
                 k4,  k5,  k6,  k7, nk0, nk1, nk2, nk3);
            let yk5l = _mm256_setr_epi32(
                 k3,  k4,  k5,  k6,  k7, nk0, nk1, nk2);
            let yk6l = _mm256_setr_epi32(
                 k2,  k3,  k4,  k5,  k6,  k7, nk0, nk1);
            let yk7l = _mm256_setr_epi32(
                 k1,  k2,  k3,  k4,  k5,  k6,  k7, nk0);
            let yk0h = _mm256_srli_epi64(yk0l, 32);
            let yk1h = _mm256_srli_epi64(yk1l, 32);
            let yk2h = _mm256_srli_epi64(yk2l, 32);
            let yk3h = _mm256_srli_epi64(yk3l, 32);
            let yk4h = _mm256_srli_epi64(yk4l, 32);
            let yk5h = _mm256_srli_epi64(yk5l, 32);
            let yk6h = _mm256_srli_epi64(yk6l, 32);
            let yk7h = _mm256_srli_epi64(yk7l, 32);

            let xscl = _mm_cvtsi32_si128(scl as i32);
            let xnscl = _mm_cvtsi32_si128(31 - (scl as i32));
            let mut ycc0 = _mm256_setzero_si256();
            let mut ycc1 = _mm256_setzero_si256();
            let y31 = _mm256_set1_epi32(0x7FFFFFFF);
            let y31lo = _mm256_set1_epi64x(0x7FFFFFFF);
            for i in 0..Flen {
                    // Next word, shifted.
                    let yf;
                    if i < flen {
                        yf = _mm256_loadu_si256(fp.wrapping_add(i));
                    } else {
                        yf = ysignf;
                    }
                    let yfs = _mm256_or_si256(yt,
                        _mm256_and_si256(_mm256_sll_epi32(yf, xscl), y31));
                    yt = _mm256_srl_epi32(yf, xnscl);

                    let xfs0 = _mm256_castsi256_si128(yfs);
                    let xfs1 = _mm256_extracti128_si256(yfs, 1);
                    let yfs0 = _mm256_broadcastd_epi32(xfs0);
                    let yfs1 = _mm256_broadcastd_epi32(
                        _mm_bsrli_si128(xfs0, 4));
                    let yfs2 = _mm256_broadcastd_epi32(
                        _mm_bsrli_si128(xfs0, 8));
                    let yfs3 = _mm256_broadcastd_epi32(
                        _mm_bsrli_si128(xfs0, 12));
                    let yfs4 = _mm256_broadcastd_epi32(xfs1);
                    let yfs5 = _mm256_broadcastd_epi32(
                        _mm_bsrli_si128(xfs1, 4));
                    let yfs6 = _mm256_broadcastd_epi32(
                        _mm_bsrli_si128(xfs1, 8));
                    let yfs7 = _mm256_broadcastd_epi32(
                        _mm_bsrli_si128(xfs1, 12));

                    let yF = _mm256_loadu_si256(Fp.wrapping_add(i));
                    let yF0 = _mm256_and_si256(yF, y31lo);
                    let yF1 = _mm256_srli_epi64(yF, 32);

                    let yv0l = _mm256_mul_epi32(yfs0, yk0l);
                    let yv0h = _mm256_mul_epi32(yfs0, yk0h);
                    let yv1l = _mm256_mul_epi32(yfs1, yk1l);
                    let yv1h = _mm256_mul_epi32(yfs1, yk1h);
                    let yv2l = _mm256_mul_epi32(yfs2, yk2l);
                    let yv2h = _mm256_mul_epi32(yfs2, yk2h);
                    let yv3l = _mm256_mul_epi32(yfs3, yk3l);
                    let yv3h = _mm256_mul_epi32(yfs3, yk3h);
                    let yv4l = _mm256_mul_epi32(yfs4, yk4l);
                    let yv4h = _mm256_mul_epi32(yfs4, yk4h);
                    let yv5l = _mm256_mul_epi32(yfs5, yk5l);
                    let yv5h = _mm256_mul_epi32(yfs5, yk5h);
                    let yv6l = _mm256_mul_epi32(yfs6, yk6l);
                    let yv6h = _mm256_mul_epi32(yfs6, yk6h);
                    let yv7l = _mm256_mul_epi32(yfs7, yk7l);
                    let yv7h = _mm256_mul_epi32(yfs7, yk7h);

                    let yz0 = _mm256_add_epi64(
                        _mm256_add_epi64(ycc0, yF0),
                        _mm256_add_epi64(
                            _mm256_add_epi64(
                                _mm256_add_epi64(yv0l, yv1l),
                                _mm256_add_epi64(yv2l, yv3l)),
                            _mm256_add_epi64(
                                _mm256_add_epi64(yv4l, yv5l),
                                _mm256_add_epi64(yv6l, yv7l))));
                    let yz1 = _mm256_add_epi64(
                        _mm256_add_epi64(ycc1, yF1),
                        _mm256_add_epi64(
                            _mm256_add_epi64(
                                _mm256_add_epi64(yv0h, yv1h),
                                _mm256_add_epi64(yv2h, yv3h)),
                            _mm256_add_epi64(
                                _mm256_add_epi64(yv4h, yv5h),
                                _mm256_add_epi64(yv6h, yv7h))));
                    ycc0 = _mm256_blend_epi32(
                        _mm256_srli_epi64(yz0, 31),
                        _mm256_srai_epi32(yz0, 31), 0xAA);
                    ycc1 = _mm256_blend_epi32(
                        _mm256_srli_epi64(yz1, 31),
                        _mm256_srai_epi32(yz1, 31), 0xAA);
                    let yF = _mm256_or_si256(
                        _mm256_and_si256(yz0, y31lo),
                        _mm256_slli_epi64(
                            _mm256_and_si256(yz1, y31lo), 32));
                    _mm256_storeu_si256(Fp.wrapping_add(i), yF);
            }
        }

        _ => {
            let n = 1usize << logn;
            for i in 0..n {
                let kf = k[i].wrapping_neg() as i32;
                for j in i..n {
                    zint_add_scaled_mul_small(
                        &mut F[j..], Flen,
                        &f[(j - i)..], flen, n, kf, sch, scl);
                }
                let kf = kf.wrapping_neg();
                for j in 0..i {
                    zint_add_scaled_mul_small(
                        &mut F[j..], Flen,
                        &f[((j + n) - i)..], flen, n, kf, sch, scl);
                }
            }
        }
    }
}

// Subtract f*k*2^scale_k from F. This is similar to poly_sub_scaled(),
// except that:
//   - f is in RNS+NTT, and over flen+1 words (even though the plain
//     representation was over flen words).
//   - An extra temporary array is provided, with at least n*(flen+4) free
//     words.
// The multiplication f*k is internally computed using the NTT; this is
// faster at large degree.
// The value of logn MUST be at least 3.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_sub_scaled_ntt(logn: u32, F: &mut [u32], Flen: usize,
    f: &[u32], flen: usize, k: &[u32], sc: u32, tmp: &mut [u32])
{
    assert!(logn >= 3);
    let n = 1usize << logn;
    let tlen = flen + 1;

    // Compute k*f into a temporary area in RNS format, flen+1 words.
    let (gm, work) = tmp.split_at_mut(n);
    let (igm, work) = work.split_at_mut(n);
    let (fk, t1) = work.split_at_mut(tlen * n);
    for i in 0..tlen {
        let p = PRIMES[i].p;
        let p0i = PRIMES[i].p0i;
        let R2 = PRIMES[i].R2;
        mp_mkgmigm(logn, PRIMES[i].g, PRIMES[i].ig, p, p0i, gm, igm);

        let yp = _mm256_set1_epi32(p as i32);
        let kp: *const __m256i = transmute(k.as_ptr());
        let t1p: *mut __m256i = transmute(t1.as_mut_ptr());
        for j in 0..(n >> 3) {
            let yk = _mm256_loadu_si256(kp.wrapping_add(j));
            _mm256_storeu_si256(t1p.wrapping_add(j), mp_set_x8(yk, yp));
        }

        mp_NTT(logn, t1, gm, p, p0i);
        let fs = &f[(i << logn)..];
        let ff = &mut fk[(i << logn)..];

        let yp0i = _mm256_set1_epi32(p0i as i32);
        let yr2 = _mm256_set1_epi32(R2 as i32);
        let fsp: *const __m256i = transmute(fs.as_ptr());
        let ffp: *mut __m256i = transmute(ff.as_mut_ptr());
        for j in 0..(n >> 3) {
            let y1 = _mm256_loadu_si256(t1p.wrapping_add(j));
            let y2 = _mm256_loadu_si256(fsp.wrapping_add(j));
            let y3 = mp_mmul_x8(mp_mmul_x8(y1, y2, yp, yp0i), yr2, yp, yp0i);
            _mm256_storeu_si256(ffp.wrapping_add(j), y3);
        }

        mp_iNTT(logn, ff, igm, p, p0i);
    }

    // Rebuild k*f in plain representation.
    zint_rebuild_CRT(fk, tlen, n, 1, true, t1);

    // Subtract k*f, with scaling, from F.
    let (sch, scl) = divrem31(sc);
    for i in 0..n {
        zint_sub_scaled(&mut F[i..], Flen, &fk[i..], tlen, n, sch, scl);
    }
}

// Subtract (k*2^scale_k_*(f,g) from (F,G). This is a specialized function
// for NTRU solving at depth 1, because we really want to use the NTT (degree
// is large) but we do not have enough room in our buffers to keep (f,g)
// in RNS+NTT modulo enough primes. Instead, we recompute them dynamically
// here.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_sub_kfg_scaled_depth1(logn_top: u32,
    F: &mut [u32], G: &mut [u32], FGlen: usize,
    k: &mut [u32], sc: u32, f: &[i8], g: &[i8], tmp: &mut [u32])
{
    let logn = logn_top - 1;
    let n = 1usize << logn;
    let hn = n >> 1;
    let (gm, tmp) = tmp.split_at_mut(n);
    let (t1, t2) = tmp.split_at_mut(n);

    // Convert F and G to RNS. Normally, FGlen is equal to 2; the code
    // below also covers the case FGlen = 1, which could be used in some
    // algorithms leveraging the same kind of NTRU lattice.
    if FGlen == 1 {
        let p = PRIMES[0].p;
        for i in 0..n {
            let xf = F[i];
            let xg = G[i];
            let xf = xf | ((xf & 0x40000000) << 1);
            let xg = xg | ((xg & 0x40000000) << 1);
            F[i] = mp_set(xf as i32, p);
            G[i] = mp_set(xg as i32, p);
        }
    } else {
        assert!(FGlen == 2);
        let p0 = PRIMES[0].p;
        let p0_0i = PRIMES[0].p0i;
        let z0 = mp_half(PRIMES[0].R2, p0);
        let p1 = PRIMES[1].p;
        let p1_0i = PRIMES[1].p0i;
        let z1 = mp_half(PRIMES[1].R2, p1);
        for i in 0..n {
            let xl = F[i];
            let xh = F[i + n] | ((F[i + n] & 0x40000000) << 1);
            let yl0 = mp_set_u(xl, p0);
            let yh0 = mp_set(xh as i32, p0);
            let r0 = mp_add(yl0, mp_mmul(yh0, z0, p0, p0_0i), p0);
            let yl1 = mp_set_u(xl, p1);
            let yh1 = mp_set(xh as i32, p1);
            let r1 = mp_add(yl1, mp_mmul(yh1, z1, p1, p1_0i), p1);
            F[i] = r0;
            F[i + n] = r1;

            let xl = G[i];
            let xh = G[i + n] | ((G[i + n] & 0x40000000) << 1);
            let yl0 = mp_set_u(xl, p0);
            let yh0 = mp_set(xh as i32, p0);
            let r0 = mp_add(yl0, mp_mmul(yh0, z0, p0, p0_0i), p0);
            let yl1 = mp_set_u(xl, p1);
            let yh1 = mp_set(xh as i32, p1);
            let r1 = mp_add(yl1, mp_mmul(yh1, z1, p1, p1_0i), p1);
            G[i] = r0;
            G[i + n] = r1;
        }
    }

    // For FGlen small primes, convert F and G to RNS+NTT, and subtract
    // (2^sc)*(ft,gt). ft and gt are computed dynamically from the
    // top-level (f,g).
    for i in 0..FGlen {
        let p = PRIMES[i].p;
        let p0i = PRIMES[i].p0i;
        let R2 = PRIMES[i].R2;
        let R3 = mp_mmul(R2, R2, p, p0i);
        mp_mkgm(logn, PRIMES[i].g, p, p0i, gm);

        // k <- (2^sc)*k (and into NTT).
        // We modify k in place because we do not have enough room to make
        // a copy.
        let mut scv = mp_mmul(1u32 << (sc & 31), R2, p, p0i);
        for _ in 0..(sc >> 5) {
            scv = mp_mmul(scv, R2, p, p0i);
        }
        for j in 0..n {
            let x = mp_set(k[j] as i32, p);
            k[j] = mp_mmul(scv, x, p, p0i);
        }
        mp_NTT(logn, k, gm, p, p0i);

        // Convert F and G to NTT.
        let Fu = &mut F[(i << logn)..];
        let Gu = &mut G[(i << logn)..];
        mp_NTT(logn, Fu, gm, p, p0i);
        mp_NTT(logn, Gu, gm, p, p0i);

        // Given the top-level f, we obtain ft = N(f) with:
        //    f = f_e(X^2) + X*f_o(X^2)
        // with f_e and f_o being modulo X^n+1 (with n = 2^logn) while
        // f is modulo X^(2*n)+1 (with 2*n = 2^logn_top). Then:
        //    N(f) = f_e^2 - X*f_o^2
        // The NTT representation of X is obtained from the gm[] tab:
        //    NTT(X)[2*j + 0] = gm[j + n/2]
        //    NTT(X)[2*j + 1] = -NTT(X)[2*j + 0]
        // Note: the values in gm[] are in Montgomery representation.
        for j in 0..n {
            t1[j] = mp_set(f[(j << 1) + 0] as i32, p);
            t2[j] = mp_set(f[(j << 1) + 1] as i32, p);
        }
        mp_NTT(logn, t1, gm, p, p0i);
        mp_NTT(logn, t2, gm, p, p0i);
        for j in 0..hn {
            let xe0 = t1[(j << 1) + 0];
            let xe1 = t1[(j << 1) + 1];
            let xo0 = t2[(j << 1) + 0];
            let xo1 = t2[(j << 1) + 1];
            let xv0 = gm[j + hn];
            let xv1 = p - xv0;      // values in gm[] are non-zero
            let xe0 = mp_mmul(xe0, xe0, p, p0i);
            let xe1 = mp_mmul(xe1, xe1, p, p0i);
            let xo0 = mp_mmul(xo0, xo0, p, p0i);
            let xo1 = mp_mmul(xo1, xo1, p, p0i);
            let xf0 = mp_sub(xe0, mp_mmul(xo0, xv0, p, p0i), p);
            let xf1 = mp_sub(xe1, mp_mmul(xo1, xv1, p, p0i), p);
            let xkf0 = mp_mmul(
                mp_mmul(xf0, k[(j << 1) + 0], p, p0i), R3, p, p0i);
            let xkf1 = mp_mmul(
                mp_mmul(xf1, k[(j << 1) + 1], p, p0i), R3, p, p0i);
            Fu[(j << 1) + 0] = mp_sub(Fu[(j << 1) + 0], xkf0, p);
            Fu[(j << 1) + 1] = mp_sub(Fu[(j << 1) + 1], xkf1, p);
        }

        // Same treatment for G and gt.
        for j in 0..n {
            t1[j] = mp_set(g[(j << 1) + 0] as i32, p);
            t2[j] = mp_set(g[(j << 1) + 1] as i32, p);
        }
        mp_NTT(logn, t1, gm, p, p0i);
        mp_NTT(logn, t2, gm, p, p0i);
        for j in 0..hn {
            let xe0 = t1[(j << 1) + 0];
            let xe1 = t1[(j << 1) + 1];
            let xo0 = t2[(j << 1) + 0];
            let xo1 = t2[(j << 1) + 1];
            let xv0 = gm[j + hn];
            let xv1 = p - xv0;      // values in gm[] are non-zero
            let xe0 = mp_mmul(xe0, xe0, p, p0i);
            let xe1 = mp_mmul(xe1, xe1, p, p0i);
            let xo0 = mp_mmul(xo0, xo0, p, p0i);
            let xo1 = mp_mmul(xo1, xo1, p, p0i);
            let xg0 = mp_sub(xe0, mp_mmul(xo0, xv0, p, p0i), p);
            let xg1 = mp_sub(xe1, mp_mmul(xo1, xv1, p, p0i), p);
            let xkg0 = mp_mmul(
                mp_mmul(xg0, k[(j << 1) + 0], p, p0i), R3, p, p0i);
            let xkg1 = mp_mmul(
                mp_mmul(xg1, k[(j << 1) + 1], p, p0i), R3, p, p0i);
            Gu[(j << 1) + 0] = mp_sub(Gu[(j << 1) + 0], xkg0, p);
            Gu[(j << 1) + 1] = mp_sub(Gu[(j << 1) + 1], xkg1, p);
        }

        // Convert back F and G to RNS.
        mp_mkigm(logn, PRIMES[i].ig, p, p0i, t1);
        mp_iNTT(logn, Fu, t1, p, p0i);
        mp_iNTT(logn, Gu, t1, p, p0i);

        // We replaced k (plain 32-bit) with (2^sc)*k (NTT); we must
        // put it back to its initial value for the next iteration.
        if (i + 1) < FGlen {
            mp_iNTT(logn, k, t1, p, p0i);
            scv = 1u32 << (sc.wrapping_neg() & 31);
            for _ in 0..(sc >> 5) {
                scv = mp_mmul(scv, 1, p, p0i);
            }
            for j in 0..n {
                k[j] = mp_norm(mp_mmul(scv, k[j], p, p0i), p) as u32;
            }
        }
    }

    // F and G are in RNS (non-NTT), but we want plain integers.
    if FGlen == 1 {
        let p = PRIMES[0].p;
        for i in 0..n {
            F[i] = (mp_norm(F[i], p) as u32) & 0x7FFFFFFF;
            G[i] = (mp_norm(G[i], p) as u32) & 0x7FFFFFFF;
        }
    } else {
        let p0 = PRIMES[0].p;
        let p1 = PRIMES[1].p;
        let p1_0i = PRIMES[1].p0i;
        let s = PRIMES[1].s;
        let pp = (p0 as u64) * (p1 as u64);
        let hpp = pp >> 1;
        for i in 0..n {
            let x0 = F[i];
            let x1 = F[i + n];
            let x0m1 = x0.wrapping_sub(p1 & !tbmask(x0.wrapping_sub(p1)));
            let y = mp_mmul(mp_sub(x1, x0m1, p1), s, p1, p1_0i);
            let z = (x0 as u64) + (p0 as u64) * (y as u64);
            let z = z.wrapping_sub(pp & (hpp.wrapping_sub(z) >> 63)
                .wrapping_neg());
            F[i] = (z as u32) & 0x7FFFFFFF;
            F[i + n] = ((z >> 31) as u32) & 0x7FFFFFFF;
        }
        for i in 0..n {
            let x0 = G[i];
            let x1 = G[i + n];
            let x0m1 = x0.wrapping_sub(p1 & !tbmask(x0.wrapping_sub(p1)));
            let y = mp_mmul(mp_sub(x1, x0m1, p1), s, p1, p1_0i);
            let z = (x0 as u64) + (p0 as u64) * (y as u64);
            let z = z.wrapping_sub(pp & (hpp.wrapping_sub(z) >> 63)
                .wrapping_neg());
            G[i] = (z as u32) & 0x7FFFFFFF;
            G[i + n] = ((z >> 31) as u32) & 0x7FFFFFFF;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    unsafe fn inner_NTT(logn: u32, g: u32, ig: u32, p: u32, p0i: u32, R2: u32) {
        let mut tmp = [0u32; 5 * 1024];
        let n = 1 << logn;
        let (t1, tx) = tmp.split_at_mut(n);
        let (t2, tx) = tx.split_at_mut(n);
        let (w3, tx) = tx.split_at_mut(2 * n);
        let (t5, _) = tx.split_at_mut(n);

        // Generate random polynomials in t1 and t2.
        let mut sh = Sha256::new();
        for i in 0..n {
            sh.update((p as u64).to_le_bytes());
            sh.update((i as u16).to_le_bytes());
            let hv = sh.finalize_reset();
            t1[i] = (u64::from_le_bytes(*<&[u8; 8]>::try_from(&hv[0..8]).unwrap()) % (p as u64)) as u32;
            t2[i] = (u64::from_le_bytes(*<&[u8; 8]>::try_from(&hv[8..16]).unwrap()) % (p as u64)) as u32;
        }

        // Compute the product t1*t2 into w3 "manually", then reduce it
        // modulo X^n+1.
        for i in 0..(2 * n) {
            w3[i] = 0;
        }
        for i in 0..n {
            for j in 0..n {
                let z = (t1[i] as u64) * (t2[j] as u64) + (w3[i + j] as u64);
                w3[i + j] = (z % (p as u64)) as u32;
            }
        }
        for i in 0..n {
            let x = w3[i];
            let y = w3[i + n];
            if y > x {
                t5[i] = (x + p) - y;
            } else {
                t5[i] = x - y;
            }
        }

        // Convert t1 and t2 to the NTT domain, do the multiplication
        // in that domain, then convert back. This should yield the same
        // result as the "manual" process.
        let (gm, igm) = w3.split_at_mut(n);
        mp_mkgmigm(logn, g, ig, p, p0i, gm, igm);
        mp_NTT(logn, t1, gm, p, p0i);
        mp_NTT(logn, t2, gm, p, p0i);
        for i in 0..n {
            t1[i] = mp_mmul(t1[i], mp_mmul(t2[i], R2, p, p0i), p, p0i);
        }
        mp_iNTT(logn, t1, igm, p, p0i);
        assert!(t1 == t5);
    }

    #[test]
    fn NTT() {
        if fn_dsa_comm::has_avx2() {
            unsafe {
                for logn in 1..11 {
                    for i in 0..5 {
                        inner_NTT(logn,
                            PRIMES[i].g, PRIMES[i].ig,
                            PRIMES[i].p, PRIMES[i].p0i, PRIMES[i].R2);
                    }
                }
            }
        }
    }
}
