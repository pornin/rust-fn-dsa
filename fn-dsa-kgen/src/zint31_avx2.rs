#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

// ========================================================================
// Big integers (with AVX2 optimizations)
// ========================================================================

use super::mp31::{mp_mmul, mp_sub, PRIMES};
use super::poly_avx2::{mp_add_x8, mp_half_x8, mp_mmul_x8, mp_sub_x8};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use core::mem::transmute;

// Most of the zint31 functions do not have AVX2-optimized versions, so we
// re-export the plain ones.
pub(crate) use crate::zint31::{
    zint_mul_small,
    zint_mod_small_unsigned,
    zint_mod_small_signed,
    zint_add_mul_small,
    zint_norm_zero,
    zint_bezout,
    zint_add_scaled_mul_small,
    zint_sub_scaled,
    bitlength,
};

// Parallel version of zint_mod_small_unsigned()
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn zint_mod_small_unsigned_x8(
    d: *const __m256i, dlen: usize, dstride: usize,
    yp: __m256i, yp0i: __m256i, yR2: __m256i) -> __m256i
{
    let mut yx = _mm256_setzero_si256();
    let yz = mp_half_x8(yR2, yp);
    let mut dp = d.wrapping_add(dlen * (dstride >> 3));
    for _ in 0..dlen {
        dp = dp.wrapping_sub(dstride >> 3);
        let yw = _mm256_sub_epi32(_mm256_loadu_si256(dp), yp);
        let yw = _mm256_add_epi32(yw,
            _mm256_and_si256(yp, _mm256_srai_epi32(yw, 31)));
        yx = mp_mmul_x8(yx, yz, yp, yp0i);
        yx = mp_add_x8(yx, yw, yp);
    }
    yx
}

// Parallel version of zint_mod_small_signed()
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn zint_mod_small_signed_x8(
    d: *const __m256i, dlen: usize, dstride: usize,
    yp: __m256i, yp0i: __m256i, yR2: __m256i, yRx: __m256i) -> __m256i
{
    if dlen == 0 {
        return _mm256_setzero_si256();
    }
    let yz = zint_mod_small_unsigned_x8(d, dlen, dstride, yp, yp0i, yR2);
    let yl = _mm256_loadu_si256(d.wrapping_add((dlen - 1) * (dstride >> 3)));
    let ym = _mm256_sub_epi32(
        _mm256_setzero_si256(),
        _mm256_srli_epi32(yl, 30));
    let yz = mp_sub_x8(yz, _mm256_and_si256(yRx, ym), yp);
    yz
}

// Parallel version of zint_add_mul_small()
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn zint_add_mul_small_x8(
    d: *mut __m256i, dstride: usize, a: &[u32], ys: __m256i)
{
    let mut cc0 = _mm256_setzero_si256();
    let mut cc1 = _mm256_setzero_si256();
    let ys0 = ys;
    let ys1 = _mm256_srli_epi64(ys, 32);
    let yw32 = _mm256_set1_epi64x(0xFFFFFFFF);
    let ym31 = _mm256_set1_epi32(0x7FFFFFFF);
    let mut dp = d;
    for i in 0..a.len() {
        let ya = _mm256_set1_epi64x(a[i] as i64);
        let z0 = _mm256_mul_epu32(ya, ys0);
        let z1 = _mm256_mul_epu32(ya, ys1);
        let yd = _mm256_loadu_si256(dp);
        let yd0 = _mm256_and_si256(yd, yw32);
        let yd1 = _mm256_srli_epi64(yd, 32);
        let z0 = _mm256_add_epi64(z0, _mm256_add_epi64(yd0, cc0));
        let z1 = _mm256_add_epi64(z1, _mm256_add_epi64(yd1, cc1));
        cc0 = _mm256_srli_epi64(z0, 31);
        cc1 = _mm256_srli_epi64(z1, 31);
        let yd = _mm256_blend_epi32(z0, _mm256_slli_epi64(z1, 32), 0xAA);
        _mm256_storeu_si256(dp, _mm256_and_si256(yd, ym31));
        dp = dp.wrapping_add(dstride >> 3);
    }

    _mm256_storeu_si256(dp,
        _mm256_and_si256(_mm256_blend_epi32(
            cc0, _mm256_slli_epi64(cc1, 32), 0xAA), ym31));
}

// Parallel version of zint_norm_zero()
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn zint_norm_zero_x8(
    xp: *mut __m256i, xstride: usize, m: &[u32])
{
    // Compare x with p/2. We use the shifted version of p, and p
    // is odd, so we really compare with (p-1)/2; we want to perform
    // the subtraction if and only if x > (p-1)/2.
    let mut yr = _mm256_setzero_si256();
    let yone = _mm256_set1_epi32(1);
    let mut bb = 0u32;
    let mut xp = xp.wrapping_add(m.len() * (xstride >> 3));
    for i in (0..m.len()).rev() {
        xp = xp.wrapping_sub(xstride >> 3);

        // Get the two words to compare in wx and wp (both over
        // 31 bits exactly).
        let yx = _mm256_loadu_si256(xp);
        let wp = (m[i] >> 1) | (bb << 30);
        bb = m[i] & 1;

        // We set cc to -1, 0 or 1, depending on whether wp is
        // lower than, equal to, or greater than wx.
        let ycc = _mm256_sub_epi32(_mm256_set1_epi32(wp as i32), yx);
        let ycc = _mm256_or_si256(
            _mm256_srli_epi32(_mm256_sub_epi32(
                _mm256_setzero_si256(), ycc), 31),
            _mm256_srai_epi32(ycc, 31));

        // If r != 0 then it is either 1 or -1, and we keep its
        // value. Otherwise, if r = 0, then we replace it with cc.
        yr = _mm256_or_si256(yr, _mm256_and_si256(ycc,
            _mm256_sub_epi32(_mm256_and_si256(yr, yone), yone)));
    }

    // At this point, r = -1, 0 or 1, depending on whether (p-1)/2
    // is lower than, equal to, or greater than x. We thus want to
    // do the subtraction only if r = -1.
    let mut ycc = _mm256_setzero_si256();
    let ym = _mm256_srai_epi32(yr, 31);
    let y31 = _mm256_set1_epi32(0x7FFFFFFF);
    for j in 0..m.len() {
        let yx = _mm256_loadu_si256(xp);
        let y = _mm256_sub_epi32(
            _mm256_sub_epi32(yx, ycc),
            _mm256_set1_epi32(m[j] as i32));
        ycc = _mm256_srli_epi32(y, 31);
        let yx = _mm256_or_si256(
            _mm256_andnot_si256(ym, yx),
            _mm256_and_si256(ym, _mm256_and_si256(y, y31)));
        _mm256_storeu_si256(xp, yx);
        xp = xp.wrapping_add(xstride >> 3);
    }
}

// Rebuild several integers from their RNS representation. There are
// 'num_sets' sets of 'n' integers. Within each set, the n integers
// are interleaved, so that words of a given integer occur every n
// slots in RAM (i.e. each integer has stride 'n'). The sets are
// consecutive in RAM. Each integer has xlen elements. Thus, the
// input/output data uses num_sets*n*xlen words in total.
//
// If 'normalized_signed' is true, then the output values are normalized
// into the [-m/2, +m/2] interval (where m is the product of all small
// prime moduli); otherwise, returned values are in [0, m-1].
//
// tmp[] is used to store temporary values and must have size at least
// xlen elements.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn zint_rebuild_CRT(xx: &mut [u32], xlen: usize, n: usize,
    num_sets: usize, normalize_signed: bool, tmp: &mut [u32])
{
    tmp[0] = PRIMES[0].p;
    for i in 1..xlen {
        // At entry of each iteration:
        //  - the first i words of each integer have been converted
        //  - the first i words of tmp[] contain the product of the
        //    first i prime moduli (denoted q in later comments)
        let p = PRIMES[i].p;
        let p0i = PRIMES[i].p0i;
        let R2 = PRIMES[i].R2;
        let s = PRIMES[i].s;
        let yp = _mm256_set1_epi32(p as i32);
        let yp0i = _mm256_set1_epi32(p0i as i32);
        let yR2 = _mm256_set1_epi32(R2 as i32);
        let ys = _mm256_set1_epi32(s as i32);
        for j in 0..num_sets {
            let set_base = j * (n * xlen);

            {
                let xxbp: *mut __m256i = transmute(xx.as_mut_ptr());
                let xxbp = xxbp.wrapping_add(set_base >> 3);
                for k in 0..(n >> 3) {
                    let ap = xxbp.wrapping_add(k);
                    let y1 = _mm256_loadu_si256(ap.wrapping_add((i * n) >> 3));
                    let y2 = zint_mod_small_unsigned_x8(
                        ap, i, n, yp, yp0i, yR2);
                    let y3 = mp_mmul_x8(ys, mp_sub_x8(y1, y2, yp), yp, yp0i);
                    zint_add_mul_small_x8(ap, n, &tmp[..i], y3);
                }
            }

            for k in (n & !7usize)..n {
                // We are processing x (integer number k in set j).
                // x starts at offset j*(n*xlen) + k and has stride n.
                //
                // Let q_i = prod_{m<i} p_m (the products of the
                // previous primes). At this point, we have rebuilt
                // xq_i = x mod q_i, in the first i elements of x. In
                // element i we have xp_i = x mod p_i. We compute x
                // modulo q_{i+1} as:
                //   xq_{i+1} = xq_i + q_i*(s_i*(xp_i - xq_i) mod p_i)
                // with s_i = 1/q_i mod p_i.
                let xq = &mut xx[set_base + k..];
                let xp = xq[i * n];
                let xr = zint_mod_small_unsigned(xq, i, n, p, p0i, R2);
                let xt = mp_mmul(s, mp_sub(xp, xr, p), p, p0i);
                zint_add_mul_small(xq, n, &tmp[..i], xt);
            }
        }

        // Multiply xq_i (in tmp[]) with p_i to prepare for the next
        // iteration (this is also useful for the last iteration: the
        // product of all small primes is used for signed normalization).
        tmp[i] = zint_mul_small(&mut tmp[0..i], p);
    }

    // Apply signed normalization if requested.
    if normalize_signed {
        for j in 0..num_sets {
            {
                let ap: *mut __m256i = transmute(xx.as_mut_ptr());
                let ap = ap.wrapping_add((j * n * xlen) >> 3);
                for k in 0..(n >> 3) {
                    zint_norm_zero_x8(ap.wrapping_add(k), n, &tmp[..xlen]);
                }
            }
            for k in (n & !7usize)..n {
                zint_norm_zero(&mut xx[j * n * xlen + k..], n, &tmp[..xlen]);
            }
        }
    }
}
