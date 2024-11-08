#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use crate::flr::FLR;
use core::arch::x86_64::*;
use core::mem::transmute;

// ========================================================================
// Floating-point polynomials (AVX2 specialization)
// ========================================================================

// This file defines functions similar to those in poly.rs, but leveraging
// AVX2 opcodes. They are called from sign_avx2.rs, whose use is gated
// by check of AVX2 support by the CPU at runtime.

// Complex multiplication.
#[inline(always)]
pub(crate) fn flc_mul(x_re: FLR, x_im: FLR, y_re: FLR, y_im: FLR)
    -> (FLR, FLR)
{
    (x_re * y_re - x_im * y_im, x_re * y_im + x_im * y_re)
}

// Convert a polynomial from normal representation to FFT.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn FFT(logn: u32, f: &mut [FLR]) {
    // First iteration of the FFT algorithm would compute
    // f[j] + i*f[j + n/2] for all j < n/2; since this is exactly our
    // storage format for complex numbers in the FFT representation,
    // that first iteration is a no-op, hence we can start the computation
    // at the second iteration.

    assert!(logn >= 1);
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut t = hn;
    let fp = transmute::<*mut FLR, *mut f64>(f.as_mut_ptr());
    for lm in 1..logn {
        let m = 1 << lm;
        let hm = m >> 1;
        let ht = t >> 1;
        let mut j0 = 0;
        for i in 0..hm {
            if ht >= 4 {
                let s_re = _mm256_set1_pd(GM[((m + i) << 1) + 0].to_f64());
                let s_im = _mm256_set1_pd(GM[((m + i) << 1) + 1].to_f64());
                let f1_re = fp.wrapping_add(j0);
                let f1_im = fp.wrapping_add(j0 + hn);
                let f2_re = fp.wrapping_add(j0 + ht);
                let f2_im = fp.wrapping_add(j0 + ht + hn);
                for j in 0..(ht >> 2) {
                    let x_re = _mm256_loadu_pd(f1_re.wrapping_add(j << 2));
                    let x_im = _mm256_loadu_pd(f1_im.wrapping_add(j << 2));
                    let y_re = _mm256_loadu_pd(f2_re.wrapping_add(j << 2));
                    let y_im = _mm256_loadu_pd(f2_im.wrapping_add(j << 2));
                    let z_re = _mm256_sub_pd(
                        _mm256_mul_pd(s_re, y_re),
                        _mm256_mul_pd(s_im, y_im));
                    let z_im = _mm256_add_pd(
                        _mm256_mul_pd(s_re, y_im),
                        _mm256_mul_pd(s_im, y_re));
                    _mm256_storeu_pd(f1_re.wrapping_add(j << 2),
                        _mm256_add_pd(x_re, z_re));
                    _mm256_storeu_pd(f1_im.wrapping_add(j << 2),
                        _mm256_add_pd(x_im, z_im));
                    _mm256_storeu_pd(f2_re.wrapping_add(j << 2),
                        _mm256_sub_pd(x_re, z_re));
                    _mm256_storeu_pd(f2_im.wrapping_add(j << 2),
                        _mm256_sub_pd(x_im, z_im));
                }
            } else {
                let s_re = GM[((m + i) << 1) + 0];
                let s_im = GM[((m + i) << 1) + 1];
                for j in 0..ht {
                    let j1 = j0 + j;
                    let j2 = j1 + ht;
                    let x_re = f[j1];
                    let x_im = f[j1 + hn];
                    let y_re = f[j2];
                    let y_im = f[j2 + hn];
                    let (z_re, z_im) = flc_mul(y_re, y_im, s_re, s_im);
                    f[j1] = x_re + z_re;
                    f[j1 + hn] = x_im + z_im;
                    f[j2] = x_re - z_re;
                    f[j2 + hn] = x_im - z_im;
                }
            }
            j0 += t;
        }
        t = ht;
    }
}

// Convert a polynomial from FFT representation to normal.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn iFFT(logn: u32, f: &mut [FLR]) {
    // This is the reverse of FFT. We use the fact that if
    // w = exp(i*k*pi/N), then 1/w is the conjugate of w; thus, we can
    // get inverses from the table GM[] itself by simply negating the
    // imaginary part.
    //
    // The last iteration is a no-op (like the first iteration in FFT).
    // Since the last iteration is skipped, we have to perform only
    // a division by n/2 at the end.

    assert!(logn >= 1);
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut t = 1;
    let fp = transmute::<*mut FLR, *mut f64>(f.as_mut_ptr());
    for lm in 1..logn {
        let hm = 1 << (logn - lm);
        let dt = t << 1;
        let mut j0 = 0;
        for i in 0..(hm >> 1) {
            if t >= 4 {
                let s_re = _mm256_set1_pd(GM[((hm + i) << 1) + 0].to_f64());
                let s_im = _mm256_set1_pd(-GM[((hm + i) << 1) + 1].to_f64());
                let f1_re = fp.wrapping_add(j0);
                let f1_im = fp.wrapping_add(j0 + hn);
                let f2_re = fp.wrapping_add(j0 + t);
                let f2_im = fp.wrapping_add(j0 + t + hn);
                for j in 0..(t >> 2) {
                    let x_re = _mm256_loadu_pd(f1_re.wrapping_add(j << 2));
                    let x_im = _mm256_loadu_pd(f1_im.wrapping_add(j << 2));
                    let y_re = _mm256_loadu_pd(f2_re.wrapping_add(j << 2));
                    let y_im = _mm256_loadu_pd(f2_im.wrapping_add(j << 2));
                    _mm256_storeu_pd(f1_re.wrapping_add(j << 2),
                        _mm256_add_pd(x_re, y_re));
                    _mm256_storeu_pd(f1_im.wrapping_add(j << 2),
                        _mm256_add_pd(x_im, y_im));
                    let x_re = _mm256_sub_pd(x_re, y_re);
                    let x_im = _mm256_sub_pd(x_im, y_im);
                    let z_re = _mm256_sub_pd(
                        _mm256_mul_pd(x_re, s_re),
                        _mm256_mul_pd(x_im, s_im));
                    let z_im = _mm256_add_pd(
                        _mm256_mul_pd(x_re, s_im),
                        _mm256_mul_pd(x_im, s_re));
                    _mm256_storeu_pd(f2_re.wrapping_add(j << 2), z_re);
                    _mm256_storeu_pd(f2_im.wrapping_add(j << 2), z_im);
                }
            } else {
                let s_re = GM[((hm + i) << 1) + 0];
                let s_im = -GM[((hm + i) << 1) + 1];
                for j in 0..t {
                    let j1 = j0 + j;
                    let j2 = j1 + t;
                    let x_re = f[j1];
                    let x_im = f[j1 + hn];
                    let y_re = f[j2];
                    let y_im = f[j2 + hn];
                    f[j1] = x_re + y_re;
                    f[j1 + hn] = x_im + y_im;
                    let x_re = x_re - y_re;
                    let x_im = x_im - y_im;
                    let (z_re, z_im) = flc_mul(x_re, x_im, s_re, s_im);
                    f[j2] = z_re;
                    f[j2 + hn] = z_im;
                }
            }
            j0 += dt;
        }
        t = dt;
    }

    // We have logn-1 delayed halvings to perform, i.e. we must divide
    // all returned values by n/2.
    if logn >= 2 {
        let d = _mm256_set1_pd(FLR::INV_POW2[(logn + 126) as usize]);
        for j in 0..(1usize << (logn - 2)) {
            let y = _mm256_loadu_pd(fp.wrapping_add(j << 2));
            let y = _mm256_mul_pd(y, d);
            _mm256_storeu_pd(fp.wrapping_add(j << 2), y);
        }
    } else {
        FLR::slice_div2e(&mut f[..n], logn - 1);
    }
}

// Set polynomial d from polynomial f with small coefficients.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_set_small(logn: u32, d: &mut [FLR], f: &[i8]) {
    if logn >= 4 {
        let fp = transmute::<*const i8, *const __m128i>(f.as_ptr());
        let dp = transmute::<*mut FLR, *mut f64>(d.as_mut_ptr());
        for i in 0..(1usize << (logn - 4)) {
            let x0 = _mm_loadu_si128(fp.wrapping_add(i));
            let x1 = _mm_shuffle_epi32(x0, 0x55);
            let x2 = _mm_shuffle_epi32(x0, 0xAA);
            let x3 = _mm_shuffle_epi32(x0, 0xFF);
            let y0 = _mm256_cvtepi32_pd(_mm_cvtepi8_epi32(x0));
            let y1 = _mm256_cvtepi32_pd(_mm_cvtepi8_epi32(x1));
            let y2 = _mm256_cvtepi32_pd(_mm_cvtepi8_epi32(x2));
            let y3 = _mm256_cvtepi32_pd(_mm_cvtepi8_epi32(x3));
            _mm256_storeu_pd(dp.wrapping_add((i << 4) +  0), y0);
            _mm256_storeu_pd(dp.wrapping_add((i << 4) +  4), y1);
            _mm256_storeu_pd(dp.wrapping_add((i << 4) +  8), y2);
            _mm256_storeu_pd(dp.wrapping_add((i << 4) + 12), y3);
        }
    } else {
        for i in 0..(1usize << logn) {
            d[i] = FLR::from_i32(f[i] as i32);
        }
    }
}

// Add polynomial b to polynomial a.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_add(logn: u32, a: &mut [FLR], b: &[FLR]) {
    if logn >= 2 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let bp = transmute::<*const FLR, *const f64>(b.as_ptr());
        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let yb = _mm256_loadu_pd(bp.wrapping_add(i << 2));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), _mm256_add_pd(ya, yb));
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] += b[i];
        }
    }
}

// Subtract polynomial b from polynomial a.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_sub(logn: u32, a: &mut [FLR], b: &[FLR]) {
    if logn >= 2 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let bp = transmute::<*const FLR, *const f64>(b.as_ptr());
        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let yb = _mm256_loadu_pd(bp.wrapping_add(i << 2));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), _mm256_sub_pd(ya, yb));
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] -= b[i];
        }
    }
}

// Negate polynomial a.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_neg(logn: u32, a: &mut [FLR]) {
    if logn >= 2 {
        // We can do negation by simply flipping the high bit of each
        // value, because we do not care about NaNs.
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let ym = _mm256_set1_pd(-0.0);
        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), _mm256_xor_pd(ya, ym));
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] = -a[i];
        }
    }
}

// Multiply polynomial a with polynomial b. The polynomials must be in
// FFT representation.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_mul_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);
    if logn >= 3 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let bp = transmute::<*const FLR, *const f64>(b.as_ptr());
        for i in 0..(1usize << (logn - 3)) {
            let a_re = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let a_im = _mm256_loadu_pd(ap.wrapping_add((i << 2) + hn));
            let b_re = _mm256_loadu_pd(bp.wrapping_add(i << 2));
            let b_im = _mm256_loadu_pd(bp.wrapping_add((i << 2) + hn));
            let d_re = _mm256_sub_pd(
                _mm256_mul_pd(a_re, b_re),
                _mm256_mul_pd(a_im, b_im));
            let d_im = _mm256_add_pd(
                _mm256_mul_pd(a_re, b_im),
                _mm256_mul_pd(a_im, b_re));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), d_re);
            _mm256_storeu_pd(ap.wrapping_add((i << 2) + hn), d_im);
        }
    } else {
        for i in 0..hn {
            let (re, im) = flc_mul(a[i], a[i + hn], b[i], b[i + hn]);
            a[i] = re;
            a[i + hn] = im;
        }
    }
}

// Multiply polynomial a with the adjoint of polynomial b. The polynomials
// must be in FFT representation.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_muladj_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);
    if logn >= 3 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let bp = transmute::<*const FLR, *const f64>(b.as_ptr());
        for i in 0..(1usize << (logn - 3)) {
            let a_re = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let a_im = _mm256_loadu_pd(ap.wrapping_add((i << 2) + hn));
            let b_re = _mm256_loadu_pd(bp.wrapping_add(i << 2));
            let b_im = _mm256_loadu_pd(bp.wrapping_add((i << 2) + hn));
            let d_re = _mm256_add_pd(
                _mm256_mul_pd(a_re, b_re),
                _mm256_mul_pd(a_im, b_im));
            let d_im = _mm256_sub_pd(
                _mm256_mul_pd(a_im, b_re),
                _mm256_mul_pd(a_re, b_im));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), d_re);
            _mm256_storeu_pd(ap.wrapping_add((i << 2) + hn), d_im);
        }
    } else {
        for i in 0..hn {
            let (re, im) = flc_mul(a[i], a[i + hn], b[i], -b[i + hn]);
            a[i] = re;
            a[i + hn] = im;
        }
    }
}

// Multiply polynomial a with its own adjoint. The polynomial must be in
// FFT representation. Since the result is a self-adjoint polynomial,
// coefficients n/2 to n-1 are set to zero.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_mulownadj_fft(logn: u32, a: &mut [FLR]) {
    let hn = 1usize << (logn - 1);
    if logn >= 3 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let zero = _mm256_set1_pd(0.0);
        for i in 0..(1usize << (logn - 3)) {
            let a_re = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            let a_im = _mm256_loadu_pd(ap.wrapping_add((i << 2) + hn));
            let d_re = _mm256_add_pd(
                _mm256_mul_pd(a_re, a_re),
                _mm256_mul_pd(a_im, a_im));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), d_re);
            _mm256_storeu_pd(ap.wrapping_add((i << 2) + hn), zero);
        }
    } else {
        for i in 0..hn {
            a[i] = a[i].square() + a[i + hn].square();
            a[i + hn] = FLR::ZERO;
        }
    }
}

// Multiply polynomial a with a real constant x.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_mulconst(logn: u32, a: &mut [FLR], x: FLR) {
    if logn >= 2 {
        let ap = transmute::<*mut FLR, *mut f64>(a.as_mut_ptr());
        let ym = _mm256_set1_pd(x.to_f64());
        for i in 0..(1usize << (logn - 2)) {
            let ya = _mm256_loadu_pd(ap.wrapping_add(i << 2));
            _mm256_storeu_pd(ap.wrapping_add(i << 2), _mm256_mul_pd(ya, ym));
        }
    } else {
        for i in 0..(1usize << logn) {
            a[i] *= x;
        }
    }
}

// Perform an LDL decomposition of a self-adjoint matrix G. The matrix
// is G = [[g00, g01], [adj(g01), g11]]; g00 and g11 are self-adjoint
// polynomials. The decomposition is G = L*D*adj(L), with:
//    D = [[g00, 0], [0, d11]]
//    L = [[1, 0], [l10, 1]]
// The output polynomials l10 and d11 are written over g01 and g11,
// respectively. Like g11, d11 is self-adjoint and uses only n/2
// coefficients. g00 is unmodified. All polynomials are in FFT
// representation.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_LDL_fft(logn: u32,
    g00: &[FLR], g01: &mut [FLR], g11: &mut [FLR])
{
    let hn = 1usize << (logn - 1);
    if logn >= 3 {
        let g00p = transmute::<*const FLR, *const f64>(g00.as_ptr());
        let g01p = transmute::<*mut FLR, *mut f64>(g01.as_mut_ptr());
        let g11p = transmute::<*mut FLR, *mut f64>(g11.as_mut_ptr());
        let one = _mm256_set1_pd(1.0);
        let mzero = _mm256_set1_pd(-0.0);
        for i in 0..(1usize << (logn - 3)) {
            let g00_re = _mm256_loadu_pd(g00p.wrapping_add(i << 2));
            let g01_re = _mm256_loadu_pd(g01p.wrapping_add(i << 2));
            let g01_im = _mm256_loadu_pd(g01p.wrapping_add((i << 2) + hn));
            let g11_re = _mm256_loadu_pd(g11p.wrapping_add(i << 2));
            let inv_g00_re = _mm256_div_pd(one, g00_re);
            let mu_re = _mm256_mul_pd(g01_re, inv_g00_re);
            let mu_im = _mm256_mul_pd(g01_im, inv_g00_re);
            let zo_re = _mm256_add_pd(
                _mm256_mul_pd(mu_re, g01_re),
                _mm256_mul_pd(mu_im, g01_im));
            _mm256_storeu_pd(g11p.wrapping_add(i << 2),
                _mm256_sub_pd(g11_re, zo_re));
            _mm256_storeu_pd(g01p.wrapping_add(i << 2), mu_re);
            _mm256_storeu_pd(g01p.wrapping_add((i << 2) + hn),
                _mm256_xor_pd(mu_im, mzero));
        }
    } else {
        for i in 0..hn {
            // g00 and g11 are self-adjoint
            let g00_re = g00[i];
            let (g01_re, g01_im) = (g01[i], g01[i + hn]);
            let g11_re = g11[i];
            let inv_g00_re = FLR::ONE / g00_re;
            let (mu_re, mu_im) = (g01_re * inv_g00_re, g01_im * inv_g00_re);
            let zo_re = mu_re * g01_re + mu_im * g01_im;
            g11[i] = g11_re - zo_re;
            g01[i] = mu_re;
            g01[i + hn] = -mu_im;
        }
    }
}

// Split operation on a polynomial: for input polynomial f, half-size
// polynomials f0 and f1 (modulo X^(n/2)+1) are such that
// f = f0(x^2) + x*f1(x^2). All polynomials are in FFT representation.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_split_fft(logn: u32,
    f0: &mut [FLR], f1: &mut [FLR], f: &[FLR])
{
    let hn = 1usize << (logn - 1);
    let qn = hn >> 1;

    if logn >= 3 {
        let n = 1usize << logn;
        let f0p = transmute::<*mut FLR, *mut f64>(f0.as_mut_ptr());
        let f1p = transmute::<*mut FLR, *mut f64>(f1.as_mut_ptr());
        let fp = transmute::<*const FLR, *const f64>(f.as_ptr());
        let gp = transmute::<*const FLR, *const f64>((&GM[..]).as_ptr());
        let yh = _mm256_set1_pd(0.5);
        let sv = _mm256_set_pd(-0.0, 0.0, -0.0, 0.0);
        for i in 0..(1usize << (logn - 3)) {
            // Elements "odd" and "even" are interleaved.
            let ab_re = _mm256_loadu_pd(fp.wrapping_add(i << 2));
            let ab_im = _mm256_loadu_pd(fp.wrapping_add((i << 2) + hn));

            let ff0 = _mm256_mul_pd(_mm256_hadd_pd(ab_re, ab_im), yh);
            let ff0 = _mm256_permute4x64_pd(ff0, 0xD8);
            _mm_storeu_pd(f0p.wrapping_add(i << 1),
                _mm256_extractf128_pd(ff0, 0));
            _mm_storeu_pd(f0p.wrapping_add((i << 1) + qn),
                _mm256_extractf128_pd(ff0, 1));

            let ff1 = _mm256_mul_pd(_mm256_hsub_pd(ab_re, ab_im), yh);
            let gmt = _mm256_loadu_pd(gp.wrapping_add((i << 2) + n));
            let ff2 = _mm256_shuffle_pd(ff1, ff1, 0x5);
            let ff3 = _mm256_hadd_pd(
                _mm256_mul_pd(ff1, gmt),
                _mm256_xor_pd(_mm256_mul_pd(ff2, gmt), sv));
            let ff3 = _mm256_permute4x64_pd(ff3, 0xD8);
            _mm_storeu_pd(f1p.wrapping_add(i << 1),
                _mm256_extractf128_pd(ff3, 0));
            _mm_storeu_pd(f1p.wrapping_add((i << 1) + qn),
                _mm256_extractf128_pd(ff3, 1));
        }
    } else {
        // If logn = 1 then the loop is entirely skipped.
        f0[0] = f[0];
        f1[0] = f[hn];

        for i in 0..qn {
            let (a_re, a_im) = (f[(i << 1) + 0], f[(i << 1) + 0 + hn]);
            let (b_re, b_im) = (f[(i << 1) + 1], f[(i << 1) + 1 + hn]);

            let (t_re, t_im) = (a_re + b_re, a_im + b_im);
            f0[i] = t_re.half();
            f0[i + qn] = t_im.half();

            let (t_re, t_im) = (a_re - b_re, a_im - b_im);
            let (u_re, u_im) = flc_mul(t_re, t_im,
                GM[((i + hn) << 1) + 0], -GM[((i + hn) << 1) + 1]);
            f1[i] = u_re.half();
            f1[i + qn] = u_im.half();
        }
    }
}

// Specialized version of poly_split_fft() when the source polynomial
// is self-adjoint (i.e. all its FFT coefficients are real). On output,
// f0 is self-adjoint, but f1 is not necessarily self-adjoint.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_split_selfadj_fft(logn: u32,
    f0: &mut [FLR], f1: &mut [FLR], f: &[FLR])
{
    let hn = 1usize << (logn - 1);
    let qn = hn >> 1;

    if logn >= 3 {
        let n = 1usize << logn;
        let f0p = transmute::<*mut FLR, *mut f64>(f0.as_mut_ptr());
        let f1p = transmute::<*mut FLR, *mut f64>(f1.as_mut_ptr());
        let fp = transmute::<*const FLR, *const f64>(f.as_ptr());
        let gp = transmute::<*const FLR, *const f64>((&GM[..]).as_ptr());
        let yh = _mm256_set1_pd(0.5);
        let sv = _mm256_set_pd(-0.0, 0.0, -0.0, 0.0);
        let zero = _mm256_set1_pd(0.0);
        let zero_x = _mm_set1_pd(0.0);
        for i in 0..(1usize << (logn - 3)) {
            // Elements "odd" and "even" are interleaved.
            let ab_re = _mm256_loadu_pd(fp.wrapping_add(i << 2));

            let ff0 = _mm256_mul_pd(_mm256_hadd_pd(ab_re, zero), yh);
            let ff0 = _mm256_permute4x64_pd(ff0, 0xD8);
            _mm_storeu_pd(f0p.wrapping_add(i << 1),
                _mm256_extractf128_pd(ff0, 0));
            _mm_storeu_pd(f0p.wrapping_add((i << 1) + qn), zero_x);

            let ff1 = _mm256_mul_pd(_mm256_hsub_pd(ab_re, zero), yh);
            let gmt = _mm256_loadu_pd(gp.wrapping_add((i << 2) + n));
            let ff2 = _mm256_shuffle_pd(ff1, ff1, 0x5);
            let ff3 = _mm256_hadd_pd(
                _mm256_mul_pd(ff1, gmt),
                _mm256_xor_pd(_mm256_mul_pd(ff2, gmt), sv));
            let ff3 = _mm256_permute4x64_pd(ff3, 0xD8);
            _mm_storeu_pd(f1p.wrapping_add(i << 1),
                _mm256_extractf128_pd(ff3, 0));
            _mm_storeu_pd(f1p.wrapping_add((i << 1) + qn),
                _mm256_extractf128_pd(ff3, 1));
        }
    } else {
        // If logn = 1 then the loop is entirely skipped.
        f0[0] = f[0];
        f1[0] = FLR::ZERO;

        for i in 0..qn {
            let a_re = f[(i << 1) + 0];
            let b_re = f[(i << 1) + 1];

            let t_re = a_re + b_re;
            f0[i] = t_re.half();
            f0[i + qn] = FLR::ZERO;

            let t_re = (a_re - b_re).half();
            f1[i] = t_re * GM[((i + hn) << 1) + 0];
            f1[i + qn] = t_re * -GM[((i + hn) << 1) + 1];
        }
    }
}

// Merge operation on a polynomial: for input half-size polynomials f0
// and f1 (modulo X^(n/2)+1), compute f = f0(x^2) + x*f1(x^2). All
// polynomials are in FFT representation.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn poly_merge_fft(logn: u32,
    f: &mut [FLR], f0: &[FLR], f1: &[FLR])
{
    let hn = 1usize << (logn - 1);
    let qn = hn >> 1;

    if logn >= 4 {
        let n = 1usize << logn;
        let fp = transmute::<*mut FLR, *mut f64>(f.as_mut_ptr());
        let f0p = transmute::<*const FLR, *const f64>(f0.as_ptr());
        let f1p = transmute::<*const FLR, *const f64>(f1.as_ptr());
        let gp = transmute::<*const FLR, *const f64>((&GM[..]).as_ptr());
        for i in 0..(1usize << (logn - 4)) {
            let a_re = _mm256_loadu_pd(f0p.wrapping_add(i << 2));
            let a_im = _mm256_loadu_pd(f0p.wrapping_add((i << 2) + qn));
            let c_re = _mm256_loadu_pd(f1p.wrapping_add(i << 2));
            let c_im = _mm256_loadu_pd(f1p.wrapping_add((i << 2) + qn));

            let gm1 = _mm256_loadu_pd(gp.wrapping_add((i << 3) + n));
            let gm2 = _mm256_loadu_pd(gp.wrapping_add((i << 3) + n + 4));
            let g_re = _mm256_unpacklo_pd(gm1, gm2);
            let g_im = _mm256_unpackhi_pd(gm1, gm2);
            let g_re = _mm256_permute4x64_pd(g_re, 0xD8);
            let g_im = _mm256_permute4x64_pd(g_im, 0xD8);

            let b_re = _mm256_sub_pd(
                _mm256_mul_pd(c_re, g_re),
                _mm256_mul_pd(c_im, g_im));
            let b_im = _mm256_add_pd(
                _mm256_mul_pd(c_re, g_im),
                _mm256_mul_pd(c_im, g_re));

            let t_re = _mm256_add_pd(a_re, b_re);
            let t_im = _mm256_add_pd(a_im, b_im);
            let u_re = _mm256_sub_pd(a_re, b_re);
            let u_im = _mm256_sub_pd(a_im, b_im);

            let tu1_re = _mm256_unpacklo_pd(t_re, u_re);
            let tu2_re = _mm256_unpackhi_pd(t_re, u_re);
            let tu1_im = _mm256_unpacklo_pd(t_im, u_im);
            let tu2_im = _mm256_unpackhi_pd(t_im, u_im);
            _mm256_storeu_pd(fp.wrapping_add(i << 3),
                _mm256_permute2f128_pd(tu1_re, tu2_re, 0x20));
            _mm256_storeu_pd(fp.wrapping_add((i << 3) + 4),
                _mm256_permute2f128_pd(tu1_re, tu2_re, 0x31));
            _mm256_storeu_pd(fp.wrapping_add((i << 3) + hn),
                _mm256_permute2f128_pd(tu1_im, tu2_im, 0x20));
            _mm256_storeu_pd(fp.wrapping_add((i << 3) + hn + 4),
                _mm256_permute2f128_pd(tu1_im, tu2_im, 0x31));
        }
    } else {
        // If logn = 1 then the loop is entirely skipped.
        f[0] = f0[0];
        f[hn] = f1[0];

        for i in 0..qn {
            let (a_re, a_im) = (f0[i], f0[i + qn]);
            let (b_re, b_im) = flc_mul(f1[i], f1[i + qn],
                GM[((i + hn) << 1) + 0], GM[((i + hn) << 1) + 1]);
            f[(i << 1) + 0] = a_re + b_re;
            f[(i << 1) + 0 + hn] = a_im + b_im;
            f[(i << 1) + 1] = a_re - b_re;
            f[(i << 1) + 1 + hn] = a_im - b_im;
        }
    }
}

// FFT constants are shared with the non-AVX2 module.
use crate::poly::GM;

#[cfg(test)]
mod tests {

    use super::*;
    use crate::flr::FLR;
    use fn_dsa_comm::shake::SHAKE256x4;

    fn rand_poly(rng: &mut SHAKE256x4, f: &mut [FLR]) {
        for i in 0..f.len() {
            f[i] = FLR::from_i64(((rng.next_u16() & 0x3FF) as i64) - 512);
        }
    }

    unsafe fn poly_inner(logn: u32) {
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut rng = SHAKE256x4::new(&[logn as u8]);
        let mut tmp = [FLR::ZERO; 5 * 1024];
        let (f, tmp) = tmp.split_at_mut(n);
        let (g, tmp) = tmp.split_at_mut(n);
        let (h, tmp) = tmp.split_at_mut(n);
        let (f0, tmp) = tmp.split_at_mut(hn);
        let (f1, tmp) = tmp.split_at_mut(hn);
        let (g0, tmp) = tmp.split_at_mut(hn);
        let (g1, _)   = tmp.split_at_mut(hn);
        for ctr in 0..(1u32 << (15 - logn)) {
            rand_poly(&mut rng, f);
            g.copy_from_slice(f);
            FFT(logn, g);
            iFFT(logn, g);
            for i in 0..n {
                assert!(f[i].rint() == g[i].rint());
            }

            if ctr < 5 {
                rand_poly(&mut rng, g);
                for i in 0..n {
                    h[i] = FLR::ZERO;
                }
                for i in 0..n {
                    for j in 0..n {
                        let s = f[i] * g[j];
                        let k = i + j;
                        if i + j < n {
                            h[k] += s;
                        } else {
                            h[k - n] -= s;
                        }
                    }
                }
                FFT(logn, f);
                FFT(logn, g);
                poly_mul_fft(logn, f, g);
                iFFT(logn, f);
                for i in 0..n {
                    assert!(f[i].rint() == h[i].rint());
                }
            }

            rand_poly(&mut rng, f);
            h.copy_from_slice(f);
            FFT(logn, f);
            poly_split_fft(logn, f0, f1, f);

            g0.copy_from_slice(f0);
            g1.copy_from_slice(f1);
            iFFT(logn - 1, g0);
            iFFT(logn - 1, g1);
            for i in 0..(n >> 1) {
                assert!(g0[i].rint() == h[2 * i].rint());
                assert!(g1[i].rint() == h[2 * i + 1].rint());
            }

            poly_merge_fft(logn, g, f0, f1);
            iFFT(logn, g);
            for i in 0..n {
                assert!(g[i].rint() == h[i].rint());
            }
        }
    }

    #[test]
    fn poly() {
        if fn_dsa_comm::has_avx2() {
            unsafe {
                for logn in 2..11 {
                    poly_inner(logn);
                }
            }
        }
    }
}
