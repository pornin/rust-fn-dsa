#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use super::flr::FLR;

// ========================================================================
// Floating-point polynomials
// ========================================================================

// We consider here polynomials in R[X]/(X^n+1), for n a power of two
// between 4 and 1024. We express n = 2^logn for logn in [2, 10]. For
// each such polynomial:
//
//   - The "normal representation" of f = \sum_{i=0}^{n-1} f_i*X^i is
//     the sequence (f_0, f_1, f_2, ... f_{n-1}) as a slice of size n.
//     Elements are FLR instances.
//
//   - The "FFT representation" consists of n/2 complex numbers; the
//     first n/2 elements are the real parts, and for i = 0 to n/2-1,
//     the element i+n/2 in the slice contains the imaginary part
//     corresponding to element i in the slice. Only n/2 complex numbers
//     are needed for the FFT representation because all polynomials
//     are real (in normal representation), making the FFT representation
//     redundant.
//
//   - If a polynomial is self-adjoint then its FFT representation itself
//     contains only real numbers, and the corresponding slice only
//     has n/2 elements; the remaining n/2 (the imaginary parts of the
//     FFT coefficients) are implicitly zero and are omitted.

// Complex multiplication.
#[allow(dead_code)]
#[inline(always)]
pub(crate) fn flc_mul(x_re: FLR, x_im: FLR, y_re: FLR, y_im: FLR)
    -> (FLR, FLR)
{
    (x_re * y_re - x_im * y_im, x_re * y_im + x_im * y_re)
}

/* unused
// Complex division.
#[inline(always)]
fn flc_div(x_re: FLR, x_im: FLR, y_re: FLR, y_im: FLR) -> (FLR, FLR) {
    let m = FLR::ONE / (y_re.square() + y_im.square());
    let b_re = m * y_re;
    let b_im = m * -y_im;
    flc_mul(x_re, x_im, b_re, b_im)
}
*/

// Convert a polynomial from normal representation to FFT.
pub(crate) fn FFT(logn: u32, f: &mut [FLR]) {
    // First iteration of the FFT algorithm would compute
    // f[j] + i*f[j + n/2] for all j < n/2; since this is exactly our
    // storage format for complex numbers in the FFT representation,
    // that first iteration is a no-op, hence we can start the computation
    // at the second iteration.

    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut t = hn;
        let ff: *mut f64 = transmute(f.as_mut_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        for lm in 1..(logn - 1) {
            let m = 1 << lm;
            let hm = m >> 1;
            let ht = t >> 1;
            let mut j0 = 0;
            for i in 0..hm {
                let s = _mm_loadu_pd(ggm.wrapping_add((m + i) << 1));
                let s_re = _mm_shuffle_pd(s, s, 0);
                let s_im = _mm_shuffle_pd(s, s, 3);
                for j in 0..(ht >> 1) {
                    let j1 = j0 + (j << 1);
                    let j2 = j1 + ht;
                    let x_re = _mm_loadu_pd(ff.wrapping_add(j1));
                    let x_im = _mm_loadu_pd(ff.wrapping_add(j1 + hn));
                    let y_re = _mm_loadu_pd(ff.wrapping_add(j2));
                    let y_im = _mm_loadu_pd(ff.wrapping_add(j2 + hn));
                    let z_re = _mm_sub_pd(
                        _mm_mul_pd(y_re, s_re),
                        _mm_mul_pd(y_im, s_im));
                    let z_im = _mm_add_pd(
                        _mm_mul_pd(y_im, s_re),
                        _mm_mul_pd(y_re, s_im));
                    _mm_storeu_pd(ff.wrapping_add(j1),
                        _mm_add_pd(x_re, z_re));
                    _mm_storeu_pd(ff.wrapping_add(j1 + hn),
                        _mm_add_pd(x_im, z_im));
                    _mm_storeu_pd(ff.wrapping_add(j2),
                        _mm_sub_pd(x_re, z_re));
                    _mm_storeu_pd(ff.wrapping_add(j2 + hn),
                        _mm_sub_pd(x_im, z_im));
                }
                j0 += t;
            }
            t = ht;
        }

        /* Last iteration: m = n/2, hm = n/4, t = 2, ht = 1 */
        if logn >= 2 {
            let cz = _mm_castsi128_pd(_mm_setr_epi32(0, 0, 0, -0x80000000));
            for i in 0..(hn >> 1) {
                let s = _mm_loadu_pd(ggm.wrapping_add(n + (i << 1)));
                let xy_re = _mm_loadu_pd(ff.wrapping_add(i << 1));
                let xy_im = _mm_loadu_pd(ff.wrapping_add((i << 1) + hn));
                let y1 = _mm_shuffle_pd(xy_re, xy_im, 3);
                let y2 = _mm_shuffle_pd(xy_im, xy_re, 3);
                let z_re = _mm_mul_pd(y1, s);
                let z_im = _mm_mul_pd(y2, s);
                let u_re = _mm_sub_pd(z_re, _mm_shuffle_pd(z_re, z_re, 1));
                let u_im = _mm_xor_pd(cz,
                    _mm_add_pd(z_im, _mm_shuffle_pd(z_im, z_im, 1)));
                let u_re = _mm_add_pd(u_re, _mm_shuffle_pd(xy_re, xy_re, 0));
                let u_im = _mm_add_pd(u_im, _mm_shuffle_pd(xy_im, xy_im, 0));
                _mm_storeu_pd(ff.wrapping_add(i << 1), u_re);
                _mm_storeu_pd(ff.wrapping_add((i << 1) + hn), u_im);
            }
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut t = hn;
        let ff: *mut f64 = transmute(f.as_mut_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        for lm in 1..(logn - 1) {
            let m = 1 << lm;
            let hm = m >> 1;
            let ht = t >> 1;
            let mut j0 = 0;
            for i in 0..hm {
                let s = vld1q_f64(ggm.wrapping_add((m + i) << 1));
                let s_re = vzip1q_f64(s, s);
                let s_im = vzip2q_f64(s, s);
                for j in 0..(ht >> 1) {
                    let j1 = j0 + (j << 1);
                    let j2 = j1 + ht;
                    let x_re = vld1q_f64(ff.wrapping_add(j1));
                    let x_im = vld1q_f64(ff.wrapping_add(j1 + hn));
                    let y_re = vld1q_f64(ff.wrapping_add(j2));
                    let y_im = vld1q_f64(ff.wrapping_add(j2 + hn));
                    let z_re = vsubq_f64(
                        vmulq_f64(y_re, s_re),
                        vmulq_f64(y_im, s_im));
                    let z_im = vaddq_f64(
                        vmulq_f64(y_im, s_re),
                        vmulq_f64(y_re, s_im));
                    vst1q_f64(ff.wrapping_add(j1), vaddq_f64(x_re, z_re));
                    vst1q_f64(ff.wrapping_add(j1 + hn), vaddq_f64(x_im, z_im));
                    vst1q_f64(ff.wrapping_add(j2), vsubq_f64(x_re, z_re));
                    vst1q_f64(ff.wrapping_add(j2 + hn), vsubq_f64(x_im, z_im));
                }
                j0 += t;
            }
            t = ht;
        }

        if logn >= 2 {
            let cz: uint64x2_t = transmute([FLR::ZERO, FLR::NZERO]);
            for i in 0..(hn >> 1) {
                let s = vld1q_f64(ggm.wrapping_add(n + (i << 1)));
                let xy_re = vld1q_f64(ff.wrapping_add(i << 1));
                let xy_im = vld1q_f64(ff.wrapping_add((i << 1) + hn));
                let y1 = vzip2q_f64(xy_re, xy_im);
                let y2 = vzip2q_f64(xy_im, xy_re);
                let z_re = vmulq_f64(y1, s);
                let z_im = vmulq_f64(y2, s);
                let u_re = vsubq_f64(z_re, vextq_f64(z_re, z_re, 1));
                let u_im = vreinterpretq_f64_u64(
                    veorq_u64(cz, vreinterpretq_u64_f64(
                        vaddq_f64(z_im, vextq_f64(z_im, z_im, 1)))));
                let u_re = vaddq_f64(u_re, vdupq_laneq_f64(xy_re, 0));
                let u_im = vaddq_f64(u_im, vdupq_laneq_f64(xy_im, 0));
                vst1q_f64(ff.wrapping_add(i << 1), u_re);
                vst1q_f64(ff.wrapping_add((i << 1) + hn), u_im);
            }
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut t = hn;
        for lm in 1..logn {
            let m = 1 << lm;
            let hm = m >> 1;
            let ht = t >> 1;
            let mut j0 = 0;
            for i in 0..hm {
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
                j0 += t;
            }
            t = ht;
        }
    }
}

// Convert a polynomial from FFT representation to normal.
pub(crate) fn iFFT(logn: u32, f: &mut [FLR]) {
    // This is the reverse of FFT. We use the fact that if
    // w = exp(i*k*pi/N), then 1/w is the conjugate of w; thus, we can
    // get inverses from the table GM[] itself by simply negating the
    // imaginary part.
    //
    // The last iteration is a no-op (like the first iteration in FFT).
    // Since the last iteration is skipped, we have to perform only
    // a division by n/2 at the end.

    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let ff: *mut f64 = transmute(f.as_mut_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        if logn >= 2 {
            let cz = _mm_castsi128_pd(_mm_setr_epi32(0, 0, 0, -0x80000000));
            for i in 0..(hn >> 1) {
                let s = _mm_loadu_pd(ggm.wrapping_add(n + (i << 1)));
                let sc = _mm_xor_pd(s, cz);
                let xy_re = _mm_loadu_pd(ff.wrapping_add(i << 1));
                let xy_im = _mm_loadu_pd(ff.wrapping_add((i << 1) + hn));
                let x = _mm_shuffle_pd(xy_re, xy_im, 0);
                let y = _mm_shuffle_pd(xy_re, xy_im, 3);
                let u = _mm_add_pd(x, y);
                let z = _mm_sub_pd(x, y);
                let v1 = _mm_mul_pd(z, s);
                let v2 = _mm_mul_pd(z, _mm_shuffle_pd(sc, sc, 1));
                let v = _mm_add_pd(
                    _mm_shuffle_pd(v1, v2, 2),
                    _mm_shuffle_pd(v1, v2, 1));
                _mm_storeu_pd(ff.wrapping_add(i << 1),
                    _mm_shuffle_pd(u, v, 0));
                _mm_storeu_pd(ff.wrapping_add((i << 1) + hn),
                    _mm_shuffle_pd(u, v, 3));
            }
        }

        let mut t = 2;
        for lm in 2..logn {
            let hm = 1 << (logn - lm);
            let dt = t << 1;
            let mut j0 = 0;
            for i in 0..(hm >> 1) {
                let s = _mm_loadu_pd(ggm.wrapping_add((hm + i) << 1));
                let s_re = _mm_shuffle_pd(s, s, 0);
                let s_im = _mm_shuffle_pd(s, s, 3);
                for j in 0..(t >> 1) {
                    let j1 = j0 + (j << 1);
                    let j2 = j1 + t;
                    let x_re = _mm_loadu_pd(ff.wrapping_add(j1));
                    let x_im = _mm_loadu_pd(ff.wrapping_add(j1 + hn));
                    let y_re = _mm_loadu_pd(ff.wrapping_add(j2));
                    let y_im = _mm_loadu_pd(ff.wrapping_add(j2 + hn));
                    _mm_storeu_pd(ff.wrapping_add(j1),
                        _mm_add_pd(x_re, y_re));
                    _mm_storeu_pd(ff.wrapping_add(j1 + hn),
                        _mm_add_pd(x_im, y_im));
                    let x_re = _mm_sub_pd(x_re, y_re);
                    let x_im = _mm_sub_pd(x_im, y_im);
                    let z_re = _mm_add_pd(
                        _mm_mul_pd(x_re, s_re),
                        _mm_mul_pd(x_im, s_im));
                    let z_im = _mm_sub_pd(
                        _mm_mul_pd(x_im, s_re),
                        _mm_mul_pd(x_re, s_im));
                    _mm_storeu_pd(ff.wrapping_add(j2), z_re);
                    _mm_storeu_pd(ff.wrapping_add(j2 + hn), z_im);
                }
                j0 += dt;
            }
            t = dt;
        }

        // We have logn-1 delayed halvings to perform, i.e. we must divide
        // all returned values by n/2.
        if logn >= 2 {
            // INV_POW2[i] = 1/(2^(i + 1))
            const INV_POW2: [f64; 9] = [
                0.50000000000000000000000000000000000000000,
                0.25000000000000000000000000000000000000000,
                0.12500000000000000000000000000000000000000,
                0.062500000000000000000000000000000000000000,
                0.031250000000000000000000000000000000000000,
                0.015625000000000000000000000000000000000000,
                0.0078125000000000000000000000000000000000000,
                0.0039062500000000000000000000000000000000000,
                0.0019531250000000000000000000000000000000000,
            ];
            let e = _mm_set1_pd(INV_POW2[(logn - 2) as usize]);
            for i in 0..hn {
                let x = _mm_loadu_pd(ff.wrapping_add(i << 1));
                let x = _mm_mul_pd(x, e);
                _mm_storeu_pd(ff.wrapping_add(i << 1), x);
            }
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let ff: *mut f64 = transmute(f.as_mut_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        if logn >= 2 {
            let cz: uint64x2_t = transmute([FLR::ZERO, FLR::NZERO]);
            for i in 0..(hn >> 1) {
                let s = vld1q_f64(ggm.wrapping_add(n + (i << 1)));
                let sc = vreinterpretq_f64_u64(
                    veorq_u64(cz, vreinterpretq_u64_f64(s)));
                let xy_re = vld1q_f64(ff.wrapping_add(i << 1));
                let xy_im = vld1q_f64(ff.wrapping_add((i << 1) + hn));
                let x = vzip1q_f64(xy_re, xy_im);
                let y = vzip2q_f64(xy_re, xy_im);
                let u = vaddq_f64(x, y);
                let z = vsubq_f64(x, y);
                let v1 = vmulq_f64(z, s);
                let v2 = vmulq_f64(z, vextq_f64(sc, sc, 1));
                let v = vpaddq_f64(v1, v2);
                vst1q_f64(ff.wrapping_add(i << 1), vzip1q_f64(u, v));
                vst1q_f64(ff.wrapping_add((i << 1) + hn), vzip2q_f64(u, v));
            }
        }

        let mut t = 2;
        for lm in 2..logn {
            let hm = 1 << (logn - lm);
            let dt = t << 1;
            let mut j0 = 0;
            for i in 0..(hm >> 1) {
                let s = vld1q_f64(ggm.wrapping_add((hm + i) << 1));
                let s_re = vzip1q_f64(s, s);
                let s_im = vzip2q_f64(s, s);
                for j in 0..(t >> 1) {
                    let j1 = j0 + (j << 1);
                    let j2 = j1 + t;
                    let x_re = vld1q_f64(ff.wrapping_add(j1));
                    let x_im = vld1q_f64(ff.wrapping_add(j1 + hn));
                    let y_re = vld1q_f64(ff.wrapping_add(j2));
                    let y_im = vld1q_f64(ff.wrapping_add(j2 + hn));
                    vst1q_f64(ff.wrapping_add(j1), vaddq_f64(x_re, y_re));
                    vst1q_f64(ff.wrapping_add(j1 + hn), vaddq_f64(x_im, y_im));
                    let x_re = vsubq_f64(x_re, y_re);
                    let x_im = vsubq_f64(x_im, y_im);
                    let z_re = vaddq_f64(
                        vmulq_f64(x_re, s_re),
                        vmulq_f64(x_im, s_im));
                    let z_im = vsubq_f64(
                        vmulq_f64(x_im, s_re),
                        vmulq_f64(x_re, s_im));
                    vst1q_f64(ff.wrapping_add(j2), z_re);
                    vst1q_f64(ff.wrapping_add(j2 + hn), z_im);
                }
                j0 += dt;
            }
            t = dt;
        }

        // We have logn-1 delayed halvings to perform, i.e. we must divide
        // all returned values by n/2.
        if logn >= 2 {
            // INV_POW2[i] = 1/(2^(i + 1))
            const INV_POW2: [f64; 9] = [
                0.50000000000000000000000000000000000000000,
                0.25000000000000000000000000000000000000000,
                0.12500000000000000000000000000000000000000,
                0.062500000000000000000000000000000000000000,
                0.031250000000000000000000000000000000000000,
                0.015625000000000000000000000000000000000000,
                0.0078125000000000000000000000000000000000000,
                0.0039062500000000000000000000000000000000000,
                0.0019531250000000000000000000000000000000000,
            ];
            let e = vdupq_n_f64(INV_POW2[(logn - 2) as usize]);
            for i in 0..hn {
                let x = vld1q_f64(ff.wrapping_add(i << 1));
                let x = vmulq_f64(x, e);
                vst1q_f64(ff.wrapping_add(i << 1), x);
            }
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut t = 1;
        for lm in 1..logn {
            let hm = 1 << (logn - lm);
            let dt = t << 1;
            let mut j0 = 0;
            for i in 0..(hm >> 1) {
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
                j0 += dt;
            }
            t = dt;
        }

        // We have logn-1 delayed halvings to perform, i.e. we must divide
        // all returned values by n/2.
        FLR::slice_div2e(&mut f[..n], logn - 1);
    }
}

// Set polynomial d from polynomial f with small coefficients.
pub(crate) fn poly_set_small(logn: u32, d: &mut [FLR], f: &[i8]) {
    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        assert!(logn >= 2);
        let dd: *mut f64 = transmute(d.as_mut_ptr());
        for i in 0..(1usize << (logn - 2)) {
            let x = _mm_setr_epi32(
                f[(i << 2) + 0] as i32,
                f[(i << 2) + 1] as i32,
                f[(i << 2) + 2] as i32,
                f[(i << 2) + 3] as i32);
            let y0 = _mm_cvtepi32_pd(x);
            let y1 = _mm_cvtepi32_pd(_mm_bsrli_si128(x, 8));
            _mm_storeu_pd(dd.wrapping_add(i << 2), y0);
            _mm_storeu_pd(dd.wrapping_add((i << 2) + 2), y1);
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        assert!(logn >= 2);
        let ff: *const i8 = transmute(f.as_ptr());
        let dd: *mut f64 = transmute(d.as_mut_ptr());
        if logn >= 3 {
            for i in 0..(1usize << (logn - 3)) {
                let x1 = vld1_s8(ff.wrapping_add(i << 3));
                let x2 = vmovl_s8(x1);
                let x30 = vmovl_s16(vget_low_s16(x2));
                let x31 = vmovl_high_s16(x2);
                let x40 = vmovl_s32(vget_low_s32(x30));
                let x41 = vmovl_high_s32(x30);
                let x42 = vmovl_s32(vget_low_s32(x31));
                let x43 = vmovl_high_s32(x31);

                let y0 = vcvtq_f64_s64(x40);
                let y1 = vcvtq_f64_s64(x41);
                let y2 = vcvtq_f64_s64(x42);
                let y3 = vcvtq_f64_s64(x43);
                vst1q_f64(dd.wrapping_add((i << 3) + 0), y0);
                vst1q_f64(dd.wrapping_add((i << 3) + 2), y1);
                vst1q_f64(dd.wrapping_add((i << 3) + 4), y2);
                vst1q_f64(dd.wrapping_add((i << 3) + 6), y3);
            }
        } else {
            for i in 0..4 {
                vst1_f64(dd.wrapping_add(i),
                    vcvt_f64_s64(vcreate_s64(f[i] as u64)));
            }
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        for i in 0..(1usize << logn) {
            d[i] = FLR::from_i32(f[i] as i32);
        }
    }
}

// Add polynomial b to polynomial a.
pub(crate) fn poly_add(logn: u32, a: &mut [FLR], b: &[FLR]) {
    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let bb: *const f64 = transmute(b.as_ptr());
        if logn >= 1 {
            for i in 0..(1usize << (logn - 1)) {
                let xa = _mm_loadu_pd(aa.wrapping_add(i << 1));
                let xb = _mm_loadu_pd(bb.wrapping_add(i << 1));
                _mm_storeu_pd(aa.wrapping_add(i << 1), _mm_add_pd(xa, xb));
            }
        } else {
            let xa = _mm_load_sd(aa);
            let xb = _mm_load_sd(bb);
            _mm_store_sd(aa, _mm_add_sd(xa, xb));
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let bb: *const f64 = transmute(b.as_ptr());
        if logn >= 1 {
            for i in 0..(1usize << (logn - 1)) {
                let xa = vld1q_f64(aa.wrapping_add(i << 1));
                let xb = vld1q_f64(bb.wrapping_add(i << 1));
                vst1q_f64(aa.wrapping_add(i << 1), vaddq_f64(xa, xb));
            }
        } else {
            let xa = vld1_f64(aa);
            let xb = vld1_f64(bb);
            vst1_f64(aa, vadd_f64(xa, xb));
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        for i in 0..(1usize << logn) {
            a[i] += b[i];
        }
    }
}

// Subtract polynomial b from polynomial a.
pub(crate) fn poly_sub(logn: u32, a: &mut [FLR], b: &[FLR]) {
    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let bb: *const f64 = transmute(b.as_ptr());
        if logn >= 1 {
            for i in 0..(1usize << (logn - 1)) {
                let xa = _mm_loadu_pd(aa.wrapping_add(i << 1));
                let xb = _mm_loadu_pd(bb.wrapping_add(i << 1));
                _mm_storeu_pd(aa.wrapping_add(i << 1), _mm_sub_pd(xa, xb));
            }
        } else {
            let xa = _mm_load_sd(aa);
            let xb = _mm_load_sd(bb);
            _mm_store_sd(aa, _mm_sub_sd(xa, xb));
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let bb: *const f64 = transmute(b.as_ptr());
        if logn >= 1 {
            for i in 0..(1usize << (logn - 1)) {
                let xa = vld1q_f64(aa.wrapping_add(i << 1));
                let xb = vld1q_f64(bb.wrapping_add(i << 1));
                vst1q_f64(aa.wrapping_add(i << 1), vsubq_f64(xa, xb));
            }
        } else {
            let xa = vld1_f64(aa);
            let xb = vld1_f64(bb);
            vst1_f64(aa, vsub_f64(xa, xb));
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        for i in 0..(1usize << logn) {
            a[i] -= b[i];
        }
    }
}

// Negate polynomial a.
pub(crate) fn poly_neg(logn: u32, a: &mut [FLR]) {
    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let xnz: __m128d = transmute([FLR::NZERO, FLR::NZERO]);
        if logn >= 1 {
            for i in 0..(1usize << (logn - 1)) {
                let xa = _mm_loadu_pd(aa.wrapping_add(i << 1));
                _mm_storeu_pd(aa.wrapping_add(i << 1), _mm_xor_pd(xnz, xa));
            }
        } else {
            let xa = _mm_load_sd(aa);
            _mm_store_sd(aa, _mm_xor_pd(xnz, xa));
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        if logn >= 1 {
            for i in 0..(1usize << (logn - 1)) {
                let xa = vld1q_f64(aa.wrapping_add(i << 1));
                vst1q_f64(aa.wrapping_add(i << 1), vnegq_f64(xa));
            }
        } else {
            let xa = vld1_f64(aa);
            vst1_f64(aa, vneg_f64(xa));
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        for i in 0..(1usize << logn) {
            a[i] = -a[i];
        }
    }
}

/* unused
// Replace polynomial a with its Hermitian adjoint adj(a). The polynomial
// must be in FFT representation.
pub(crate) fn poly_adj_fft(logn: u32, a: &mut [FLR]) {
    let n = 1usize << logn;
    for i in (n >> 1)..n {
        a[i] = -a[i];
    }
}
*/

// Multiply polynomial a with polynomial b. The polynomials must be in
// FFT representation.
pub(crate) fn poly_mul_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let bb: *const f64 = transmute(b.as_ptr());
        if logn >= 2 {
            let hn = 1usize << (logn - 1);
            for i in 0..(1usize << (logn - 2)) {
                let xar = _mm_loadu_pd(aa.wrapping_add(i << 1));
                let xai = _mm_loadu_pd(aa.wrapping_add((i << 1) + hn));
                let xbr = _mm_loadu_pd(bb.wrapping_add(i << 1));
                let xbi = _mm_loadu_pd(bb.wrapping_add((i << 1) + hn));
                let xcr = _mm_sub_pd(
                    _mm_mul_pd(xar, xbr),
                    _mm_mul_pd(xai, xbi));
                let xci = _mm_add_pd(
                    _mm_mul_pd(xai, xbr),
                    _mm_mul_pd(xar, xbi));
                _mm_storeu_pd(aa.wrapping_add(i << 1), xcr);
                _mm_storeu_pd(aa.wrapping_add((i << 1) + hn), xci);
            }
        } else {
            let xa = _mm_loadu_pd(aa);
            let xb = _mm_loadu_pd(bb);
            let x1 = _mm_mul_pd(xa, xb);
            let x2 = _mm_mul_pd(xa, _mm_shuffle_pd(xb, xb, 1));
            let xcr = _mm_sub_pd(x1, _mm_shuffle_pd(x1, x1, 1));
            let xci = _mm_add_pd(x2, _mm_shuffle_pd(x2, x2, 1));
            let xc = _mm_shuffle_pd(xcr, xci, 0);
            _mm_storeu_pd(aa, xc);
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let bb: *const f64 = transmute(b.as_ptr());
        if logn >= 2 {
            let hn = 1usize << (logn - 1);
            for i in 0..(1usize << (logn - 2)) {
                let xar = vld1q_f64(aa.wrapping_add(i << 1));
                let xai = vld1q_f64(aa.wrapping_add((i << 1) + hn));
                let xbr = vld1q_f64(bb.wrapping_add(i << 1));
                let xbi = vld1q_f64(bb.wrapping_add((i << 1) + hn));
                let xcr = vsubq_f64(
                    vmulq_f64(xar, xbr),
                    vmulq_f64(xai, xbi));
                let xci = vaddq_f64(
                    vmulq_f64(xai, xbr),
                    vmulq_f64(xar, xbi));
                vst1q_f64(aa.wrapping_add(i << 1), xcr);
                vst1q_f64(aa.wrapping_add((i << 1) + hn), xci);
            }
        } else {
            let cz: uint64x2_t = transmute([FLR::ZERO, FLR::NZERO]);
            let xa = vld1q_f64(aa);
            let xb = vld1q_f64(bb);
            let xcr = vmulq_f64(xa, xb);
            let xci = vmulq_f64(xa, vextq_f64(xb, xb, 1));
            let xcr = vreinterpretq_f64_u64(
                veorq_u64(vreinterpretq_u64_f64(xcr), cz));
            let xc = vpaddq_f64(xcr, xci);
            vst1q_f64(aa, xc);
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            let (re, im) = flc_mul(a[i], a[i + hn], b[i], b[i + hn]);
            a[i] = re;
            a[i + hn] = im;
        }
    }
}

// Multiply polynomial a with the adjoint of polynomial b. The polynomials
// must be in FFT representation.
pub(crate) fn poly_muladj_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let bb: *const f64 = transmute(b.as_ptr());
        if logn >= 2 {
            let hn = 1usize << (logn - 1);
            for i in 0..(1usize << (logn - 2)) {
                let xar = _mm_loadu_pd(aa.wrapping_add(i << 1));
                let xai = _mm_loadu_pd(aa.wrapping_add((i << 1) + hn));
                let xbr = _mm_loadu_pd(bb.wrapping_add(i << 1));
                let xbi = _mm_loadu_pd(bb.wrapping_add((i << 1) + hn));
                let xcr = _mm_add_pd(
                    _mm_mul_pd(xar, xbr),
                    _mm_mul_pd(xai, xbi));
                let xci = _mm_sub_pd(
                    _mm_mul_pd(xai, xbr),
                    _mm_mul_pd(xar, xbi));
                _mm_storeu_pd(aa.wrapping_add(i << 1), xcr);
                _mm_storeu_pd(aa.wrapping_add((i << 1) + hn), xci);
            }
        } else {
            let xa = _mm_loadu_pd(aa);
            let xb = _mm_loadu_pd(bb);
            let x1 = _mm_mul_pd(xa, xb);
            let x2 = _mm_mul_pd(xa, _mm_shuffle_pd(xb, xb, 1));
            let xcr = _mm_add_pd(x1, _mm_shuffle_pd(x1, x1, 1));
            let xci = _mm_sub_pd(x2, _mm_shuffle_pd(x2, x2, 1));
            let xc = _mm_shuffle_pd(xcr, xci, 2);
            _mm_storeu_pd(aa, xc);
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let bb: *const f64 = transmute(b.as_ptr());
        if logn >= 2 {
            let hn = 1usize << (logn - 1);
            for i in 0..(1usize << (logn - 2)) {
                let xar = vld1q_f64(aa.wrapping_add(i << 1));
                let xai = vld1q_f64(aa.wrapping_add((i << 1) + hn));
                let xbr = vld1q_f64(bb.wrapping_add(i << 1));
                let xbi = vld1q_f64(bb.wrapping_add((i << 1) + hn));
                let xcr = vaddq_f64(
                    vmulq_f64(xar, xbr),
                    vmulq_f64(xai, xbi));
                let xci = vsubq_f64(
                    vmulq_f64(xai, xbr),
                    vmulq_f64(xar, xbi));
                vst1q_f64(aa.wrapping_add(i << 1), xcr);
                vst1q_f64(aa.wrapping_add((i << 1) + hn), xci);
            }
        } else {
            let cz: uint64x2_t = transmute([FLR::ZERO, FLR::NZERO]);
            let xa = vld1q_f64(aa);
            let xb = vld1q_f64(bb);
            let xcr = vmulq_f64(xa, xb);
            let xb = vreinterpretq_f64_u64(
                veorq_u64(vreinterpretq_u64_f64(xb), cz));
            let xci = vmulq_f64(xa, vextq_f64(xb, xb, 1));
            let xc = vpaddq_f64(xcr, xci);
            vst1q_f64(aa, xc);
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        let hn = 1usize << (logn - 1);
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
pub(crate) fn poly_mulownadj_fft(logn: u32, a: &mut [FLR]) {
    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let xz = _mm_setzero_pd();
        if logn >= 2 {
            let hn = 1usize << (logn - 1);
            for i in 0..(1usize << (logn - 2)) {
                let xar = _mm_loadu_pd(aa.wrapping_add(i << 1));
                let xai = _mm_loadu_pd(aa.wrapping_add((i << 1) + hn));
                let xcr = _mm_add_pd(
                    _mm_mul_pd(xar, xar),
                    _mm_mul_pd(xai, xai));
                _mm_storeu_pd(aa.wrapping_add(i << 1), xcr);
                _mm_storeu_pd(aa.wrapping_add((i << 1) + hn), xz);
            }
        } else {
            let xa = _mm_loadu_pd(aa);
            let x1 = _mm_mul_pd(xa, xa);
            let xcr = _mm_add_pd(x1, _mm_shuffle_pd(x1, x1, 1));
            let xc = _mm_shuffle_pd(xcr, xz, 2);
            _mm_storeu_pd(aa, xc);
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let xz = vdupq_lane_f64(vcreate_f64(0), 0);
        if logn >= 2 {
            let hn = 1usize << (logn - 1);
            for i in 0..(1usize << (logn - 2)) {
                let xar = vld1q_f64(aa.wrapping_add(i << 1));
                let xai = vld1q_f64(aa.wrapping_add((i << 1) + hn));
                let xcr = vaddq_f64(
                    vmulq_f64(xar, xar),
                    vmulq_f64(xai, xai));
                vst1q_f64(aa.wrapping_add(i << 1), xcr);
                vst1q_f64(aa.wrapping_add((i << 1) + hn), xz);
            }
        } else {
            let xa = vld1q_f64(aa);
            let xcr = vmulq_f64(xa, xa);
            let xc = vpaddq_f64(xcr, xz);
            vst1q_f64(aa, xc);
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            a[i] = a[i].square() + a[i + hn].square();
            a[i + hn] = FLR::ZERO;
        }
    }
}

// Multiply polynomial a with a real constant x.
pub(crate) fn poly_mulconst(logn: u32, a: &mut [FLR], x: FLR) {
    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let xf: f64 = transmute(x);
        let xx = _mm_set1_pd(xf);
        if logn >= 1 {
            for i in 0..(1usize << (logn - 1)) {
                let xa = _mm_loadu_pd(aa.wrapping_add(i << 1));
                _mm_storeu_pd(aa.wrapping_add(i << 1), _mm_mul_pd(xa, xx));
            }
        } else {
            let xa = _mm_load_sd(aa);
            _mm_store_sd(aa, _mm_mul_sd(xa, xx));
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let aa: *mut f64 = transmute(a.as_mut_ptr());
        let x1: float64x1_t = transmute(x);
        if logn >= 2 {
            let x2 = vdupq_lane_f64(x1, 0);
            for i in 0..(1usize << (logn - 1)) {
                let xa = vld1q_f64(aa.wrapping_add(i << 1));
                vst1q_f64(aa.wrapping_add(i << 1), vmulq_f64(xa, x2));
            }
        } else {
            let xa = vld1_f64(aa);
            vst1_f64(aa, vmul_f64(xa, x1));
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        for i in 0..(1usize << logn) {
            a[i] *= x;
        }
    }
}

/* unused
// Divide polynomial a by polynomial b. The polynomials MUST be in FFT
// representation.
pub(crate) fn poly_div_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let (re, im) = flc_div(a[i], a[i + hn], b[i], b[i + hn]);
        a[i] = re;
        a[i + hn] = im;
    }
}
*/

/* unused
// Set polynomial d to 1/(f*adj(f) + g*adj(g)). All polynomials are in
// FFT representation. Since the output d is self-adjoint, only its
// first n/2 coefficients are set; the other n/2 coefficients are
// implicitly zero, but need not exist in the destination slice.
pub(crate) fn poly_invnorm2_fft(logn: u32,
    d: &mut [FLR], f: &[FLR], g: &[FLR])
{
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let nf = f[i].square() + f[i + hn].square();
        let ng = g[i].square() + g[i + hn].square();
        d[i] = FLR::ONE / (nf + ng);
    }
}
*/

/* unused
// Given polynomial F, G, f and g, set d to F*adj(f) + G*adj(g). All
// polynomials are in FFT representation.
pub(crate) fn poly_add_muladj_fft(logn: u32,
    d: &mut [FLR], F: &[FLR], G: &[FLR], f: &[FLR], g: &[FLR])
{
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let (a_re, a_im) = flc_mul(F[i], F[i + hn], f[i], f[i + hn]);
        let (b_re, b_im) = flc_mul(G[i], G[i + hn], g[i], g[i + hn]);
        d[i] = a_re + b_re;
        d[i + hn] = a_im + b_im;
    }
}
*/

/* unused
// Multiply polynomial a by polynomial b, where b is self-adjoint. Only
// the first n/2 coefficients of b are accessed. All polynomials are in
// FFT representation.
pub(crate) fn poly_mul_selfadj_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        a[i] *= b[i];
        a[i + hn] *= b[i];
    }
}
*/

/* unused
// Divide polynomial a by polynomial b, where b is self-adjoint. Only
// the first n/2 coefficients of b are accessed. All polynomials are in
// FFT representation.
pub(crate) fn poly_div_selfadj_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let x = FLR::ONE / b[i];
        a[i] *= x;
        a[i + hn] *= x;
    }
}
*/

// Perform an LDL decomposition of a self-adjoint matrix G. The matrix
// is G = [[g00, g01], [adj(g01), g11]]; g00 and g11 are self-adjoint
// polynomials. The decomposition is G = L*D*adj(L), with:
//    D = [[g00, 0], [0, d11]]
//    L = [[1, 0], [l10, 1]]
// The output polynomials l10 and d11 are written over g01 and g11,
// respectively. Like g11, d11 is self-adjoint and uses only n/2
// coefficients. g00 is unmodified. All polynomials are in FFT
// representation.
pub(crate) fn poly_LDL_fft(logn: u32,
    g00: &[FLR], g01: &mut [FLR], g11: &mut [FLR])
{
    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let hn = 1usize << (logn - 1);
        let one: __m128d = transmute([FLR::ONE, FLR::ONE]);
        let nz: __m128d = transmute([FLR::NZERO, FLR::NZERO]);
        let gg00: *const f64 = transmute(g00.as_ptr());
        let gg01: *mut f64 = transmute(g01.as_mut_ptr());
        let gg11: *mut f64 = transmute(g11.as_mut_ptr());
        if logn >= 2 {
            for i in 0..(1usize << (logn - 2)) {
                let g00_re = _mm_loadu_pd(gg00.wrapping_add(i << 1));
                let g01_re = _mm_loadu_pd(gg01.wrapping_add(i << 1));
                let g01_im = _mm_loadu_pd(gg01.wrapping_add((i << 1) + hn));
                let g11_re = _mm_loadu_pd(gg11.wrapping_add(i << 1));
                let inv_g00_re = _mm_div_pd(one, g00_re);
                let mu_re = _mm_mul_pd(g01_re, inv_g00_re);
                let mu_im = _mm_mul_pd(g01_im, inv_g00_re);
                let zo_re = _mm_add_pd(
                    _mm_mul_pd(mu_re, g01_re),
                    _mm_mul_pd(mu_im, g01_im));
                _mm_storeu_pd(gg11.wrapping_add(i << 1),
                    _mm_sub_pd(g11_re, zo_re));
                _mm_storeu_pd(gg01.wrapping_add(i << 1),
                    mu_re);
                _mm_storeu_pd(gg01.wrapping_add((i << 1) + hn),
                    _mm_xor_pd(nz, mu_im));
            }
        } else {
            let g00_re = _mm_load_sd(gg00);
            let g01_re = _mm_load_sd(gg01);
            let g01_im = _mm_load_sd(gg01.wrapping_add(1));
            let g11_re = _mm_load_sd(gg11);
            let inv_g00_re = _mm_div_sd(one, g00_re);
            let mu_re = _mm_mul_sd(g01_re, inv_g00_re);
            let mu_im = _mm_mul_sd(g01_im, inv_g00_re);
            let zo_re = _mm_add_sd(
                _mm_mul_sd(mu_re, g01_re),
                _mm_mul_sd(mu_im, g01_im));
            _mm_store_sd(gg11, _mm_sub_sd(g11_re, zo_re));
            _mm_store_sd(gg01, mu_re);
            _mm_store_sd(gg01.wrapping_add(1), _mm_xor_pd(nz, mu_im));
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let hn = 1usize << (logn - 1);
        let gg00: *const f64 = transmute(g00.as_ptr());
        let gg01: *mut f64 = transmute(g01.as_mut_ptr());
        let gg11: *mut f64 = transmute(g11.as_mut_ptr());
        if logn >= 2 {
            let one: float64x2_t = transmute([FLR::ONE, FLR::ONE]);
            for i in 0..(1usize << (logn - 2)) {
                let g00_re = vld1q_f64(gg00.wrapping_add(i << 1));
                let g01_re = vld1q_f64(gg01.wrapping_add(i << 1));
                let g01_im = vld1q_f64(gg01.wrapping_add((i << 1) + hn));
                let g11_re = vld1q_f64(gg11.wrapping_add(i << 1));
                let inv_g00_re = vdivq_f64(one, g00_re);
                let mu_re = vmulq_f64(g01_re, inv_g00_re);
                let mu_im = vmulq_f64(g01_im, inv_g00_re);
                let zo_re = vaddq_f64(
                    vmulq_f64(mu_re, g01_re),
                    vmulq_f64(mu_im, g01_im));
                vst1q_f64(gg11.wrapping_add(i << 1), vsubq_f64(g11_re, zo_re));
                vst1q_f64(gg01.wrapping_add(i << 1), mu_re);
                vst1q_f64(gg01.wrapping_add((i << 1) + hn), vnegq_f64(mu_im));
            }
        } else {
            let one: float64x1_t = transmute(FLR::ONE);
            let g00_re = vld1_f64(gg00);
            let g01_re = vld1_f64(gg01);
            let g01_im = vld1_f64(gg01.wrapping_add(1));
            let g11_re = vld1_f64(gg11);
            let inv_g00_re = vdiv_f64(one, g00_re);
            let mu_re = vmul_f64(g01_re, inv_g00_re);
            let mu_im = vmul_f64(g01_im, inv_g00_re);
            let zo_re = vadd_f64(
                vmul_f64(mu_re, g01_re),
                vmul_f64(mu_im, g01_im));
            vst1_f64(gg11, vsub_f64(g11_re, zo_re));
            vst1_f64(gg01, mu_re);
            vst1_f64(gg01.wrapping_add(1), vneg_f64(mu_im));
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        let hn = 1usize << (logn - 1);
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

/* unused
// This is identical to poly_LDL_fft() except that the output polynomials
// l10 and d11 are written into separate output buffers instead of
// overwriting the provided g01 and g11.
pub(crate) fn poly_LDLmv_fft(logn: u32,
    d11: &mut [FLR], l10: &mut [FLR], g00: &[FLR], g01: &[FLR], g11: &[FLR])
{
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let (g00_re, g00_im) = (g00[i], g00[i + hn]);
        let (g01_re, g01_im) = (g01[i], g01[i + hn]);
        let (g11_re, g11_im) = (g11[i], g11[i + hn]);
        let (mu_re, mu_im) = flc_div(g01_re, g01_im, g00_re, g00_im);
        let (zo_re, zo_im) = flc_mul(mu_re, mu_im, g01_re, -g01_im);
        d11[i] = g11_re - zo_re;
        d11[i + hn] = g11_im - zo_im;
        l10[i] = mu_re;
        l10[i + hn] = -mu_im;
    }
}
*/

// Split operation on a polynomial: for input polynomial f, half-size
// polynomials f0 and f1 (modulo X^(n/2)+1) are such that
// f = f0(x^2) + x*f1(x^2). All polynomials are in FFT representation.
pub(crate) fn poly_split_fft(logn: u32,
    f0: &mut [FLR], f1: &mut [FLR], f: &[FLR])
{
    // If logn = 1 then the loop is entirely skipped.
    if logn == 1 {
        f0[0] = f[0];
        f1[0] = f[1];
        return;
    }

    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        let h: __m128d = transmute([
            FLR::scaled(4503599627370496, -53),
            FLR::scaled(4503599627370496, -53),
        ]);
        let ff: *const f64 = transmute(f.as_ptr());
        let ff0: *mut f64 = transmute(f0.as_mut_ptr());
        let ff1: *mut f64 = transmute(f1.as_mut_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        let cz: __m128d = transmute([FLR::ZERO, FLR::NZERO]);
        for i in 0..qn {
            let ab_re = _mm_loadu_pd(ff.wrapping_add(i << 1));
            let ab_im = _mm_loadu_pd(ff.wrapping_add((i << 1) + hn));
            let a = _mm_shuffle_pd(ab_re, ab_im, 0);
            let b = _mm_shuffle_pd(ab_re, ab_im, 3);
            let u = _mm_add_pd(a, b);
            let v = _mm_sub_pd(a, b);
            let s = _mm_loadu_pd(ggm.wrapping_add((i + hn) << 1));
            let sc = _mm_xor_pd(s, cz);
            let w1 = _mm_mul_pd(v, s);
            let w2 = _mm_mul_pd(v, _mm_shuffle_pd(sc, sc, 1));
            let w = _mm_add_pd(
                _mm_shuffle_pd(w1, w2, 0),
                _mm_shuffle_pd(w1, w2, 3));
            let u = _mm_mul_pd(u, h);
            let w = _mm_mul_pd(w, h);
            _mm_store_sd(ff0.wrapping_add(i), u);
            _mm_store_sd(ff0.wrapping_add(i + qn), _mm_shuffle_pd(u, u, 1));
            _mm_store_sd(ff1.wrapping_add(i), w);
            _mm_store_sd(ff1.wrapping_add(i + qn), _mm_shuffle_pd(w, w, 1));
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        let h: float64x2_t = transmute([
            FLR::scaled(4503599627370496, -53),
            FLR::scaled(4503599627370496, -53),
        ]);
        let ff: *const f64 = transmute(f.as_ptr());
        let ff0: *mut f64 = transmute(f0.as_mut_ptr());
        let ff1: *mut f64 = transmute(f1.as_mut_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        let cz: uint64x2_t = transmute([FLR::ZERO, FLR::NZERO]);
        for i in 0..qn {
            let ab_re = vld1q_f64(ff.wrapping_add(i << 1));
            let ab_im = vld1q_f64(ff.wrapping_add((i << 1) + hn));
            let a = vzip1q_f64(ab_re, ab_im);
            let b = vzip2q_f64(ab_re, ab_im);
            let u = vaddq_f64(a, b);
            let v = vsubq_f64(a, b);
            let s = vld1q_f64(ggm.wrapping_add((i + hn) << 1));
            let sc = vreinterpretq_f64_u64(
                veorq_u64(vreinterpretq_u64_f64(s), cz));
            let w1 = vmulq_f64(v, s);
            let w2 = vmulq_f64(v, vextq_f64(sc, sc, 1));
            let w = vaddq_f64(
                vzip1q_f64(w1, w2),
                vzip2q_f64(w1, w2));
            let u = vmulq_f64(u, h);
            let w = vmulq_f64(w, h);
            vst1_f64(ff0.wrapping_add(i), vget_low_f64(u));
            vst1_f64(ff0.wrapping_add(i + qn), vget_high_f64(u)); 
            vst1_f64(ff1.wrapping_add(i), vget_low_f64(w));
            vst1_f64(ff1.wrapping_add(i + qn), vget_high_f64(w));
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
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
pub(crate) fn poly_split_selfadj_fft(logn: u32,
    f0: &mut [FLR], f1: &mut [FLR], f: &[FLR])
{
    // If logn = 1 then the loop is entirely skipped.
    if logn == 1 {
        f0[0] = f[0];
        f1[0] = FLR::ZERO;
        return;
    }

    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        let h: __m128d = transmute([
            FLR::scaled(4503599627370496, -53),
            FLR::scaled(4503599627370496, -53),
        ]);
        let ff: *const f64 = transmute(f.as_ptr());
        let ff0: *mut f64 = transmute(f0.as_mut_ptr());
        let ff1: *mut f64 = transmute(f1.as_mut_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        for i in 0..qn {
            let ab_re = _mm_loadu_pd(ff.wrapping_add(i << 1));
            let t = _mm_shuffle_pd(ab_re, ab_re, 1);
            let u = _mm_mul_pd(h, _mm_add_pd(ab_re, t));
            let v = _mm_mul_pd(h, _mm_sub_pd(ab_re, t));
            let s = _mm_loadu_pd(ggm.wrapping_add((i + hn) << 1));
            let w = _mm_mul_pd(v, s);
            _mm_store_sd(ff0.wrapping_add(i), u);
            _mm_store_sd(ff0.wrapping_add(i + qn), _mm_setzero_pd());
            _mm_store_sd(ff1.wrapping_add(i), w);
            _mm_store_sd(ff1.wrapping_add(i + qn), _mm_shuffle_pd(w, w, 1));
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        let h: float64x2_t = transmute([
            FLR::scaled(4503599627370496, -53),
            FLR::scaled(4503599627370496, -53),
        ]);
        let ff: *const f64 = transmute(f.as_ptr());
        let ff0: *mut f64 = transmute(f0.as_mut_ptr());
        let ff1: *mut f64 = transmute(f1.as_mut_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        let z1 = vcreate_f64(0);
        for i in 0..qn {
            let ab_re = vld1q_f64(ff.wrapping_add(i << 1));
            let t = vextq_f64(ab_re, ab_re, 1);
            let u = vmulq_f64(h, vaddq_f64(ab_re, t));
            let v = vmulq_f64(h, vsubq_f64(ab_re, t));
            let s = vld1q_f64(ggm.wrapping_add((i + hn) << 1));
            let w = vmulq_f64(v, s);
            vst1_f64(ff0.wrapping_add(i), vget_low_f64(u));
            vst1_f64(ff0.wrapping_add(i + qn), z1);
            vst1_f64(ff1.wrapping_add(i), vget_low_f64(w));
            vst1_f64(ff1.wrapping_add(i + qn), vget_high_f64(w));
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
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
pub(crate) fn poly_merge_fft(logn: u32,
    f: &mut [FLR], f0: &[FLR], f1: &[FLR])
{
    // If logn = 1 then the loop is entirely skipped.
    if logn == 1 {
        f[0] = f0[0];
        f[1] = f1[0];
        return;
    }

    #[cfg(target_feature = "sse2")]
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        use core::mem::transmute;

        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        let ff: *mut f64 = transmute(f.as_mut_ptr());
        let ff0: *const f64 = transmute(f0.as_ptr());
        let ff1: *const f64 = transmute(f1.as_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        let cz: __m128d = transmute([FLR::ZERO, FLR::NZERO]);
        for i in 0..qn {
            let a_re = _mm_load_sd(ff0.wrapping_add(i));
            let a_im = _mm_load_sd(ff0.wrapping_add(i + qn));
            let b_re = _mm_load_sd(ff1.wrapping_add(i));
            let b_im = _mm_load_sd(ff1.wrapping_add(i + qn));
            let s = _mm_loadu_pd(ggm.wrapping_add((i + hn) << 1));
            let c1 = _mm_mul_pd(s, _mm_shuffle_pd(b_re, b_im, 0));
            let c2 = _mm_mul_pd(s, _mm_shuffle_pd(b_im, b_re, 0));
            let c_re = _mm_sub_pd(c1, _mm_shuffle_pd(c1, c1, 1));
            let c_im = _mm_xor_pd(cz,
                _mm_add_pd(c2, _mm_shuffle_pd(c2, c2, 1)));
            _mm_storeu_pd(ff.wrapping_add(i << 1),
                _mm_add_pd(c_re, _mm_shuffle_pd(a_re, a_re, 0)));
            _mm_storeu_pd(ff.wrapping_add((i << 1) + hn),
                _mm_add_pd(c_im, _mm_shuffle_pd(a_im, a_im, 0)));
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    unsafe {
        use core::arch::aarch64::*;
        use core::mem::transmute;

        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        let ff: *mut f64 = transmute(f.as_mut_ptr());
        let ff0: *const f64 = transmute(f0.as_ptr());
        let ff1: *const f64 = transmute(f1.as_ptr());
        let ggm: *const f64 = transmute((&GM).as_ptr());
        let cz: uint64x2_t = transmute([FLR::ZERO, FLR::NZERO]);
        for i in 0..qn {
            let a_re = vld1_f64(ff0.wrapping_add(i));
            let a_im = vld1_f64(ff0.wrapping_add(i + qn));
            let b_re = vld1_f64(ff1.wrapping_add(i));
            let b_im = vld1_f64(ff1.wrapping_add(i + qn));
            let b = vcombine_f64(b_re, b_im);
            let s = vld1q_f64(ggm.wrapping_add((i + hn) << 1));
            let c1 = vmulq_f64(s, b);
            let c2 = vmulq_f64(s, vextq_f64(b, b, 1));
            let c_re = vsubq_f64(c1, vextq_f64(c1, c1, 1));
            let c_im = vreinterpretq_f64_u64(
                veorq_u64(cz, vreinterpretq_u64_f64(
                    vaddq_f64(c2, vextq_f64(c2, c2, 1)))));
            vst1q_f64(ff.wrapping_add(i << 1),
                vaddq_f64(c_re, vdupq_lane_f64(a_re, 0)));
            vst1q_f64(ff.wrapping_add((i << 1) + hn),
                vaddq_f64(c_im, vdupq_lane_f64(a_im, 0)));
        }
    }

    #[cfg(not(any(
        target_feature = "sse2",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    {
        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
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

// Table of constants for FFT. For k = 1 to 1023, define j = rev10(k), with
// rev10() being the bit-reversal function over 10 bits. Then:
//   GM[2*k + 0] = cos(k*pi/1024)
//   GM[2*k + 1] = sin(k*pi/1024)
// Here, all values are computed from integer approximations which were
// obtained from Sage, which employs sufficient precision to get an exact
// rounding. Specifically, we round x = cos(j*pi/1024) by looking for the
// integer n such that abs(x)*2^n is in [2^52, 2^53[, and make the value
// as round(x*2^n)/2^n (with FLR::scaled()).
// A test makes sure that the generated FLR constants have exactly the
// expected values.
//
// GM[0] and GM[1] (corresponding to k = 0) are unused and left to zero.

const fn mkflr(x: i64, sc: i32) -> FLR {
    FLR::scaled(x, sc)
}
pub(crate) const GM: [FLR; 2048] = [
    FLR::ZERO, FLR::ZERO,
    FLR::NZERO, FLR::ONE,
    mkflr(   6369051672525773, -53), mkflr(   6369051672525773, -53),
    mkflr(  -6369051672525773, -53), mkflr(   6369051672525773, -53),
    mkflr(   8321567036706118, -53), mkflr(   6893811853601123, -54),
    mkflr(  -6893811853601123, -54), mkflr(   8321567036706118, -53),
    mkflr(   6893811853601123, -54), mkflr(   8321567036706118, -53),
    mkflr(  -8321567036706118, -53), mkflr(   6893811853601123, -54),
    mkflr(   8834128446708912, -53), mkflr(   7028869612283403, -55),
    mkflr(  -7028869612283403, -55), mkflr(   8834128446708912, -53),
    mkflr(   5004131788810440, -53), mkflr(   7489212472271267, -53),
    mkflr(  -7489212472271267, -53), mkflr(   5004131788810440, -53),
    mkflr(   7489212472271267, -53), mkflr(   5004131788810440, -53),
    mkflr(  -5004131788810440, -53), mkflr(   7489212472271267, -53),
    mkflr(   7028869612283403, -55), mkflr(   8834128446708912, -53),
    mkflr(  -8834128446708912, -53), mkflr(   7028869612283403, -55),
    mkflr(   8963827128411430, -53), mkflr(   7062879306626092, -56),
    mkflr(  -7062879306626092, -56), mkflr(   8963827128411430, -53),
    mkflr(   5714106716331478, -53), mkflr(   6962659179435841, -53),
    mkflr(  -6962659179435841, -53), mkflr(   5714106716331478, -53),
    mkflr(   7943640554978737, -53), mkflr(   8491928673252923, -54),
    mkflr(  -8491928673252923, -54), mkflr(   7943640554978737, -53),
    mkflr(   5229303857258246, -54), mkflr(   8619352278838746, -53),
    mkflr(  -8619352278838746, -53), mkflr(   5229303857258246, -54),
    mkflr(   8619352278838746, -53), mkflr(   5229303857258246, -54),
    mkflr(  -5229303857258246, -54), mkflr(   8619352278838746, -53),
    mkflr(   8491928673252923, -54), mkflr(   7943640554978737, -53),
    mkflr(  -7943640554978737, -53), mkflr(   8491928673252923, -54),
    mkflr(   6962659179435841, -53), mkflr(   5714106716331478, -53),
    mkflr(  -5714106716331478, -53), mkflr(   6962659179435841, -53),
    mkflr(   7062879306626092, -56), mkflr(   8963827128411430, -53),
    mkflr(  -8963827128411430, -53), mkflr(   7062879306626092, -56),
    mkflr(   8996349688769918, -53), mkflr(   7071397114140692, -57),
    mkflr(  -7071397114140692, -57), mkflr(   8996349688769918, -53),
    mkflr(   6048865317612704, -53), mkflr(   6673894424096687, -53),
    mkflr(  -6673894424096687, -53), mkflr(   6048865317612704, -53),
    mkflr(   8142411687315315, -53), mkflr(   7702147837811904, -54),
    mkflr(  -7702147837811904, -54), mkflr(   8142411687315315, -53),
    mkflr(   6068868072808413, -54), mkflr(   8480675002222309, -53),
    mkflr(  -8480675002222309, -53), mkflr(   6068868072808413, -54),
    mkflr(   8737264780849367, -53), mkflr(   8754283581366043, -55),
    mkflr(  -8754283581366043, -55), mkflr(   8737264780849367, -53),
    mkflr(   4630625854357486, -53), mkflr(   7725732496764478, -53),
    mkflr(  -7725732496764478, -53), mkflr(   4630625854357486, -53),
    mkflr(   7234650278954817, -53), mkflr(   5365582331473973, -53),
    mkflr(  -5365582331473973, -53), mkflr(   7234650278954817, -53),
    mkflr(   5286522480648506, -55), mkflr(   8909709923362071, -53),
    mkflr(  -8909709923362071, -53), mkflr(   5286522480648506, -55),
    mkflr(   8909709923362071, -53), mkflr(   5286522480648506, -55),
    mkflr(  -5286522480648506, -55), mkflr(   8909709923362071, -53),
    mkflr(   5365582331473973, -53), mkflr(   7234650278954817, -53),
    mkflr(  -7234650278954817, -53), mkflr(   5365582331473973, -53),
    mkflr(   7725732496764478, -53), mkflr(   4630625854357486, -53),
    mkflr(  -4630625854357486, -53), mkflr(   7725732496764478, -53),
    mkflr(   8754283581366043, -55), mkflr(   8737264780849367, -53),
    mkflr(  -8737264780849367, -53), mkflr(   8754283581366043, -55),
    mkflr(   8480675002222309, -53), mkflr(   6068868072808413, -54),
    mkflr(  -6068868072808413, -54), mkflr(   8480675002222309, -53),
    mkflr(   7702147837811904, -54), mkflr(   8142411687315315, -53),
    mkflr(  -8142411687315315, -53), mkflr(   7702147837811904, -54),
    mkflr(   6673894424096687, -53), mkflr(   6048865317612704, -53),
    mkflr(  -6048865317612704, -53), mkflr(   6673894424096687, -53),
    mkflr(   7071397114140692, -57), mkflr(   8996349688769918, -53),
    mkflr(  -8996349688769918, -53), mkflr(   7071397114140692, -57),
    mkflr(   9004486454725901, -53), mkflr(   7073527528384126, -58),
    mkflr(  -7073527528384126, -58), mkflr(   9004486454725901, -53),
    mkflr(   6210829080669407, -53), mkflr(   6523437785808790, -53),
    mkflr(  -6523437785808790, -53), mkflr(   6210829080669407, -53),
    mkflr(   8234469430249786, -53), mkflr(   7300178522992010, -54),
    mkflr(  -7300178522992010, -54), mkflr(   8234469430249786, -53),
    mkflr(   6483292609725855, -54), mkflr(   8403652042342972, -53),
    mkflr(  -8403652042342972, -53), mkflr(   6483292609725855, -54),
    mkflr(   8788343498532233, -53), mkflr(   7893954108215139, -55),
    mkflr(  -7893954108215139, -55), mkflr(   8788343498532233, -53),
    mkflr(   4818830163135267, -53), mkflr(   7609764403282432, -53),
    mkflr(  -7609764403282432, -53), mkflr(   4818830163135267, -53),
    mkflr(   7364149319706498, -53), mkflr(   5186419112612575, -53),
    mkflr(  -5186419112612575, -53), mkflr(   7364149319706498, -53),
    mkflr(   6159551188123590, -55), mkflr(   8874592046238633, -53),
    mkflr(  -8874592046238633, -53), mkflr(   6159551188123590, -55),
    mkflr(   8939460924383187, -53), mkflr(   8820618739413774, -56),
    mkflr(  -8820618739413774, -56), mkflr(   8939460924383187, -53),
    mkflr(   5541513524170937, -53), mkflr(   7100793355396091, -53),
    mkflr(  -7100793355396091, -53), mkflr(   5541513524170937, -53),
    mkflr(   7837046897874218, -53), mkflr(   8879264459430586, -54),
    mkflr(  -8879264459430586, -54), mkflr(   7837046897874218, -53),
    mkflr(   4804669900715639, -54), mkflr(   8680923061569891, -53),
    mkflr(  -8680923061569891, -53), mkflr(   4804669900715639, -54),
    mkflr(   8552589520593170, -53), mkflr(   5650787876693505, -54),
    mkflr(  -5650787876693505, -54), mkflr(   8552589520593170, -53),
    mkflr(   8099477666776158, -54), mkflr(   8045449260044789, -53),
    mkflr(  -8045449260044789, -53), mkflr(   8099477666776158, -54),
    mkflr(   6820330957936494, -53), mkflr(   5883257944270313, -53),
    mkflr(  -5883257944270313, -53), mkflr(   6820330957936494, -53),
    mkflr(   5300885459442166, -56), mkflr(   8982793858156602, -53),
    mkflr(  -8982793858156602, -53), mkflr(   5300885459442166, -56),
    mkflr(   8982793858156602, -53), mkflr(   5300885459442166, -56),
    mkflr(  -5300885459442166, -56), mkflr(   8982793858156602, -53),
    mkflr(   5883257944270313, -53), mkflr(   6820330957936494, -53),
    mkflr(  -6820330957936494, -53), mkflr(   5883257944270313, -53),
    mkflr(   8045449260044789, -53), mkflr(   8099477666776158, -54),
    mkflr(  -8099477666776158, -54), mkflr(   8045449260044789, -53),
    mkflr(   5650787876693505, -54), mkflr(   8552589520593170, -53),
    mkflr(  -8552589520593170, -53), mkflr(   5650787876693505, -54),
    mkflr(   8680923061569891, -53), mkflr(   4804669900715639, -54),
    mkflr(  -4804669900715639, -54), mkflr(   8680923061569891, -53),
    mkflr(   8879264459430586, -54), mkflr(   7837046897874218, -53),
    mkflr(  -7837046897874218, -53), mkflr(   8879264459430586, -54),
    mkflr(   7100793355396091, -53), mkflr(   5541513524170937, -53),
    mkflr(  -5541513524170937, -53), mkflr(   7100793355396091, -53),
    mkflr(   8820618739413774, -56), mkflr(   8939460924383187, -53),
    mkflr(  -8939460924383187, -53), mkflr(   8820618739413774, -56),
    mkflr(   8874592046238633, -53), mkflr(   6159551188123590, -55),
    mkflr(  -6159551188123590, -55), mkflr(   8874592046238633, -53),
    mkflr(   5186419112612575, -53), mkflr(   7364149319706498, -53),
    mkflr(  -7364149319706498, -53), mkflr(   5186419112612575, -53),
    mkflr(   7609764403282432, -53), mkflr(   4818830163135267, -53),
    mkflr(  -4818830163135267, -53), mkflr(   7609764403282432, -53),
    mkflr(   7893954108215139, -55), mkflr(   8788343498532233, -53),
    mkflr(  -8788343498532233, -53), mkflr(   7893954108215139, -55),
    mkflr(   8403652042342972, -53), mkflr(   6483292609725855, -54),
    mkflr(  -6483292609725855, -54), mkflr(   8403652042342972, -53),
    mkflr(   7300178522992010, -54), mkflr(   8234469430249786, -53),
    mkflr(  -8234469430249786, -53), mkflr(   7300178522992010, -54),
    mkflr(   6523437785808790, -53), mkflr(   6210829080669407, -53),
    mkflr(  -6210829080669407, -53), mkflr(   6523437785808790, -53),
    mkflr(   7073527528384126, -58), mkflr(   9004486454725901, -53),
    mkflr(  -9004486454725901, -53), mkflr(   7073527528384126, -58),
    mkflr(   9006521029202651, -53), mkflr(   7074060192106372, -59),
    mkflr(  -7074060192106372, -59), mkflr(   9006521029202651, -53),
    mkflr(   6290414033205309, -53), mkflr(   6446730156091567, -53),
    mkflr(  -6446730156091567, -53), mkflr(   6290414033205309, -53),
    mkflr(   8278641599964811, -53), mkflr(   7097529619223511, -54),
    mkflr(  -7097529619223511, -54), mkflr(   8278641599964811, -53),
    mkflr(   6689055905271015, -54), mkflr(   8363239276060827, -53),
    mkflr(  -8363239276060827, -53), mkflr(   6689055905271015, -54),
    mkflr(   8811899492445997, -53), mkflr(   7461973733147729, -55),
    mkflr(  -7461973733147729, -55), mkflr(   8811899492445997, -53),
    mkflr(   4911850829306697, -53), mkflr(   7550056943179025, -53),
    mkflr(  -7550056943179025, -53), mkflr(   4911850829306697, -53),
    mkflr(   7427240153512674, -53), mkflr(   5095659144473433, -53),
    mkflr(  -5095659144473433, -53), mkflr(   7427240153512674, -53),
    mkflr(   6594706969509681, -55), mkflr(   8855027013722231, -53),
    mkflr(  -8855027013722231, -53), mkflr(   6594706969509681, -55),
    mkflr(   8952318119487099, -53), mkflr(   7942347067146965, -56),
    mkflr(  -7942347067146965, -56), mkflr(   8952318119487099, -53),
    mkflr(   5628233915913940, -53), mkflr(   7032255783343117, -53),
    mkflr(  -7032255783343117, -53), mkflr(   5628233915913940, -53),
    mkflr(   7890937899537737, -53), mkflr(   8686250625038550, -54),
    mkflr(  -8686250625038550, -54), mkflr(   7890937899537737, -53),
    mkflr(   5017364677319486, -54), mkflr(   8650789058710388, -53),
    mkflr(  -8650789058710388, -53), mkflr(   5017364677319486, -54),
    mkflr(   8586617456218381, -53), mkflr(   5440455523270994, -54),
    mkflr(  -5440455523270994, -54), mkflr(   8586617456218381, -53),
    mkflr(   8296327868244873, -54), mkflr(   7995146927371163, -53),
    mkflr(  -7995146927371163, -53), mkflr(   8296327868244873, -54),
    mkflr(   6892014024666815, -53), mkflr(   5799118993295673, -53),
    mkflr(  -5799118993295673, -53), mkflr(   6892014024666815, -53),
    mkflr(   6182347902460953, -56), mkflr(   8973986217941769, -53),
    mkflr(  -8973986217941769, -53), mkflr(   6182347902460953, -56),
    mkflr(   8990248722657709, -53), mkflr(   8837249445142752, -57),
    mkflr(  -8837249445142752, -57), mkflr(   8990248722657709, -53),
    mkflr(   5966510898238870, -53), mkflr(   6747620774451057, -53),
    mkflr(  -6747620774451057, -53), mkflr(   5966510898238870, -53),
    mkflr(   8094539977653340, -53), mkflr(   7901407713763047, -54),
    mkflr(  -7901407713763047, -54), mkflr(   8094539977653340, -53),
    mkflr(   5860269242247018, -54), mkflr(   8517273596445054, -53),
    mkflr(  -8517273596445054, -53), mkflr(   5860269242247018, -54),
    mkflr(   8709749749347266, -53), mkflr(   4591251558497710, -54),
    mkflr(  -4591251558497710, -54), mkflr(   8709749749347266, -53),
    mkflr(   4535470554627767, -53), mkflr(   7781975665774802, -53),
    mkflr(  -7781975665774802, -53), mkflr(   4535470554627767, -53),
    mkflr(   7168261574088514, -53), mkflr(   5453958600874483, -53),
    mkflr(  -5453958600874483, -53), mkflr(   7168261574088514, -53),
    mkflr(   4848781029471607, -55), mkflr(   8925257479345985, -53),
    mkflr(  -8925257479345985, -53), mkflr(   4848781029471607, -55),
    mkflr(   8892820597836187, -53), mkflr(   5723467800985178, -55),
    mkflr(  -5723467800985178, -55), mkflr(   8892820597836187, -53),
    mkflr(   5276398025110506, -53), mkflr(   7299949472100244, -53),
    mkflr(  -7299949472100244, -53), mkflr(   5276398025110506, -53),
    mkflr(   7668325860857618, -53), mkflr(   4725083798866319, -53),
    mkflr(  -4725083798866319, -53), mkflr(   7668325860857618, -53),
    mkflr(   8324745682830097, -55), mkflr(   8763464012413658, -53),
    mkflr(  -8763464012413658, -53), mkflr(   8324745682830097, -55),
    mkflr(   8442799249538603, -53), mkflr(   6276552954161094, -54),
    mkflr(  -6276552954161094, -54), mkflr(   8442799249538603, -53),
    mkflr(   7501728046727114, -54), mkflr(   8189057179727324, -53),
    mkflr(  -8189057179727324, -53), mkflr(   7501728046727114, -54),
    mkflr(   6599163009790561, -53), mkflr(   6130308800119180, -53),
    mkflr(  -6130308800119180, -53), mkflr(   6599163009790561, -53),
    mkflr(   5304479856743885, -57), mkflr(   9001095837710173, -53),
    mkflr(  -9001095837710173, -53), mkflr(   5304479856743885, -57),
    mkflr(   9001095837710173, -53), mkflr(   5304479856743885, -57),
    mkflr(  -5304479856743885, -57), mkflr(   9001095837710173, -53),
    mkflr(   6130308800119180, -53), mkflr(   6599163009790561, -53),
    mkflr(  -6599163009790561, -53), mkflr(   6130308800119180, -53),
    mkflr(   8189057179727324, -53), mkflr(   7501728046727114, -54),
    mkflr(  -7501728046727114, -54), mkflr(   8189057179727324, -53),
    mkflr(   6276552954161094, -54), mkflr(   8442799249538603, -53),
    mkflr(  -8442799249538603, -53), mkflr(   6276552954161094, -54),
    mkflr(   8763464012413658, -53), mkflr(   8324745682830097, -55),
    mkflr(  -8324745682830097, -55), mkflr(   8763464012413658, -53),
    mkflr(   4725083798866319, -53), mkflr(   7668325860857618, -53),
    mkflr(  -7668325860857618, -53), mkflr(   4725083798866319, -53),
    mkflr(   7299949472100244, -53), mkflr(   5276398025110506, -53),
    mkflr(  -5276398025110506, -53), mkflr(   7299949472100244, -53),
    mkflr(   5723467800985178, -55), mkflr(   8892820597836187, -53),
    mkflr(  -8892820597836187, -53), mkflr(   5723467800985178, -55),
    mkflr(   8925257479345985, -53), mkflr(   4848781029471607, -55),
    mkflr(  -4848781029471607, -55), mkflr(   8925257479345985, -53),
    mkflr(   5453958600874483, -53), mkflr(   7168261574088514, -53),
    mkflr(  -7168261574088514, -53), mkflr(   5453958600874483, -53),
    mkflr(   7781975665774802, -53), mkflr(   4535470554627767, -53),
    mkflr(  -4535470554627767, -53), mkflr(   7781975665774802, -53),
    mkflr(   4591251558497710, -54), mkflr(   8709749749347266, -53),
    mkflr(  -8709749749347266, -53), mkflr(   4591251558497710, -54),
    mkflr(   8517273596445054, -53), mkflr(   5860269242247018, -54),
    mkflr(  -5860269242247018, -54), mkflr(   8517273596445054, -53),
    mkflr(   7901407713763047, -54), mkflr(   8094539977653340, -53),
    mkflr(  -8094539977653340, -53), mkflr(   7901407713763047, -54),
    mkflr(   6747620774451057, -53), mkflr(   5966510898238870, -53),
    mkflr(  -5966510898238870, -53), mkflr(   6747620774451057, -53),
    mkflr(   8837249445142752, -57), mkflr(   8990248722657709, -53),
    mkflr(  -8990248722657709, -53), mkflr(   8837249445142752, -57),
    mkflr(   8973986217941769, -53), mkflr(   6182347902460953, -56),
    mkflr(  -6182347902460953, -56), mkflr(   8973986217941769, -53),
    mkflr(   5799118993295673, -53), mkflr(   6892014024666815, -53),
    mkflr(  -6892014024666815, -53), mkflr(   5799118993295673, -53),
    mkflr(   7995146927371163, -53), mkflr(   8296327868244873, -54),
    mkflr(  -8296327868244873, -54), mkflr(   7995146927371163, -53),
    mkflr(   5440455523270994, -54), mkflr(   8586617456218381, -53),
    mkflr(  -8586617456218381, -53), mkflr(   5440455523270994, -54),
    mkflr(   8650789058710388, -53), mkflr(   5017364677319486, -54),
    mkflr(  -5017364677319486, -54), mkflr(   8650789058710388, -53),
    mkflr(   8686250625038550, -54), mkflr(   7890937899537737, -53),
    mkflr(  -7890937899537737, -53), mkflr(   8686250625038550, -54),
    mkflr(   7032255783343117, -53), mkflr(   5628233915913940, -53),
    mkflr(  -5628233915913940, -53), mkflr(   7032255783343117, -53),
    mkflr(   7942347067146965, -56), mkflr(   8952318119487099, -53),
    mkflr(  -8952318119487099, -53), mkflr(   7942347067146965, -56),
    mkflr(   8855027013722231, -53), mkflr(   6594706969509681, -55),
    mkflr(  -6594706969509681, -55), mkflr(   8855027013722231, -53),
    mkflr(   5095659144473433, -53), mkflr(   7427240153512674, -53),
    mkflr(  -7427240153512674, -53), mkflr(   5095659144473433, -53),
    mkflr(   7550056943179025, -53), mkflr(   4911850829306697, -53),
    mkflr(  -4911850829306697, -53), mkflr(   7550056943179025, -53),
    mkflr(   7461973733147729, -55), mkflr(   8811899492445997, -53),
    mkflr(  -8811899492445997, -53), mkflr(   7461973733147729, -55),
    mkflr(   8363239276060827, -53), mkflr(   6689055905271015, -54),
    mkflr(  -6689055905271015, -54), mkflr(   8363239276060827, -53),
    mkflr(   7097529619223511, -54), mkflr(   8278641599964811, -53),
    mkflr(  -8278641599964811, -53), mkflr(   7097529619223511, -54),
    mkflr(   6446730156091567, -53), mkflr(   6290414033205309, -53),
    mkflr(  -6290414033205309, -53), mkflr(   6446730156091567, -53),
    mkflr(   7074060192106372, -59), mkflr(   9006521029202651, -53),
    mkflr(  -9006521029202651, -53), mkflr(   7074060192106372, -59),
    mkflr(   9007029696760466, -53), mkflr(   7074193361797233, -60),
    mkflr(  -7074193361797233, -60), mkflr(   9007029696760466, -53),
    mkflr(   6329852010540816, -53), mkflr(   6408011543315061, -53),
    mkflr(  -6408011543315061, -53), mkflr(   6329852010540816, -53),
    mkflr(   8300260568395001, -53), mkflr(   6995802430416048, -54),
    mkflr(  -6995802430416048, -54), mkflr(   8300260568395001, -53),
    mkflr(   6791561728666308, -54), mkflr(   8342560202721672, -53),
    mkflr(  -8342560202721672, -53), mkflr(   6791561728666308, -54),
    mkflr(   8823180063448708, -53), mkflr(   7245558068298598, -55),
    mkflr(  -7245558068298598, -55), mkflr(   8823180063448708, -53),
    mkflr(   4958084643600824, -53), mkflr(   7519776265388244, -53),
    mkflr(  -7519776265388244, -53), mkflr(   4958084643600824, -53),
    mkflr(   7458366714537629, -53), mkflr(   5049990531286555, -53),
    mkflr(  -5049990531286555, -53), mkflr(   7458366714537629, -53),
    mkflr(   6811916523300038, -55), mkflr(   8844744230026167, -53),
    mkflr(  -8844744230026167, -53), mkflr(   6811916523300038, -55),
    mkflr(   8958241260309380, -53), mkflr(   7502754424118275, -56),
    mkflr(  -7502754424118275, -56), mkflr(   8958241260309380, -53),
    mkflr(   5671277076310961, -53), mkflr(   6997589209028812, -53),
    mkflr(  -6997589209028812, -53), mkflr(   5671277076310961, -53),
    mkflr(   7917438270796208, -53), mkflr(   8589251339374868, -54),
    mkflr(  -8589251339374868, -54), mkflr(   7917438270796208, -53),
    mkflr(   5123430714424177, -54), mkflr(   8635233224599694, -53),
    mkflr(  -8635233224599694, -53), mkflr(   5123430714424177, -54),
    mkflr(   8603146819336178, -53), mkflr(   5334980119757703, -54),
    mkflr(  -5334980119757703, -54), mkflr(   8603146819336178, -53),
    mkflr(   8394286290816088, -54), mkflr(   7969543765584135, -53),
    mkflr(  -7969543765584135, -53), mkflr(   8394286290816088, -54),
    mkflr(   6927467009660074, -53), mkflr(   5756721223463751, -53),
    mkflr(  -5756721223463751, -53), mkflr(   6927467009660074, -53),
    mkflr(   6622738275719969, -56), mkflr(   8969075513488470, -53),
    mkflr(  -8969075513488470, -53), mkflr(   6622738275719969, -56),
    mkflr(   8993468505216860, -53), mkflr(   7954473020348387, -57),
    mkflr(  -7954473020348387, -57), mkflr(   8993468505216860, -53),
    mkflr(   6007801203085623, -53), mkflr(   6710883929767346, -53),
    mkflr(  -6710883929767346, -53), mkflr(   6007801203085623, -53),
    mkflr(   8118628663374582, -53), mkflr(   7801924644814081, -54),
    mkflr(  -7801924644814081, -54), mkflr(   8118628663374582, -53),
    mkflr(   5964680940960804, -54), mkflr(   8499134293134885, -53),
    mkflr(  -8499134293134885, -53), mkflr(   5964680940960804, -54),
    mkflr(   8723671485748716, -53), mkflr(   8968562179829241, -55),
    mkflr(  -8968562179829241, -55), mkflr(   8723671485748716, -53),
    mkflr(   4583134480704026, -53), mkflr(   7754000048129257, -53),
    mkflr(  -7754000048129257, -53), mkflr(   4583134480704026, -53),
    mkflr(   7201591494446370, -53), mkflr(   5409872305491543, -53),
    mkflr(  -5409872305491543, -53), mkflr(   7201591494446370, -53),
    mkflr(   5067747153968079, -55), mkflr(   8917651573624763, -53),
    mkflr(  -8917651573624763, -53), mkflr(   5067747153968079, -55),
    mkflr(   8901432827556552, -53), mkflr(   5505098772745492, -55),
    mkflr(  -5505098772745492, -55), mkflr(   8901432827556552, -53),
    mkflr(   5321090346314263, -53), mkflr(   7267436682969301, -53),
    mkflr(  -7267436682969301, -53), mkflr(   5321090346314263, -53),
    mkflr(   7697174075937797, -53), mkflr(   4677942887564769, -53),
    mkflr(  -4677942887564769, -53), mkflr(   7697174075937797, -53),
    mkflr(   8539675389073947, -55), mkflr(   8750529122869341, -53),
    mkflr(  -8750529122869341, -53), mkflr(   8539675389073947, -55),
    mkflr(   8461896418689196, -53), mkflr(   6172826715203219, -54),
    mkflr(  -6172826715203219, -54), mkflr(   8461896418689196, -53),
    mkflr(   7602081049296905, -54), mkflr(   8165888154058130, -53),
    mkflr(  -8165888154058130, -53), mkflr(   7602081049296905, -54),
    mkflr(   6636653650073061, -53), mkflr(   6089701695779408, -53),
    mkflr(  -6089701695779408, -53), mkflr(   6636653650073061, -53),
    mkflr(   6188054973828419, -57), mkflr(   8998892164841951, -53),
    mkflr(  -8998892164841951, -53), mkflr(   6188054973828419, -57),
    mkflr(   9002960624407544, -53), mkflr(   8841410057981697, -58),
    mkflr(  -8841410057981697, -58), mkflr(   9002960624407544, -53),
    mkflr(   6170685101797492, -53), mkflr(   6561423914750605, -53),
    mkflr(  -6561423914750605, -53), mkflr(   6170685101797492, -53),
    mkflr(   8211917892022175, -53), mkflr(   7401092608336357, -54),
    mkflr(  -7401092608336357, -54), mkflr(   8211917892022175, -53),
    mkflr(   6380042884447767, -54), mkflr(   8423384213768154, -53),
    mkflr(  -8423384213768154, -53), mkflr(   6380042884447767, -54),
    mkflr(   8776068962491037, -53), mkflr(   8109502554616454, -55),
    mkflr(  -8109502554616454, -55), mkflr(   8776068962491037, -53),
    mkflr(   4772046813433470, -53), mkflr(   7639188937642932, -53),
    mkflr(  -7639188937642932, -53), mkflr(   4772046813433470, -53),
    mkflr(   7332187422259511, -53), mkflr(   5231507050503336, -53),
    mkflr(  -5231507050503336, -53), mkflr(   7332187422259511, -53),
    mkflr(   5941621343897074, -55), mkflr(   8883873558446555, -53),
    mkflr(  -8883873558446555, -53), mkflr(   5941621343897074, -55),
    mkflr(   8932527354167686, -53), mkflr(   4629632351109917, -55),
    mkflr(  -4629632351109917, -55), mkflr(   8932527354167686, -53),
    mkflr(   5497839557798690, -53), mkflr(   7134661772733911, -53),
    mkflr(  -7134661772733911, -53), mkflr(   5497839557798690, -53),
    mkflr(   7809658296434922, -53), mkflr(   8975271741297168, -54),
    mkflr(  -8975271741297168, -54), mkflr(   7809658296434922, -53),
    mkflr(   4698049169054608, -54), mkflr(   8695500095790524, -53),
    mkflr(  -8695500095790524, -53), mkflr(   4698049169054608, -54),
    mkflr(   8535092229218300, -53), mkflr(   5755636907708500, -54),
    mkflr(  -5755636907708500, -54), mkflr(   8535092229218300, -53),
    mkflr(   8000593299177483, -54), mkflr(   8070146537076992, -53),
    mkflr(  -8070146537076992, -53), mkflr(   8000593299177483, -54),
    mkflr(   6784103575026380, -53), mkflr(   5924995957629083, -53),
    mkflr(  -5924995957629083, -53), mkflr(   6784103575026380, -53),
    mkflr(   4859846576245171, -56), mkflr(   8986690462315460, -53),
    mkflr(  -8986690462315460, -53), mkflr(   4859846576245171, -56),
    mkflr(   8978559056886080, -53), mkflr(   5741724767297686, -56),
    mkflr(  -5741724767297686, -56), mkflr(   8978559056886080, -53),
    mkflr(   5841298429575172, -53), mkflr(   6856301559240908, -53),
    mkflr(  -6856301559240908, -53), mkflr(   5841298429575172, -53),
    mkflr(   8020449076395251, -53), mkflr(   8198057093618523, -54),
    mkflr(  -8198057093618523, -54), mkflr(   8020449076395251, -53),
    mkflr(   5545726096708791, -54), mkflr(   8569764811806532, -53),
    mkflr(  -8569764811806532, -53), mkflr(   5545726096708791, -54),
    mkflr(   8666019195502468, -53), mkflr(   4911109739270519, -54),
    mkflr(  -4911109739270519, -54), mkflr(   8666019195502468, -53),
    mkflr(   8782922878275687, -54), mkflr(   7864140438927325, -53),
    mkflr(  -7864140438927325, -53), mkflr(   8782922878275687, -54),
    mkflr(   7066657597201826, -53), mkflr(   5584978855691076, -53),
    mkflr(  -5584978855691076, -53), mkflr(   7066657597201826, -53),
    mkflr(   8381640685297609, -56), mkflr(   8946057928947489, -53),
    mkflr(  -8946057928947489, -53), mkflr(   8381640685297609, -56),
    mkflr(   8864976410656110, -53), mkflr(   6377249128729266, -55),
    mkflr(  -6377249128729266, -55), mkflr(   8864976410656110, -53),
    mkflr(   5141135908973599, -53), mkflr(   7395833961093832, -53),
    mkflr(  -7395833961093832, -53), mkflr(   5141135908973599, -53),
    mkflr(   7580053365593204, -53), mkflr(   4865432086605035, -53),
    mkflr(  -4865432086605035, -53), mkflr(   7580053365593204, -53),
    mkflr(   7678108458903330, -55), mkflr(   8800287158407901, -53),
    mkflr(  -8800287158407901, -53), mkflr(   7678108458903330, -55),
    mkflr(   8383603478168160, -53), mkflr(   6586298242701558, -54),
    mkflr(  -6586298242701558, -54), mkflr(   8383603478168160, -53),
    mkflr(   7198989590052351, -54), mkflr(   8256710945357489, -53),
    mkflr(  -8256710945357489, -53), mkflr(   7198989590052351, -54),
    mkflr(   6485206053121402, -53), mkflr(   6250739225336809, -53),
    mkflr(  -6250739225336809, -53), mkflr(   6485206053121402, -53),
    mkflr(   5305378684473085, -58), mkflr(   9005673271218593, -53),
    mkflr(  -9005673271218593, -53), mkflr(   5305378684473085, -58),
    mkflr(   9005673271218593, -53), mkflr(   5305378684473085, -58),
    mkflr(  -5305378684473085, -58), mkflr(   9005673271218593, -53),
    mkflr(   6250739225336809, -53), mkflr(   6485206053121402, -53),
    mkflr(  -6485206053121402, -53), mkflr(   6250739225336809, -53),
    mkflr(   8256710945357489, -53), mkflr(   7198989590052351, -54),
    mkflr(  -7198989590052351, -54), mkflr(   8256710945357489, -53),
    mkflr(   6586298242701558, -54), mkflr(   8383603478168160, -53),
    mkflr(  -8383603478168160, -53), mkflr(   6586298242701558, -54),
    mkflr(   8800287158407901, -53), mkflr(   7678108458903330, -55),
    mkflr(  -7678108458903330, -55), mkflr(   8800287158407901, -53),
    mkflr(   4865432086605035, -53), mkflr(   7580053365593204, -53),
    mkflr(  -7580053365593204, -53), mkflr(   4865432086605035, -53),
    mkflr(   7395833961093832, -53), mkflr(   5141135908973599, -53),
    mkflr(  -5141135908973599, -53), mkflr(   7395833961093832, -53),
    mkflr(   6377249128729266, -55), mkflr(   8864976410656110, -53),
    mkflr(  -8864976410656110, -53), mkflr(   6377249128729266, -55),
    mkflr(   8946057928947489, -53), mkflr(   8381640685297609, -56),
    mkflr(  -8381640685297609, -56), mkflr(   8946057928947489, -53),
    mkflr(   5584978855691076, -53), mkflr(   7066657597201826, -53),
    mkflr(  -7066657597201826, -53), mkflr(   5584978855691076, -53),
    mkflr(   7864140438927325, -53), mkflr(   8782922878275687, -54),
    mkflr(  -8782922878275687, -54), mkflr(   7864140438927325, -53),
    mkflr(   4911109739270519, -54), mkflr(   8666019195502468, -53),
    mkflr(  -8666019195502468, -53), mkflr(   4911109739270519, -54),
    mkflr(   8569764811806532, -53), mkflr(   5545726096708791, -54),
    mkflr(  -5545726096708791, -54), mkflr(   8569764811806532, -53),
    mkflr(   8198057093618523, -54), mkflr(   8020449076395251, -53),
    mkflr(  -8020449076395251, -53), mkflr(   8198057093618523, -54),
    mkflr(   6856301559240908, -53), mkflr(   5841298429575172, -53),
    mkflr(  -5841298429575172, -53), mkflr(   6856301559240908, -53),
    mkflr(   5741724767297686, -56), mkflr(   8978559056886080, -53),
    mkflr(  -8978559056886080, -53), mkflr(   5741724767297686, -56),
    mkflr(   8986690462315460, -53), mkflr(   4859846576245171, -56),
    mkflr(  -4859846576245171, -56), mkflr(   8986690462315460, -53),
    mkflr(   5924995957629083, -53), mkflr(   6784103575026380, -53),
    mkflr(  -6784103575026380, -53), mkflr(   5924995957629083, -53),
    mkflr(   8070146537076992, -53), mkflr(   8000593299177483, -54),
    mkflr(  -8000593299177483, -54), mkflr(   8070146537076992, -53),
    mkflr(   5755636907708500, -54), mkflr(   8535092229218300, -53),
    mkflr(  -8535092229218300, -53), mkflr(   5755636907708500, -54),
    mkflr(   8695500095790524, -53), mkflr(   4698049169054608, -54),
    mkflr(  -4698049169054608, -54), mkflr(   8695500095790524, -53),
    mkflr(   8975271741297168, -54), mkflr(   7809658296434922, -53),
    mkflr(  -7809658296434922, -53), mkflr(   8975271741297168, -54),
    mkflr(   7134661772733911, -53), mkflr(   5497839557798690, -53),
    mkflr(  -5497839557798690, -53), mkflr(   7134661772733911, -53),
    mkflr(   4629632351109917, -55), mkflr(   8932527354167686, -53),
    mkflr(  -8932527354167686, -53), mkflr(   4629632351109917, -55),
    mkflr(   8883873558446555, -53), mkflr(   5941621343897074, -55),
    mkflr(  -5941621343897074, -55), mkflr(   8883873558446555, -53),
    mkflr(   5231507050503336, -53), mkflr(   7332187422259511, -53),
    mkflr(  -7332187422259511, -53), mkflr(   5231507050503336, -53),
    mkflr(   7639188937642932, -53), mkflr(   4772046813433470, -53),
    mkflr(  -4772046813433470, -53), mkflr(   7639188937642932, -53),
    mkflr(   8109502554616454, -55), mkflr(   8776068962491037, -53),
    mkflr(  -8776068962491037, -53), mkflr(   8109502554616454, -55),
    mkflr(   8423384213768154, -53), mkflr(   6380042884447767, -54),
    mkflr(  -6380042884447767, -54), mkflr(   8423384213768154, -53),
    mkflr(   7401092608336357, -54), mkflr(   8211917892022175, -53),
    mkflr(  -8211917892022175, -53), mkflr(   7401092608336357, -54),
    mkflr(   6561423914750605, -53), mkflr(   6170685101797492, -53),
    mkflr(  -6170685101797492, -53), mkflr(   6561423914750605, -53),
    mkflr(   8841410057981697, -58), mkflr(   9002960624407544, -53),
    mkflr(  -9002960624407544, -53), mkflr(   8841410057981697, -58),
    mkflr(   8998892164841951, -53), mkflr(   6188054973828419, -57),
    mkflr(  -6188054973828419, -57), mkflr(   8998892164841951, -53),
    mkflr(   6089701695779408, -53), mkflr(   6636653650073061, -53),
    mkflr(  -6636653650073061, -53), mkflr(   6089701695779408, -53),
    mkflr(   8165888154058130, -53), mkflr(   7602081049296905, -54),
    mkflr(  -7602081049296905, -54), mkflr(   8165888154058130, -53),
    mkflr(   6172826715203219, -54), mkflr(   8461896418689196, -53),
    mkflr(  -8461896418689196, -53), mkflr(   6172826715203219, -54),
    mkflr(   8750529122869341, -53), mkflr(   8539675389073947, -55),
    mkflr(  -8539675389073947, -55), mkflr(   8750529122869341, -53),
    mkflr(   4677942887564769, -53), mkflr(   7697174075937797, -53),
    mkflr(  -7697174075937797, -53), mkflr(   4677942887564769, -53),
    mkflr(   7267436682969301, -53), mkflr(   5321090346314263, -53),
    mkflr(  -5321090346314263, -53), mkflr(   7267436682969301, -53),
    mkflr(   5505098772745492, -55), mkflr(   8901432827556552, -53),
    mkflr(  -8901432827556552, -53), mkflr(   5505098772745492, -55),
    mkflr(   8917651573624763, -53), mkflr(   5067747153968079, -55),
    mkflr(  -5067747153968079, -55), mkflr(   8917651573624763, -53),
    mkflr(   5409872305491543, -53), mkflr(   7201591494446370, -53),
    mkflr(  -7201591494446370, -53), mkflr(   5409872305491543, -53),
    mkflr(   7754000048129257, -53), mkflr(   4583134480704026, -53),
    mkflr(  -4583134480704026, -53), mkflr(   7754000048129257, -53),
    mkflr(   8968562179829241, -55), mkflr(   8723671485748716, -53),
    mkflr(  -8723671485748716, -53), mkflr(   8968562179829241, -55),
    mkflr(   8499134293134885, -53), mkflr(   5964680940960804, -54),
    mkflr(  -5964680940960804, -54), mkflr(   8499134293134885, -53),
    mkflr(   7801924644814081, -54), mkflr(   8118628663374582, -53),
    mkflr(  -8118628663374582, -53), mkflr(   7801924644814081, -54),
    mkflr(   6710883929767346, -53), mkflr(   6007801203085623, -53),
    mkflr(  -6007801203085623, -53), mkflr(   6710883929767346, -53),
    mkflr(   7954473020348387, -57), mkflr(   8993468505216860, -53),
    mkflr(  -8993468505216860, -53), mkflr(   7954473020348387, -57),
    mkflr(   8969075513488470, -53), mkflr(   6622738275719969, -56),
    mkflr(  -6622738275719969, -56), mkflr(   8969075513488470, -53),
    mkflr(   5756721223463751, -53), mkflr(   6927467009660074, -53),
    mkflr(  -6927467009660074, -53), mkflr(   5756721223463751, -53),
    mkflr(   7969543765584135, -53), mkflr(   8394286290816088, -54),
    mkflr(  -8394286290816088, -54), mkflr(   7969543765584135, -53),
    mkflr(   5334980119757703, -54), mkflr(   8603146819336178, -53),
    mkflr(  -8603146819336178, -53), mkflr(   5334980119757703, -54),
    mkflr(   8635233224599694, -53), mkflr(   5123430714424177, -54),
    mkflr(  -5123430714424177, -54), mkflr(   8635233224599694, -53),
    mkflr(   8589251339374868, -54), mkflr(   7917438270796208, -53),
    mkflr(  -7917438270796208, -53), mkflr(   8589251339374868, -54),
    mkflr(   6997589209028812, -53), mkflr(   5671277076310961, -53),
    mkflr(  -5671277076310961, -53), mkflr(   6997589209028812, -53),
    mkflr(   7502754424118275, -56), mkflr(   8958241260309380, -53),
    mkflr(  -8958241260309380, -53), mkflr(   7502754424118275, -56),
    mkflr(   8844744230026167, -53), mkflr(   6811916523300038, -55),
    mkflr(  -6811916523300038, -55), mkflr(   8844744230026167, -53),
    mkflr(   5049990531286555, -53), mkflr(   7458366714537629, -53),
    mkflr(  -7458366714537629, -53), mkflr(   5049990531286555, -53),
    mkflr(   7519776265388244, -53), mkflr(   4958084643600824, -53),
    mkflr(  -4958084643600824, -53), mkflr(   7519776265388244, -53),
    mkflr(   7245558068298598, -55), mkflr(   8823180063448708, -53),
    mkflr(  -8823180063448708, -53), mkflr(   7245558068298598, -55),
    mkflr(   8342560202721672, -53), mkflr(   6791561728666308, -54),
    mkflr(  -6791561728666308, -54), mkflr(   8342560202721672, -53),
    mkflr(   6995802430416048, -54), mkflr(   8300260568395001, -53),
    mkflr(  -8300260568395001, -53), mkflr(   6995802430416048, -54),
    mkflr(   6408011543315061, -53), mkflr(   6329852010540816, -53),
    mkflr(  -6329852010540816, -53), mkflr(   6408011543315061, -53),
    mkflr(   7074193361797233, -60), mkflr(   9007029696760466, -53),
    mkflr(  -9007029696760466, -53), mkflr(   7074193361797233, -60),
    mkflr(   9007156865146114, -53), mkflr(   7074226654454970, -61),
    mkflr(  -7074226654454970, -61), mkflr(   9007156865146114, -53),
    mkflr(   6349481723403377, -53), mkflr(   6388561673708188, -53),
    mkflr(  -6388561673708188, -53), mkflr(   6349481723403377, -53),
    mkflr(   8310952915477583, -53), mkflr(   6944839825747268, -54),
    mkflr(  -6944839825747268, -54), mkflr(   8310952915477583, -53),
    mkflr(   6842718994272319, -54), mkflr(   8332102832176454, -53),
    mkflr(  -8332102832176454, -53), mkflr(   6842718994272319, -54),
    mkflr(   8828695804602461, -53), mkflr(   7137247429536506, -55),
    mkflr(  -7137247429536506, -55), mkflr(   8828695804602461, -53),
    mkflr(   4981131658359743, -53), mkflr(   7504529686575502, -53),
    mkflr(  -7504529686575502, -53), mkflr(   4981131658359743, -53),
    mkflr(   7473824766646994, -53), mkflr(   5027084818466930, -53),
    mkflr(  -5027084818466930, -53), mkflr(   7473824766646994, -53),
    mkflr(   6920425636632580, -55), mkflr(   8839477938633966, -53),
    mkflr(  -8839477938633966, -53), mkflr(   6920425636632580, -55),
    mkflr(   8961076366892190, -53), mkflr(   7282851139856476, -56),
    mkflr(  -7282851139856476, -56), mkflr(   8961076366892190, -53),
    mkflr(   5692718687339392, -53), mkflr(   6980157044180565, -53),
    mkflr(  -6980157044180565, -53), mkflr(   5692718687339392, -53),
    mkflr(   7930576735691761, -53), mkflr(   8540630200145957, -54),
    mkflr(  -8540630200145957, -54), mkflr(   7930576735691761, -53),
    mkflr(   5176391646926010, -54), mkflr(   8627333353592832, -53),
    mkflr(  -8627333353592832, -53), mkflr(   5176391646926010, -54),
    mkflr(   8611290075458352, -53), mkflr(   5282166847391008, -54),
    mkflr(  -5282166847391008, -54), mkflr(   8611290075458352, -53),
    mkflr(   8443147217093086, -54), mkflr(   7956629605695492, -53),
    mkflr(  -7956629605695492, -53), mkflr(   8443147217093086, -54),
    mkflr(   6945095779491208, -53), mkflr(   5735440961974946, -53),
    mkflr(  -5735440961974946, -53), mkflr(   6945095779491208, -53),
    mkflr(   6842840994885793, -56), mkflr(   8966493518975884, -53),
    mkflr(  -8966493518975884, -53), mkflr(   6842840994885793, -56),
    mkflr(   8994951428947667, -53), mkflr(   7512970424714007, -57),
    mkflr(  -7512970424714007, -57), mkflr(   8994951428947667, -53),
    mkflr(   6028361630966943, -53), mkflr(   6692420672738099, -53),
    mkflr(  -6692420672738099, -53), mkflr(   6028361630966943, -53),
    mkflr(   8130558439301216, -53), mkflr(   7752072724043411, -54),
    mkflr(  -7752072724043411, -54), mkflr(   8130558439301216, -53),
    mkflr(   6016802823104436, -54), mkflr(   8489944602974586, -53),
    mkflr(  -8489944602974586, -53), mkflr(   6016802823104436, -54),
    mkflr(   8730509220737932, -53), mkflr(   8861464584337410, -55),
    mkflr(  -8861464584337410, -55), mkflr(   8730509220737932, -53),
    mkflr(   4606901848488119, -53), mkflr(   7739902697902825, -53),
    mkflr(  -7739902697902825, -53), mkflr(   4606901848488119, -53),
    mkflr(   7218154856711858, -53), mkflr(   5387752674272799, -53),
    mkflr(  -5387752674272799, -53), mkflr(   7218154856711858, -53),
    mkflr(   5177159182005257, -55), mkflr(   8913722698169820, -53),
    mkflr(  -8913722698169820, -53), mkflr(   5177159182005257, -55),
    mkflr(   8905613286971281, -53), mkflr(   5395836020528807, -55),
    mkflr(  -5395836020528807, -55), mkflr(   8905613286971281, -53),
    mkflr(   5343361485770773, -53), mkflr(   7251077605914050, -53),
    mkflr(  -7251077605914050, -53), mkflr(   5343361485770773, -53),
    mkflr(   7711489578089543, -53), mkflr(   4654306275012748, -53),
    mkflr(  -4654306275012748, -53), mkflr(   7711489578089543, -53),
    mkflr(   8647020179743560, -55), mkflr(   8743938102497119, -53),
    mkflr(  -8743938102497119, -53), mkflr(   8647020179743560, -55),
    mkflr(   8471325578127065, -53), mkflr(   6120876200014774, -54),
    mkflr(  -6120876200014774, -54), mkflr(   8471325578127065, -53),
    mkflr(   7652150456031602, -54), mkflr(   8154188295849595, -53),
    mkflr(  -8154188295849595, -53), mkflr(   7652150456031602, -54),
    mkflr(   6655305358219218, -53), mkflr(   6069312070034399, -53),
    mkflr(  -6069312070034399, -53), mkflr(   6655305358219218, -53),
    mkflr(   6629757244884614, -57), mkflr(   8997663271522660, -53),
    mkflr(  -8997663271522660, -53), mkflr(   6629757244884614, -57),
    mkflr(   9003765913003641, -53), mkflr(   7957506242722589, -58),
    mkflr(  -7957506242722589, -58), mkflr(   9003765913003641, -53),
    mkflr(   6190786226252304, -53), mkflr(   6542461640350018, -53),
    mkflr(  -6542461640350018, -53), mkflr(   6190786226252304, -53),
    mkflr(   8223232361233372, -53), mkflr(   7350670159317696, -54),
    mkflr(  -7350670159317696, -54), mkflr(   8223232361233372, -53),
    mkflr(   6431698015882422, -54), mkflr(   8413557723860353, -53),
    mkflr(  -8413557723860353, -53), mkflr(   6431698015882422, -54),
    mkflr(   8782247561441008, -53), mkflr(   8001765989250269, -55),
    mkflr(  -8001765989250269, -55), mkflr(   8782247561441008, -53),
    mkflr(   4795461056637271, -53), mkflr(   7624512552870645, -53),
    mkflr(  -7624512552870645, -53), mkflr(   4795461056637271, -53),
    mkflr(   7348202953025374, -53), mkflr(   5208987596045498, -53),
    mkflr(  -5208987596045498, -53), mkflr(   7348202953025374, -53),
    mkflr(   6050614741355486, -55), mkflr(   8879274589899640, -53),
    mkflr(  -8879274589899640, -53), mkflr(   6050614741355486, -55),
    mkflr(   8936036193963400, -53), mkflr(   4519992132352091, -55),
    mkflr(  -4519992132352091, -55), mkflr(   8936036193963400, -53),
    mkflr(   5519702517755945, -53), mkflr(   7117761061603948, -53),
    mkflr(  -7117761061603948, -53), mkflr(   5519702517755945, -53),
    mkflr(   7823389415514919, -53), mkflr(   8927310113985246, -54),
    mkflr(  -8927310113985246, -54), mkflr(   7823389415514919, -53),
    mkflr(   4751381895793102, -54), mkflr(   8688252467250769, -53),
    mkflr(  -8688252467250769, -53), mkflr(   4751381895793102, -54),
    mkflr(   8543881084037075, -53), mkflr(   5703239232730864, -54),
    mkflr(  -5703239232730864, -54), mkflr(   8543881084037075, -53),
    mkflr(   8050073368155017, -54), mkflr(   8057835820270665, -53),
    mkflr(  -8057835820270665, -53), mkflr(   8050073368155017, -54),
    mkflr(   6802249279161855, -53), mkflr(   5904154737026182, -53),
    mkflr(  -5904154737026182, -53), mkflr(   6802249279161855, -53),
    mkflr(   5080389927126093, -56), mkflr(   8984784444342543, -53),
    mkflr(  -8984784444342543, -53), mkflr(   5080389927126093, -56),
    mkflr(   8980718722493792, -53), mkflr(   5521331097805465, -56),
    mkflr(  -5521331097805465, -56), mkflr(   8980718722493792, -53),
    mkflr(   5862305776050047, -53), mkflr(   6838348441158650, -53),
    mkflr(  -6838348441158650, -53), mkflr(   5862305776050047, -53),
    mkflr(   8032986972986387, -53), mkflr(   8148805730028833, -54),
    mkflr(  -8148805730028833, -54), mkflr(   8032986972986387, -53),
    mkflr(   5598283333288561, -54), mkflr(   8561217456919463, -53),
    mkflr(  -8561217456919463, -53), mkflr(   5598283333288561, -54),
    mkflr(   8673511947735049, -53), mkflr(   4857912682255224, -54),
    mkflr(  -4857912682255224, -54), mkflr(   8673511947735049, -53),
    mkflr(   8831135229857187, -54), mkflr(   7850630614963393, -53),
    mkflr(  -7850630614963393, -53), mkflr(   8831135229857187, -54),
    mkflr(   7083758813816853, -53), mkflr(   5563272371750168, -53),
    mkflr(  -5563272371750168, -53), mkflr(   7083758813816853, -53),
    mkflr(   8601170191100479, -56), mkflr(   8942801513192182, -53),
    mkflr(  -8942801513192182, -53), mkflr(   8601170191100479, -56),
    mkflr(   8869825971537420, -53), mkflr(   6268429658850061, -55),
    mkflr(  -6268429658850061, -55), mkflr(   8869825971537420, -53),
    mkflr(   5163801812627728, -53), mkflr(   7380026372209606, -53),
    mkflr(  -7380026372209606, -53), mkflr(   5163801812627728, -53),
    mkflr(   7594944627693494, -53), mkflr(   4842153912968527, -53),
    mkflr(  -4842153912968527, -53), mkflr(   7594944627693494, -53),
    mkflr(   7786067926277549, -55), mkflr(   8794356716387429, -53),
    mkflr(  -8794356716387429, -53), mkflr(   7786067926277549, -55),
    mkflr(   8393667262452058, -53), mkflr(   6534826180350098, -54),
    mkflr(  -6534826180350098, -54), mkflr(   8393667262452058, -53),
    mkflr(   7249618174605810, -54), mkflr(   8245628993303844, -53),
    mkflr(  -8245628993303844, -53), mkflr(   7249618174605810, -54),
    mkflr(   6504352530186687, -53), mkflr(   6230813476397823, -53),
    mkflr(  -6230813476397823, -53), mkflr(   6504352530186687, -53),
    mkflr(   6189482235310630, -58), mkflr(   9005122242792311, -53),
    mkflr(  -9005122242792311, -53), mkflr(   6189482235310630, -58),
    mkflr(   9006139534818257, -53), mkflr(   8842450394781643, -59),
    mkflr(  -8842450394781643, -59), mkflr(   9006139534818257, -53),
    mkflr(   6270606139937627, -53), mkflr(   6465998534826869, -53),
    mkflr(  -6465998534826869, -53), mkflr(   6270606139937627, -53),
    mkflr(   8267715182103167, -53), mkflr(   7148293245867151, -54),
    mkflr(  -7148293245867151, -54), mkflr(   8267715182103167, -53),
    mkflr(   6637708312305582, -54), mkflr(   8373460784215450, -53),
    mkflr(  -8373460784215450, -53), mkflr(   6637708312305582, -54),
    mkflr(   8806134768774068, -53), mkflr(   7570076722248107, -55),
    mkflr(  -7570076722248107, -55), mkflr(   8806134768774068, -53),
    mkflr(   4888664464941756, -53), mkflr(   7565090757143791, -53),
    mkflr(  -7565090757143791, -53), mkflr(   4888664464941756, -53),
    mkflr(   7411571937572131, -53), mkflr(   5118421614990306, -53),
    mkflr(  -5118421614990306, -53), mkflr(   7411571937572131, -53),
    mkflr(   6486008573510911, -55), mkflr(   8860043409240618, -53),
    mkflr(  -8860043409240618, -53), mkflr(   6486008573510911, -55),
    mkflr(   8949230140998484, -53), mkflr(   8162032288300481, -56),
    mkflr(  -8162032288300481, -56), mkflr(   8949230140998484, -53),
    mkflr(   5606632771683968, -53), mkflr(   7049489866514174, -53),
    mkflr(  -7049489866514174, -53), mkflr(   5606632771683968, -53),
    mkflr(   7877576242606407, -53), mkflr(   8734627858479102, -54),
    mkflr(  -8734627858479102, -54), mkflr(   7877576242606407, -53),
    mkflr(   4964260571050563, -54), mkflr(   8658444875396786, -53),
    mkflr(  -8658444875396786, -53), mkflr(   4964260571050563, -54),
    mkflr(   8578231504803418, -53), mkflr(   5493116661642923, -54),
    mkflr(  -5493116661642923, -54), mkflr(   8578231504803418, -53),
    mkflr(   8247231293972637, -54), mkflr(   8007835688282839, -53),
    mkflr(  -8007835688282839, -53), mkflr(   8247231293972637, -54),
    mkflr(   6874190143201685, -53), mkflr(   5820236102574833, -53),
    mkflr(  -5820236102574833, -53), mkflr(   6874190143201685, -53),
    mkflr(   5962064393489674, -56), mkflr(   8976314881661062, -53),
    mkflr(  -8976314881661062, -53), mkflr(   5962064393489674, -56),
    mkflr(   8988511894135185, -53), mkflr(   4639257482637412, -56),
    mkflr(  -4639257482637412, -56), mkflr(   8988511894135185, -53),
    mkflr(   5945781409913510, -53), mkflr(   6765894016324346, -53),
    mkflr(  -6765894016324346, -53), mkflr(   5945781409913510, -53),
    mkflr(   8082381294590617, -53), mkflr(   7951037925568809, -54),
    mkflr(  -7951037925568809, -54), mkflr(   8082381294590617, -53),
    mkflr(   5807980408439539, -54), mkflr(   8526223038860894, -53),
    mkflr(  -8526223038860894, -53), mkflr(   5807980408439539, -54),
    mkflr(   8702665878971716, -53), mkflr(   4644672222488094, -54),
    mkflr(  -4644672222488094, -54), mkflr(   8702665878971716, -53),
    mkflr(   4511574444966625, -53), mkflr(   7795853669876749, -53),
    mkflr(  -7795853669876749, -53), mkflr(   4511574444966625, -53),
    mkflr(   7151495329710049, -53), mkflr(   5475924850081677, -53),
    mkflr(  -5475924850081677, -53), mkflr(   7151495329710049, -53),
    mkflr(   4739228994004870, -55), mkflr(   8928934438022583, -53),
    mkflr(  -8928934438022583, -53), mkflr(   4739228994004870, -55),
    mkflr(   8888388908592136, -53), mkflr(   5832572021635720, -55),
    mkflr(  -5832572021635720, -55), mkflr(   8888388908592136, -53),
    mkflr(   5253977264024408, -53), mkflr(   7316102878153182, -53),
    mkflr(  -7316102878153182, -53), mkflr(   5253977264024408, -53),
    mkflr(   7653793419459571, -53), mkflr(   4748587653907638, -53),
    mkflr(  -4748587653907638, -53), mkflr(   7653793419459571, -53),
    mkflr(   8217162790256110, -55), mkflr(   8769807759837646, -53),
    mkflr(  -8769807759837646, -53), mkflr(   8217162790256110, -55),
    mkflr(   8433131419575708, -53), mkflr(   6328327701619659, -54),
    mkflr(  -6328327701619659, -54), mkflr(   8433131419575708, -53),
    mkflr(   7451445395452699, -54), mkflr(   8200526129112289, -53),
    mkflr(  -8200526129112289, -53), mkflr(   7451445395452699, -54),
    mkflr(   6580324430530404, -53), mkflr(   6150525896504412, -53),
    mkflr(  -6150525896504412, -53), mkflr(   6580324430530404, -53),
    mkflr(   4862615327261055, -57), mkflr(   9002070596517294, -53),
    mkflr(  -9002070596517294, -53), mkflr(   4862615327261055, -57),
    mkflr(   9000036357160980, -53), mkflr(   5746294458442105, -57),
    mkflr(  -5746294458442105, -57), mkflr(   9000036357160980, -53),
    mkflr(   6110034002932808, -53), mkflr(   6617939475215195, -53),
    mkflr(  -6617939475215195, -53), mkflr(   6110034002932808, -53),
    mkflr(   8177511151817401, -53), mkflr(   7551940088880137, -54),
    mkflr(  -7551940088880137, -54), mkflr(   8177511151817401, -53),
    mkflr(   6224719129395714, -54), mkflr(   8452387612659540, -53),
    mkflr(  -8452387612659540, -53), mkflr(   6224719129395714, -54),
    mkflr(   8757037779928840, -53), mkflr(   8432250219727258, -55),
    mkflr(  -8432250219727258, -55), mkflr(   8757037779928840, -53),
    mkflr(   4701535469536748, -53), mkflr(   7682786125052197, -53),
    mkflr(  -7682786125052197, -53), mkflr(   4701535469536748, -53),
    mkflr(   7283727356142706, -53), mkflr(   5298769122728888, -53),
    mkflr(  -5298769122728888, -53), mkflr(   7283727356142706, -53),
    mkflr(   5614309708875923, -55), mkflr(   8897168584465961, -53),
    mkflr(  -8897168584465961, -53), mkflr(   5614309708875923, -55),
    mkflr(   8921496512746829, -53), mkflr(   4958287426364647, -55),
    mkflr(  -4958287426364647, -55), mkflr(   8921496512746829, -53),
    mkflr(   5431941016931809, -53), mkflr(   7184960348059028, -53),
    mkflr(  -7184960348059028, -53), mkflr(   5431941016931809, -53),
    mkflr(   7768024414754142, -53), mkflr(   4559323974712726, -53),
    mkflr(  -4559323974712726, -53), mkflr(   7768024414754142, -53),
    mkflr(   4537787679899090, -54), mkflr(   8716751640241088, -53),
    mkflr(  -8716751640241088, -53), mkflr(   4537787679899090, -54),
    mkflr(   8508243986206341, -53), mkflr(   5912502916968520, -54),
    mkflr(  -5912502916968520, -54), mkflr(   8508243986206341, -53),
    mkflr(   7851703130898649, -54), mkflr(   8106622471823008, -53),
    mkflr(  -8106622471823008, -53), mkflr(   7851703130898649, -54),
    mkflr(   6729284021401222, -53), mkflr(   5987184227491324, -53),
    mkflr(  -5987184227491324, -53), mkflr(   6729284021401222, -53),
    mkflr(   8395900745453257, -57), mkflr(   8991900931535341, -53),
    mkflr(  -8991900931535341, -53), mkflr(   8395900745453257, -57),
    mkflr(   8971573087646471, -53), mkflr(   6402573220819241, -56),
    mkflr(  -6402573220819241, -56), mkflr(   8971573087646471, -53),
    mkflr(   5777947300499967, -53), mkflr(   6909773035871137, -53),
    mkflr(  -6909773035871137, -53), mkflr(   5777947300499967, -53),
    mkflr(   7982382913091674, -53), mkflr(   8345346354319577, -54),
    mkflr(  -8345346354319577, -54), mkflr(   7982382913091674, -53),
    mkflr(   5387743177259695, -54), mkflr(   8594922587119653, -53),
    mkflr(  -8594922587119653, -53), mkflr(   5387743177259695, -54),
    mkflr(   8643051817502737, -53), mkflr(   5070421558241214, -54),
    mkflr(  -5070421558241214, -54), mkflr(   8643051817502737, -53),
    mkflr(   8637791633298976, -54), mkflr(   7904225283956311, -53),
    mkflr(  -7904225283956311, -53), mkflr(   8637791633298976, -54),
    mkflr(   7014955509902409, -53), mkflr(   5649782085062796, -53),
    mkflr(  -5649782085062796, -53), mkflr(   7014955509902409, -53),
    mkflr(   7722587089598028, -56), mkflr(   8955321835348103, -53),
    mkflr(  -8955321835348103, -53), mkflr(   7722587089598028, -56),
    mkflr(   8849927271317175, -53), mkflr(   6703343293614876, -55),
    mkflr(  -6703343293614876, -55), mkflr(   8849927271317175, -53),
    mkflr(   5072848711672022, -53), mkflr(   7442838461440245, -53),
    mkflr(  -7442838461440245, -53), mkflr(   5072848711672022, -53),
    mkflr(   7534952065202888, -53), mkflr(   4934990961460965, -53),
    mkflr(  -4934990961460965, -53), mkflr(   7534952065202888, -53),
    mkflr(   7353800509108698, -55), mkflr(   8817581275163911, -53),
    mkflr(  -8817581275163911, -53), mkflr(   7353800509108698, -55),
    mkflr(   8352939049913017, -53), mkflr(   6740340538294756, -54),
    mkflr(  -6740340538294756, -54), mkflr(   8352939049913017, -53),
    mkflr(   7046699187928017, -54), mkflr(   8289490096098815, -53),
    mkflr(  -8289490096098815, -53), mkflr(   7046699187928017, -54),
    mkflr(   6427401098276813, -53), mkflr(   6310162718700422, -53),
    mkflr(  -6310162718700422, -53), mkflr(   6427401098276813, -53),
    mkflr(   5305603405682435, -59), mkflr(   9006817750781007, -53),
    mkflr(  -9006817750781007, -53), mkflr(   5305603405682435, -59),
    mkflr(   9006817750781007, -53), mkflr(   5305603405682435, -59),
    mkflr(  -5305603405682435, -59), mkflr(   9006817750781007, -53),
    mkflr(   6310162718700422, -53), mkflr(   6427401098276813, -53),
    mkflr(  -6427401098276813, -53), mkflr(   6310162718700422, -53),
    mkflr(   8289490096098815, -53), mkflr(   7046699187928017, -54),
    mkflr(  -7046699187928017, -54), mkflr(   8289490096098815, -53),
    mkflr(   6740340538294756, -54), mkflr(   8352939049913017, -53),
    mkflr(  -8352939049913017, -53), mkflr(   6740340538294756, -54),
    mkflr(   8817581275163911, -53), mkflr(   7353800509108698, -55),
    mkflr(  -7353800509108698, -55), mkflr(   8817581275163911, -53),
    mkflr(   4934990961460965, -53), mkflr(   7534952065202888, -53),
    mkflr(  -7534952065202888, -53), mkflr(   4934990961460965, -53),
    mkflr(   7442838461440245, -53), mkflr(   5072848711672022, -53),
    mkflr(  -5072848711672022, -53), mkflr(   7442838461440245, -53),
    mkflr(   6703343293614876, -55), mkflr(   8849927271317175, -53),
    mkflr(  -8849927271317175, -53), mkflr(   6703343293614876, -55),
    mkflr(   8955321835348103, -53), mkflr(   7722587089598028, -56),
    mkflr(  -7722587089598028, -56), mkflr(   8955321835348103, -53),
    mkflr(   5649782085062796, -53), mkflr(   7014955509902409, -53),
    mkflr(  -7014955509902409, -53), mkflr(   5649782085062796, -53),
    mkflr(   7904225283956311, -53), mkflr(   8637791633298976, -54),
    mkflr(  -8637791633298976, -54), mkflr(   7904225283956311, -53),
    mkflr(   5070421558241214, -54), mkflr(   8643051817502737, -53),
    mkflr(  -8643051817502737, -53), mkflr(   5070421558241214, -54),
    mkflr(   8594922587119653, -53), mkflr(   5387743177259695, -54),
    mkflr(  -5387743177259695, -54), mkflr(   8594922587119653, -53),
    mkflr(   8345346354319577, -54), mkflr(   7982382913091674, -53),
    mkflr(  -7982382913091674, -53), mkflr(   8345346354319577, -54),
    mkflr(   6909773035871137, -53), mkflr(   5777947300499967, -53),
    mkflr(  -5777947300499967, -53), mkflr(   6909773035871137, -53),
    mkflr(   6402573220819241, -56), mkflr(   8971573087646471, -53),
    mkflr(  -8971573087646471, -53), mkflr(   6402573220819241, -56),
    mkflr(   8991900931535341, -53), mkflr(   8395900745453257, -57),
    mkflr(  -8395900745453257, -57), mkflr(   8991900931535341, -53),
    mkflr(   5987184227491324, -53), mkflr(   6729284021401222, -53),
    mkflr(  -6729284021401222, -53), mkflr(   5987184227491324, -53),
    mkflr(   8106622471823008, -53), mkflr(   7851703130898649, -54),
    mkflr(  -7851703130898649, -54), mkflr(   8106622471823008, -53),
    mkflr(   5912502916968520, -54), mkflr(   8508243986206341, -53),
    mkflr(  -8508243986206341, -53), mkflr(   5912502916968520, -54),
    mkflr(   8716751640241088, -53), mkflr(   4537787679899090, -54),
    mkflr(  -4537787679899090, -54), mkflr(   8716751640241088, -53),
    mkflr(   4559323974712726, -53), mkflr(   7768024414754142, -53),
    mkflr(  -7768024414754142, -53), mkflr(   4559323974712726, -53),
    mkflr(   7184960348059028, -53), mkflr(   5431941016931809, -53),
    mkflr(  -5431941016931809, -53), mkflr(   7184960348059028, -53),
    mkflr(   4958287426364647, -55), mkflr(   8921496512746829, -53),
    mkflr(  -8921496512746829, -53), mkflr(   4958287426364647, -55),
    mkflr(   8897168584465961, -53), mkflr(   5614309708875923, -55),
    mkflr(  -5614309708875923, -55), mkflr(   8897168584465961, -53),
    mkflr(   5298769122728888, -53), mkflr(   7283727356142706, -53),
    mkflr(  -7283727356142706, -53), mkflr(   5298769122728888, -53),
    mkflr(   7682786125052197, -53), mkflr(   4701535469536748, -53),
    mkflr(  -4701535469536748, -53), mkflr(   7682786125052197, -53),
    mkflr(   8432250219727258, -55), mkflr(   8757037779928840, -53),
    mkflr(  -8757037779928840, -53), mkflr(   8432250219727258, -55),
    mkflr(   8452387612659540, -53), mkflr(   6224719129395714, -54),
    mkflr(  -6224719129395714, -54), mkflr(   8452387612659540, -53),
    mkflr(   7551940088880137, -54), mkflr(   8177511151817401, -53),
    mkflr(  -8177511151817401, -53), mkflr(   7551940088880137, -54),
    mkflr(   6617939475215195, -53), mkflr(   6110034002932808, -53),
    mkflr(  -6110034002932808, -53), mkflr(   6617939475215195, -53),
    mkflr(   5746294458442105, -57), mkflr(   9000036357160980, -53),
    mkflr(  -9000036357160980, -53), mkflr(   5746294458442105, -57),
    mkflr(   9002070596517294, -53), mkflr(   4862615327261055, -57),
    mkflr(  -4862615327261055, -57), mkflr(   9002070596517294, -53),
    mkflr(   6150525896504412, -53), mkflr(   6580324430530404, -53),
    mkflr(  -6580324430530404, -53), mkflr(   6150525896504412, -53),
    mkflr(   8200526129112289, -53), mkflr(   7451445395452699, -54),
    mkflr(  -7451445395452699, -54), mkflr(   8200526129112289, -53),
    mkflr(   6328327701619659, -54), mkflr(   8433131419575708, -53),
    mkflr(  -8433131419575708, -53), mkflr(   6328327701619659, -54),
    mkflr(   8769807759837646, -53), mkflr(   8217162790256110, -55),
    mkflr(  -8217162790256110, -55), mkflr(   8769807759837646, -53),
    mkflr(   4748587653907638, -53), mkflr(   7653793419459571, -53),
    mkflr(  -7653793419459571, -53), mkflr(   4748587653907638, -53),
    mkflr(   7316102878153182, -53), mkflr(   5253977264024408, -53),
    mkflr(  -5253977264024408, -53), mkflr(   7316102878153182, -53),
    mkflr(   5832572021635720, -55), mkflr(   8888388908592136, -53),
    mkflr(  -8888388908592136, -53), mkflr(   5832572021635720, -55),
    mkflr(   8928934438022583, -53), mkflr(   4739228994004870, -55),
    mkflr(  -4739228994004870, -55), mkflr(   8928934438022583, -53),
    mkflr(   5475924850081677, -53), mkflr(   7151495329710049, -53),
    mkflr(  -7151495329710049, -53), mkflr(   5475924850081677, -53),
    mkflr(   7795853669876749, -53), mkflr(   4511574444966625, -53),
    mkflr(  -4511574444966625, -53), mkflr(   7795853669876749, -53),
    mkflr(   4644672222488094, -54), mkflr(   8702665878971716, -53),
    mkflr(  -8702665878971716, -53), mkflr(   4644672222488094, -54),
    mkflr(   8526223038860894, -53), mkflr(   5807980408439539, -54),
    mkflr(  -5807980408439539, -54), mkflr(   8526223038860894, -53),
    mkflr(   7951037925568809, -54), mkflr(   8082381294590617, -53),
    mkflr(  -8082381294590617, -53), mkflr(   7951037925568809, -54),
    mkflr(   6765894016324346, -53), mkflr(   5945781409913510, -53),
    mkflr(  -5945781409913510, -53), mkflr(   6765894016324346, -53),
    mkflr(   4639257482637412, -56), mkflr(   8988511894135185, -53),
    mkflr(  -8988511894135185, -53), mkflr(   4639257482637412, -56),
    mkflr(   8976314881661062, -53), mkflr(   5962064393489674, -56),
    mkflr(  -5962064393489674, -56), mkflr(   8976314881661062, -53),
    mkflr(   5820236102574833, -53), mkflr(   6874190143201685, -53),
    mkflr(  -6874190143201685, -53), mkflr(   5820236102574833, -53),
    mkflr(   8007835688282839, -53), mkflr(   8247231293972637, -54),
    mkflr(  -8247231293972637, -54), mkflr(   8007835688282839, -53),
    mkflr(   5493116661642923, -54), mkflr(   8578231504803418, -53),
    mkflr(  -8578231504803418, -53), mkflr(   5493116661642923, -54),
    mkflr(   8658444875396786, -53), mkflr(   4964260571050563, -54),
    mkflr(  -4964260571050563, -54), mkflr(   8658444875396786, -53),
    mkflr(   8734627858479102, -54), mkflr(   7877576242606407, -53),
    mkflr(  -7877576242606407, -53), mkflr(   8734627858479102, -54),
    mkflr(   7049489866514174, -53), mkflr(   5606632771683968, -53),
    mkflr(  -5606632771683968, -53), mkflr(   7049489866514174, -53),
    mkflr(   8162032288300481, -56), mkflr(   8949230140998484, -53),
    mkflr(  -8949230140998484, -53), mkflr(   8162032288300481, -56),
    mkflr(   8860043409240618, -53), mkflr(   6486008573510911, -55),
    mkflr(  -6486008573510911, -55), mkflr(   8860043409240618, -53),
    mkflr(   5118421614990306, -53), mkflr(   7411571937572131, -53),
    mkflr(  -7411571937572131, -53), mkflr(   5118421614990306, -53),
    mkflr(   7565090757143791, -53), mkflr(   4888664464941756, -53),
    mkflr(  -4888664464941756, -53), mkflr(   7565090757143791, -53),
    mkflr(   7570076722248107, -55), mkflr(   8806134768774068, -53),
    mkflr(  -8806134768774068, -53), mkflr(   7570076722248107, -55),
    mkflr(   8373460784215450, -53), mkflr(   6637708312305582, -54),
    mkflr(  -6637708312305582, -54), mkflr(   8373460784215450, -53),
    mkflr(   7148293245867151, -54), mkflr(   8267715182103167, -53),
    mkflr(  -8267715182103167, -53), mkflr(   7148293245867151, -54),
    mkflr(   6465998534826869, -53), mkflr(   6270606139937627, -53),
    mkflr(  -6270606139937627, -53), mkflr(   6465998534826869, -53),
    mkflr(   8842450394781643, -59), mkflr(   9006139534818257, -53),
    mkflr(  -9006139534818257, -53), mkflr(   8842450394781643, -59),
    mkflr(   9005122242792311, -53), mkflr(   6189482235310630, -58),
    mkflr(  -6189482235310630, -58), mkflr(   9005122242792311, -53),
    mkflr(   6230813476397823, -53), mkflr(   6504352530186687, -53),
    mkflr(  -6504352530186687, -53), mkflr(   6230813476397823, -53),
    mkflr(   8245628993303844, -53), mkflr(   7249618174605810, -54),
    mkflr(  -7249618174605810, -54), mkflr(   8245628993303844, -53),
    mkflr(   6534826180350098, -54), mkflr(   8393667262452058, -53),
    mkflr(  -8393667262452058, -53), mkflr(   6534826180350098, -54),
    mkflr(   8794356716387429, -53), mkflr(   7786067926277549, -55),
    mkflr(  -7786067926277549, -55), mkflr(   8794356716387429, -53),
    mkflr(   4842153912968527, -53), mkflr(   7594944627693494, -53),
    mkflr(  -7594944627693494, -53), mkflr(   4842153912968527, -53),
    mkflr(   7380026372209606, -53), mkflr(   5163801812627728, -53),
    mkflr(  -5163801812627728, -53), mkflr(   7380026372209606, -53),
    mkflr(   6268429658850061, -55), mkflr(   8869825971537420, -53),
    mkflr(  -8869825971537420, -53), mkflr(   6268429658850061, -55),
    mkflr(   8942801513192182, -53), mkflr(   8601170191100479, -56),
    mkflr(  -8601170191100479, -56), mkflr(   8942801513192182, -53),
    mkflr(   5563272371750168, -53), mkflr(   7083758813816853, -53),
    mkflr(  -7083758813816853, -53), mkflr(   5563272371750168, -53),
    mkflr(   7850630614963393, -53), mkflr(   8831135229857187, -54),
    mkflr(  -8831135229857187, -54), mkflr(   7850630614963393, -53),
    mkflr(   4857912682255224, -54), mkflr(   8673511947735049, -53),
    mkflr(  -8673511947735049, -53), mkflr(   4857912682255224, -54),
    mkflr(   8561217456919463, -53), mkflr(   5598283333288561, -54),
    mkflr(  -5598283333288561, -54), mkflr(   8561217456919463, -53),
    mkflr(   8148805730028833, -54), mkflr(   8032986972986387, -53),
    mkflr(  -8032986972986387, -53), mkflr(   8148805730028833, -54),
    mkflr(   6838348441158650, -53), mkflr(   5862305776050047, -53),
    mkflr(  -5862305776050047, -53), mkflr(   6838348441158650, -53),
    mkflr(   5521331097805465, -56), mkflr(   8980718722493792, -53),
    mkflr(  -8980718722493792, -53), mkflr(   5521331097805465, -56),
    mkflr(   8984784444342543, -53), mkflr(   5080389927126093, -56),
    mkflr(  -5080389927126093, -56), mkflr(   8984784444342543, -53),
    mkflr(   5904154737026182, -53), mkflr(   6802249279161855, -53),
    mkflr(  -6802249279161855, -53), mkflr(   5904154737026182, -53),
    mkflr(   8057835820270665, -53), mkflr(   8050073368155017, -54),
    mkflr(  -8050073368155017, -54), mkflr(   8057835820270665, -53),
    mkflr(   5703239232730864, -54), mkflr(   8543881084037075, -53),
    mkflr(  -8543881084037075, -53), mkflr(   5703239232730864, -54),
    mkflr(   8688252467250769, -53), mkflr(   4751381895793102, -54),
    mkflr(  -4751381895793102, -54), mkflr(   8688252467250769, -53),
    mkflr(   8927310113985246, -54), mkflr(   7823389415514919, -53),
    mkflr(  -7823389415514919, -53), mkflr(   8927310113985246, -54),
    mkflr(   7117761061603948, -53), mkflr(   5519702517755945, -53),
    mkflr(  -5519702517755945, -53), mkflr(   7117761061603948, -53),
    mkflr(   4519992132352091, -55), mkflr(   8936036193963400, -53),
    mkflr(  -8936036193963400, -53), mkflr(   4519992132352091, -55),
    mkflr(   8879274589899640, -53), mkflr(   6050614741355486, -55),
    mkflr(  -6050614741355486, -55), mkflr(   8879274589899640, -53),
    mkflr(   5208987596045498, -53), mkflr(   7348202953025374, -53),
    mkflr(  -7348202953025374, -53), mkflr(   5208987596045498, -53),
    mkflr(   7624512552870645, -53), mkflr(   4795461056637271, -53),
    mkflr(  -4795461056637271, -53), mkflr(   7624512552870645, -53),
    mkflr(   8001765989250269, -55), mkflr(   8782247561441008, -53),
    mkflr(  -8782247561441008, -53), mkflr(   8001765989250269, -55),
    mkflr(   8413557723860353, -53), mkflr(   6431698015882422, -54),
    mkflr(  -6431698015882422, -54), mkflr(   8413557723860353, -53),
    mkflr(   7350670159317696, -54), mkflr(   8223232361233372, -53),
    mkflr(  -8223232361233372, -53), mkflr(   7350670159317696, -54),
    mkflr(   6542461640350018, -53), mkflr(   6190786226252304, -53),
    mkflr(  -6190786226252304, -53), mkflr(   6542461640350018, -53),
    mkflr(   7957506242722589, -58), mkflr(   9003765913003641, -53),
    mkflr(  -9003765913003641, -53), mkflr(   7957506242722589, -58),
    mkflr(   8997663271522660, -53), mkflr(   6629757244884614, -57),
    mkflr(  -6629757244884614, -57), mkflr(   8997663271522660, -53),
    mkflr(   6069312070034399, -53), mkflr(   6655305358219218, -53),
    mkflr(  -6655305358219218, -53), mkflr(   6069312070034399, -53),
    mkflr(   8154188295849595, -53), mkflr(   7652150456031602, -54),
    mkflr(  -7652150456031602, -54), mkflr(   8154188295849595, -53),
    mkflr(   6120876200014774, -54), mkflr(   8471325578127065, -53),
    mkflr(  -8471325578127065, -53), mkflr(   6120876200014774, -54),
    mkflr(   8743938102497119, -53), mkflr(   8647020179743560, -55),
    mkflr(  -8647020179743560, -55), mkflr(   8743938102497119, -53),
    mkflr(   4654306275012748, -53), mkflr(   7711489578089543, -53),
    mkflr(  -7711489578089543, -53), mkflr(   4654306275012748, -53),
    mkflr(   7251077605914050, -53), mkflr(   5343361485770773, -53),
    mkflr(  -5343361485770773, -53), mkflr(   7251077605914050, -53),
    mkflr(   5395836020528807, -55), mkflr(   8905613286971281, -53),
    mkflr(  -8905613286971281, -53), mkflr(   5395836020528807, -55),
    mkflr(   8913722698169820, -53), mkflr(   5177159182005257, -55),
    mkflr(  -5177159182005257, -55), mkflr(   8913722698169820, -53),
    mkflr(   5387752674272799, -53), mkflr(   7218154856711858, -53),
    mkflr(  -7218154856711858, -53), mkflr(   5387752674272799, -53),
    mkflr(   7739902697902825, -53), mkflr(   4606901848488119, -53),
    mkflr(  -4606901848488119, -53), mkflr(   7739902697902825, -53),
    mkflr(   8861464584337410, -55), mkflr(   8730509220737932, -53),
    mkflr(  -8730509220737932, -53), mkflr(   8861464584337410, -55),
    mkflr(   8489944602974586, -53), mkflr(   6016802823104436, -54),
    mkflr(  -6016802823104436, -54), mkflr(   8489944602974586, -53),
    mkflr(   7752072724043411, -54), mkflr(   8130558439301216, -53),
    mkflr(  -8130558439301216, -53), mkflr(   7752072724043411, -54),
    mkflr(   6692420672738099, -53), mkflr(   6028361630966943, -53),
    mkflr(  -6028361630966943, -53), mkflr(   6692420672738099, -53),
    mkflr(   7512970424714007, -57), mkflr(   8994951428947667, -53),
    mkflr(  -8994951428947667, -53), mkflr(   7512970424714007, -57),
    mkflr(   8966493518975884, -53), mkflr(   6842840994885793, -56),
    mkflr(  -6842840994885793, -56), mkflr(   8966493518975884, -53),
    mkflr(   5735440961974946, -53), mkflr(   6945095779491208, -53),
    mkflr(  -6945095779491208, -53), mkflr(   5735440961974946, -53),
    mkflr(   7956629605695492, -53), mkflr(   8443147217093086, -54),
    mkflr(  -8443147217093086, -54), mkflr(   7956629605695492, -53),
    mkflr(   5282166847391008, -54), mkflr(   8611290075458352, -53),
    mkflr(  -8611290075458352, -53), mkflr(   5282166847391008, -54),
    mkflr(   8627333353592832, -53), mkflr(   5176391646926010, -54),
    mkflr(  -5176391646926010, -54), mkflr(   8627333353592832, -53),
    mkflr(   8540630200145957, -54), mkflr(   7930576735691761, -53),
    mkflr(  -7930576735691761, -53), mkflr(   8540630200145957, -54),
    mkflr(   6980157044180565, -53), mkflr(   5692718687339392, -53),
    mkflr(  -5692718687339392, -53), mkflr(   6980157044180565, -53),
    mkflr(   7282851139856476, -56), mkflr(   8961076366892190, -53),
    mkflr(  -8961076366892190, -53), mkflr(   7282851139856476, -56),
    mkflr(   8839477938633966, -53), mkflr(   6920425636632580, -55),
    mkflr(  -6920425636632580, -55), mkflr(   8839477938633966, -53),
    mkflr(   5027084818466930, -53), mkflr(   7473824766646994, -53),
    mkflr(  -7473824766646994, -53), mkflr(   5027084818466930, -53),
    mkflr(   7504529686575502, -53), mkflr(   4981131658359743, -53),
    mkflr(  -4981131658359743, -53), mkflr(   7504529686575502, -53),
    mkflr(   7137247429536506, -55), mkflr(   8828695804602461, -53),
    mkflr(  -8828695804602461, -53), mkflr(   7137247429536506, -55),
    mkflr(   8332102832176454, -53), mkflr(   6842718994272319, -54),
    mkflr(  -6842718994272319, -54), mkflr(   8332102832176454, -53),
    mkflr(   6944839825747268, -54), mkflr(   8310952915477583, -53),
    mkflr(  -8310952915477583, -53), mkflr(   6944839825747268, -54),
    mkflr(   6388561673708188, -53), mkflr(   6349481723403377, -53),
    mkflr(  -6349481723403377, -53), mkflr(   6388561673708188, -53),
    mkflr(   7074226654454970, -61), mkflr(   9007156865146114, -53),
    mkflr(  -9007156865146114, -53), mkflr(   7074226654454970, -61),
];

#[cfg(test)]
mod tests {

    use super::*;
    use crate::flr::FLR;
    use fn_dsa_comm::shake::{SHAKE256, SHAKE256x4};

    fn rand_poly(rng: &mut SHAKE256x4, f: &mut [FLR]) {
        for i in 0..f.len() {
            f[i] = FLR::from_i64(((rng.next_u16() & 0x3FF) as i64) - 512);
        }
    }

    fn poly_inner(logn: u32) {
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
        for logn in 2..11 {
            poly_inner(logn);
        }
    }

    #[test]
    fn check_GM() {
        let mut sh = SHAKE256::new();
        for i in 0..2048 {
            let x = GM[i].encode();
            sh.inject(&x);
        }
        sh.flip();
        let mut buf = [0u8; 32];
        sh.extract(&mut buf);
        // Reference hash was obtained from the constants in the Falcon
        // reference code, which were initially computed with Sage with
        // large precision.
        assert!(buf[..] == hex::decode("f45a496cf56ccc6e3e3395a20209206d81d71a7905a661447bd5bc0e24e0af1e").unwrap());
    }
}
