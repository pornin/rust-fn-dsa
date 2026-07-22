#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use super::flr::FLR;
use super::poly::*;
use fn_dsa_comm::PRNG;

#[cfg(all(target_arch = "x86", target_feature = "sse2"))]
use core::arch::x86::*;

// ========================================================================
// Gaussian sampling
// ========================================================================

// The sampler generates random integer values that follow a Gaussian
// distribution. The centre and standard deviation of that distribution
// are not integral, vary within each signature generation, and are
// secret.

// A sampler state includes a PRNG, from which random bytes are obtained,
// and the (logarithmic) degree for the overall scheme (some constants
// depend on the used degree).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sampler<T: PRNG> {
    rng: T,
    logn: u32,
}

// 1/(2*(1.8205^2))
const INV_2SQRSIGMA0: FLR = FLR::scaled(5435486223186882, -55);

// For logn = 1 to 10, n = 2^logn:
//    q = 12289
//    gs_norm = (117/100)*sqrt(q)
//    bitsec = max(2, n/4)
//    eps = 1/sqrt(bitsec*2^64)
//    smoothz2n = sqrt(log(4*n*(1 + 1/eps))/pi)/sqrt(2*pi)
//    sigma = smoothz2n*gs_norm
//    sigma_min = sigma/gs_norm = smoothz2n
// We store precomputed values for 1/sigma and for sigma_min, indexed by logn.
//
// Note: the fpr_inv_sigma[] constants used in the reference C code used
// these expressions, except that "117/100" was written "1.17". It turns out
// that in Sage (at least version 10.4), this silently degrades the precision
// to 53 bits, and the result is a bit off; namely, for all INV_SIGMA[]
// values, the corresponding constant in the C code is 1 bit higher than
// here.
const INV_SIGMA: [FLR; 11] = [
    FLR::ZERO, // unused
    FLR::scaled(7961475618707097, -60),   // 0.0069054793295940881528
    FLR::scaled(7851656902127320, -60),   // 0.0068102267767177965681
    FLR::scaled(7746260754658859, -60),   // 0.0067188101910722700565
    FLR::scaled(7595833604889141, -60),   // 0.0065883354370073655600
    FLR::scaled(7453842886538220, -60),   // 0.0064651781207602890978
    FLR::scaled(7319528409832599, -60),   // 0.0063486788828078985744
    FLR::scaled(7192222552237877, -60),   // 0.0062382586529084365056
    FLR::scaled(7071336252758509, -60),   // 0.0061334065020930252290
    FLR::scaled(6956347512113097, -60),   // 0.0060336696681577231923
    FLR::scaled(6846791885593314, -60),   // 0.0059386453095331150985
];
const SIGMA_MIN: [FLR; 11] = [
    FLR::ZERO, // unused
    FLR::scaled(5028307297130123, -52),   // 1.1165085072329102589
    FLR::scaled(5098636688852518, -52),   // 1.1321247692325272406
    FLR::scaled(5168009084304506, -52),   // 1.1475285353733668685
    FLR::scaled(5270355833453349, -52),   // 1.1702540788534828940
    FLR::scaled(5370752584786614, -52),   // 1.1925466358390344011
    FLR::scaled(5469306724145091, -52),   // 1.2144300507766139921
    FLR::scaled(5566116128735780, -52),   // 1.2359260567719808790
    FLR::scaled(5661270305715104, -52),   // 1.2570545284063214163
    FLR::scaled(5754851361258101, -52),   // 1.2778336969128335860
    FLR::scaled(5846934829975396, -52),   // 1.2982803343442918540
];

// Values from Table 5 (Distribution for BaseSampler), split into
// three chunks of 31, 24 and 24 bits, in high-to-low order,
// respectively.
const GAUSS0: [[u32; 3]; 18] = [
    [ 1375468055,  6936092,  9176346 ],
    [  711562636,  1023934, 15582455 ],
    [  289335016,  4826132, 14746371 ],
    [   90749601, 12313548, 10843417 ],
    [   21676598,  5732767,  9419414 ],
    [    3908963, 11171514,  6206010 ],
    [     529006, 11146683, 11891888 ],
    [      53503, 15610582, 11661180 ],
    [       4032,  7095613, 11671091 ],
    [        225, 16701698,   407118 ],
    [          9,  6787688,  1638204 ],
    [          0,  4870085,  8687822 ],
    [          0,   111406, 13946073 ],
    [          0,     1887, 12017202 ],
    [          0,       23, 11452285 ],
    [          0,        0,  3689579 ],
    [          0,        0,    25354 ],
    [          0,        0,      129 ],
];

// log(2)
const LOG2: FLR = FLR::scaled(6243314768165359, -53);

// 1/log(2)
const INV_LOG2: FLR = FLR::scaled(6497320848556798, -52);

impl<T: PRNG> Sampler<T> {

    pub(crate) fn new(logn: u32, seed: &[u8]) -> Self {
        let rng = T::new(seed);
        Self { rng, logn }
    }

    // Get some bytes directly from the internal PRNG.
    pub(crate) fn next_bytes(&mut self, dst: &mut [u8]) {
        self.rng.next_bytes(dst);
    }

    // SSE2 variant of next() (for 32-bit x86).
    #[cfg(all(target_arch = "x86", target_feature = "sse2"))]
    #[allow(dead_code)]
    pub(crate) fn next(&mut self, mu: FLR, isigma: FLR) -> i32 {
        unsafe {
            let fmu: f64 = core::mem::transmute(mu);
            let fisigma: f64 = core::mem::transmute(isigma);
            self.next_sse2(_mm_set_sd(fmu), _mm_set_sd(fisigma))
        }
    }

    // Sample the next small integer, using the proper Gaussian
    // distribution with centre mu and inverse of the standard
    // deviation isigma.
    #[cfg(not(all(target_arch = "x86", target_feature = "sse2")))]
    pub(crate) fn next(&mut self, mu: FLR, isigma: FLR) -> i32 {

        // Centre is mu. We split it into s + r, for an integer
        // s, and 0 <= r < 1.
        let s = mu.floor();
        let r = mu - FLR::from_i64(s);
        let s = s as i32;

        // dss = 1/(2*sigma^2) = 0.5*(isigma^2)
        let dss = isigma.square().half();

        // ccs = sigma_min / sigma = sigma_min * isigma
        let ccs = isigma * SIGMA_MIN[self.logn as usize];

        // We need to sample on centre r.
        loop {
            // Sample z for a Gaussian distribution, then get a random
            // bit b to turn the sampling into a bimodal distribution:
            // if b = 1, we use z+1, otherwise we use -z. We thus have
            // two situations:
            //
            //  - b = 1: z >= 1 and sampled against a Gaussian
            //    distribution centred on 1.
            //  - b = 0: z <= 0 and sampled against a Gaussian
            //    distribution centred on 0.
            let (z0, b) = self.gaussian0();
            let z = b + ((b << 1) - 1) * z0;

            // Rejection sampling. We want a Gaussian centred on r,
            // but we sampled against a bimodal Gaussian (with "centres"
            // at 0 and 1). However, we know that z is always in the
            // range where our sampling distribution is greater than the
            // Gaussian distribution, so rejection works.
            //
            // We got z with distribution:
            //    G(z) = exp(-((z-b)^2)/(2*sigma0^2))
            // We target distribution:
            //    S(z) = exp(-((z-r)^2)/(2*sigma^2))
            // Rejection sampling works by keeping the value z with
            // probability S(z)/G(z), and starting again otherwise.
            // This requires S(z) <= G(z), which is the case here. Thus,
            // we simply need to keep our z with probability:
            //    P = exp(-x)
            // where:
            //    x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
            //
            // Here, we scale up the Bernouilli distribution, which makes
            // rejection more probable, but also makes the rejection rate
            // sufficiently decorrelated from the Gaussian centre and
            // standard deviation that the measurement of the rejection
            // rate leaks no usable information for attackers (and thus
            // makes the whole sampler nominally "constant-time").
            let mut x = (FLR::from_i64(z as i64) - r).square() * dss;
            x -= FLR::from_i64((z0 * z0) as i64) * INV_2SQRSIGMA0;
            if self.ber_exp(x, ccs) {
                // Rejection sampling was centred on r, but the actual
                // centre is mu = s + r.
                return s + z;
            }
        }
    }

    #[cfg(all(target_arch = "x86", target_feature = "sse2"))]
    unsafe fn next_sse2(&mut self, mu: __m128d, isigma: __m128d) -> i32 {
        // 0.5
        let h: __m128d = core::mem::transmute([
            FLR::scaled(4503599627370496, -53),
            FLR::scaled(4503599627370496, -53),
        ]);
        // 1/(2*(1.8205^2))
        let inv2ss: __m128d = core::mem::transmute([
            INV_2SQRSIGMA0, INV_2SQRSIGMA0,
        ]);

        // Split mu into s + r
        let s = _mm_cvttsd_si32(mu);
        let s = s - _mm_comilt_sd(mu, _mm_cvtsi32_sd(_mm_setzero_pd(), s));
        let r = _mm_sub_sd(mu, _mm_cvtsi32_sd(_mm_setzero_pd(), s));

        // dss = 1/(2*sigma^2) = 0.5*(isigma^2)
        let dss = _mm_mul_sd(_mm_mul_sd(isigma, isigma), h);

        // ccs = sigma_min / sigma = sigma_min * isigma
        let psm: *const f64 = core::mem::transmute((&SIGMA_MIN).as_ptr());
        let ccs = _mm_mul_sd(isigma,
            _mm_load_sd(psm.wrapping_add(self.logn as usize)));

        loop {
            // z from a Gaussian, and bit b to make a "bimodal" distribution.
            let (z0, b) = self.gaussian0();
            let z = b + ((b << 1) - 1) * z0;

            // Rejection sampling.
            let x = _mm_sub_sd(_mm_cvtsi32_sd(_mm_setzero_pd(), z), r);
            let x = _mm_mul_sd(_mm_mul_sd(x, x), dss);
            let x = _mm_sub_sd(x, _mm_mul_sd(
                _mm_cvtsi32_sd(_mm_setzero_pd(), z0 * z0),
                inv2ss));
            if self.ber_exp_sse2(x, ccs) {
                // Rejection sampling was centred on r, but the actual
                // centre is mu = s + r.
                return s + z;
            }
        }
    }

    // Sample a value from a given half-Gaussian centred on zero; only
    // non-negative values are returned, but also an extra random sign
    // bit. 80 bits from the random source are used.
    fn gaussian0(&mut self) -> (i32, i32) {
        // Get a random 72-bit value, into three 24-bit limbs v0..v2.
        let lo = self.rng.next_u64();
        let hi = self.rng.next_u16();
        let b = (lo as i32) & 1;
        let v0 = ((lo as u32) >> 1) & 0x00FFFFFF;
        let v1 = ((lo >> 25) as u32) & 0x00FFFFFF;
        let v2 = ((lo >> 49) as u32) | ((hi as u32) << 15);

        // Sampled value is z, such that v0..v2 is lower than the first
        // z elements of the table.
        let mut z = 0;
        for i in 0..GAUSS0.len() {
            let cc = v0.wrapping_sub(GAUSS0[i][2]) >> 31;
            let cc = v1.wrapping_sub(GAUSS0[i][1]).wrapping_sub(cc) >> 31;
            let cc = v2.wrapping_sub(GAUSS0[i][0]).wrapping_sub(cc) >> 31;
            z += cc as i32;
        }
        (z, b)
    }

    // Sample a bit with probability ccs*exp(-x) (with x >= 0).
    #[cfg(not(all(target_arch = "x86", target_feature = "sse2")))]
    fn ber_exp(&mut self, x: FLR, ccs: FLR) -> bool {
        // Reduce x modulo log(2): x = s*log(2) + r, with s an integer,
        // and 0 <= r < log(2). We can use trunc() because x >= 0
        // (trunc() is presumably a bit faster than floor()).
        let s = (x * INV_LOG2).trunc();
        let r = x - FLR::from_i64(s) * LOG2;

        // If s >= 64, sigma = 1.2, r = 0 and b = 1, then we get s >= 64
        // if the half-Gaussian produced z >= 13, which happens with
        // probability about 2^(-32). When s >= 64, ber_exp() will return
        // true with probability less than 2^(-64), so we can simply
        // saturate s at 63 (i.e. the bias introduced here is lower than
        // 2^(-96) and would require something like 2^192 samplings to
        // be simply detectable in any way, while the number of signatures
        // is bounded at 2^64 and each will involve less than 2^16 calls
        // to ber_exp()).
        let sw = s as u32;
        let s = (sw | (63u32.wrapping_sub(sw) >> 16)) & 63;

        // Compute ccs*exp(-x). Since x = s*log(2) + r, we compute
        // ccs*exp(-r)/2^s. We know that 0 <= r < log(2) at this
        // point, so we can use FLR::expm_p63(), which yields a result
        // scaled by 63 bits. We scale it up 1 bit further (to 64 bits),
        // then right-shift by s bits to account for the division by 2^s.
        //
        // The "-1" operation makes sure that the value fits on 64 bits
        // (i.e. if r = 0 then we may get 2^64 and we prefer 2^64-1 in
        // that case). The bias is neligible since expm_p63() only
        // computes with 51 bits of precision or so.
        //
        // Since the shift is over a 64-bit value and the shift count is
        // nominally secret, we should use a special shift process because
        // some 32-bit architecture employ a non-constant-time routine
        // in that case.
        let z = (r.expm_p63(ccs) << 1).wrapping_sub(1);
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"))]
        let z = z >> s;
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64")))]
        let z = (z ^ ((z ^ (z >> 32)) & ((s >> 5) as u64).wrapping_neg()))
            >> (s & 31);

        // Sample a bit with probability ccs*exp(-x). We lazily compare 
        // the value z with a uniform 64-bit integer, consuming only as
        // many bytes as necessary. Note that since the PRNG is good
        // (uniform, and information on output bytes cannot be inferred
        // from the value of other output bytes), we leak no more
        // information with lazy comparison than the fact that we already
        // leak or not, i.e. whether the value was rejected or accepted.
        for i in 0..8 {
            let w = self.rng.next_u8();
            let bz = (z >> (56 - (i << 3))) as u8;
            if w != bz {
                return w < bz;
            }
        }
        false
    }

    // Variant of ber_exp() for 32-bit x86 with SSE2.
    #[cfg(all(target_arch = "x86", target_feature = "sse2"))]
    unsafe fn ber_exp_sse2(&mut self, x: __m128d, ccs: __m128d) -> bool {
        let log2: __m128d = core::mem::transmute([LOG2, LOG2]);
        let invlog2: __m128d = core::mem::transmute([INV_LOG2, INV_LOG2]);

        // x = s*log(2) + r
        let si = _mm_cvttsd_si32(_mm_mul_sd(x, invlog2));
        let r = _mm_sub_sd(x,
            _mm_mul_sd(_mm_cvtsi32_sd(_mm_setzero_pd(), si), log2));

        // saturate s at 63
        let mut s = si as u32;
        s |= 63u32.wrapping_sub(s) >> 26;
        s &= 63;

        // z <- ccs*exp(-x), scaled, then right-shift by s.
        let z = (Self::expm_p63_sse2(r, ccs) << 1).wrapping_sub(1);
        let z = (z ^ ((z ^ (z >> 32)) & ((s >> 5) as u64).wrapping_neg()))
            >> (s & 31);

        // rejection sampling
        for i in 0..8 {
            let w = self.rng.next_u8();
            let bz = (z >> (56 - (i << 3))) as u8;
            if w != bz {
                return w < bz;
            }
        }
        false
    }

    // Variant of expm_p63() for 32-bit x86 with SSE2.
    #[cfg(all(target_arch = "x86", target_feature = "sse2"))]
    unsafe fn expm_p63_sse2(r: __m128d, ccs: __m128d) -> u64 {
        #[inline(always)]
        unsafe fn mtwop63(x: __m128d) -> i64 {
            // 2^21
            let twop21: __m128d = core::mem::transmute([
                FLR::scaled(4503599627370496, -31),
                FLR::scaled(4503599627370496, -31),
            ]);
            let x = _mm_mul_sd(x, twop21);
            let z2 = _mm_cvttsd_si32(x);
            let x = _mm_sub_sd(x, _mm_cvtsi32_sd(_mm_setzero_pd(), z2));
            let x = _mm_mul_sd(x, twop21);
            let z1 = _mm_cvttsd_si32(x);
            let x = _mm_sub_sd(x, _mm_cvtsi32_sd(_mm_setzero_pd(), z1));
            let x = _mm_mul_sd(x, twop21);
            let z0 = _mm_cvttsd_si32(x);
            ((z2 as i64) << 42) + ((z1 as i64) << 21) + (z0 as i64)
        }

        let mut y = FLR::EXPM_COEFFS[0];
        let z = (mtwop63(r) as u64) << 1;
        let w = (mtwop63(ccs) as u64) << 1;
        let (z0, z1) = (z as u32, (z >> 32) as u32);
        for i in 1..FLR::EXPM_COEFFS.len() {
            let (y0, y1) = (y as u32, (y >> 32) as u32);
            let f = (z0 as u64) * (y0 as u64);
            let a = (z0 as u64) * (y1 as u64) + (f >> 32);
            let b = (z1 as u64) * (y0 as u64);
            let c = (a >> 32) + (b >> 32)
                + ((((a as u32) as u64) + ((b as u32) as u64)) >> 32)
                + (z1 as u64) * (y1 as u64);
            y = FLR::EXPM_COEFFS[i].wrapping_sub(c);
        }
        let (w0, w1) = (w as u32, (w >> 32) as u32);
        let (y0, y1) = (y as u32, (y >> 32) as u32);
        let f = (w0 as u64) * (y0 as u64);
        let a = (w0 as u64) * (y1 as u64) + (f >> 32);
        let b = (w1 as u64) * (y0 as u64);
        let y = (a >> 32) + (b >> 32)
            + ((((a as u32) as u64) + ((b as u32) as u64)) >> 32)
            + (w1 as u64) * (y1 as u64);
        y
    }

    // Fast Fourier Sampling.
    // The target vector is t, provided as two polynomials t0 and t1.
    // The Gram matrix is provided (G = [[g00, g01], [adj(g01), g11]]).
    // The sampled vector is written over (t0,t1) and the Gram matrix
    // is also modified. The temporary buffer (tmp) must have room for
    // four extra polynomials. All polynomials are in FFT representation.
    pub(crate) fn ffsamp_fft(&mut self,
        t0: &mut [FLR], t1: &mut [FLR],
        g00: &mut [FLR], g01: &mut [FLR], g11: &mut [FLR], tmp: &mut [FLR])
    {
        self.ffsamp_fft_inner(self.logn, t0, t1, g00, g01, g11, tmp);
    }

    // Inner function for Fast Fourier Sampling (recursive). The
    // degree at this level is provided as the 'logn' parameter (the
    // overall degree is in self.logn).
    fn ffsamp_fft_inner(&mut self, logn: u32,
        t0: &mut [FLR], t1: &mut [FLR],
        g00: &mut [FLR], g01: &mut [FLR], g11: &mut [FLR], tmp: &mut [FLR])
    {
        // When logn = 1, arrays have length 2; we unroll the last steps.
        #[cfg(all(target_arch = "x86", target_feature = "sse2"))]
        if logn == 1 {
            unsafe {
                use core::mem::transmute;

                let tt0: *mut f64 = transmute(t0.as_mut_ptr());
                let tt1: *mut f64 = transmute(t1.as_mut_ptr());
                let gg00: *mut f64 = transmute(g00.as_mut_ptr());
                let gg01: *mut f64 = transmute(g01.as_mut_ptr());
                let gg11: *mut f64 = transmute(g11.as_mut_ptr());
                let one: __m128d = transmute([FLR::ONE, FLR::ONE]);
                let cz: __m128d = transmute([FLR::ZERO, FLR::NZERO]);

                let pi: *const f64 = transmute((&INV_SIGMA).as_ptr());
                let isigma = _mm_load_sd(pi.wrapping_add(self.logn as usize));

                // Decompose G into LDL.
                let g00_re = _mm_load_sd(gg00);
                let g01_cc = _mm_loadu_pd(gg01);
                let g11_re = _mm_load_sd(gg11);
                let inv_g00_re = _mm_div_sd(one, g00_re);
                let inv_g00 = _mm_shuffle_pd(inv_g00_re, inv_g00_re, 0);
                let mu = _mm_mul_pd(g01_cc, inv_g00);
                let zo = _mm_mul_pd(mu, g01_cc);
                let zo_re = _mm_add_sd(zo, _mm_shuffle_pd(zo, zo, 1));
                let d00_re = g00_re;
                let l01 = _mm_xor_pd(cz, mu);
                let d11_re = _mm_sub_sd(g11_re, zo_re);

                // No split on d00 and d11

                // t1 split is trivial
                let w = _mm_loadu_pd(tt1);
                let w0 = w;
                let w1 = _mm_shuffle_pd(w, w, 3);

                // Recursive call (right sub-tree)
                let leaf = _mm_mul_sd(
                    _mm_sqrt_sd(_mm_setzero_pd(), d11_re),
                    isigma);
                let y0 = _mm_cvtsi32_sd(_mm_setzero_pd(),
                    self.next_sse2(w0, leaf));
                let y1 = _mm_cvtsi32_sd(_mm_setzero_pd(),
                    self.next_sse2(w1, leaf));

                // Merge is trivial

                // tb0 = t0 + (t1 - z1)*l10 (into [x0, x1]).
                // z1 is moved into t1.
                let y = _mm_shuffle_pd(y0, y1, 0);
                let a = _mm_sub_pd(w, y);
                let b1 = _mm_mul_pd(a, _mm_xor_pd(cz, l01));
                let b2 = _mm_mul_pd(a, _mm_shuffle_pd(l01, l01, 1));
                let b = _mm_add_pd(
                    _mm_shuffle_pd(b1, b2, 2),
                    _mm_shuffle_pd(b1, b2, 1));
                let x = _mm_add_pd(b, _mm_loadu_pd(tt0));
                _mm_storeu_pd(tt1, y);

                // Second recursive invocation
                let x0 = x;
                let x1 = _mm_shuffle_pd(x, x, 3);
                let leaf = _mm_mul_sd(
                    _mm_sqrt_sd(_mm_setzero_pd(), d00_re),
                    isigma);
                let y0 = _mm_cvtsi32_sd(_mm_setzero_pd(),
                    self.next_sse2(x0, leaf));
                let y1 = _mm_cvtsi32_sd(_mm_setzero_pd(),
                    self.next_sse2(x1, leaf));
                _mm_store_sd(tt0, y0);
                _mm_store_sd(tt0.wrapping_add(1), y1);

                return;
            }
        }

        #[cfg(not(all(target_arch = "x86", target_feature = "sse2")))]
        if logn == 1 {
            // Decompose G into LDL. g00 and g11 are self-adjoint and thus
            // use one coefficient each.
            let g00_re = g00[0];
            let (g01_re, g01_im) = (g01[0], g01[1]);
            let g11_re = g11[0];
            let inv_g00_re = FLR::ONE / g00_re;
            let (mu_re, mu_im) = (g01_re * inv_g00_re, g01_im * inv_g00_re);
            let zo_re = mu_re * g01_re + mu_im * g01_im;
            let d00_re = g00_re;
            let l01_re = mu_re;
            let l01_im = -mu_im;
            let d11_re = g11_re - zo_re;

            // No split on d00 and d11, since they have a single coefficient.

            // The half-size Gram matrices for the recursive LDL tree
            // exploration are now:
            //   - left sub-tree:   d00_re, zero, d00_re
            //   - right sub-tree:  d11_re, zero, d11_re

            // t1 split is trivial, since logn = 1.
            let w0 = t1[0];
            let w1 = t1[1];

            // Recursive call on the two halves, using the right sub-tree.
            let leaf = d11_re.sqrt() * INV_SIGMA[self.logn as usize];
            let y0 = FLR::from_i32(self.next(w0, leaf));
            let y1 = FLR::from_i32(self.next(w1, leaf));

            // Merge is trivial, since logn = 1.

            // At this point:
            //   t0 and t1 are unmodified; t1 is also [w0, w1]
            //   l10 is in [l01_re, l01_im]
            //   z1 is [y0, y1]
            // Compute tb0 = t0 + (t1 - z1)*l10 (into [x0, x1]).
            // z1 is moved into t1.
            let (a_re, a_im) = (w0 - y0, w1 - y1);
            let (b_re, b_im) = flc_mul(a_re, a_im, l01_re, l01_im);
            let (x0, x1) = (t0[0] + b_re, t0[1] + b_im);
            t1[0] = y0;
            t1[1] = y1;

            // Second recursive invocation, on the split tb0, using the
            // left sub-tree. tb0 is [x0, x1] and its split is trivial
            // since logn = 1.
            let leaf = d00_re.sqrt() * INV_SIGMA[self.logn as usize];
            t0[0] = FLR::from_i32(self.next(x0, leaf));
            t0[1] = FLR::from_i32(self.next(x1, leaf));

            return;
        }

        // General case: logn >= 2.
        let n = 1usize << logn;
        let hn = n >> 1;

        // Decompose G into LDL; the decomposed matrix replaces G.
        poly_LDL_fft(logn, &*g00, g01, g11);

        // Split d00 and d11 (currently in g00 and g11) and expand them
        // into half-size quasi-cyclic Gram matrices. We also
        // save l10 (in g01) into tmp.
        if logn > 1 {
            // If n = 2 then the two splits below are no-ops.
            let (w0, w1) = tmp.split_at_mut(hn);
            poly_split_selfadj_fft(logn, w0, w1, &*g00);
            g00[0..hn].copy_from_slice(&w0[0..hn]);
            g00[hn..n].copy_from_slice(&w1[0..hn]);
            poly_split_selfadj_fft(logn, w0, w1, &*g11);
            g11[0..hn].copy_from_slice(&w0[0..hn]);
            g11[hn..n].copy_from_slice(&w1[0..hn]);
        }
        tmp[0..n].copy_from_slice(&g01[0..n]);
        g01[0..hn].copy_from_slice(&g00[0..hn]);
        g01[hn..n].copy_from_slice(&g11[0..hn]);

        // The half-size Gram matrices for the recursive LDL tree
        // exploration are now:
        //   - left sub-tree:   g00[0..hn], g00[hn..n], g01[0..hn]
        //   - right sub-tree:  g11[0..hn], g11[hn..n], g01[hn..n]
        // l10 is in tmp[0..n].
        let (left_00, left_01) = g00.split_at_mut(hn);
        let (right_00, right_01) = g11.split_at_mut(hn);
        let (left_11, right_11) = g01.split_at_mut(hn);

        // We split t1 and use the first recursive call on the two
        // halves, using the right sub-tree. The result is merged
        // back into tmp[2*n..3*n].
        {
            let (_, tmp) = tmp.split_at_mut(n);
            let (w0, tmp) = tmp.split_at_mut(hn);
            let (w1, tmp) = tmp.split_at_mut(hn);
            poly_split_fft(logn, w0, w1, &*t1);
            self.ffsamp_fft_inner(logn - 1, w0, w1,
                right_00, right_01, right_11, tmp);
            poly_merge_fft(logn, tmp, &*w0, &*w1);
        }

        // At this point:
        //   t0 and t1 are unmodified
        //   l10 is in tmp[0..n]
        //   z1 is in tmp[2*n..3*n]
        // Compute tb0 = t0 + (t1 - z1)*l10.
        // tb0 is written over t0.
        // z1 is moved into t1.
        // l10 is scratched.
        {
            let (l10, tmp) = tmp.split_at_mut(n);
            let (w, z1) = tmp.split_at_mut(n);
            w[0..n].copy_from_slice(&t1[0..n]);
            poly_sub(logn, w, &*z1);
            t1[0..n].copy_from_slice(&z1[0..n]);
            poly_mul_fft(logn, l10, &*w);
            poly_add(logn, t0, &*l10);
        }

        // Second recursive invocation, on the split tb0 (currently in t0),
        // using the left sub-tree.
        // tmp is free at this point.
        {
            let (w0, tmp) = tmp.split_at_mut(hn);
            let (w1, tmp) = tmp.split_at_mut(hn);
            poly_split_fft(logn, w0, w1, &*t0);
            self.ffsamp_fft_inner(logn - 1, w0, w1,
                left_00, left_01, left_11, tmp);
            poly_merge_fft(logn, t0, &*w0, &*w1);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;
    use crate::flr::FLR;
    use fn_dsa_comm::shake::SHAKE256_PRNG;

    #[test]
    fn sampler() {
        let mut samp = Sampler::<SHAKE256_PRNG>::new(9, &KAT_SAMPLER_512_SEED);
        let mut nonce = [0u8; 40];
        samp.next_bytes(&mut nonce);
        assert!(nonce == KAT_SAMPLER_512_NONCE);
        for i in 0..KAT_SAMPLER_512_MU.len() {
            let mu = KAT_SAMPLER_512_MU[i];
            let isigma = KAT_SAMPLER_512_INVSIGMA[i];
            let r = KAT_SAMPLER_512_OUT[i] as i32;
            let x = samp.next(mu, isigma);
            assert!(x == r);
        }
    }

    pub(crate) const KAT_SAMPLER_512_SEED: [u8; 41] = [
        0x97, 0xE0, 0xA2, 0x37, 0x71, 0x24, 0x1D, 0x1D, 0x67, 0xD3,
        0x20, 0xDC, 0x78, 0xB9, 0x67, 0x13, 0xD6, 0xD2, 0x2A, 0x12,
        0x13, 0xBB, 0xD7, 0x27, 0x1D, 0xA7, 0x89, 0x61, 0xF4, 0x95,
        0xD9, 0x7E, 0xFC, 0xDF, 0x61, 0x24, 0x83, 0x1C, 0x6F, 0xBD,
        0x00,
    ];

    pub(crate) const KAT_SAMPLER_512_NONCE: [u8; 40] = [
        0x21, 0x58, 0x62, 0xEC, 0x78, 0xDD, 0x57, 0xF2, 0xCC, 0x86,
        0xDC, 0xE0, 0x2E, 0xCE, 0x34, 0x34, 0xA8, 0x80, 0x15, 0x36,
        0x0E, 0x05, 0x5A, 0x5A, 0x04, 0xC4, 0xEF, 0xD7, 0x40, 0x2D,
        0x87, 0x04, 0xE2, 0x8E, 0x35, 0xA8, 0x72, 0xC6, 0x0D, 0xAA,
    ];

    pub(crate) const KAT_SAMPLER_512_MU: [FLR; 1024] = [
        FLR::scaled(-0x139DB0B6FC3017, -52 + 6),  // -7.846391081454963512e+01
        FLR::scaled( 0x10109A521E4A04, -52 + 4),  // +1.606485474814873271e+01
        FLR::scaled(-0x15F5A07B9B45DF, -52 + 5),  // -4.391896004754720906e+01
        FLR::scaled(-0x19117F49FCE7D3, -52 + 5),  // -5.013669705246834241e+01
        FLR::scaled(-0x155B465DC24834, -52 + 4),  // -2.135654245370115234e+01
        FLR::scaled(-0x197455A314CCEA, -52 + 4),  // -2.545443171747039202e+01
        FLR::scaled(-0x1B6F11C5A76C3C, -52 + 5),  // -5.486772986102047867e+01
        FLR::scaled(-0x11E94A2FBD2DA8, -52 + 5),  // -3.582257649171089042e+01
        FLR::scaled(-0x1939F4BAB36296, -52 + 4),  // -2.522639052276152682e+01
        FLR::scaled( 0x1E6911AA441350, -52 + 2),  // +7.602606449513430675e+00
        FLR::scaled(-0x1947649AB1AD3F, -52 + 5),  // -5.055775769878027148e+01
        FLR::scaled(-0x169AF4E2C27DEC, -52 + 6),  // -9.042119664185855754e+01
        FLR::scaled(-0x1AA8A14DBDAFE0, -52 + 5),  // -5.331742259752331847e+01
        FLR::scaled(-0x1D5ED6A9A8CB86, -52 + 6),  // -1.174818519733799747e+02
        FLR::scaled(-0x12E0FE0AC1D4FC, -52 + 5),  // -3.775775274719669028e+01
        FLR::scaled(-0x1FF60D193577B1, -52 + 0),  // -1.997571085426425919e+00
        FLR::scaled(-0x14B969D668F3A4, -52 + 6),  // -8.289708481072608492e+01
        FLR::scaled( 0x1EDDEC71B10E80, -52 - 2),  // +4.822951421994972065e-01
        FLR::scaled(-0x1BB60148006D87, -52 + 5),  // -5.542191410084620173e+01
        FLR::scaled(-0x13DFF220601E77, -52 + 6),  // -7.949915322672482887e+01
        FLR::scaled( 0x197E4B3BFFB371, -52 + 4),  // +2.549333548538874439e+01
        FLR::scaled(-0x115831CDB3D7DA, -52 + 6),  // -6.937803976595697009e+01
        FLR::scaled(-0x1391287D711312, -52 + 3),  // -9.783512039235152002e+00
        FLR::scaled(-0x1CD82915A0AF44, -52 + 5),  // -5.768875379892281785e+01
        FLR::scaled(-0x15BE29BDBBC101, -52 + 6),  // -8.697129767737716577e+01
        FLR::scaled(-0x12E53901857C7C, -52 + 5),  // -3.779080218332180152e+01
        FLR::scaled(-0x11E8B8DBE00DCF, -52 + 5),  // -3.581814144554265766e+01
        FLR::scaled(-0x173EF0056EB26B, -52 + 6),  // -9.298339973268745950e+01
        FLR::scaled(-0x1290249D2E25FC, -52 + 3),  // -9.281529342540117966e+00
        FLR::scaled(-0x1D04F0BEA00051, -52 + 5),  // -5.803859694302139616e+01
        FLR::scaled(-0x10DB3126564532, -52 + 4),  // -1.685621871572693209e+01
        FLR::scaled(-0x1F69938CE6992B, -52 + 4),  // -3.141240769033280955e+01
        FLR::scaled(-0x1DBCAA3D2DBA3E, -52 + 5),  // -5.947394528134144309e+01
        FLR::scaled( 0x119F44BAF4E868, -52 + 1),  // +2.202767811392778441e+00
        FLR::scaled(-0x11E2199E7ADB40, -52 + 5),  // -3.576640683173036450e+01
        FLR::scaled(-0x128F7E6F30593D, -52 + 5),  // -3.712104596958895542e+01
        FLR::scaled(-0x1803382B6F2265, -52 + 2),  // -6.003143957765677108e+00
        FLR::scaled( 0x12B7A5F78A60A8, -52 + 4),  // +1.871737620476110919e+01
        FLR::scaled(-0x196AFACB6DC3FF, -52 + 4),  // -2.541788932256531197e+01
        FLR::scaled(-0x14A38EA0DDA07E, -52 + 6),  // -8.255558034556631242e+01
        FLR::scaled(-0x17FED4ADAE7D40, -52 + 6),  // -9.598173086204496940e+01
        FLR::scaled(-0x1E4F22C25D0462, -52 + 4),  // -3.030912413378644743e+01
        FLR::scaled( 0x1F7A4A72B2726C, -52 - 1),  // +9.836780777146265642e-01
        FLR::scaled( 0x12F74F6F3B182A, -52 + 2),  // +4.741513956052623158e+00
        FLR::scaled( 0x1333C003DEB620, -52 + 3),  // +9.601074334083989470e+00
        FLR::scaled(-0x1D7D9208C19A5C, -52 + 4),  // -2.949050955511698646e+01
        FLR::scaled(-0x15950C36BDF0D5, -52 + 3),  // -1.079110880917179749e+01
        FLR::scaled(-0x1BFF74678E2337, -52 + 5),  // -5.599573988380728196e+01
        FLR::scaled(-0x1911C2F99F0DCE, -52 + 6),  // -1.002775253346692068e+02
        FLR::scaled( 0x10B820BF2D2C7C, -52 + 6),  // +6.687699870501995747e+01
        FLR::scaled(-0x158FE585CBE325, -52 + 4),  // -2.156209598758427504e+01
        FLR::scaled(-0x117BE12C235E28, -52 + 6),  // -6.993561843351255902e+01
        FLR::scaled(-0x1128B84FDAAA04, -52 + 6),  // -6.863624950746458353e+01
        FLR::scaled(-0x1480BF8A028ABF, -52 + 5),  // -4.100584530948753326e+01
        FLR::scaled(-0x14171A9CCF214F, -52 - 1),  // -6.278203070333264746e-01
        FLR::scaled(-0x1CC5EA49D542D5, -52 + 5),  // -5.754621241486680816e+01
        FLR::scaled(-0x1BD87FE17D3092, -52 + 5),  // -5.569140261280803372e+01
        FLR::scaled(-0x15D870334761E9, -52 + 6),  // -8.738184816332763205e+01
        FLR::scaled(-0x15A2DF8E4DE376, -52 + 5),  // -4.327244738391065937e+01
        FLR::scaled(-0x1A2B29B6F5C0D6, -52 + 6),  // -1.046744210624632103e+02
        FLR::scaled(-0x113133BF82A3E8, -52 + 3),  // -8.596097931573197570e+00
        FLR::scaled(-0x15492BEE9912E6, -52 + 6),  // -8.514330639790168220e+01
        FLR::scaled(-0x13C3A74B04AA08, -52 + 4),  // -1.976427143920776075e+01
        FLR::scaled(-0x1D08E7B088D68A, -52 + 5),  // -5.806957060510201529e+01
        FLR::scaled(-0x15112717061B6D, -52 + 5),  // -4.213400543020438960e+01
        FLR::scaled(-0x1E1C81EC994F5A, -52 + 4),  // -3.011135748618048780e+01
        FLR::scaled(-0x1589635D75D3D6, -52 + 4),  // -2.153667244078300058e+01
        FLR::scaled(-0x1181288A98657A, -52 + 6),  // -7.001809944994411694e+01
        FLR::scaled(-0x15BC17AF5DC44C, -52 + 5),  // -4.346947280958610804e+01
        FLR::scaled(-0x17C48EBFD16C80, -52 + 6),  // -9.507121272517724719e+01
        FLR::scaled(-0x1FEF8EB4B9D11F, -52 + 5),  // -6.387154254029359635e+01
        FLR::scaled(-0x18D354161B9D70, -52 + 6),  // -9.930200722405220404e+01
        FLR::scaled(-0x1CDABE84D60B97, -52 + 5),  // -5.770893917514256799e+01
        FLR::scaled( 0x111FA8E1221ED7, -52 + 5),  // +3.424734129110373004e+01
        FLR::scaled(-0x19FDC2C789D689, -52 + 3),  // -1.299562667424767604e+01
        FLR::scaled( 0x144FC259EB02D8, -52 + 4),  // +2.031155931460929764e+01
        FLR::scaled(-0x13FD18A0E195CE, -52 + 6),  // -7.995462820081522182e+01
        FLR::scaled(-0x1F3A25FC12B899, -52 + 5),  // -6.245428419984927615e+01
        FLR::scaled(-0x1B88E0EE524EA8, -52 + 3),  // -1.376734108690955338e+01
        FLR::scaled(-0x1BDA62034CA721, -52 + 4),  // -2.785305805798919110e+01
        FLR::scaled(-0x1A803063A123A0, -52 + 5),  // -5.300147672050593428e+01
        FLR::scaled( 0x12729AEE49C958, -52 + 6),  // +7.379070622640335841e+01
        FLR::scaled(-0x17860205E914B5, -52 + 4),  // -2.352346836986972178e+01
        FLR::scaled(-0x1BF7408E9EB3A8, -52 + 5),  // -5.593165762662039242e+01
        FLR::scaled(-0x10274F2CAF534C, -52 + 5),  // -3.230710371552285665e+01
        FLR::scaled(-0x11194A02B0917B, -52 + 4),  // -1.709878556071042155e+01
        FLR::scaled(-0x17B2B350F057BE, -52 + 3),  // -1.184902432378646253e+01
        FLR::scaled(-0x1C1209B17A6248, -52 + 4),  // -2.807046040761841255e+01
        FLR::scaled(-0x14E78084BAB832, -52 + 5),  // -4.180860957257426946e+01
        FLR::scaled(-0x1EAE5560910688, -52 + 1),  // -3.835123781610324301e+00
        FLR::scaled(-0x10F74F1EA74C33, -52 + 5),  // -3.393210204285460208e+01
        FLR::scaled(-0x1B0D4458213B09, -52 + 6),  // -1.082072964024083745e+02
        FLR::scaled(-0x18F30482193043, -52 + 5),  // -4.989857507924946134e+01
        FLR::scaled( 0x10C2DBF40E34E8, -52 + 2),  // +4.190292180411439915e+00
        FLR::scaled(-0x1803B4A4435711, -52 + 4),  // -2.401447512287183272e+01
        FLR::scaled(-0x1D9A8B00B165FE, -52 + 5),  // -5.920736702596694556e+01
        FLR::scaled(-0x1B40B0F6A0D859, -52 + 6),  // -1.090108009882691391e+02
        FLR::scaled( 0x1D5186372FA172, -52 + 5),  // +5.863690843415942311e+01
        FLR::scaled(-0x12E3612ABF9EDB, -52 + 5),  // -3.777640280109854842e+01
        FLR::scaled(-0x15E3F2F5CD2360, -52 + 4),  // -2.189042602785355029e+01
        FLR::scaled(-0x11F8D50AEB233E, -52 + 4),  // -1.797200077286401410e+01
        FLR::scaled(-0x190337315F6C0F, -52 + 5),  // -5.002512185248644272e+01
        FLR::scaled(-0x17399D4AAF6509, -52 + 4),  // -2.322505633146377946e+01
        FLR::scaled(-0x1C4191E14B30BD, -52 + 5),  // -5.651226440593152489e+01
        FLR::scaled(-0x1D69FC3C8003E4, -52 + 5),  // -5.882801014185659483e+01
        FLR::scaled( 0x151CE417E4148D, -52 + 4),  // +2.111285542791715741e+01
        FLR::scaled(-0x152533624A9BCC, -52 + 5),  // -4.229063061373707910e+01
        FLR::scaled(-0x150D5816925D81, -52 + 3),  // -1.052606268440900017e+01
        FLR::scaled(-0x1109AB6F31F076, -52 + 6),  // -6.815108852269062822e+01
        FLR::scaled(-0x12585654072CD2, -52 + 6),  // -7.338026905728045790e+01
        FLR::scaled( 0x17DB4CE962E200, -52 + 3),  // +1.192832116443696577e+01
        FLR::scaled(-0x100568B068FD37, -52 + 6),  // -6.408451471569865987e+01
        FLR::scaled(-0x10C3257E28CDB4, -52 + 6),  // -6.704916337952346339e+01
        FLR::scaled(-0x1939401804EBBC, -52 + 5),  // -5.044726848831439270e+01
        FLR::scaled(-0x100A275F256749, -52 + 6),  // -6.415865305569344912e+01
        FLR::scaled(-0x13CAFC8E1017A4, -52 + 6),  // -7.917166472980039771e+01
        FLR::scaled(-0x116CC90F2F1A2A, -52 + 5),  // -3.484988584327614092e+01
        FLR::scaled(-0x1212544CA1BF52, -52 + 6),  // -7.228639522357596547e+01
        FLR::scaled(-0x147F61E465F779, -52 + 5),  // -4.099517493227808274e+01
        FLR::scaled(-0x18F43A7D435F94, -52 + 6),  // -9.981606990413121139e+01
        FLR::scaled(-0x1D196AB2D51DDE, -52 + 5),  // -5.819856868177497233e+01
        FLR::scaled(-0x18155447A1AD96, -52 + 5),  // -4.816663451570927634e+01
        FLR::scaled(-0x135BC340A2942D, -52 + 6),  // -7.743379226567112994e+01
        FLR::scaled(-0x177AC97F786BDE, -52 + 5),  // -4.695927422885846170e+01
        FLR::scaled( 0x113028EA750435, -52 + 4),  // +1.718812432629438902e+01
        FLR::scaled(-0x1C394EEFC30458, -52 + 5),  // -5.644772145292580490e+01
        FLR::scaled(-0x1665692A8D710A, -52 + 4),  // -2.239613595917857225e+01
        FLR::scaled(-0x108D9B689BDA16, -52 + 5),  // -3.310630519494968382e+01
        FLR::scaled( 0x1C8F14CFB42B70, -52 + 1),  // +3.569863913236467567e+00
        FLR::scaled( 0x16C72133188415, -52 + 5),  // +4.555570067116801880e+01
        FLR::scaled(-0x185765AC73683A, -52 + 3),  // -1.217069758328226570e+01
        FLR::scaled(-0x1455BE2EA7898D, -52 + 6),  // -8.133973280297341546e+01
        FLR::scaled(-0x10109AFA59F0FC, -52 + 6),  // -6.425945910247168058e+01
        FLR::scaled(-0x1C1E9EA6039642, -52 + 6),  // -1.124784331355122333e+02
        FLR::scaled(-0x146779083B38C8, -52 + 6),  // -8.161676221640948370e+01
        FLR::scaled(-0x1AA7D221F8D231, -52 + 6),  // -1.066222004823582807e+02
        FLR::scaled(-0x14817668DEAAE6, -52 + 4),  // -2.050571303783626576e+01
        FLR::scaled( 0x17AE8E3894BDC0, -52 + 3),  // +1.184092881026924715e+01
        FLR::scaled(-0x19766C21EBAF7A, -52 + 3),  // -1.273129373552341193e+01
        FLR::scaled(-0x145CB8595FFF08, -52 + 5),  // -4.072437588870349146e+01
        FLR::scaled(-0x1A9454F2B3C282, -52 + 5),  // -5.315884240891774937e+01
        FLR::scaled(-0x184C3D1C25C5AC, -52 + 5),  // -4.859561492771476310e+01
        FLR::scaled( 0x1EF969AFF78EFA, -52 + 2),  // +7.743567227825900900e+00
        FLR::scaled(-0x1B31ED5DBB367F, -52 + 5),  // -5.439005633965734177e+01
        FLR::scaled(-0x1018B4E2CCC554, -52 + 3),  // -8.048255050178944714e+00
        FLR::scaled( 0x12CB63186A87F2, -52 + 3),  // +9.397240412716175939e+00
        FLR::scaled(-0x139FE70617CC78, -52 + 3),  // -9.812309446721187101e+00
        FLR::scaled(-0x17DB75BA0C537F, -52 + 4),  // -2.385726511765414770e+01
        FLR::scaled( 0x1A0D0D6E413C00, -52 - 5),  // +5.088083239444785022e-02
        FLR::scaled(-0x11094D8858F5E0, -52 + 6),  // -6.814535721480888242e+01
        FLR::scaled( 0x17CC920760F209, -52 + 2),  // +5.949775805751877478e+00
        FLR::scaled(-0x12B5D66A806317, -52 + 5),  // -3.742060595768833053e+01
        FLR::scaled(-0x14C07F8D354B96, -52 + 4),  // -2.075194628287461995e+01
        FLR::scaled(-0x114D824403C66D, -52 + 5),  // -3.460553789314585771e+01
        FLR::scaled(-0x1BD319546D529B, -52 + 3),  // -1.391230262598519651e+01
        FLR::scaled(-0x1E16E35241E911, -52 + 5),  // -6.017881229608804716e+01
        FLR::scaled(-0x15B287A441EAD0, -52 + 4),  // -2.169738222703273323e+01
        FLR::scaled(-0x1B7C249405D8B4, -52 + 4),  // -2.748493313925492032e+01
        FLR::scaled(-0x17DC932D3A2182, -52 + 5),  // -4.772324147547170980e+01
        FLR::scaled(-0x11E440927A644B, -52 + 5),  // -3.578322058654938331e+01
        FLR::scaled(-0x149749EAB50168, -52 + 6),  // -8.236388652492826168e+01
        FLR::scaled(-0x181662A49EAF8C, -52 + 4),  // -2.408744267343676881e+01
        FLR::scaled(-0x19242CD21359F3, -52 + 6),  // -1.005652356327989736e+02
        FLR::scaled(-0x13C343FA94612C, -52 + 4),  // -1.976275602457569391e+01
        FLR::scaled(-0x104E2E1B181E26, -52 + 4),  // -1.630539101923763923e+01
        FLR::scaled(-0x103903DAA0D06F, -52 + 5),  // -3.244543011524444154e+01
        FLR::scaled(-0x142BBB38F79538, -52 + 4),  // -2.017082553905967757e+01
        FLR::scaled(-0x156917AADB9B00, -52 + 6),  // -8.564206954427572782e+01
        FLR::scaled(-0x171C5BACCADA43, -52 + 4),  // -2.311077384903388676e+01
        FLR::scaled(-0x1CFFD39CC87615, -52 + 4),  // -2.899932269949029617e+01
        FLR::scaled(-0x1DD77DA01CCAB8, -52 + 5),  // -5.968352128415921243e+01
        FLR::scaled(-0x11C142CAE8600C, -52 + 6),  // -7.101970169728173232e+01
        FLR::scaled(-0x128A8E908E84E1, -52 + 4),  // -1.854123786429852672e+01
        FLR::scaled(-0x130CD565520283, -52 + 6),  // -7.620052464493532796e+01
        FLR::scaled(-0x1312D95AABC4DF, -52 + 5),  // -3.814725812327537113e+01
        FLR::scaled(-0x1336A1FA50B95C, -52 + 5),  // -3.842681816999058242e+01
        FLR::scaled(-0x1523A962CAF90B, -52 + 5),  // -4.227860674773008753e+01
        FLR::scaled( 0x1228FB05E3C14D, -52 + 6),  // +7.264032122842509409e+01
        FLR::scaled(-0x168FBF90FB2085, -52 + 6),  // -9.024606728099941222e+01
        FLR::scaled(-0x158DB86D54DABD, -52 + 5),  // -4.310719076770099178e+01
        FLR::scaled(-0x15BBF9D5398241, -52 + 5),  // -4.346856179531142317e+01
        FLR::scaled(-0x13950928BC7EE5, -52 + 5),  // -3.916434201434984885e+01
        FLR::scaled(-0x10D556A7D5DB01, -52 + 4),  // -1.683335350962716248e+01
        FLR::scaled(-0x1A3240229B9DD5, -52 + 6),  // -1.047851645011608781e+02
        FLR::scaled(-0x17359710A777FB, -52 + 5),  // -4.641867263962918599e+01
        FLR::scaled(-0x16794108171D58, -52 + 6),  // -8.989459421403205397e+01
        FLR::scaled(-0x14E6BB2E658460, -52 + 6),  // -8.360517463601854615e+01
        FLR::scaled(-0x1F820A79C26A0F, -52 + 5),  // -6.301594469063649484e+01
        FLR::scaled(-0x1A59C1DEDC389C, -52 + 4),  // -2.635061447979443017e+01
        FLR::scaled(-0x163740A0CFB408, -52 + 5),  // -4.443165979520568953e+01
        FLR::scaled(-0x12E487610EB8C0, -52 + 6),  // -7.557076288640655548e+01
        FLR::scaled(-0x1F73D05EDB64D8, -52 + 5),  // -6.290479646408647341e+01
        FLR::scaled(-0x14CDB06B4F9351, -52 + 5),  // -4.160694638619919061e+01
        FLR::scaled(-0x19439C8B8D68AF, -52 + 3),  // -1.263205371953185185e+01
        FLR::scaled(-0x1DDBC1711D039A, -52 + 4),  // -2.985842043836928639e+01
        FLR::scaled(-0x1B82EDC28CE664, -52 + 5),  // -5.502288085822945618e+01
        FLR::scaled(-0x13B6B14B214EE1, -52 + 5),  // -3.942728556753514368e+01
        FLR::scaled(-0x1A5FDD70186780, -52 + 0),  // -1.648404538986568468e+00
        FLR::scaled(-0x1148A34ED5B05A, -52 + 5),  // -3.456748376306559578e+01
        FLR::scaled(-0x11DB6B31ECFBEC, -52 + 5),  // -3.571420883246887001e+01
        FLR::scaled(-0x1363916A077243, -52 + 5),  // -3.877787518848028725e+01
        FLR::scaled(-0x1EB6D8DC0F10C5, -52 + 4),  // -3.071424651496706204e+01
        FLR::scaled(-0x10313FAB08F039, -52 + 5),  // -3.238475549637264095e+01
        FLR::scaled(-0x11DE26606E7BC7, -52 + 5),  // -3.573554616350843816e+01
        FLR::scaled(-0x180E607768FE09, -52 + 5),  // -4.811231892229631768e+01
        FLR::scaled(-0x1F390E90DDF460, -52 + 6),  // -1.248915140311742107e+02
        FLR::scaled(-0x115D991C2ECEE3, -52 + 6),  // -6.946247009821995277e+01
        FLR::scaled(-0x17EABD4181AD4D, -52 + 6),  // -9.566780126250996830e+01
        FLR::scaled(-0x1CC56AE75B0FC2, -52 + 5),  // -5.754232494303097667e+01
        FLR::scaled( 0x1EEAFD03209360, -52 + 1),  // +3.864740395003920526e+00
        FLR::scaled(-0x1B699113C8B6B6, -52 + 4),  // -2.741236995363461659e+01
        FLR::scaled(-0x15FC8A5892D76A, -52 + 5),  // -4.397297198457711431e+01
        FLR::scaled(-0x136BDC11222AD5, -52 + 4),  // -1.942132670482790857e+01
        FLR::scaled(-0x12F7BAB0A3B076, -52 + 6),  // -7.587076965317996269e+01
        FLR::scaled(-0x15CC76D19A6F6E, -52 + 3),  // -1.089934401521869844e+01
        FLR::scaled(-0x15BCEA9AC5A114, -52 + 6),  // -8.695181912708022764e+01
        FLR::scaled(-0x1B5D7AD42678A0, -52 - 2),  // -4.275805541782435881e-01
        FLR::scaled(-0x1405DE030EB2E0, -52 + 4),  // -2.002291888340812420e+01
        FLR::scaled(-0x1DE1FD3AED48C7, -52 + 5),  // -5.976554047189852525e+01
        FLR::scaled(-0x146940558CF869, -52 + 7),  // -1.632891032937361899e+02
        FLR::scaled(-0x1EF7A6B1C12E50, -52 + 5),  // -6.193477460796987089e+01
        FLR::scaled(-0x13996DE498FC14, -52 + 6),  // -7.839733233394537137e+01
        FLR::scaled(-0x19359BAB0DCD1B, -52 + 2),  // -6.302351639478071199e+00
        FLR::scaled(-0x16FF69192A6004, -52 + 6),  // -9.199078969133557848e+01
        FLR::scaled(-0x1A0461AE4F0886, -52 + 6),  // -1.040684619685945052e+02
        FLR::scaled(-0x1FBDCF1821CE70, -52 + 3),  // -1.587072062885928858e+01
        FLR::scaled(-0x10030DB354D625, -52 + 6),  // -6.404771121296705871e+01
        FLR::scaled(-0x1A22046EF48E9B, -52 + 6),  // -1.045315205944302051e+02
        FLR::scaled(-0x1667FF20BEA142, -52 + 4),  // -2.240623669294405573e+01
        FLR::scaled(-0x1AF5577D0F269D, -52 + 5),  // -5.391673243751322531e+01
        FLR::scaled( 0x1C2468E250C4D5, -52 + 1),  // +3.517778175439711053e+00
        FLR::scaled(-0x18CC4FE2686B9C, -52 + 5),  // -4.959618787859582767e+01
        FLR::scaled(-0x10C7FF05A0445A, -52 + 6),  // -6.712494030619691898e+01
        FLR::scaled(-0x1E2E20987B8A1C, -52 + 2),  // -7.545046217479946193e+00
        FLR::scaled(-0x16F712980F591E, -52 + 6),  // -9.186050988673056850e+01
        FLR::scaled(-0x12A21C32FEFFCC, -52 + 5),  // -3.726648557139523632e+01
        FLR::scaled(-0x14293388C5FF97, -52 + 4),  // -2.016094260057397136e+01
        FLR::scaled(-0x15F31807602F1B, -52 + 4),  // -2.194958540056459739e+01
        FLR::scaled(-0x11F71AF0D94253, -52 + 5),  // -3.593050966842988458e+01
        FLR::scaled(-0x159B0F17603437, -52 + 5),  // -4.321139805028399650e+01
        FLR::scaled(-0x1A75CEFBE60E7C, -52 + 4),  // -2.646018957487693513e+01
        FLR::scaled( 0x1C124032E8699F, -52 + 3),  // +1.403564604842250496e+01
        FLR::scaled(-0x177FA9DA94D3D9, -52 + 5),  // -4.699737102763146623e+01
        FLR::scaled(-0x1796D11B15D025, -52 + 4),  // -2.358912820131822130e+01
        FLR::scaled(-0x12F9A3386BF86A, -52 + 4),  // -1.897514679561610507e+01
        FLR::scaled(-0x1311B4728265D4, -52 + 6),  // -7.627663862928540084e+01
        FLR::scaled( 0x18D46B0B5CE439, -52 + 4),  // +2.482975836770876654e+01
        FLR::scaled(-0x164CD09439E127, -52 + 5),  // -4.460011532617709662e+01
        FLR::scaled(-0x160932D388FA14, -52 + 4),  // -2.203593179792558487e+01
        FLR::scaled(-0x1BA9DE4B249966, -52 + 5),  // -5.532709636008330278e+01
        FLR::scaled(-0x16D2EBC6E1D074, -52 + 6),  // -9.129564067890333945e+01
        FLR::scaled(-0x10A2A8E1B4505A, -52 + 6),  // -6.654155771836067856e+01
        FLR::scaled(-0x1E0753990E9159, -52 + 5),  // -6.005723870478932014e+01
        FLR::scaled(-0x16AC972EFE107D, -52 + 5),  // -4.534836375623215332e+01
        FLR::scaled(-0x13B075C55131F0, -52 + 6),  // -7.875718815736013312e+01
        FLR::scaled(-0x16842001CB56F4, -52 + 4),  // -2.251611338819834884e+01
        FLR::scaled(-0x1E19FDE104A3B5, -52 + 5),  // -6.020306027151620043e+01
        FLR::scaled( 0x148F3715C5913D, -52 + 5),  // +4.111886856219141606e+01
        FLR::scaled(-0x107DAE2AF83C7B, -52 + 4),  // -1.649093884048896186e+01
        FLR::scaled(-0x124F262F3547A4, -52 + 6),  // -7.323670559123144130e+01
        FLR::scaled(-0x1260F97B57DF40, -52 + 5),  // -3.675761358061436113e+01
        FLR::scaled(-0x151018F53E8A92, -52 + 5),  // -4.212576165727399768e+01
        FLR::scaled(-0x106CABD343B6A1, -52 + 6),  // -6.569798738110195302e+01
        FLR::scaled(-0x194F12E0552CE0, -52 + 6),  // -1.012355271178998919e+02
        FLR::scaled(-0x10913D7F63788C, -52 + 6),  // -6.626937851633027776e+01
        FLR::scaled(-0x17A8A429F81280, -52 + 1),  // -2.957344367869438884e+00
        FLR::scaled(-0x1B813F827A9E5F, -52 + 3),  // -1.375243766543206725e+01
        FLR::scaled(-0x1055EC9685A65F, -52 + 3),  // -8.167820648016627771e+00
        FLR::scaled(-0x1819616CDDDDD2, -52 + 5),  // -4.819828568299602978e+01
        FLR::scaled(-0x144ECEA0298BD7, -52 + 6),  // -8.123136142785311620e+01
        FLR::scaled(-0x12AC1F64E2A19C, -52 - 1),  // -5.835110636153788555e-01
        FLR::scaled(-0x124FB28EB96155, -52 + 6),  // -7.324527328589950059e+01
        FLR::scaled(-0x1A6427E2FF39C4, -52 + 5),  // -5.278246724569501680e+01
        FLR::scaled( 0x138C2198D514EE, -52 + 3),  // +9.773693824778515449e+00
        FLR::scaled(-0x12C6AC45524F6E, -52 + 6),  // -7.510426457441437265e+01
        FLR::scaled(-0x1FBE2CD3638CFF, -52 + 5),  // -6.348574297295453306e+01
        FLR::scaled(-0x1D6D30B11BB5B0, -52 + 1),  // -3.678315528543599555e+00
        FLR::scaled(-0x12D9293DE45880, -52 + 6),  // -7.539314219760308333e+01
        FLR::scaled(-0x14F289DC3E7F01, -52 + 3),  // -1.047370804083721119e+01
        FLR::scaled(-0x1344CEB15BFF9D, -52 + 5),  // -3.853755776397813548e+01
        FLR::scaled(-0x1CEEB31818E831, -52 + 3),  // -1.446621012977638721e+01
        FLR::scaled(-0x1E5469BD47E1FB, -52 + 3),  // -1.516486922743296439e+01
        FLR::scaled(-0x1251B0BE41A344, -52 + 5),  // -3.663820627407997677e+01
        FLR::scaled(-0x1E4615722DB17A, -52 + 5),  // -6.054752948027721970e+01
        FLR::scaled(-0x106ADFDE2FA5F4, -52 + 5),  // -3.283495690657210275e+01
        FLR::scaled(-0x134A3CB0A2F0F0, -52 + 6),  // -7.715995422279570448e+01
        FLR::scaled(-0x12D0D4C3060757, -52 + 6),  // -7.526298595036256245e+01
        FLR::scaled(-0x13F4745610F4DF, -52 + 4),  // -1.995490014947869994e+01
        FLR::scaled(-0x11EB9F5AED36B6, -52 + 5),  // -3.584080063421917828e+01
        FLR::scaled( 0x18ED68851C6A3E, -52 + 4),  // +2.492737609809613986e+01
        FLR::scaled( 0x1E53DDAE9DDBCB, -52 + 3),  // +1.516380067517265751e+01
        FLR::scaled(-0x11F46722731D40, -52 + 6),  // -7.181879483453394641e+01
        FLR::scaled( 0x1424387610F932, -52 + 4),  // +2.014148652948751561e+01
        FLR::scaled(-0x143D982CE1F538, -52 + 5),  // -4.048120652230358019e+01
        FLR::scaled(-0x14FF4CF492B863, -52 + 4),  // -2.099726799566304791e+01
        FLR::scaled(-0x165E4DA09BC8D2, -52 + 5),  // -4.473674399954474268e+01
        FLR::scaled(-0x172A44FB635E4A, -52 + 6),  // -9.266046032623231099e+01
        FLR::scaled( 0x1573588C8A8A00, -52 - 2),  // +3.351651546928735570e-01
        FLR::scaled(-0x1B6DD90BCF14DB, -52 + 5),  // -5.485818622218513241e+01
        FLR::scaled(-0x1F8E14A6935C05, -52 + 3),  // -1.577750130223103930e+01
        FLR::scaled(-0x1BBD5EC063FC13, -52 + 5),  // -5.547945408708633153e+01
        FLR::scaled(-0x11BAA04E77298F, -52 + 5),  // -3.545801716631387279e+01
        FLR::scaled( 0x17E1DB7F425091, -52 + 4),  // +2.388225551003467118e+01
        FLR::scaled(-0x1709526B498506, -52 + 6),  // -9.214565546207094826e+01
        FLR::scaled(-0x1FFAB5B430E70B, -52 + 4),  // -3.197933508104237532e+01
        FLR::scaled( 0x1DA12E473F0396, -52 + 3),  // +1.481480620044912300e+01
        FLR::scaled(-0x14522E23CB87B1, -52 + 6),  // -8.128406615138989366e+01
        FLR::scaled(-0x107271670D4264, -52 + 4),  // -1.644704288552965465e+01
        FLR::scaled( 0x141C4AC9D498D2, -52 + 3),  // +1.005525809021165529e+01
        FLR::scaled(-0x1F68D78D024E8E, -52 + 5),  // -6.281907808888091438e+01
        FLR::scaled(-0x13745A1641F480, -52 + 5),  // -3.890899923534834670e+01
        FLR::scaled(-0x1AD379B8A8B606, -52 + 5),  // -5.365215214002459732e+01
        FLR::scaled(-0x175D712BBBB0B8, -52 + 4),  // -2.336500809986384297e+01
        FLR::scaled(-0x1333A9C0E6F3C1, -52 + 6),  // -7.680723593286440121e+01
        FLR::scaled(-0x1FA2EC2F6DCA01, -52 + 5),  // -6.327283280239863217e+01
        FLR::scaled(-0x1C4351A1B1233B, -52 + 6),  // -1.130518573980197488e+02
        FLR::scaled(-0x1957A59C219E00, -52 + 5),  // -5.068474151269401773e+01
        FLR::scaled(-0x139E517BC26058, -52 + 4),  // -1.961843083854213887e+01
        FLR::scaled(-0x119B2D8566C5E4, -52 + 5),  // -3.521232669370854751e+01
        FLR::scaled(-0x14925E7A9D59BA, -52 + 5),  // -4.114350826914910897e+01
        FLR::scaled(-0x10389971CCDF9E, -52 + 6),  // -6.488436551100900829e+01
        FLR::scaled(-0x13A4824AB494C0, -52 - 1),  // -6.138316592302075492e-01
        FLR::scaled(-0x173DD0865ED75C, -52 + 2),  // -5.810365771807337154e+00
        FLR::scaled(-0x11B40E0DF932E0, -52 + 6),  // -7.081335782371343157e+01
        FLR::scaled(-0x13D1AEFADEBBEF, -52 + 5),  // -3.963815246463479269e+01
        FLR::scaled(-0x18C26135D61979, -52 + 5),  // -4.951859162286832117e+01
        FLR::scaled(-0x14B5A3B26CACE3, -52 + 6),  // -8.283811627018762636e+01
        FLR::scaled(-0x105553D75329F9, -52 + 6),  // -6.533324225541572616e+01
        FLR::scaled(-0x15A624D4BBFEB9, -52 + 6),  // -8.659599798544776661e+01
        FLR::scaled(-0x1CF0EE10C1C299, -52 + 5),  // -5.788226518116898234e+01
        FLR::scaled(-0x12C2B6F59B9B4E, -52 + 6),  // -7.504241695590937411e+01
        FLR::scaled( 0x160D6A172722AF, -52 + 3),  // +1.102620003082969724e+01
        FLR::scaled(-0x1D5B13B6CA5AEE, -52 + 3),  // -1.467788478107601335e+01
        FLR::scaled(-0x152124D2BEC192, -52 + 3),  // -1.056473406389776315e+01
        FLR::scaled( 0x102872D4592056, -52 + 6),  // +6.463200863555661613e+01
        FLR::scaled(-0x10CC8AA629359F, -52 + 5),  // -3.359798123371296441e+01
        FLR::scaled(-0x16C277AB77D350, -52 + 4),  // -2.275963851619172829e+01
        FLR::scaled( 0x16D0C743F3DE54, -52 + 2),  // +5.703885137328672528e+00
        FLR::scaled(-0x10C6E802B8F3FD, -52 + 6),  // -6.710791080533813613e+01
        FLR::scaled( 0x1DF1905FA732F9, -52 - 6),  // +2.924180587597200245e-02
        FLR::scaled(-0x1D74638AF82F72, -52 + 3),  // -1.472732195167165870e+01
        FLR::scaled(-0x11581CF50D6994, -52 + 5),  // -3.468838370470908217e+01
        FLR::scaled(-0x164CB0FA248A5B, -52 + 5),  // -4.459915091308786117e+01
        FLR::scaled(-0x1D49D35637CF12, -52 + 3),  // -1.464419049674282647e+01
        FLR::scaled(-0x1066F491938716, -52 + 4),  // -1.640216932155370699e+01
        FLR::scaled(-0x17D5CBF04C22CA, -52 + 4),  // -2.383514310702120298e+01
        FLR::scaled(-0x19A57FB7CA8D39, -52 + 5),  // -5.129296014204232534e+01
        FLR::scaled(-0x1884CCE1B62FBB, -52 + 6),  // -9.807500498572964887e+01
        FLR::scaled(-0x1566F155E50B4C, -52 + 5),  // -4.280423997577472051e+01
        FLR::scaled(-0x1B01307B5578A0, -52 + 6),  // -1.080185840925864795e+02
        FLR::scaled(-0x167CBDBA1CD898, -52 + 5),  // -4.497454000862597923e+01
        FLR::scaled(-0x140D063A478D9A, -52 + 6),  // -8.020350510585413417e+01
        FLR::scaled(-0x122C49B83E66D6, -52 + 6),  // -7.269199949354091927e+01
        FLR::scaled( 0x119FD8368F836A, -52 + 5),  // +3.524878580100524061e+01
        FLR::scaled(-0x1007ABE7CC8DBA, -52 + 5),  // -3.205993363845796296e+01
        FLR::scaled( 0x193E3534D26079, -52 + 1),  // +3.155374920530502170e+00
        FLR::scaled( 0x165749309B8E60, -52 + 1),  // +2.792620067355343849e+00
        FLR::scaled(-0x117485D20983E8, -52 + 6),  // -6.982066775254463664e+01
        FLR::scaled(-0x17ACEED058C46A, -52 + 6),  // -9.470207604092288989e+01
        FLR::scaled(-0x19C5E66A9D7D08, -52 + 5),  // -5.154609425248969501e+01
        FLR::scaled(-0x103A0DD18619D4, -52 + 6),  // -6.490709341140546940e+01
        FLR::scaled( 0x10BB0E26451856, -52 + 5),  // +3.346136930822164857e+01
        FLR::scaled(-0x1DB98EFE7DC340, -52 + 1),  // -3.715604770863507156e+00
        FLR::scaled(-0x152A3BF87317DE, -52 + 5),  // -4.232995515460764580e+01
        FLR::scaled(-0x1DFB48D2AB7B06, -52 + 5),  // -5.996315987942766412e+01
        FLR::scaled(-0x126CD093217110, -52 + 5),  // -3.685011519558804594e+01
        FLR::scaled( 0x145633031FC000, -52 + 1),  // +2.542089485556061845e+00
        FLR::scaled(-0x13D5DFF13F4921, -52 + 5),  // -3.967089667883033854e+01
        FLR::scaled(-0x14F497D643393A, -52 + 6),  // -8.382176739277647926e+01
        FLR::scaled( 0x1E1501AC75A6FA, -52 + 4),  // +3.008205678818101347e+01
        FLR::scaled(-0x1655A44EA0DEF9, -52 + 5),  // -4.466907675604847583e+01
        FLR::scaled(-0x1EAC4F85DFEDB3, -52 + 5),  // -6.134617684778222468e+01
        FLR::scaled(-0x18A9B93F61FC48, -52 + 4),  // -2.466298290388320424e+01
        FLR::scaled(-0x17ACFE8B7C4840, -52 + 6),  // -9.470303618561683834e+01
        FLR::scaled( 0x159587D58210E1, -52 + 3),  // +1.079205195629805480e+01
        FLR::scaled(-0x12F60FBCF71956, -52 + 6),  // -7.584471058016546863e+01
        FLR::scaled( 0x199BFF8468E2F8, -52 + 3),  // +1.280468381672243083e+01
        FLR::scaled(-0x18DAD42A8FEA88, -52 + 5),  // -4.970959980036883508e+01
        FLR::scaled(-0x18F8F4D97C9DA2, -52 + 5),  // -4.994497221550706456e+01
        FLR::scaled(-0x18FFBB3292DD25, -52 + 6),  // -9.999580063192532009e+01
        FLR::scaled(-0x1FE28406ABE45A, -52 + 4),  // -3.188482705780584325e+01
        FLR::scaled(-0x14E3E8A5146C4C, -52 + 6),  // -8.356107451433598499e+01
        FLR::scaled(-0x104B41DB23BE2F, -52 + 4),  // -1.629397363302831181e+01
        FLR::scaled(-0x105FF77754F131, -52 + 6),  // -6.549947913451320858e+01
        FLR::scaled(-0x1071C2BFAE0752, -52 + 7),  // -1.315550230406757350e+02
        FLR::scaled( 0x11000050E60216, -52 + 6),  // +6.800001928769810888e+01
        FLR::scaled(-0x1B78BAC7737A35, -52 + 5),  // -5.494320004595321194e+01
        FLR::scaled( 0x17055878DE8EA6, -52 + 1),  // +2.877610153476626742e+00
        FLR::scaled(-0x1D3E5DA53F8B78, -52 + 6),  // -1.169744656677775083e+02
        FLR::scaled(-0x1CDC6ACC7693F4, -52 + 5),  // -5.772200923719347543e+01
        FLR::scaled( 0x17925B34440EDF, -52 + 2),  // +5.892926041273056192e+00
        FLR::scaled(-0x1FD987C3EAF9C4, -52 + 5),  // -6.369945572827739966e+01
        FLR::scaled(-0x1461BD1ECE77F2, -52 + 5),  // -4.076358399468871596e+01
        FLR::scaled( 0x17B4A06EB54BFC, -52 + 5),  // +4.741114600994475836e+01
        FLR::scaled(-0x1BF755DFB5DDC9, -52 + 3),  // -1.398307704062507817e+01
        FLR::scaled(-0x1DFBFF049B82EF, -52 + 5),  // -5.996872003167469956e+01
        FLR::scaled(-0x102F8AD80C0B78, -52 + 5),  // -3.237142468059658995e+01
        FLR::scaled(-0x176668C4925BCE, -52 + 6),  // -9.360014452259858331e+01
        FLR::scaled(-0x1331230B753171, -52 + 2),  // -4.797985247638608008e+00
        FLR::scaled(-0x14FCC4571D662A, -52 + 5),  // -4.197474183021070360e+01
        FLR::scaled(-0x10830FEC4A2B4E, -52 + 6),  // -6.604784686320383003e+01
        FLR::scaled( 0x1353A610B1723E, -52 + 4),  // +1.932675270397361800e+01
        FLR::scaled(-0x15245C199DA414, -52 + 4),  // -2.114203033541350862e+01
        FLR::scaled(-0x1D039531FE9E16, -52 + 5),  // -5.802799057896133661e+01
        FLR::scaled(-0x134D49A159AEB1, -52 + 5),  // -3.860380951766035906e+01
        FLR::scaled( 0x1066BCF2EE87F0, -52 + 2),  // +4.100330158051278318e+00
        FLR::scaled(-0x103AFE83B4B19F, -52 + 5),  // -3.246089216540280376e+01
        FLR::scaled(-0x13E97CF5739DFC, -52 + 5),  // -3.982412593980185989e+01
        FLR::scaled(-0x1CD0776DFBC3A4, -52 + 5),  // -5.762864470284628737e+01
        FLR::scaled(-0x191F39698915F7, -52 + 4),  // -2.512196979138203901e+01
        FLR::scaled(-0x1E5C534FE4C6C6, -52 + 5),  // -6.072129248305058979e+01
        FLR::scaled(-0x161ED6C306EEBE, -52 + 6),  // -8.848185802151689927e+01
        FLR::scaled(-0x1D15E37A4AE408, -52 + 5),  // -5.817100456864142188e+01
        FLR::scaled(-0x103C14AF39E168, -52 + 4),  // -1.623469062007043817e+01
        FLR::scaled(-0x1DDF573FA61E11, -52 + 3),  // -1.493621252920914522e+01
        FLR::scaled(-0x10E144A558D9A7, -52 + 5),  // -3.375990740621937647e+01
        FLR::scaled(-0x1288C760AD0F6A, -52 + 4),  // -1.853429226136305630e+01
        FLR::scaled( 0x1283E5FE130F0B, -52 + 5),  // +3.703045631342509836e+01
        FLR::scaled(-0x1DE3F2EA1A4C96, -52 + 4),  // -2.989042533056325368e+01
        FLR::scaled(-0x14B55E637F62E0, -52 + 5),  // -4.141694301338225159e+01
        FLR::scaled(-0x16D8A672340A66, -52 + 6),  // -9.138515906412212075e+01
        FLR::scaled(-0x164E854B9D4D0D, -52 + 5),  // -4.461344285183631797e+01
        FLR::scaled(-0x16853BA82115FD, -52 + 5),  // -4.504088307967683846e+01
        FLR::scaled(-0x1202ABD14BB9A2, -52 + 6),  // -7.204173691172630356e+01
        FLR::scaled( 0x1AC76E9677EBD4, -52 + 5),  // +5.355806237082984467e+01
        FLR::scaled( 0x19DCD0D44A1FFE, -52 + 3),  // +1.293128074078412837e+01
        FLR::scaled(-0x10F494B7F36D38, -52 + 6),  // -6.782157706043369672e+01
        FLR::scaled(-0x142E2626474E1F, -52 + 6),  // -8.072107846225161154e+01
        FLR::scaled(-0x14654B89987645, -52 + 5),  // -4.079136772102769015e+01
        FLR::scaled(-0x10804AF70A9960, -52 + 6),  // -6.600457550082273883e+01
        FLR::scaled( 0x194B42178FC88F, -52 + 2),  // +6.323494308615535964e+00
        FLR::scaled(-0x10AE09568E7A9C, -52 + 6),  // -6.671931995309790864e+01
        FLR::scaled(-0x1CBC4E2CC1671A, -52 + 5),  // -5.747113570636265933e+01
        FLR::scaled( 0x13882E79137960, -52 + 4),  // +1.953195912099306497e+01
        FLR::scaled(-0x120472B3114B35, -52 + 5),  // -3.603475035042212227e+01
        FLR::scaled(-0x16B6CECFBEB023, -52 + 5),  // -4.542818638621272243e+01
        FLR::scaled(-0x140A48891AA466, -52 + 5),  // -4.008033860970390094e+01
        FLR::scaled(-0x1DD001E1ADF454, -52 + 5),  // -5.962505742067210690e+01
        FLR::scaled(-0x10AA5F58B670E6, -52 + 4),  // -1.666551737264753541e+01
        FLR::scaled(-0x1F1B3626FDC102, -52 + 4),  // -3.110629504866756889e+01
        FLR::scaled(-0x147A0D594922B8, -52 + 4),  // -2.047676618609941102e+01
        FLR::scaled(-0x182844E087C95B, -52 + 6),  // -9.662920392284779325e+01
        FLR::scaled(-0x1548B4ABE1E534, -52 + 6),  // -8.513602730808344177e+01
        FLR::scaled(-0x12F9050E8B050E, -52 + 6),  // -7.589093364311358414e+01
        FLR::scaled(-0x18CE2ED25C03AA, -52 + 5),  // -4.961080388539205899e+01
        FLR::scaled(-0x1333B59F193FFC, -52 + 4),  // -1.920199007383779133e+01
        FLR::scaled(-0x155DAD043B1256, -52 + 2),  // -5.341480318170019004e+00
        FLR::scaled(-0x17D85880DA3725, -52 + 2),  // -5.961275113409816306e+00
        FLR::scaled(-0x1422799276C720, -52 + 6),  // -8.053867017363927516e+01
        FLR::scaled( 0x132F310A23B7A7, -52 + 5),  // +3.836868407005322723e+01
        FLR::scaled(-0x1B036EAD11454C, -52 + 4),  // -2.701340753242156723e+01
        FLR::scaled( 0x14FE46FD39244F, -52 + 3),  // +1.049663535425693617e+01
        FLR::scaled(-0x196B2C24B5D47B, -52 + 5),  // -5.083728464964311655e+01
        FLR::scaled(-0x18FC13D816FACB, -52 + 5),  // -4.996935559389165604e+01
        FLR::scaled(-0x181A90A8F430F9, -52 + 4),  // -2.410376983606053969e+01
        FLR::scaled(-0x105F48CB608558, -52 + 6),  // -6.548881802011362652e+01
        FLR::scaled(-0x1D178082528286, -52 + 5),  // -5.818360928562928791e+01
        FLR::scaled( 0x137AE969CDE3ED, -52 + 4),  // +1.948012410427684316e+01
        FLR::scaled(-0x1D209239F9EF06, -52 + 4),  // -2.912723123886009802e+01
        FLR::scaled(-0x1CCA5CE6348373, -52 + 5),  // -5.758096005977758836e+01
        FLR::scaled(-0x1FAD94976DBD00, -52 - 1),  // -9.899390180197826794e-01
        FLR::scaled(-0x1888976917CDB1, -52 + 5),  // -4.906712068235663793e+01
        FLR::scaled(-0x169FD8B965FDD1, -52 + 5),  // -4.524880139808704627e+01
        FLR::scaled(-0x1BB88FCD5076CA, -52 + 6),  // -1.108837769780904239e+02
        FLR::scaled(-0x140DDA697A2D71, -52 + 6),  // -8.021645581179997464e+01
        FLR::scaled( 0x13D583E0E9BF6C, -52 + 4),  // +1.983404355723125434e+01
        FLR::scaled(-0x1410271B4512F8, -52 + 3),  // -1.003154835909070641e+01
        FLR::scaled(-0x1348DA8F1D5C22, -52 + 6),  // -7.713833978526284341e+01
        FLR::scaled(-0x161793CA296244, -52 + 2),  // -5.523024710441465146e+00
        FLR::scaled(-0x18299FE414D014, -52 + 5),  // -4.832519198433161023e+01
        FLR::scaled(-0x1F6AA0F546F391, -52 + 4),  // -3.141651852590763738e+01
        FLR::scaled( 0x18BF898D71C6B7, -52 + 1),  // +3.093524079355883583e+00
        FLR::scaled(-0x12F77CF3DBDC10, -52 + 5),  // -3.793350074992497412e+01
        FLR::scaled(-0x1618268F444297, -52 + 4),  // -2.209433837334162476e+01
        FLR::scaled(-0x1344E23CBF4CFE, -52 + 6),  // -7.707630842858995379e+01
        FLR::scaled(-0x14CE2299BD60E5, -52 + 6),  // -8.322086184972756939e+01
        FLR::scaled(-0x1898CFABB2FE2E, -52 + 5),  // -4.919383760681044748e+01
        FLR::scaled(-0x154911C195F627, -52 + 6),  // -8.514170875210457723e+01
        FLR::scaled( 0x10D31572CB67F6, -52 + 4),  // +1.682454602685898948e+01
        FLR::scaled(-0x1CECF47B22C149, -52 + 3),  // -1.446280274199729554e+01
        FLR::scaled(-0x18F3585BFD4ADA, -52 + 6),  // -9.980226802573761802e+01
        FLR::scaled( 0x165F0D670BD078, -52 + 2),  // +5.592824564071740667e+00
        FLR::scaled(-0x10FA0E5B7964A1, -52 + 5),  // -3.395356315066715780e+01
        FLR::scaled(-0x1FDA15B599ADE2, -52 + 5),  // -6.370378751758450164e+01
        FLR::scaled(-0x1260379D2863C7, -52 + 5),  // -3.675169720146327990e+01
        FLR::scaled(-0x1D216F249CFAE9, -52 + 4),  // -2.913060215790293128e+01
        FLR::scaled(-0x171E200FEBED8F, -52 + 5),  // -4.623535346050186234e+01
        FLR::scaled(-0x134D404F1F7022, -52 + 6),  // -7.720705011434668563e+01
        FLR::scaled(-0x1B6D2B61D38A75, -52 + 5),  // -5.485288641766684492e+01
        FLR::scaled(-0x14C6EA83B25C6E, -52 + 4),  // -2.077701590637700946e+01
        FLR::scaled(-0x183FCE3DFAACA5, -52 + 4),  // -2.424924075479488650e+01
        FLR::scaled(-0x1B26CCB555A19E, -52 + 6),  // -1.086062444053881961e+02
        FLR::scaled(-0x108C30EF3CD2FF, -52 + 6),  // -6.619048672618735907e+01
        FLR::scaled(-0x1B6BF110071EDD, -52 + 6),  // -1.096865882939850536e+02
        FLR::scaled(-0x11237FC282D47F, -52 + 4),  // -1.713866820997327167e+01
        FLR::scaled(-0x10B9B4646FCEF2, -52 + 4),  // -1.672540881852814465e+01
        FLR::scaled(-0x18CC96A7105FA5, -52 + 5),  // -4.959834755229466197e+01
        FLR::scaled(-0x1F50F2C2AD0718, -52 + 2),  // -7.829051057635091126e+00
        FLR::scaled(-0x1E8B686AEE7575, -52 + 5),  // -6.108912407535073186e+01
        FLR::scaled(-0x1DA337896FC01A, -52 + 5),  // -5.927513235050737705e+01
        FLR::scaled( 0x10503F01BD02C0, -52 + 0),  // +1.019591337957692190e+00
        FLR::scaled(-0x1F4FE0EAAF6A7C, -52 + 5),  // -6.262405141415817411e+01
        FLR::scaled(-0x198C4500EB3567, -52 + 1),  // -3.193490988901135363e+00
        FLR::scaled(-0x17B4CA3AC1D86E, -52 + 5),  // -4.741242155518635570e+01
        FLR::scaled(-0x11FA8F3CD346E7, -52 + 6),  // -7.191499252922550056e+01
        FLR::scaled(-0x114863CA0B3F6A, -52 + 5),  // -3.456554532574848793e+01
        FLR::scaled(-0x1BAB15CB7F5D9B, -52 + 5),  // -5.533660262793565465e+01
        FLR::scaled(-0x185D1C85590A8D, -52 + 6),  // -9.745486577697211317e+01
        FLR::scaled(-0x1263661F0C72A6, -52 + 6),  // -7.355310798850641163e+01
        FLR::scaled(-0x156DEA1BDB7488, -52 + 3),  // -1.071467673353096473e+01
        FLR::scaled(-0x1DD71768101BA1, -52 + 2),  // -7.460050226195478196e+00
        FLR::scaled(-0x1CA63E3BA31CD0, -52 + 5),  // -5.729877419914703296e+01
        FLR::scaled( 0x130B0E5578F434, -52 + 9),  // +6.093819989633107070e+02
        FLR::scaled( 0x115B5E8F3F2A18, -52 + 6),  // +6.942764645737076989e+01
        FLR::scaled( 0x1BEBFFA2FB33C0, -52 + 7),  // +2.233749556452075922e+02
        FLR::scaled( 0x1B3011DE96E85F, -52 + 9),  // +8.700087253369964628e+02
        FLR::scaled( 0x19A16C23E797D1, -52 + 9),  // +8.201778028577047053e+02
        FLR::scaled( 0x1B851C2E43E82A, -52 + 8),  // +4.403193800594914364e+02
        FLR::scaled(-0x189B09B012A37D, -52 + 8),  // -3.936898651817389805e+02
        FLR::scaled( 0x113F76A2F70C83, -52 + 9),  // +5.519329280186360620e+02
        FLR::scaled( 0x14CE187DBD9D42, -52 + 9),  // +6.657619585813156391e+02
        FLR::scaled( 0x121C0FC087899D, -52 + 8),  // +2.897538457197604771e+02
        FLR::scaled( 0x11BD70101D3A06, -52 + 5),  // +3.547998238970835416e+01
        FLR::scaled( 0x13FE2114A46017, -52 + 9),  // +6.397661526529144567e+02
        FLR::scaled( 0x1C7F3FB1BBB282, -52 + 7),  // +2.279765251794779601e+02
        FLR::scaled( 0x1404D023ABDD36, -52 + 9),  // +6.406016305376895161e+02
        FLR::scaled(-0x1020F4886FB4ED, -52 + 9),  // -5.161194008566941420e+02
        FLR::scaled( 0x1EE10BFEBD1332, -52 + 8),  // +4.940654284845105622e+02
        FLR::scaled( 0x1CF05E4C5BA3A6, -52 + 8),  // +4.630230220393808622e+02
        FLR::scaled( 0x101DABC7449949, -52 + 9),  // +5.157088761672285955e+02
        FLR::scaled(-0x157396B516D86F, -52 + 7),  // -1.716121468969535897e+02
        FLR::scaled( 0x1ECA169250D3E7, -52 + 8),  // +4.926305106313070041e+02
        FLR::scaled( 0x16B244CAE66BB0, -52 + 8),  // +3.631417950630957421e+02
        FLR::scaled( 0x17CF6FEFAE4DCA, -52 + 8),  // +3.809648281868691129e+02
        FLR::scaled(-0x19056E498DC452, -52 + 8),  // -4.003394256150978663e+02
        FLR::scaled( 0x1CDDA557DD391E, -52 + 8),  // +4.618528669969108478e+02
        FLR::scaled( 0x19719147674232, -52 + 9),  // +8.141959369723392683e+02
        FLR::scaled( 0x1A6F97F6599F41, -52 + 8),  // +4.229746001721251218e+02
        FLR::scaled(-0x1320BF794AA93F, -52 + 6),  // -7.651168663302540551e+01
        FLR::scaled( 0x10C738F8B16318, -52 + 8),  // +2.684514090470488554e+02
        FLR::scaled( 0x136F1B746E6ACE, -52 + 8),  // +3.109442028344318487e+02
        FLR::scaled( 0x18BD9154F3C803, -52 + 9),  // +7.916959628148473485e+02
        FLR::scaled(-0x130CF416CE6ABA, -52 + 8),  // -3.048095920622978383e+02
        FLR::scaled( 0x16BC19208C53B6, -52 + 8),  // +3.637561345559619213e+02
        FLR::scaled( 0x1C9DFF9C7094B1, -52 + 8),  // +4.578749050519646175e+02
        FLR::scaled( 0x196A73DA8CDE85, -52 + 8),  // +4.066532845976547037e+02
        FLR::scaled( 0x1159C3F4485A40, -52 + 6),  // +6.940258509698560374e+01
        FLR::scaled( 0x16C7853E5FF585, -52 + 7),  // +1.822350150942039875e+02
        FLR::scaled( 0x1E64F98432F6B6, -52 + 7),  // +2.431554585452446986e+02
        FLR::scaled( 0x11190226BF202C, -52 + 9),  // +5.471260504657452657e+02
        FLR::scaled( 0x1191C3D7FD0BB3, -52 + 6),  // +7.027757835113042972e+01
        FLR::scaled( 0x13F4995E4B5B6B, -52 + 9),  // +6.385748868834756422e+02
        FLR::scaled( 0x171BE0D6054E06, -52 + 8),  // +3.697423916060655529e+02
        FLR::scaled( 0x12AAA45792E016, -52 + 9),  // +5.973302451586375810e+02
        FLR::scaled(-0x190509513AC396, -52 + 7),  // -2.001573873660788081e+02
        FLR::scaled( 0x1047244B178890, -52 + 9),  // +5.208927213514853065e+02
        FLR::scaled( 0x1F2A70E4DD31B4, -52 + 7),  // +2.493262810058782861e+02
        FLR::scaled( 0x17A0BC3BE33EE8, -52 + 9),  // +7.560919111016819443e+02
        FLR::scaled(-0x154E9F3961664D, -52 + 8),  // -3.409138730816528664e+02
        FLR::scaled( 0x1C3A7096B8A9C8, -52 + 8),  // +4.516524874890715182e+02
        FLR::scaled( 0x19208C79F9A3D8, -52 + 9),  // +8.040685920241476197e+02
        FLR::scaled( 0x12F475760ABABE, -52 + 9),  // +6.065573540533293908e+02
        FLR::scaled( 0x1C8537EA5FA37C, -52 + 5),  // +5.704076890630582852e+01
        FLR::scaled( 0x1001C6746A12C5, -52 + 8),  // +2.561109508651246074e+02
        FLR::scaled( 0x16FC86353F0BD9, -52 + 8),  // +3.677827656233544644e+02
        FLR::scaled( 0x12E9D6C5155C77, -52 + 8),  // +3.026149340471669689e+02
        FLR::scaled( 0x19D18972277391, -52 + 4),  // +2.581850350821656903e+01
        FLR::scaled( 0x1D04D8153D068F, -52 + 8),  // +4.643027546294987928e+02
        FLR::scaled( 0x1002F4F3289FDF, -52 + 8),  // +2.561848022066969293e+02
        FLR::scaled( 0x13AF1D6DEACE43, -52 + 8),  // +3.149446849033449212e+02
        FLR::scaled(-0x1163EE201AAD74, -52 + 7),  // -1.391228180428548740e+02
        FLR::scaled( 0x1F4D552DD88CF5, -52 + 8),  // +5.008332956751831375e+02
        FLR::scaled( 0x142B50646E118E, -52 + 8),  // +3.227071270274690278e+02
        FLR::scaled( 0x14CFEC454CE342, -52 + 9),  // +6.659903665549138623e+02
        FLR::scaled(-0x135E9F731D6CBF, -52 + 8),  // -3.099139281415372693e+02
        FLR::scaled( 0x139A20A13D2DD3, -52 + 9),  // +6.272659325389489595e+02
        FLR::scaled( 0x15C58D7CCDCD42, -52 + 8),  // +3.483470428504116398e+02
        FLR::scaled( 0x16535FEBD9987C, -52 + 7),  // +1.786054591417231450e+02
        FLR::scaled( 0x1820E11295F963, -52 + 7),  // +1.930274746827300021e+02
        FLR::scaled( 0x18AD0E56CDF0DA, -52 + 9),  // +7.896320015038611473e+02
        FLR::scaled( 0x11D8863E888B1D, -52 + 7),  // +1.427663872401107312e+02
        FLR::scaled( 0x12159121C71A9A, -52 + 9),  // +5.786958652071946290e+02
        FLR::scaled( 0x1B6546B9765B2B, -52 + 3),  // +1.369780520982529559e+01
        FLR::scaled( 0x17ED126508C010, -52 + 8),  // +3.828169908849531566e+02
        FLR::scaled( 0x12189A9B354A98, -52 + 9),  // +5.790754913485898214e+02
        FLR::scaled( 0x1587AA05A788B5, -52 + 8),  // +3.444790092987344110e+02
        FLR::scaled(-0x101F7F3B1B9B4F, -52 + 8),  // -2.579685622290025435e+02
        FLR::scaled( 0x1244E81B435CFA, -52 + 9),  // +5.846133332503079600e+02
        FLR::scaled( 0x1A941204F7D8E5, -52 + 7),  // +2.126271996346251001e+02
        FLR::scaled( 0x1D32ECCAB39FE0, -52 + 8),  // +4.671828104988653649e+02
        FLR::scaled(-0x191E6135E95B31, -52 + 7),  // -2.009493665273417093e+02
        FLR::scaled( 0x1669960DF6A04E, -52 + 9),  // +7.171982688205405339e+02
        FLR::scaled( 0x1558A9CF98F416, -52 + 9),  // +6.830829154920090787e+02
        FLR::scaled( 0x13C59128CFA0D4, -52 + 8),  // +3.163479393110731053e+02
        FLR::scaled(-0x1CCBB882C3C8C1, -52 + 6),  // -1.151831366455035237e+02
        FLR::scaled( 0x1A9F4580CD6873, -52 + 8),  // +4.259544685386419474e+02
        FLR::scaled( 0x156B2E89AB1EB2, -52 + 8),  // +3.426988617596026643e+02
        FLR::scaled( 0x115A21A4358BDF, -52 + 9),  // +5.552664264853773375e+02
        FLR::scaled(-0x1D119161058C0A, -52 + 8),  // -4.650979929176979795e+02
        FLR::scaled( 0x11A1DDAE3C155C, -52 + 8),  // +2.821166212412842924e+02
        FLR::scaled( 0x18FF362AD85BCC, -52 + 9),  // +7.999014489081396277e+02
        FLR::scaled( 0x123386E52C0FD0, -52 + 9),  // +5.824408667986226646e+02
        FLR::scaled(-0x1C02AABE298B1E, -52 + 7),  // -2.240833426295657205e+02
        FLR::scaled( 0x15C9D206F5425A, -52 + 8),  // +3.486137761669575639e+02
        FLR::scaled( 0x18B2D9AD052E9C, -52 + 8),  // +3.951781435205864454e+02
        FLR::scaled( 0x13E752E037F046, -52 + 9),  // +6.369154667253685602e+02
        FLR::scaled(-0x14F15BFACA9786, -52 + 7),  // -1.675424779850838490e+02
        FLR::scaled( 0x16533037C2EEF9, -52 + 9),  // +7.143985438565424602e+02
        FLR::scaled( 0x10E4EDDF8A70F4, -52 + 9),  // +5.406161490264626082e+02
        FLR::scaled( 0x17BFC0B36C3FF0, -52 + 9),  // +7.599690922219288041e+02
        FLR::scaled( 0x1657733652EE19, -52 + 8),  // +3.574656279792266673e+02
        FLR::scaled( 0x1ACE7805E5F007, -52 + 8),  // +4.289043024999559179e+02
        FLR::scaled( 0x157AF28CD8B022, -52 + 8),  // +3.436842163528800711e+02
        FLR::scaled( 0x194662C8DA92BC, -52 + 8),  // +4.043991173303618325e+02
        FLR::scaled(-0x126D462E37A208, -52 + 8),  // -2.948296339200173861e+02
        FLR::scaled( 0x1F93B817190828, -52 + 9),  // +1.010464887805520448e+03
        FLR::scaled( 0x1E60EF3C190046, -52 + 7),  // +2.430292034614851104e+02
        FLR::scaled( 0x17C89E3E8F598E, -52 + 9),  // +7.610772677611546442e+02
        FLR::scaled(-0x11384F870F0B96, -52 + 7),  // -1.377597079557278335e+02
        FLR::scaled( 0x1660C680293589, -52 + 6),  // +8.951211551689461032e+01
        FLR::scaled( 0x12A7D93E58683C, -52 + 8),  // +2.984905379727749732e+02
        FLR::scaled( 0x1205EDAEB7D471, -52 + 10),  // +1.153482111809102435e+03
        FLR::scaled(-0x16C357878F8788, -52 + 7),  // -1.821044347575482334e+02
        FLR::scaled( 0x1B5137AE482D2B, -52 + 8),  // +4.370760939425842366e+02
        FLR::scaled( 0x165F1B64155802, -52 + 9),  // +7.158883744876368382e+02
        FLR::scaled( 0x17B6AE1ED98976, -52 + 7),  // +1.897087549446839034e+02
        FLR::scaled( 0x145F7B652B2E0B, -52 + 1),  // +2.546622076397175416e+00
        FLR::scaled( 0x110915711E695C, -52 + 9),  // +5.451354696632292871e+02
        FLR::scaled( 0x1EAFD81D89EF4E, -52 + 8),  // +4.909902625454022882e+02
        FLR::scaled( 0x178241F2A5C71F, -52 + 9),  // +7.522822010947601257e+02
        FLR::scaled(-0x1D0F1377E38DDE, -52 + 8),  // -4.649422530068239894e+02
        FLR::scaled( 0x1D16469744F26B, -52 + 8),  // +4.653922341054191634e+02
        FLR::scaled( 0x11E8A9EA305661, -52 + 8),  // +2.865414831054859519e+02
        FLR::scaled( 0x1851C8D2EAF8F3, -52 + 8),  // +3.891115292719470631e+02
        FLR::scaled(-0x1D9B1B6F8445DD, -52 + 6),  // -1.184235495368697713e+02
        FLR::scaled( 0x103A8D053A5B8C, -52 + 8),  // +2.596594288138956017e+02
        FLR::scaled( 0x1053C04F40078C, -52 + 6),  // +6.530861264469984917e+01
        FLR::scaled( 0x1CCFB73F745EE3, -52 + 8),  // +4.609822382493713917e+02
        FLR::scaled(-0x1405F09AB1820C, -52 + 8),  // -3.203712412771135405e+02
        FLR::scaled( 0x135E0088FC8272, -52 + 9),  // +6.197502612807568312e+02
        FLR::scaled( 0x1423B568F16288, -52 + 9),  // +6.444635790689653732e+02
        FLR::scaled( 0x1B7E7C48002DBF, -52 + 7),  // +2.199526710513582373e+02
        FLR::scaled( 0x1F15C78B45F02C, -52 + 6),  // +1.243403042014112430e+02
        FLR::scaled( 0x1C3185344CBD71, -52 + 8),  // +4.510950205800682511e+02
        FLR::scaled( 0x1CE98DC0E20E54, -52 + 8),  // +4.625971077757178591e+02
        FLR::scaled( 0x10CF2DF09F7E08, -52 + 8),  // +2.689487158041160910e+02
        FLR::scaled(-0x18355DF429CF24, -52 + 8),  // -3.873354379304093982e+02
        FLR::scaled( 0x15FFA45875C47B, -52 + 9),  // +7.039552468491159516e+02
        FLR::scaled( 0x1FA8A03FE60EFB, -52 + 8),  // +5.065391234385166968e+02
        FLR::scaled( 0x10F10A7CFBF1D9, -52 + 9),  // +5.421301212008648918e+02
        FLR::scaled( 0x18B198F6611B6A, -52 + 4),  // +2.469374027128962013e+01
        FLR::scaled( 0x1729F44661592D, -52 + 8),  // +3.706221374323529858e+02
        FLR::scaled( 0x15818CB7B45D1A, -52 + 8),  // +3.440968548818069621e+02
        FLR::scaled( 0x1B648A22263AB0, -52 + 8),  // +4.382837239735918047e+02
        FLR::scaled(-0x1302782820EE17, -52 + 7),  // -1.520771675723233045e+02
        FLR::scaled( 0x14FFCBD81A7B77, -52 + 9),  // +6.719745332783630829e+02
        FLR::scaled( 0x1288D537A59344, -52 + 9),  // +5.931041100440565970e+02
        FLR::scaled( 0x107820E0F781BA, -52 + 8),  // +2.635080270450813487e+02
        FLR::scaled(-0x16D0151938CCB3, -52 + 7),  // -1.825025755032889663e+02
        FLR::scaled( 0x17E398788382F0, -52 + 8),  // +3.822247243058363892e+02
        FLR::scaled( 0x16F8EA57E54250, -52 + 9),  // +7.351144254599439591e+02
        FLR::scaled( 0x12394613C1D46C, -52 + 9),  // +5.831592173712683689e+02
        FLR::scaled(-0x1F647890713844, -52 + 7),  // -2.511397173129390694e+02
        FLR::scaled( 0x1E8CF03FFA0E4D, -52 + 8),  // +4.888086547630126120e+02
        FLR::scaled( 0x186E31E8A99639, -52 + 8),  // +3.908871847748264940e+02
        FLR::scaled( 0x1148D31572AFEC, -52 + 9),  // +5.531030682525574775e+02
        FLR::scaled(-0x1269D06B1B0FFC, -52 + 8),  // -2.946133833939672968e+02
        FLR::scaled( 0x1D326347AF42BE, -52 + 8),  // +4.671492382856484937e+02
        FLR::scaled( 0x106CA00E8D257C, -52 + 9),  // +5.255781527545036624e+02
        FLR::scaled( 0x12A708EA59FC22, -52 + 8),  // +2.984396766200098909e+02
        FLR::scaled(-0x142C41187E9890, -52 + 8),  // -3.227658925004152479e+02
        FLR::scaled( 0x1130125FD5CE8A, -52 + 9),  // +5.500089718536048622e+02
        FLR::scaled( 0x19D75F25535D9C, -52 + 8),  // +4.134607289558859975e+02
        FLR::scaled( 0x154AC705E2AC54, -52 + 8),  // +3.406735895971698938e+02
        FLR::scaled( 0x1843DE09BB222A, -52 + 8),  // +3.882417084989452860e+02
        FLR::scaled( 0x1186BC873EA060, -52 + 9),  // +5.608420548336689535e+02
        FLR::scaled( 0x14CBE62BF915D8, -52 + 8),  // +3.327436942796607582e+02
        FLR::scaled( 0x10A77B9570EF80, -52 + 9),  // +5.329353436301316833e+02
        FLR::scaled(-0x1B08F44C211F0A, -52 + 8),  // -4.325596429151343045e+02
        FLR::scaled( 0x1C55A27D2A00B4, -52 + 9),  // +9.067043402940239503e+02
        FLR::scaled( 0x1C1C6CC393C77B, -52 + 8),  // +4.497765537045121960e+02
        FLR::scaled( 0x1BE71407AF7DC1, -52 + 8),  // +4.464423901419759773e+02
        FLR::scaled(-0x121BB9627FA77C, -52 + 5),  // -3.621659499390713677e+01
        FLR::scaled( 0x11C96683BD5CC4, -52 + 9),  // +5.691750559610304663e+02
        FLR::scaled( 0x1185F4C087BD29, -52 + 8),  // +2.803722539236355829e+02
        FLR::scaled( 0x1AEF9A8871475C, -52 + 9),  // +8.619504555559065011e+02
        FLR::scaled(-0x19A8C178152FCA, -52 + 6),  // -1.026368084151173719e+02
        FLR::scaled( 0x187D6F9D3A2C1A, -52 + 9),  // +7.836794991059025506e+02
        FLR::scaled( 0x1742409C0C9FF4, -52 + 9),  // +7.442815476404489345e+02
        FLR::scaled( 0x1A848959E443DC, -52 + 8),  // +4.242835329929928321e+02
        FLR::scaled(-0x125E104EE32D7C, -52 + 8),  // -2.938789814828994622e+02
        FLR::scaled( 0x198088B79ABAE6, -52 + 9),  // +8.160667564476286771e+02
        FLR::scaled( 0x17138BF07561AA, -52 + 9),  // +7.384433297319822032e+02
        FLR::scaled( 0x150876A69C7028, -52 + 8),  // +3.365289674864638982e+02
        FLR::scaled(-0x13F26534838FB2, -52 + 8),  // -3.191497082842935242e+02
        FLR::scaled( 0x12FCDC7AA5378A, -52 + 9),  // +6.076076558024954011e+02
        FLR::scaled( 0x11F77098E35786, -52 + 8),  // +2.874649895554106251e+02
        FLR::scaled( 0x1069B62FA11E16, -52 + 9),  // +5.252139580333048343e+02
        FLR::scaled(-0x1B267C72C4ED1B, -52 + 8),  // -4.344053828899793075e+02
        FLR::scaled( 0x107FDE71527208, -52 + 10),  // +1.055967229164323726e+03
        FLR::scaled( 0x1E86F6ED5BD889, -52 + 7),  // +2.442176424783577033e+02
        FLR::scaled( 0x16BA9CEF6096C6, -52 + 9),  // +7.273266284509670641e+02
        FLR::scaled(-0x1199D621183EE3, -52 + 7),  // -1.408073888276622654e+02
        FLR::scaled( 0x113C5CD29B1525, -52 + 9),  // +5.515453235736682700e+02
        FLR::scaled( 0x169431DF485E54, -52 + 9),  // +7.225243516591822299e+02
        FLR::scaled( 0x15621D068F39C4, -52 + 6),  // +8.553302158343200290e+01
        FLR::scaled( 0x1BAFDB8B032D6D, -52 + 4),  // +2.768694371059011772e+01
        FLR::scaled( 0x1E937C0C64937E, -52 + 8),  // +4.892177852562671205e+02
        FLR::scaled( 0x1907171B8BD44C, -52 + 5),  // +5.005539268806077757e+01
        FLR::scaled( 0x10ABDFE3933AA9, -52 + 9),  // +5.334843207838322314e+02
        FLR::scaled(-0x1CD5555985C027, -52 + 8),  // -4.613333373283989545e+02
        FLR::scaled( 0x13A99A4B2EAC7C, -52 + 9),  // +6.292003387113941244e+02
        FLR::scaled( 0x116580FEF35242, -52 + 8),  // +2.783439931397189184e+02
        FLR::scaled( 0x1709806E4063C8, -52 + 8),  // +3.685938551440453921e+02
        FLR::scaled( 0x140566667DC377, -52 + 8),  // +3.203375000870359486e+02
        FLR::scaled( 0x15B066570EEEC9, -52 + 9),  // +6.940499707380887457e+02
        FLR::scaled( 0x1127EFE14D75FE, -52 + 9),  // +5.489921289493211134e+02
        FLR::scaled( 0x1A9142F07E3B04, -52 + 9),  // +8.501576852666626110e+02
        FLR::scaled(-0x15F41B764F3753, -52 + 9),  // -7.025134092510946857e+02
        FLR::scaled( 0x1D5808E2DFB01E, -52 + 8),  // +4.695021694886980868e+02
        FLR::scaled( 0x10496EFEE033F1, -52 + 9),  // +5.211791970744944820e+02
        FLR::scaled( 0x1A571E31FE27F9, -52 + 8),  // +4.214448718955969184e+02
        FLR::scaled(-0x14466F6A9FC1B4, -52 + 8),  // -3.244022012939924480e+02
        FLR::scaled( 0x149666CEBAC246, -52 + 7),  // +1.647000497481951129e+02
        FLR::scaled( 0x1F1FBC38D866A5, -52 + 8),  // +4.979834526494180977e+02
        FLR::scaled( 0x174CDC6EF0D24F, -52 + 8),  // +3.728038167388048691e+02
        FLR::scaled(-0x160F66A5E85D43, -52 + 8),  // -3.529625605656366929e+02
        FLR::scaled( 0x18D6339C0F4D90, -52 + 7),  // +1.986938000010381984e+02
        FLR::scaled( 0x197177D441FDAE, -52 + 7),  // +2.035458775795827364e+02
        FLR::scaled( 0x13D4A64C951046, -52 + 9),  // +6.345812007566062221e+02
        FLR::scaled(-0x196F0CA65B36D4, -52 + 7),  // -2.034702941686178974e+02
        FLR::scaled( 0x1019EF64C51901, -52 + 9),  // +5.152418914221053683e+02
        FLR::scaled( 0x1347D6C2A1F74E, -52 + 7),  // +1.542449658549689389e+02
        FLR::scaled( 0x1738C7C2826024, -52 + 9),  // +7.430975389657583037e+02
        FLR::scaled(-0x1B614BBDD7CFD3, -52 + 7),  // -2.190404957976412277e+02
        FLR::scaled( 0x1372D1928A18F2, -52 + 9),  // +6.223523302830565171e+02
        FLR::scaled( 0x18758AA1B8E93F, -52 + 9),  // +7.826926912733250674e+02
        FLR::scaled( 0x1218DC0E40326F, -52 + 9),  // +5.791074490561858283e+02
        FLR::scaled( 0x13567C6666D841, -52 + 8),  // +3.094053710954067924e+02
        FLR::scaled( 0x1CF396FCBD79FB, -52 + 8),  // +4.632243621255326502e+02
        FLR::scaled( 0x118C698427507E, -52 + 7),  // +1.403878803985462014e+02
        FLR::scaled( 0x14125E67927FB2, -52 + 9),  // +6.422960959859103696e+02
        FLR::scaled(-0x1349CA4177F103, -52 + 8),  // -3.086118788418972940e+02
        FLR::scaled( 0x14FB7CDB0F08D3, -52 + 9),  // +6.714359646963661135e+02
        FLR::scaled( 0x159087F861997E, -52 + 9),  // +6.900663917183844660e+02
        FLR::scaled( 0x16712366A1C674, -52 + 8),  // +3.590711427993148845e+02
        FLR::scaled(-0x12480E25EC2767, -52 + 8),  // -2.925034541344415970e+02
        FLR::scaled( 0x15650CA39C01C2, -52 + 9),  // +6.846311714351688806e+02
        FLR::scaled( 0x175CDBECCFE706, -52 + 9),  // +7.476073852770211943e+02
        FLR::scaled( 0x1AE6F77E764F44, -52 + 9),  // +8.608708466761531781e+02
        FLR::scaled(-0x14D08395FD15DA, -52 + 7),  // -1.665160627310822861e+02
        FLR::scaled( 0x15152C1336DD4A, -52 + 9),  // +6.746465210233957350e+02
        FLR::scaled( 0x18A0EF5A6FA427, -52 + 9),  // +7.881168717119188614e+02
        FLR::scaled( 0x1185B0C7098472, -52 + 8),  // +2.803556585666439105e+02
        FLR::scaled( 0x1444414F1BC79E, -52 + 2),  // +5.066655384130994477e+00
        FLR::scaled( 0x1F23B8D3CB9930, -52 + 8),  // +4.982326238587438638e+02
        FLR::scaled( 0x103670CC341195, -52 + 8),  // +2.594025384935314946e+02
        FLR::scaled( 0x1F7C95582CFF51, -52 + 8),  // +5.037864610440929596e+02
        FLR::scaled(-0x198015CBB515BB, -52 + 6),  // -1.020013303059012486e+02
        FLR::scaled( 0x1D419D21E44811, -52 + 9),  // +9.362017247995846674e+02
        FLR::scaled( 0x12D10AB6812325, -52 + 9),  // +6.021302309120989094e+02
        FLR::scaled( 0x11002BE0AD8768, -52 + 8),  // +2.720107123163675169e+02
        FLR::scaled(-0x13C91657B0B292, -52 + 4),  // -1.978549717010407250e+01
        FLR::scaled( 0x1148D813ABED77, -52 + 9),  // +5.531055062705844421e+02
        FLR::scaled( 0x1C703CA589031E, -52 + 7),  // +2.275074031520861695e+02
        FLR::scaled( 0x162F11EC3C3FCA, -52 + 9),  // +7.098837513644186856e+02
        FLR::scaled( 0x1135AA5BC31E84, -52 + 7),  // +1.376770457087442310e+02
        FLR::scaled( 0x116ADA949498C3, -52 + 9),  // +5.573567287072295358e+02
        FLR::scaled( 0x163A1DA4BC31AB, -52 + 8),  // +3.556322371817902308e+02
        FLR::scaled( 0x1713C9C61BB209, -52 + 8),  // +3.692367611963132390e+02
        FLR::scaled( 0x13B72098A256C0, -52 + 8),  // +3.154454580632555007e+02
        FLR::scaled( 0x18D0F583C9E1EB, -52 + 9),  // +7.941198802730626767e+02
        FLR::scaled( 0x16F0C600FABA7B, -52 + 7),  // +1.835241703888931113e+02
        FLR::scaled( 0x1150F83ACB497A, -52 + 9),  // +5.541212058908270137e+02
        FLR::scaled(-0x10D5B9AEAE7D25, -52 + 7),  // -1.346789163024888296e+02
        FLR::scaled( 0x1929F99804AEB0, -52 + 9),  // +8.052468719831285853e+02
        FLR::scaled( 0x183C404412EE2C, -52 + 9),  // +7.755313798407491959e+02
        FLR::scaled( 0x128BFA1ECA85DC, -52 + 9),  // +5.934971290418720855e+02
        FLR::scaled(-0x1EB69D65B834A9, -52 + 6),  // -1.228533567713626695e+02
        FLR::scaled( 0x10DF5DFFB1D7B8, -52 + 9),  // +5.399208978551823748e+02
        FLR::scaled( 0x1CA7AD7C925685, -52 + 8),  // +4.584798551288916428e+02
        FLR::scaled( 0x1C4796DA17ECDE, -52 + 9),  // +9.049486581677590493e+02
        FLR::scaled(-0x12196E40F4BCB2, -52 + 9),  // -5.791788348312459220e+02
        FLR::scaled( 0x1BC46CA60B1A02, -52 + 9),  // +8.885530510775863604e+02
        FLR::scaled( 0x1404C3EED74CD6, -52 + 9),  // +6.405956703968356578e+02
        FLR::scaled( 0x187E0D788D9EB3, -52 + 8),  // +3.918782887966182784e+02
        FLR::scaled(-0x17F79E550CBA82, -52 + 7),  // -1.917380776642422120e+02
        FLR::scaled( 0x1758D0198B0EEA, -52 + 8),  // +3.735508056098902898e+02
        FLR::scaled( 0x19CD67607C2B59, -52 + 8),  // +4.128377384996761634e+02
        FLR::scaled( 0x15A28A8643723D, -52 + 8),  // +3.461588194498652342e+02
        FLR::scaled(-0x1ABC108FB80839, -52 + 8),  // -4.277540433110003164e+02
        FLR::scaled( 0x115D24DA16EEC8, -52 + 9),  // +5.556429940978641753e+02
        FLR::scaled( 0x18662C0E9B8330, -52 + 7),  // +1.951928780591347277e+02
        FLR::scaled( 0x1963CD86C7F3B0, -52 + 8),  // +4.062376773653622877e+02
        FLR::scaled(-0x15A273FEDF7B2E, -52 + 7),  // -1.730766596188418021e+02
        FLR::scaled( 0x19929EC20A7C82, -52 + 9),  // +8.183275185412642259e+02
        FLR::scaled( 0x1BE7AAA9988719, -52 + 8),  // +4.464791656454195277e+02
        FLR::scaled( 0x15096A9A8CE82D, -52 + 9),  // +6.731770525940279413e+02
        FLR::scaled(-0x1270CB8E906CB7, -52 + 9),  // -5.900993930133034837e+02
        FLR::scaled( 0x162BE2A4BD3EC5, -52 + 8),  // +3.547428328888311739e+02
        FLR::scaled( 0x1A7D3749F6F63B, -52 + 9),  // +8.476519965452092720e+02
        FLR::scaled( 0x1328750F293242, -52 + 8),  // +3.065285789117079958e+02
        FLR::scaled(-0x18193CB0426311, -52 + 5),  // -4.819716456643630664e+01
        FLR::scaled( 0x12D17384BD3A67, -52 + 8),  // +3.010907027618144980e+02
        FLR::scaled( 0x149167E30A8358, -52 + 8),  // +3.290878630076090303e+02
        FLR::scaled( 0x1CE4C182E530EE, -52 + 8),  // +4.622972439720896318e+02
        FLR::scaled(-0x1458EAEC85CA8F, -52 + 8),  // -3.255573544717998971e+02
        FLR::scaled( 0x14ACD3575550A6, -52 + 8),  // +3.308015969593637919e+02
        FLR::scaled( 0x12EDA2E1DA540D, -52 + 9),  // +6.057045323426151526e+02
        FLR::scaled( 0x15950BCCFA1C54, -52 + 8),  // +3.453153810281703500e+02
        FLR::scaled(-0x19F21F9D01A495, -52 + 7),  // -2.075663590461814749e+02
        FLR::scaled( 0x1715E2C96DE027, -52 + 8),  // +3.693678678791060861e+02
        FLR::scaled( 0x1D32E257EBD8B6, -52 + 7),  // +2.335901298147561533e+02
        FLR::scaled( 0x1B930E2EA1E89F, -52 + 8),  // +4.411909624409253752e+02
        FLR::scaled(-0x1E00A3AD2FDD8D, -52 + 6),  // -1.200099900214610926e+02
        FLR::scaled( 0x153EE6AB849709, -52 + 9),  // +6.798626318319885513e+02
        FLR::scaled( 0x1226A25FB9E6FB, -52 + 8),  // +2.904146420728499720e+02
        FLR::scaled( 0x192B80B3B17E75, -52 + 7),  // +2.013594606844596058e+02
        FLR::scaled( 0x1D7C1C9C3763DA, -52 + 7),  // +2.358784924585186786e+02
        FLR::scaled( 0x1F091F5098843B, -52 + 8),  // +4.965701452214886444e+02
        FLR::scaled( 0x122913311DBBB8, -52 + 9),  // +5.811343710253631798e+02
        FLR::scaled( 0x1B1C48F8E0EDB2, -52 + 8),  // +4.337678154741544176e+02
        FLR::scaled(-0x172D934D911E98, -52 + 6),  // -9.271211566135241355e+01
        FLR::scaled( 0x1F4792B04F6E0E, -52 + 8),  // +5.004733126738291276e+02
        FLR::scaled( 0x115C1AEB0DC0B6, -52 + 9),  // +5.555131436418948851e+02
        FLR::scaled( 0x1256BACCB5C800, -52 + 9),  // +5.868412107659969479e+02
        FLR::scaled(-0x1FAC732566CD34, -52 + 7),  // -2.533890559203952080e+02
        FLR::scaled( 0x1C3F06F3EF06FD, -52 + 8),  // +4.519391974770549609e+02
        FLR::scaled( 0x1765E6044133C8, -52 + 4),  // +2.339804102508404071e+01
        FLR::scaled( 0x1EAC8B9466BFDE, -52 + 8),  // +4.907840770734454736e+02
        FLR::scaled(-0x11F560FDF07DC5, -52 + 6),  // -7.183404491887547749e+01
        FLR::scaled( 0x159C4D9A92841F, -52 + 9),  // +6.915378924795694502e+02
        FLR::scaled( 0x16D5CE8D363C88, -52 + 9),  // +7.307258552777502700e+02
        FLR::scaled( 0x1B17F41CD90F6C, -52 + 6),  // +1.083742744559983180e+02
        FLR::scaled( 0x12D8B543075B1F, -52 + 8),  // +3.015442533767072177e+02
        FLR::scaled( 0x1BE2B166EEBABC, -52 + 9),  // +8.923366221094834145e+02
        FLR::scaled( 0x11AF982FA939E6, -52 + 9),  // +5.659493096562189294e+02
        FLR::scaled( 0x1AB415CA88D5E4, -52 + 8),  // +4.272553201050889129e+02
        FLR::scaled(-0x108F7AAD5B6F24, -52 + 8),  // -2.649674504825254644e+02
        FLR::scaled( 0x142F0913451536, -52 + 9),  // +6.458794312855814042e+02
        FLR::scaled( 0x1B34D4D171A470, -52 + 8),  // +4.353019575537828132e+02
        FLR::scaled( 0x15B93625209612, -52 + 6),  // +8.689392975027320176e+01
        FLR::scaled( 0x1774D7C8305B59, -52 + 7),  // +1.876513405746907495e+02
        FLR::scaled( 0x1F2F34988936A4, -52 + 8),  // +4.989503407821559904e+02
        FLR::scaled( 0x164300C4223B7E, -52 + 8),  // +3.561876870476916110e+02
        FLR::scaled( 0x1AD6F6C1A94677, -52 + 9),  // +8.588704865669850506e+02
        FLR::scaled(-0x1C63A937A7CAE6, -52 + 6),  // -1.135572032106971108e+02
        FLR::scaled( 0x1D740898BBDD96, -52 + 8),  // +4.712520987833498793e+02
        FLR::scaled( 0x123A883B18207E, -52 + 9),  // +5.833165189633289174e+02
        FLR::scaled( 0x17E99BA9837F00, -52 + 8),  // +3.826005034576955950e+02
        FLR::scaled( 0x10F2D228C95F79, -52 + 8),  // +2.711763084283953162e+02
        FLR::scaled( 0x1BD03765CD4AC3, -52 + 8),  // +4.450135248202533944e+02
        FLR::scaled( 0x127E65744FD648, -52 + 8),  // +2.958997691267618393e+02
        FLR::scaled( 0x11587C062FF174, -52 + 9),  // +5.550605586762962957e+02
        FLR::scaled(-0x182D218F02B4C2, -52 + 7),  // -1.934103465130665995e+02
        FLR::scaled( 0x1EB5991F8991D7, -52 + 8),  // +4.913498835920158285e+02
        FLR::scaled( 0x1E0137D9C00F17, -52 + 7),  // +2.400380676985884918e+02
        FLR::scaled( 0x12EF115F3C7471, -52 + 9),  // +6.058834824297938439e+02
        FLR::scaled(-0x1359C2675A6FC9, -52 + 8),  // -3.096099618466074048e+02
        FLR::scaled( 0x16DDDC0D22DCB4, -52 + 9),  // +7.317324469302752732e+02
        FLR::scaled( 0x1645C60679F6B1, -52 + 8),  // +3.563608460201458570e+02
        FLR::scaled( 0x11B88CE08E9C29, -52 + 9),  // +5.670687876836210535e+02
        FLR::scaled(-0x1BDF4641F3513C, -52 + 6),  // -1.114886631847520562e+02
        FLR::scaled( 0x1BEC46CA7066E7, -52 + 8),  // +4.467672829046918537e+02
        FLR::scaled( 0x1E27F26FA78434, -52 + 9),  // +9.649933770262928192e+02
        FLR::scaled( 0x11A8A7E4E14992, -52 + 9),  // +5.650819795227600935e+02
        FLR::scaled( 0x172537D55CAD9B, -52 + 6),  // +9.258153280306434851e+01
        FLR::scaled( 0x168624929FD6B7, -52 + 8),  // +3.603839288943958650e+02
        FLR::scaled( 0x1DD9B4CE58C390, -52 + 8),  // +4.776066421000805349e+02
        FLR::scaled( 0x1CEEF2B2B0FD9A, -52 + 8),  // +4.629342524446198013e+02
        FLR::scaled(-0x13483224A20A67, -52 + 9),  // -6.170244839343475860e+02
        FLR::scaled( 0x106B18758B3CAC, -52 + 9),  // +5.253869429471865260e+02
        FLR::scaled( 0x166836B2E23412, -52 + 7),  // +1.792566770952258253e+02
        FLR::scaled( 0x159D243972A7C0, -52 + 9),  // +6.916426876981204259e+02
        FLR::scaled( 0x1AF08237981EE2, -52 + 7),  // +2.155158956500154659e+02
        FLR::scaled( 0x178F2A47E45B84, -52 + 8),  // +3.769478224678243805e+02
        FLR::scaled( 0x1E269C97D5DE90, -52 + 3),  // +1.507541346059522880e+01
        FLR::scaled( 0x167739BCCE8530, -52 + 8),  // +3.594515960757444191e+02
        FLR::scaled(-0x15C90A5B61CCD3, -52 + 9),  // -6.971300571098930732e+02
        FLR::scaled( 0x1BBCDF0C3505A7, -52 + 9),  // +8.876089100019788702e+02
        FLR::scaled( 0x12F5BEE432D13D, -52 + 9),  // +6.067182086916069466e+02
        FLR::scaled( 0x171B0A932F533D, -52 + 7),  // +1.848450408863372161e+02
        FLR::scaled( 0x1DCE2659AC3DED, -52 + 6),  // +1.192210907156038076e+02
        FLR::scaled( 0x1C97E6983C5FA8, -52 + 7),  // +2.287468987635777466e+02
        FLR::scaled( 0x1C4F50ADAE2FE5, -52 + 8),  // +4.529571968845542074e+02
        FLR::scaled( 0x122CD36173DA80, -52 + 9),  // +5.816032132197433384e+02
        FLR::scaled(-0x1764249F909C80, -52 + 8),  // -3.742589412354354863e+02
        FLR::scaled( 0x12CD85FD83C36D, -52 + 9),  // +6.016904249471677986e+02
        FLR::scaled( 0x107A71D44F8FB0, -52 + 6),  // +6.591319759149223501e+01
        FLR::scaled( 0x144A23182AD5A2, -52 + 9),  // +6.492671359392591057e+02
        FLR::scaled(-0x1640DAB97FF834, -52 + 8),  // -3.560533995627222339e+02
        FLR::scaled( 0x19EC5FDDC01777, -52 + 8),  // +4.147734048369961215e+02
        FLR::scaled( 0x1CD5FE28BA2E4E, -52 + 7),  // +2.306872752796502368e+02
        FLR::scaled( 0x1D7E4F154E74C2, -52 + 9),  // +9.437886148576146752e+02
        FLR::scaled(-0x1922341477F404, -52 + 6),  // -1.005344287082116921e+02
        FLR::scaled( 0x124CBB7000F13A, -52 + 9),  // +5.855915222238174920e+02
        FLR::scaled( 0x1077A8A233115A, -52 + 9),  // +5.269573406209631230e+02
        FLR::scaled( 0x11CF8C2051C563, -52 + 8),  // +2.849717105096989940e+02
        FLR::scaled( 0x108446D1785458, -52 + 8),  // +2.642672896099443278e+02
        FLR::scaled( 0x1C868C50A18757, -52 + 8),  // +4.564092565831865045e+02
        FLR::scaled( 0x1E36AB7D7B1D16, -52 + 8),  // +4.834168677147985136e+02
        FLR::scaled( 0x1F3958CC4E27D4, -52 + 8),  // +4.995841792157127657e+02
        FLR::scaled(-0x14A9E82A1CB8EC, -52 + 8),  // -3.306191807863203849e+02
        FLR::scaled( 0x188A897CA79087, -52 + 9),  // +7.853171322909337277e+02
        FLR::scaled( 0x10E78029688F12, -52 + 8),  // +2.704687894901591108e+02
        FLR::scaled( 0x1155B917234CD1, -52 + 9),  // +5.547153761632745272e+02
        FLR::scaled(-0x12AE8B6FA89D43, -52 + 8),  // -2.989090420328613504e+02
        FLR::scaled( 0x19C05A4649E4EA, -52 + 8),  // +4.120220396887294783e+02
        FLR::scaled( 0x1E3AEC179E5A59, -52 + 8),  // +4.836826397119198759e+02
        FLR::scaled( 0x1FF051C2A097CB, -52 + 8),  // +5.110199610016977090e+02
        FLR::scaled(-0x12828B167368CE, -52 + 7),  // -1.480794784788217271e+02
        FLR::scaled( 0x1C21A2F0F80278, -52 + 8),  // +4.501022805869938566e+02
        FLR::scaled( 0x1B83E12AB5C44A, -52 + 9),  // +8.804849447441604298e+02
        FLR::scaled( 0x157EBE36C4A06D, -52 + 8),  // +3.439214389496544868e+02
        FLR::scaled(-0x14075075E6285A, -52 + 8),  // -3.204571436872989807e+02
        FLR::scaled( 0x1E01832D204E8A, -52 + 8),  // +4.800945254575714216e+02
        FLR::scaled( 0x1BE5DF6E924682, -52 + 7),  // +2.231835244042341060e+02
        FLR::scaled( 0x10EE056E2BCDAA, -52 + 9),  // +5.417526515409601870e+02
        FLR::scaled(-0x1A06D7D88A06FD, -52 + 8),  // -4.164276967422190978e+02
        FLR::scaled( 0x10BD9BC1199A25, -52 + 9),  // +5.357010519027868440e+02
        FLR::scaled( 0x1771DE1B84B053, -52 + 8),  // +3.751167254622607174e+02
        FLR::scaled( 0x1D950DCC6FDB6B, -52 + 8),  // +4.733158687943857217e+02
        FLR::scaled(-0x12A4E5B4DE53DB, -52 + 8),  // -2.983060806927366571e+02
        FLR::scaled( 0x11663747DBA91C, -52 + 9),  // +5.567769925271018110e+02
        FLR::scaled( 0x18C3A3D1407A98, -52 + 8),  // +3.962274944800096819e+02
        FLR::scaled( 0x180E43BC455988, -52 + 9),  // +7.697830739419887323e+02
        FLR::scaled(-0x19E7537AA9230F, -52 + 7),  // -2.072289403251129158e+02
        FLR::scaled( 0x18F9C9F0090E7D, -52 + 9),  // +7.992236023623987649e+02
        FLR::scaled( 0x14CF35A401ADAE, -52 + 9),  // +6.659011917239311060e+02
        FLR::scaled( 0x1159C53252E793, -52 + 8),  // +2.776106436956844732e+02
        FLR::scaled( 0x17259C2418C29A, -52 + 4),  // +2.314691377262588645e+01
        FLR::scaled( 0x1453D32F560F96, -52 + 9),  // +6.504781176303392840e+02
        FLR::scaled( 0x18A8FA79035985, -52 + 8),  // +3.945611505633208367e+02
        FLR::scaled( 0x175E0E26F765F3, -52 + 8),  // +3.738784551300042835e+02
        FLR::scaled(-0x1D58978F1A118A, -52 + 4),  // -2.934606260668218880e+01
        FLR::scaled( 0x1242C9F281E6BA, -52 + 9),  // +5.843486070774590644e+02
        FLR::scaled( 0x1146F58909825D, -52 + 9),  // +5.528698902838619915e+02
        FLR::scaled( 0x1C2FFD91797DA2, -52 + 8),  // +4.509994063134892031e+02
        FLR::scaled(-0x15B6AEC1E448D5, -52 + 7),  // -1.737088326891595500e+02
        FLR::scaled( 0x1EC5D41F68E7F4, -52 + 8),  // +4.923642877672093618e+02
        FLR::scaled( 0x1328638AD92BF2, -52 + 9),  // +6.130486046759162946e+02
        FLR::scaled( 0x18E1E1D843039F, -52 + 8),  // +3.981176378839244876e+02
        FLR::scaled(-0x1EB0604C3A1CB7, -52 + 7),  // -2.455117550978663701e+02
        FLR::scaled( 0x142B378FB884D1, -52 + 8),  // +3.227010647971883941e+02
        FLR::scaled( 0x13B261C816D702, -52 + 9),  // +6.302977449211468866e+02
        FLR::scaled( 0x153A62DAE5C172, -52 + 8),  // +3.396491345381574547e+02
        FLR::scaled(-0x1229E78EC1AC28, -52 + 6),  // -7.265475815690354011e+01
        FLR::scaled( 0x14FB120FA7667B, -52 + 8),  // +3.356919094599795130e+02
        FLR::scaled( 0x123C2B78AAB140, -52 + 9),  // +5.835212262473432929e+02
        FLR::scaled( 0x17977D6893C1FC, -52 + 8),  // +3.774681173106944243e+02
        FLR::scaled(-0x1B4B88E9E8886A, -52 + 7),  // -2.183604630986840789e+02
        FLR::scaled( 0x1283BD339B96C5, -52 + 9),  // +5.924673835902582368e+02
        FLR::scaled( 0x15521E7427793C, -52 + 8),  // +3.411324349920212171e+02
        FLR::scaled( 0x1CBE3969C48274, -52 + 8),  // +4.598890168834834640e+02
        FLR::scaled(-0x1B1486314D861B, -52 + 8),  // -4.332827618625903483e+02
        FLR::scaled( 0x14845247D39C64, -52 + 9),  // +6.565401760608770019e+02
        FLR::scaled(-0x1B578BA95732D0, -52 + 5),  // -5.468394963033426848e+01
        FLR::scaled( 0x1BAF33192BEA20, -52 + 9),  // +8.858999503546547203e+02
        FLR::scaled(-0x13F9D178EB3AD2, -52 + 8),  // -3.196136407078421371e+02
        FLR::scaled( 0x146B84F10B2ACE, -52 + 8),  // +3.267199564396113374e+02
        FLR::scaled( 0x134E542F414FC6, -52 + 8),  // +3.088955528784975968e+02
        FLR::scaled( 0x1DAB0D3B1E5788, -52 + 8),  // +4.746907302079421243e+02
        FLR::scaled( 0x1C12050D43B6A1, -52 + 6),  // +1.122815583382857909e+02
        FLR::scaled( 0x142A8969C5E063, -52 + 9),  // +6.453170962771513359e+02
        FLR::scaled( 0x11A50B319EA210, -52 + 9),  // +5.646304657357413816e+02
        FLR::scaled( 0x10067A4F7FA644, -52 + 9),  // +5.128097219441046946e+02
        FLR::scaled(-0x1CB1CA1277B8A1, -52 + 6),  // -1.147779585045959863e+02
        FLR::scaled( 0x15D5AD376DB404, -52 + 9),  // +6.987095783777772340e+02
        FLR::scaled( 0x12FBF24C2376C4, -52 + 9),  // +6.074933092852229493e+02
        FLR::scaled( 0x19B759FEFBDC88, -52 + 9),  // +8.229189433743167683e+02
        FLR::scaled(-0x1C09EB404968D5, -52 + 7),  // -2.243099671777514743e+02
        FLR::scaled( 0x176BB2B041B87E, -52 + 8),  // +3.747311251227582716e+02
        FLR::scaled( 0x1998CB60CD0AE7, -52 + 8),  // +4.095496528634525362e+02
        FLR::scaled( 0x17D580B53B73B0, -52 + 9),  // +7.626878456730537437e+02
        FLR::scaled(-0x1FF497B0537CE0, -52 + 7),  // -2.556435166960354763e+02
        FLR::scaled( 0x140C0F97033886, -52 + 9),  // +6.415076122523903450e+02
        FLR::scaled( 0x15BEF256DBA4EA, -52 + 9),  // +6.958683297309592035e+02
        FLR::scaled( 0x1AA20C35334344, -52 + 6),  // +1.065319951058018546e+02
        FLR::scaled(-0x1937C497754AE1, -52 + 7),  // -2.017427480021351869e+02
        FLR::scaled( 0x1DFAF2B01B1C18, -52 + 8),  // +4.796842499789213434e+02
        FLR::scaled( 0x16DE1A33C44EA8, -52 + 4),  // +2.286758731405885214e+01
        FLR::scaled( 0x183B6DC76971D8, -52 + 8),  // +3.877143015021260908e+02
        FLR::scaled(-0x11FAABF9A3C051, -52 + 8),  // -2.876669861218006758e+02
        FLR::scaled( 0x1E02FF16D6D8F0, -52 + 8),  // +4.801872776405789409e+02
        FLR::scaled( 0x1012D0C2ECF6E3, -52 + 9),  // +5.143519342911571357e+02
        FLR::scaled( 0x1F80190A490778, -52 + 7),  // +2.520030566622115202e+02
        FLR::scaled( 0x1CE5D539FC5B3C, -52 + 5),  // +5.779556965658272816e+01
        FLR::scaled( 0x19456215F01A33, -52 + 8),  // +4.043364467028615650e+02
        FLR::scaled( 0x1CE41934E2A72E, -52 + 7),  // +2.311280769755189226e+02
        FLR::scaled( 0x13CBC5E46564F0, -52 + 9),  // +6.334716270371845894e+02
        FLR::scaled(-0x1032668987081B, -52 + 6),  // -6.478750837504087201e+01
        FLR::scaled( 0x16D505020C5218, -52 + 8),  // +3.653137226563717377e+02
        FLR::scaled( 0x194BBBE404478A, -52 + 9),  // +8.094667435011226644e+02
        FLR::scaled( 0x13EB7D07EC1168, -52 + 8),  // +3.187180251332670196e+02
        FLR::scaled( 0x16152BB1D775F3, -52 + 5),  // +4.416539595623535064e+01
        FLR::scaled( 0x15AA2CD8CF0845, -52 + 9),  // +6.932718979048155461e+02
        FLR::scaled( 0x106B73CDCC1086, -52 + 9),  // +5.254315448706190637e+02
        FLR::scaled( 0x1B414546D180CE, -52 + 8),  // +4.360794132407871757e+02
        FLR::scaled(-0x11ADFDB76C4159, -52 + 9),  // -5.657488850076143763e+02
        FLR::scaled( 0x1B4D21E49D4636, -52 + 8),  // +4.368207746642614211e+02
        FLR::scaled( 0x1BF55E03EAAAE1, -52 + 7),  // +2.236677264769887472e+02
        FLR::scaled( 0x137CB09920F493, -52 + 8),  // +3.117931147849387230e+02
        FLR::scaled(-0x1DEE89FAE5CD94, -52 + 7),  // -2.394543432701435677e+02
        FLR::scaled( 0x146E66EFE3E5F4, -52 + 9),  // +6.538002622417975545e+02
        FLR::scaled( 0x1F005272E06200, -52 + 7),  // +2.480100645430065924e+02
        FLR::scaled( 0x15F63079A11FF6, -52 + 8),  // +3.513868347448291161e+02
        FLR::scaled(-0x114B60741BB6F8, -52 + 9),  // -5.534220964589321738e+02
        FLR::scaled( 0x1022A19EC591CB, -52 + 9),  // +5.163289161143414958e+02
        FLR::scaled( 0x19A993D64C4B3A, -52 + 9),  // +8.211971860847909284e+02
        FLR::scaled( 0x1629934FCEAFD0, -52 + 8),  // +3.545984647821142062e+02
        FLR::scaled(-0x16BC6DCACD81A9, -52 + 7),  // -1.818884023679541144e+02
        FLR::scaled( 0x19FA0F8C50B7C9, -52 + 8),  // +4.156287959244769468e+02
        FLR::scaled( 0x1164476F4AF0FA, -52 + 9),  // +5.565348802428045474e+02
        FLR::scaled( 0x10C8BDA0B150C8, -52 + 10),  // +1.074185183306270119e+03
        FLR::scaled(-0x122BD143163DE7, -52 + 5),  // -3.634232367120767293e+01
        FLR::scaled( 0x161AB29DFF3875, -52 + 8),  // +3.536686077088882598e+02
        FLR::scaled( 0x18E4AF1590FF12, -52 + 7),  // +1.991463725883446045e+02
        FLR::scaled( 0x11602990438758, -52 + 9),  // +5.560202946925810465e+02
        FLR::scaled(-0x198368B52CE98E, -52 + 8),  // -4.082130634073627107e+02
        FLR::scaled( 0x1B2FDFCF55D625, -52 + 9),  // +8.699842821794487691e+02
        FLR::scaled( 0x1380A1FB05A642, -52 + 7),  // +1.560197730169621195e+02
        FLR::scaled( 0x15F1B2E9928B63, -52 + 8),  // +3.511061797832864499e+02
        FLR::scaled(-0x1F4FA664CE978C, -52 + 8),  // -5.009781234807967394e+02
        FLR::scaled( 0x17C28BA2E8BA2E, -52 + 9)   // +7.603181818181817562e+02
    ];

    pub(crate) const KAT_SAMPLER_512_INVSIGMA: [FLR; 1024] = [
        FLR::scaled( 0x127F10740BABFA, -52 - 1),  // +5.780107752337919624e-01
        FLR::scaled( 0x127F10740BABFA, -52 - 1),  // +5.780107752337919624e-01
        FLR::scaled( 0x1285D7F985F6E6, -52 - 1),  // +5.788383363248754687e-01
        FLR::scaled( 0x1285D7F985F6E6, -52 - 1),  // +5.788383363248754687e-01
        FLR::scaled( 0x127F34FEB7FE33, -52 - 1),  // +5.780281996703194869e-01
        FLR::scaled( 0x127F34FEB7FE33, -52 - 1),  // +5.780281996703194869e-01
        FLR::scaled( 0x1285F9BFE98E7C, -52 - 1),  // +5.788544414794638548e-01
        FLR::scaled( 0x1285F9BFE98E7C, -52 - 1),  // +5.788544414794638548e-01
        FLR::scaled( 0x1291D41AB5CF91, -52 - 1),  // +5.803013345416606628e-01
        FLR::scaled( 0x1291D41AB5CF91, -52 - 1),  // +5.803013345416606628e-01
        FLR::scaled( 0x12982AEEE900C5, -52 - 1),  // +5.810751596655100437e-01
        FLR::scaled( 0x12982AEEE900C5, -52 - 1),  // +5.810751596655100437e-01
        FLR::scaled( 0x129202C964043F, -52 - 1),  // +5.803235944187078443e-01
        FLR::scaled( 0x129202C964043F, -52 - 1),  // +5.803235944187078443e-01
        FLR::scaled( 0x1298568B3B4BF3, -52 - 1),  // +5.810959548347213177e-01
        FLR::scaled( 0x1298568B3B4BF3, -52 - 1),  // +5.810959548347213177e-01
        FLR::scaled( 0x12A6432380373A, -52 - 1),  // +5.827956860900720404e-01
        FLR::scaled( 0x12A6432380373A, -52 - 1),  // +5.827956860900720404e-01
        FLR::scaled( 0x12AAE2569726E2, -52 - 1),  // +5.833598796100114559e-01
        FLR::scaled( 0x12AAE2569726E2, -52 - 1),  // +5.833598796100114559e-01
        FLR::scaled( 0x12A710E024AB1D, -52 - 1),  // +5.828937890813424838e-01
        FLR::scaled( 0x12A710E024AB1D, -52 - 1),  // +5.828937890813424838e-01
        FLR::scaled( 0x12AB9F4D3B5397, -52 - 1),  // +5.834499844009880531e-01
        FLR::scaled( 0x12AB9F4D3B5397, -52 - 1),  // +5.834499844009880531e-01
        FLR::scaled( 0x12B9A6A1AF5E82, -52 - 1),  // +5.851624639426094010e-01
        FLR::scaled( 0x12B9A6A1AF5E82, -52 - 1),  // +5.851624639426094010e-01
        FLR::scaled( 0x12BDD52E8CEE0E, -52 - 1),  // +5.856729420842741174e-01
        FLR::scaled( 0x12BDD52E8CEE0E, -52 - 1),  // +5.856729420842741174e-01
        FLR::scaled( 0x12BA9D67E8D400, -52 - 1),  // +5.852801351053358303e-01
        FLR::scaled( 0x12BA9D67E8D400, -52 - 1),  // +5.852801351053358303e-01
        FLR::scaled( 0x12BEB957D19A9D, -52 - 1),  // +5.857817378244650763e-01
        FLR::scaled( 0x12BEB957D19A9D, -52 - 1),  // +5.857817378244650763e-01
        FLR::scaled( 0x129D282BBF2A4B, -52 - 1),  // +5.816841940334794847e-01
        FLR::scaled( 0x129D282BBF2A4B, -52 - 1),  // +5.816841940334794847e-01
        FLR::scaled( 0x12A5E65BA07FF6, -52 - 1),  // +5.827514447773853856e-01
        FLR::scaled( 0x12A5E65BA07FF6, -52 - 1),  // +5.827514447773853856e-01
        FLR::scaled( 0x129D6429E9630A, -52 - 1),  // +5.817128008448844145e-01
        FLR::scaled( 0x129D6429E9630A, -52 - 1),  // +5.817128008448844145e-01
        FLR::scaled( 0x12A62111F162A7, -52 - 1),  // +5.827794409224978933e-01
        FLR::scaled( 0x12A62111F162A7, -52 - 1),  // +5.827794409224978933e-01
        FLR::scaled( 0x12B0D868A21993, -52 - 1),  // +5.840875667206993915e-01
        FLR::scaled( 0x12B0D868A21993, -52 - 1),  // +5.840875667206993915e-01
        FLR::scaled( 0x12B91993D70784, -52 - 1),  // +5.850952041148365090e-01
        FLR::scaled( 0x12B91993D70784, -52 - 1),  // +5.850952041148365090e-01
        FLR::scaled( 0x12B12ECE87702B, -52 - 1),  // +5.841287645121203687e-01
        FLR::scaled( 0x12B12ECE87702B, -52 - 1),  // +5.841287645121203687e-01
        FLR::scaled( 0x12B96E3A69690B, -52 - 1),  // +5.851355687002820494e-01
        FLR::scaled( 0x12B96E3A69690B, -52 - 1),  // +5.851355687002820494e-01
        FLR::scaled( 0x12C843CC19BF38, -52 - 1),  // +5.869463907565437566e-01
        FLR::scaled( 0x12C843CC19BF38, -52 - 1),  // +5.869463907565437566e-01
        FLR::scaled( 0x12CE7F540A194C, -52 - 1),  // +5.877071992297628888e-01
        FLR::scaled( 0x12CE7F540A194C, -52 - 1),  // +5.877071992297628888e-01
        FLR::scaled( 0x12C93359D26329, -52 - 1),  // +5.870606188137560411e-01
        FLR::scaled( 0x12C93359D26329, -52 - 1),  // +5.870606188137560411e-01
        FLR::scaled( 0x12CF5AEDF65F25, -52 - 1),  // +5.878119132712283923e-01
        FLR::scaled( 0x12CF5AEDF65F25, -52 - 1),  // +5.878119132712283923e-01
        FLR::scaled( 0x12DC976F90C69F, -52 - 1),  // +5.894276789678832840e-01
        FLR::scaled( 0x12DC976F90C69F, -52 - 1),  // +5.894276789678832840e-01
        FLR::scaled( 0x12E2476A37C913, -52 - 1),  // +5.901219439095107822e-01
        FLR::scaled( 0x12E2476A37C913, -52 - 1),  // +5.901219439095107822e-01
        FLR::scaled( 0x12DDD41411BF19, -52 - 1),  // +5.895786659220646486e-01
        FLR::scaled( 0x12DDD41411BF19, -52 - 1),  // +5.895786659220646486e-01
        FLR::scaled( 0x12E36C207279CE, -52 - 1),  // +5.902615197881517783e-01
        FLR::scaled( 0x12E36C207279CE, -52 - 1),  // +5.902615197881517783e-01
        FLR::scaled( 0x132469606C38C8, -52 - 1),  // +5.981947787529628968e-01
        FLR::scaled( 0x132469606C38C8, -52 - 1),  // +5.981947787529628968e-01
        FLR::scaled( 0x132946BEFF0E6A, -52 - 1),  // +5.987886171719314365e-01
        FLR::scaled( 0x132946BEFF0E6A, -52 - 1),  // +5.987886171719314365e-01
        FLR::scaled( 0x13276F98B1EC5E, -52 - 1),  // +5.985639555286856872e-01
        FLR::scaled( 0x13276F98B1EC5E, -52 - 1),  // +5.985639555286856872e-01
        FLR::scaled( 0x132C103B07EEBA, -52 - 1),  // +5.991288330983117749e-01
        FLR::scaled( 0x132C103B07EEBA, -52 - 1),  // +5.991288330983117749e-01
        FLR::scaled( 0x133E987EE9AB8B, -52 - 1),  // +6.013910750165093466e-01
        FLR::scaled( 0x133E987EE9AB8B, -52 - 1),  // +6.013910750165093466e-01
        FLR::scaled( 0x13429A61D42806, -52 - 1),  // +6.018802557675833054e-01
        FLR::scaled( 0x13429A61D42806, -52 - 1),  // +6.018802557675833054e-01
        FLR::scaled( 0x1341DFE96FC247, -52 - 1),  // +6.017913398082520571e-01
        FLR::scaled( 0x1341DFE96FC247, -52 - 1),  // +6.017913398082520571e-01
        FLR::scaled( 0x1345A9C21861D5, -52 - 1),  // +6.022537985727988152e-01
        FLR::scaled( 0x1345A9C21861D5, -52 - 1),  // +6.022537985727988152e-01
        FLR::scaled( 0x134B908E796A0F, -52 - 1),  // +6.029742033672976786e-01
        FLR::scaled( 0x134B908E796A0F, -52 - 1),  // +6.029742033672976786e-01
        FLR::scaled( 0x134EAB876CE61F, -52 - 1),  // +6.033532757784917377e-01
        FLR::scaled( 0x134EAB876CE61F, -52 - 1),  // +6.033532757784917377e-01
        FLR::scaled( 0x13503B85A2DF3A, -52 - 1),  // +6.035440073091884461e-01
        FLR::scaled( 0x13503B85A2DF3A, -52 - 1),  // +6.035440073091884461e-01
        FLR::scaled( 0x135308D461D8AF, -52 - 1),  // +6.038860462274636687e-01
        FLR::scaled( 0x135308D461D8AF, -52 - 1),  // +6.038860462274636687e-01
        FLR::scaled( 0x136425C21CD47F, -52 - 1),  // +6.059750357877787819e-01
        FLR::scaled( 0x136425C21CD47F, -52 - 1),  // +6.059750357877787819e-01
        FLR::scaled( 0x1366A1079DEE7D, -52 - 1),  // +6.062779568450903378e-01
        FLR::scaled( 0x1366A1079DEE7D, -52 - 1),  // +6.062779568450903378e-01
        FLR::scaled( 0x1368E7D684CA4C, -52 - 1),  // +6.065558614557828854e-01
        FLR::scaled( 0x1368E7D684CA4C, -52 - 1),  // +6.065558614557828854e-01
        FLR::scaled( 0x136B1E7B6DF9F1, -52 - 1),  // +6.068260584577825911e-01
        FLR::scaled( 0x136B1E7B6DF9F1, -52 - 1),  // +6.068260584577825911e-01
        FLR::scaled( 0x1342D3D65116C8, -52 - 1),  // +6.019076524614428436e-01
        FLR::scaled( 0x1342D3D65116C8, -52 - 1),  // +6.019076524614428436e-01
        FLR::scaled( 0x13493F717C599F, -52 - 1),  // +6.026913849371345888e-01
        FLR::scaled( 0x13493F717C599F, -52 - 1),  // +6.026913849371345888e-01
        FLR::scaled( 0x13460ECED27284, -52 - 1),  // +6.023019828313214141e-01
        FLR::scaled( 0x13460ECED27284, -52 - 1),  // +6.023019828313214141e-01
        FLR::scaled( 0x134C320BF71FCA, -52 - 1),  // +6.030512078950718280e-01
        FLR::scaled( 0x134C320BF71FCA, -52 - 1),  // +6.030512078950718280e-01
        FLR::scaled( 0x135F92D200E532, -52 - 1),  // +6.054166890745931173e-01
        FLR::scaled( 0x135F92D200E532, -52 - 1),  // +6.054166890745931173e-01
        FLR::scaled( 0x13651F00C28AB4, -52 - 1),  // +6.060938849298822539e-01
        FLR::scaled( 0x13651F00C28AB4, -52 - 1),  // +6.060938849298822539e-01
        FLR::scaled( 0x1363422EE52B14, -52 - 1),  // +6.058665195390369185e-01
        FLR::scaled( 0x1363422EE52B14, -52 - 1),  // +6.058665195390369185e-01
        FLR::scaled( 0x1368869B29D716, -52 - 1),  // +6.065094976936247217e-01
        FLR::scaled( 0x1368869B29D716, -52 - 1),  // +6.065094976936247217e-01
        FLR::scaled( 0x136D72782C1E2D, -52 - 1),  // +6.071102473369528463e-01
        FLR::scaled( 0x136D72782C1E2D, -52 - 1),  // +6.071102473369528463e-01
        FLR::scaled( 0x1371BB5825BFCC, -52 - 1),  // +6.076332780485187435e-01
        FLR::scaled( 0x1371BB5825BFCC, -52 - 1),  // +6.076332780485187435e-01
        FLR::scaled( 0x137286486FC6E5, -52 - 1),  // +6.077300467279341811e-01
        FLR::scaled( 0x137286486FC6E5, -52 - 1),  // +6.077300467279341811e-01
        FLR::scaled( 0x13766E630AFF51, -52 - 1),  // +6.082069334442882225e-01
        FLR::scaled( 0x13766E630AFF51, -52 - 1),  // +6.082069334442882225e-01
        FLR::scaled( 0x1388977A88F5E4, -52 - 1),  // +6.104237931501157455e-01
        FLR::scaled( 0x1388977A88F5E4, -52 - 1),  // +6.104237931501157455e-01
        FLR::scaled( 0x138C33BE6AC020, -52 - 1),  // +6.108645171243587413e-01
        FLR::scaled( 0x138C33BE6AC020, -52 - 1),  // +6.108645171243587413e-01
        FLR::scaled( 0x138E0E27DC03ED, -52 - 1),  // +6.110907343391979163e-01
        FLR::scaled( 0x138E0E27DC03ED, -52 - 1),  // +6.110907343391979163e-01
        FLR::scaled( 0x13914E50F29B0D, -52 - 1),  // +6.114875393876403331e-01
        FLR::scaled( 0x13914E50F29B0D, -52 - 1),  // +6.114875393876403331e-01
        FLR::scaled( 0x138D0899D27F48, -52 - 1),  // +6.109660152760421070e-01
        FLR::scaled( 0x138D0899D27F48, -52 - 1),  // +6.109660152760421070e-01
        FLR::scaled( 0x139590EE6D3487, -52 - 1),  // +6.120075852173990638e-01
        FLR::scaled( 0x139590EE6D3487, -52 - 1),  // +6.120075852173990638e-01
        FLR::scaled( 0x138F2EFB10DDEB, -52 - 1),  // +6.112284568434324106e-01
        FLR::scaled( 0x138F2EFB10DDEB, -52 - 1),  // +6.112284568434324106e-01
        FLR::scaled( 0x1397FA8AAB9E64, -52 - 1),  // +6.123020847707718595e-01
        FLR::scaled( 0x1397FA8AAB9E64, -52 - 1),  // +6.123020847707718595e-01
        FLR::scaled( 0x13A6AE078D7F47, -52 - 1),  // +6.140966556085708516e-01
        FLR::scaled( 0x13A6AE078D7F47, -52 - 1),  // +6.140966556085708516e-01
        FLR::scaled( 0x13AF5E491F0DDD, -52 - 1),  // +6.151572635794156918e-01
        FLR::scaled( 0x13AF5E491F0DDD, -52 - 1),  // +6.151572635794156918e-01
        FLR::scaled( 0x13A8B0E396373F, -52 - 1),  // +6.143421597532564560e-01
        FLR::scaled( 0x13A8B0E396373F, -52 - 1),  // +6.143421597532564560e-01
        FLR::scaled( 0x13B1A29BD11766, -52 - 1),  // +6.154339831634672020e-01
        FLR::scaled( 0x13B1A29BD11766, -52 - 1),  // +6.154339831634672020e-01
        FLR::scaled( 0x13BC8D75E80BAA, -52 - 1),  // +6.167666724071427797e-01
        FLR::scaled( 0x13BC8D75E80BAA, -52 - 1),  // +6.167666724071427797e-01
        FLR::scaled( 0x13C143555A0C22, -52 - 1),  // +6.173416773821183146e-01
        FLR::scaled( 0x13C143555A0C22, -52 - 1),  // +6.173416773821183146e-01
        FLR::scaled( 0x13BEF04EBDDAAB, -52 - 1),  // +6.170579469606612966e-01
        FLR::scaled( 0x13BEF04EBDDAAB, -52 - 1),  // +6.170579469606612966e-01
        FLR::scaled( 0x13C3D61D30098A, -52 - 1),  // +6.176558084555818784e-01
        FLR::scaled( 0x13C3D61D30098A, -52 - 1),  // +6.176558084555818784e-01
        FLR::scaled( 0x13DD0AA2B00BFE, -52 - 1),  // +6.207326104635055852e-01
        FLR::scaled( 0x13DD0AA2B00BFE, -52 - 1),  // +6.207326104635055852e-01
        FLR::scaled( 0x13E15526141363, -52 - 1),  // +6.212564223975330924e-01
        FLR::scaled( 0x13E15526141363, -52 - 1),  // +6.212564223975330924e-01
        FLR::scaled( 0x13E0014DB39A8A, -52 - 1),  // +6.210943715676233712e-01
        FLR::scaled( 0x13E0014DB39A8A, -52 - 1),  // +6.210943715676233712e-01
        FLR::scaled( 0x13E4688F0259CD, -52 - 1),  // +6.216318886898136720e-01
        FLR::scaled( 0x13E4688F0259CD, -52 - 1),  // +6.216318886898136720e-01
        FLR::scaled( 0x13B51AF11D1B40, -52 - 1),  // +6.158575734378715083e-01
        FLR::scaled( 0x13B51AF11D1B40, -52 - 1),  // +6.158575734378715083e-01
        FLR::scaled( 0x13BF5FF79042DC, -52 - 1),  // +6.171111903405193111e-01
        FLR::scaled( 0x13BF5FF79042DC, -52 - 1),  // +6.171111903405193111e-01
        FLR::scaled( 0x13B69079C46D27, -52 - 1),  // +6.160356882350342955e-01
        FLR::scaled( 0x13B69079C46D27, -52 - 1),  // +6.160356882350342955e-01
        FLR::scaled( 0x13C1000D3ABCE6, -52 - 1),  // +6.173095949542612981e-01
        FLR::scaled( 0x13C1000D3ABCE6, -52 - 1),  // +6.173095949542612981e-01
        FLR::scaled( 0x13D04486808527, -52 - 1),  // +6.191733004563148013e-01
        FLR::scaled( 0x13D04486808527, -52 - 1),  // +6.191733004563148013e-01
        FLR::scaled( 0x13DAC8A84EBB8B, -52 - 1),  // +6.204570090538806815e-01
        FLR::scaled( 0x13DAC8A84EBB8B, -52 - 1),  // +6.204570090538806815e-01
        FLR::scaled( 0x13D1543F285FE8, -52 - 1),  // +6.193028672741975882e-01
        FLR::scaled( 0x13D1543F285FE8, -52 - 1),  // +6.193028672741975882e-01
        FLR::scaled( 0x13DBFE4006D9E3, -52 - 1),  // +6.206046343348216032e-01
        FLR::scaled( 0x13DBFE4006D9E3, -52 - 1),  // +6.206046343348216032e-01
        FLR::scaled( 0x13EA44FE7DFE77, -52 - 1),  // +6.223473520803527448e-01
        FLR::scaled( 0x13EA44FE7DFE77, -52 - 1),  // +6.223473520803527448e-01
        FLR::scaled( 0x13F00FAC6DE942, -52 - 1),  // +6.230543487320476803e-01
        FLR::scaled( 0x13F00FAC6DE942, -52 - 1),  // +6.230543487320476803e-01
        FLR::scaled( 0x13EBCA9FAB814D, -52 - 1),  // +6.225331419518994602e-01
        FLR::scaled( 0x13EBCA9FAB814D, -52 - 1),  // +6.225331419518994602e-01
        FLR::scaled( 0x13F1B7FD2E3DE7, -52 - 1),  // +6.232566780981273480e-01
        FLR::scaled( 0x13F1B7FD2E3DE7, -52 - 1),  // +6.232566780981273480e-01
        FLR::scaled( 0x140DB0C0CFDAD7, -52 - 1),  // +6.266711965425554309e-01
        FLR::scaled( 0x140DB0C0CFDAD7, -52 - 1),  // +6.266711965425554309e-01
        FLR::scaled( 0x1412E7B4B3F938, -52 - 1),  // +6.273077515941514193e-01
        FLR::scaled( 0x1412E7B4B3F938, -52 - 1),  // +6.273077515941514193e-01
        FLR::scaled( 0x140FA82974AE38, -52 - 1),  // +6.269112405474919214e-01
        FLR::scaled( 0x140FA82974AE38, -52 - 1),  // +6.269112405474919214e-01
        FLR::scaled( 0x1414E90055C169, -52 - 1),  // +6.275525099318147726e-01
        FLR::scaled( 0x1414E90055C169, -52 - 1),  // +6.275525099318147726e-01
        FLR::scaled( 0x142E79B3E9BC32, -52 - 1),  // +6.306732667852712471e-01
        FLR::scaled( 0x142E79B3E9BC32, -52 - 1),  // +6.306732667852712471e-01
        FLR::scaled( 0x1433C9846205DD, -52 - 1),  // +6.313216767886690173e-01
        FLR::scaled( 0x1433C9846205DD, -52 - 1),  // +6.313216767886690173e-01
        FLR::scaled( 0x14319D0084D0AB, -52 - 1),  // +6.310563097126949961e-01
        FLR::scaled( 0x14319D0084D0AB, -52 - 1),  // +6.310563097126949961e-01
        FLR::scaled( 0x14371770E1EF6E, -52 - 1),  // +6.317250447022908499e-01
        FLR::scaled( 0x14371770E1EF6E, -52 - 1),  // +6.317250447022908499e-01
        FLR::scaled( 0x144DE8BC8664AB, -52 - 1),  // +6.345103914383306565e-01
        FLR::scaled( 0x144DE8BC8664AB, -52 - 1),  // +6.345103914383306565e-01
        FLR::scaled( 0x145351E959D4CE, -52 - 1),  // +6.351708943972427246e-01
        FLR::scaled( 0x145351E959D4CE, -52 - 1),  // +6.351708943972427246e-01
        FLR::scaled( 0x14524F8D11CECB, -52 - 1),  // +6.350476985230327776e-01
        FLR::scaled( 0x14524F8D11CECB, -52 - 1),  // +6.350476985230327776e-01
        FLR::scaled( 0x1457E98E1D2869, -52 - 1),  // +6.357314849531238155e-01
        FLR::scaled( 0x1457E98E1D2869, -52 - 1),  // +6.357314849531238155e-01
        FLR::scaled( 0x145B7BC0FA28FD, -52 - 1),  // +6.361674088559819973e-01
        FLR::scaled( 0x145B7BC0FA28FD, -52 - 1),  // +6.361674088559819973e-01
        FLR::scaled( 0x145E571FBF8650, -52 - 1),  // +6.365161533432885932e-01
        FLR::scaled( 0x145E571FBF8650, -52 - 1),  // +6.365161533432885932e-01
        FLR::scaled( 0x145FD41EAAC9D6, -52 - 1),  // +6.366978262870428562e-01
        FLR::scaled( 0x145FD41EAAC9D6, -52 - 1),  // +6.366978262870428562e-01
        FLR::scaled( 0x1462BB78214904, -52 - 1),  // +6.370522829331837222e-01
        FLR::scaled( 0x1462BB78214904, -52 - 1),  // +6.370522829331837222e-01
        FLR::scaled( 0x147DF6CE76882E, -52 - 1),  // +6.403764755707521683e-01
        FLR::scaled( 0x147DF6CE76882E, -52 - 1),  // +6.403764755707521683e-01
        FLR::scaled( 0x1480BB8B4027E3, -52 - 1),  // +6.407144279230546635e-01
        FLR::scaled( 0x1480BB8B4027E3, -52 - 1),  // +6.407144279230546635e-01
        FLR::scaled( 0x1484666114775A, -52 - 1),  // +6.411620994656275219e-01
        FLR::scaled( 0x1484666114775A, -52 - 1),  // +6.411620994656275219e-01
        FLR::scaled( 0x14872F8A264D83, -52 - 1),  // +6.415021608576555456e-01
        FLR::scaled( 0x14872F8A264D83, -52 - 1),  // +6.415021608576555456e-01
        FLR::scaled( 0x145E2A3F10F63E, -52 - 1),  // +6.364947540057028785e-01
        FLR::scaled( 0x145E2A3F10F63E, -52 - 1),  // +6.364947540057028785e-01
        FLR::scaled( 0x146456B50BF468, -52 - 1),  // +6.372483764713594567e-01
        FLR::scaled( 0x146456B50BF468, -52 - 1),  // +6.372483764713594567e-01
        FLR::scaled( 0x1460A3E1410A42, -52 - 1),  // +6.367968940251744758e-01
        FLR::scaled( 0x1460A3E1410A42, -52 - 1),  // +6.367968940251744758e-01
        FLR::scaled( 0x1466FBCF8F6E18, -52 - 1),  // +6.375712446128458666e-01
        FLR::scaled( 0x1466FBCF8F6E18, -52 - 1),  // +6.375712446128458666e-01
        FLR::scaled( 0x1480B809107243, -52 - 1),  // +6.407127549205785533e-01
        FLR::scaled( 0x1480B809107243, -52 - 1),  // +6.407127549205785533e-01
        FLR::scaled( 0x14872FBA00247B, -52 - 1),  // +6.415022499869701411e-01
        FLR::scaled( 0x14872FBA00247B, -52 - 1),  // +6.415022499869701411e-01
        FLR::scaled( 0x14843A52FB37F2, -52 - 1),  // +6.411410923699334408e-01
        FLR::scaled( 0x14843A52FB37F2, -52 - 1),  // +6.411410923699334408e-01
        FLR::scaled( 0x148ADA770719A3, -52 - 1),  // +6.419498753319213824e-01
        FLR::scaled( 0x148ADA770719A3, -52 - 1),  // +6.419498753319213824e-01
        FLR::scaled( 0x14913B2016F4FD, -52 - 1),  // +6.427283884765128130e-01
        FLR::scaled( 0x14913B2016F4FD, -52 - 1),  // +6.427283884765128130e-01
        FLR::scaled( 0x14948F278001C7, -52 - 1),  // +6.431346675381569566e-01
        FLR::scaled( 0x14948F278001C7, -52 - 1),  // +6.431346675381569566e-01
        FLR::scaled( 0x14950AF7D5BFE6, -52 - 1),  // +6.431937065626669447e-01
        FLR::scaled( 0x14950AF7D5BFE6, -52 - 1),  // +6.431937065626669447e-01
        FLR::scaled( 0x14986CF8E6CE00, -52 - 1),  // +6.436066495284080702e-01
        FLR::scaled( 0x14986CF8E6CE00, -52 - 1),  // +6.436066495284080702e-01
        FLR::scaled( 0x14B89B3BC0C8D5, -52 - 1),  // +6.475349585582771406e-01
        FLR::scaled( 0x14B89B3BC0C8D5, -52 - 1),  // +6.475349585582771406e-01
        FLR::scaled( 0x14BBD7F151F0E9, -52 - 1),  // +6.479301179201942817e-01
        FLR::scaled( 0x14BBD7F151F0E9, -52 - 1),  // +6.479301179201942817e-01
        FLR::scaled( 0x14BE9AF064A2CC, -52 - 1),  // +6.482672400644218236e-01
        FLR::scaled( 0x14BE9AF064A2CC, -52 - 1),  // +6.482672400644218236e-01
        FLR::scaled( 0x14C1D1D6390514, -52 - 1),  // +6.486596282995003016e-01
        FLR::scaled( 0x14C1D1D6390514, -52 - 1),  // +6.486596282995003016e-01
        FLR::scaled( 0x143F4268B78376, -52 - 1),  // +6.327220959902735142e-01
        FLR::scaled( 0x143F4268B78376, -52 - 1),  // +6.327220959902735142e-01
        FLR::scaled( 0x1446046E0AB2BD, -52 - 1),  // +6.335470341924388515e-01
        FLR::scaled( 0x1446046E0AB2BD, -52 - 1),  // +6.335470341924388515e-01
        FLR::scaled( 0x143FAA6CFA6884, -52 - 1),  // +6.327716949920305645e-01
        FLR::scaled( 0x143FAA6CFA6884, -52 - 1),  // +6.327716949920305645e-01
        FLR::scaled( 0x144669E551ACE4, -52 - 1),  // +6.335954169166169159e-01
        FLR::scaled( 0x144669E551ACE4, -52 - 1),  // +6.335954169166169159e-01
        FLR::scaled( 0x1455997489A5DD, -52 - 1),  // +6.354491497160627000e-01
        FLR::scaled( 0x1455997489A5DD, -52 - 1),  // +6.354491497160627000e-01
        FLR::scaled( 0x145DEB9BCECF8B, -52 - 1),  // +6.364648860094218596e-01
        FLR::scaled( 0x145DEB9BCECF8B, -52 - 1),  // +6.364648860094218596e-01
        FLR::scaled( 0x1455F6F7948179, -52 - 1),  // +6.354937396572913899e-01
        FLR::scaled( 0x1455F6F7948179, -52 - 1),  // +6.354937396572913899e-01
        FLR::scaled( 0x145E4B14B638AB, -52 - 1),  // +6.365104107406031053e-01
        FLR::scaled( 0x145E4B14B638AB, -52 - 1),  // +6.365104107406031053e-01
        FLR::scaled( 0x146983B0FE72F4, -52 - 1),  // +6.378801781571312723e-01
        FLR::scaled( 0x146983B0FE72F4, -52 - 1),  // +6.378801781571312723e-01
        FLR::scaled( 0x146EA41A81C115, -52 - 1),  // +6.385059850418054461e-01
        FLR::scaled( 0x146EA41A81C115, -52 - 1),  // +6.385059850418054461e-01
        FLR::scaled( 0x1469F4E1CE36A2, -52 - 1),  // +6.379341516746601659e-01
        FLR::scaled( 0x1469F4E1CE36A2, -52 - 1),  // +6.379341516746601659e-01
        FLR::scaled( 0x146F1CF3D6DC1F, -52 - 1),  // +6.385636103140120978e-01
        FLR::scaled( 0x146F1CF3D6DC1F, -52 - 1),  // +6.385636103140120978e-01
        FLR::scaled( 0x1482FE4AAFB31B, -52 - 1),  // +6.409903963773077029e-01
        FLR::scaled( 0x1482FE4AAFB31B, -52 - 1),  // +6.409903963773077029e-01
        FLR::scaled( 0x148945912DC216, -52 - 1),  // +6.417568049928970009e-01
        FLR::scaled( 0x148945912DC216, -52 - 1),  // +6.417568049928970009e-01
        FLR::scaled( 0x14837A03069E9C, -52 - 1),  // +6.410493907068999242e-01
        FLR::scaled( 0x14837A03069E9C, -52 - 1),  // +6.410493907068999242e-01
        FLR::scaled( 0x1489CE02BB64C4, -52 - 1),  // +6.418218663558481474e-01
        FLR::scaled( 0x1489CE02BB64C4, -52 - 1),  // +6.418218663558481474e-01
        FLR::scaled( 0x14637DEB39E4AE, -52 - 1),  // +6.371450037251145115e-01
        FLR::scaled( 0x14637DEB39E4AE, -52 - 1),  // +6.371450037251145115e-01
        FLR::scaled( 0x146D5A732BF77A, -52 - 1),  // +6.383487939308303272e-01
        FLR::scaled( 0x146D5A732BF77A, -52 - 1),  // +6.383487939308303272e-01
        FLR::scaled( 0x1463AC42A279B0, -52 - 1),  // +6.371671010454544870e-01
        FLR::scaled( 0x1463AC42A279B0, -52 - 1),  // +6.371671010454544870e-01
        FLR::scaled( 0x146D849DE9984D, -52 - 1),  // +6.383689007022980144e-01
        FLR::scaled( 0x146D849DE9984D, -52 - 1),  // +6.383689007022980144e-01
        FLR::scaled( 0x147B6400DE1532, -52 - 1),  // +6.400623337691853099e-01
        FLR::scaled( 0x147B6400DE1532, -52 - 1),  // +6.400623337691853099e-01
        FLR::scaled( 0x14874B9550061F, -52 - 1),  // +6.415155330907430509e-01
        FLR::scaled( 0x14874B9550061F, -52 - 1),  // +6.415155330907430509e-01
        FLR::scaled( 0x147B7B26B012B0, -52 - 1),  // +6.400733714695743259e-01
        FLR::scaled( 0x147B7B26B012B0, -52 - 1),  // +6.400733714695743259e-01
        FLR::scaled( 0x148760941BE7A6, -52 - 1),  // +6.415255444292042863e-01
        FLR::scaled( 0x148760941BE7A6, -52 - 1),  // +6.415255444292042863e-01
        FLR::scaled( 0x14921E4C1BBD88, -52 - 1),  // +6.428367125026150930e-01
        FLR::scaled( 0x14921E4C1BBD88, -52 - 1),  // +6.428367125026150930e-01
        FLR::scaled( 0x1499FA813E7940, -52 - 1),  // +6.437962078378305364e-01
        FLR::scaled( 0x1499FA813E7940, -52 - 1),  // +6.437962078378305364e-01
        FLR::scaled( 0x149223501FDE8C, -52 - 1),  // +6.428391041690288965e-01
        FLR::scaled( 0x149223501FDE8C, -52 - 1),  // +6.428391041690288965e-01
        FLR::scaled( 0x1499FF97508F81, -52 - 1),  // +6.437986331334145662e-01
        FLR::scaled( 0x1499FF97508F81, -52 - 1),  // +6.437986331334145662e-01
        FLR::scaled( 0x14AD869CE7449E, -52 - 1),  // +6.461823524970389254e-01
        FLR::scaled( 0x14AD869CE7449E, -52 - 1),  // +6.461823524970389254e-01
        FLR::scaled( 0x14B6DF48AB22C8, -52 - 1),  // +6.473232669169073361e-01
        FLR::scaled( 0x14B6DF48AB22C8, -52 - 1),  // +6.473232669169073361e-01
        FLR::scaled( 0x14AD906F08FD7F, -52 - 1),  // +6.461870354323052679e-01
        FLR::scaled( 0x14AD906F08FD7F, -52 - 1),  // +6.461870354323052679e-01
        FLR::scaled( 0x14B6E96F30AEB2, -52 - 1),  // +6.473281070406839977e-01
        FLR::scaled( 0x14B6E96F30AEB2, -52 - 1),  // +6.473281070406839977e-01
        FLR::scaled( 0x152953E70D29D9, -52 - 1),  // +6.612948906634371626e-01
        FLR::scaled( 0x152953E70D29D9, -52 - 1),  // +6.612948906634371626e-01
        FLR::scaled( 0x152F848BF525DB, -52 - 1),  // +6.620505078837440882e-01
        FLR::scaled( 0x152F848BF525DB, -52 - 1),  // +6.620505078837440882e-01
        FLR::scaled( 0x152B81F41DEE03, -52 - 1),  // +6.615609901340920862e-01
        FLR::scaled( 0x152B81F41DEE03, -52 - 1),  // +6.615609901340920862e-01
        FLR::scaled( 0x15318E90B8FFE2, -52 - 1),  // +6.622994257559151610e-01
        FLR::scaled( 0x15318E90B8FFE2, -52 - 1),  // +6.622994257559151610e-01
        FLR::scaled( 0x15481B220B3B26, -52 - 1),  // +6.650520005149231917e-01
        FLR::scaled( 0x15481B220B3B26, -52 - 1),  // +6.650520005149231917e-01
        FLR::scaled( 0x155034691684C5, -52 - 1),  // +6.660406162738118363e-01
        FLR::scaled( 0x155034691684C5, -52 - 1),  // +6.660406162738118363e-01
        FLR::scaled( 0x154B6AFD62A7E4, -52 - 1),  // +6.654562901433078714e-01
        FLR::scaled( 0x154B6AFD62A7E4, -52 - 1),  // +6.654562901433078714e-01
        FLR::scaled( 0x15536FF1294F6A, -52 - 1),  // +6.664352140601128571e-01
        FLR::scaled( 0x15536FF1294F6A, -52 - 1),  // +6.664352140601128571e-01
        FLR::scaled( 0x154CC24F24C2CC, -52 - 1),  // +6.656199975751291298e-01
        FLR::scaled( 0x154CC24F24C2CC, -52 - 1),  // +6.656199975751291298e-01
        FLR::scaled( 0x1551B243A47411, -52 - 1),  // +6.662226983204410091e-01
        FLR::scaled( 0x1551B243A47411, -52 - 1),  // +6.662226983204410091e-01
        FLR::scaled( 0x154F1A18C33AE0, -52 - 1),  // +6.659059985775819257e-01
        FLR::scaled( 0x154F1A18C33AE0, -52 - 1),  // +6.659059985775819257e-01
        FLR::scaled( 0x1553E8CAEA39F5, -52 - 1),  // +6.664928401167445893e-01
        FLR::scaled( 0x1553E8CAEA39F5, -52 - 1),  // +6.664928401167445893e-01
        FLR::scaled( 0x156B83DFAB3DE2, -52 - 1),  // +6.693744057210404552e-01
        FLR::scaled( 0x156B83DFAB3DE2, -52 - 1),  // +6.693744057210404552e-01
        FLR::scaled( 0x15722F63E1E883, -52 - 1),  // +6.701886130170041644e-01
        FLR::scaled( 0x15722F63E1E883, -52 - 1),  // +6.701886130170041644e-01
        FLR::scaled( 0x156F370FB3F525, -52 - 1),  // +6.698260599802422499e-01
        FLR::scaled( 0x156F370FB3F525, -52 - 1),  // +6.698260599802422499e-01
        FLR::scaled( 0x1575CCDD474E99, -52 - 1),  // +6.706299135061782879e-01
        FLR::scaled( 0x1575CCDD474E99, -52 - 1),  // +6.706299135061782879e-01
        FLR::scaled( 0x155CAF1C8CFE12, -52 - 1),  // +6.675639684326049039e-01
        FLR::scaled( 0x155CAF1C8CFE12, -52 - 1),  // +6.675639684326049039e-01
        FLR::scaled( 0x1564A247DE6EA3, -52 - 1),  // +6.685344127358415767e-01
        FLR::scaled( 0x1564A247DE6EA3, -52 - 1),  // +6.685344127358415767e-01
        FLR::scaled( 0x15602782926D6C, -52 - 1),  // +6.679875898584390903e-01
        FLR::scaled( 0x15602782926D6C, -52 - 1),  // +6.679875898584390903e-01
        FLR::scaled( 0x1567C56D7222A0, -52 - 1),  // +6.689173829664305515e-01
        FLR::scaled( 0x1567C56D7222A0, -52 - 1),  // +6.689173829664305515e-01
        FLR::scaled( 0x1580A2E5C08BA7, -52 - 1),  // +6.719526755663211004e-01
        FLR::scaled( 0x1580A2E5C08BA7, -52 - 1),  // +6.719526755663211004e-01
        FLR::scaled( 0x158B31E72BBEC4, -52 - 1),  // +6.732415690475694880e-01
        FLR::scaled( 0x158B31E72BBEC4, -52 - 1),  // +6.732415690475694880e-01
        FLR::scaled( 0x1585375D014793, -52 - 1),  // +6.725117508415102696e-01
        FLR::scaled( 0x1585375D014793, -52 - 1),  // +6.725117508415102696e-01
        FLR::scaled( 0x158F6FC2B9C2FD, -52 - 1),  // +6.737593463168135566e-01
        FLR::scaled( 0x158F6FC2B9C2FD, -52 - 1),  // +6.737593463168135566e-01
        FLR::scaled( 0x15832F5557D2D7, -52 - 1),  // +6.722637812477739727e-01
        FLR::scaled( 0x15832F5557D2D7, -52 - 1),  // +6.722637812477739727e-01
        FLR::scaled( 0x158A1448CFB2F8, -52 - 1),  // +6.731053754898246311e-01
        FLR::scaled( 0x158A1448CFB2F8, -52 - 1),  // +6.731053754898246311e-01
        FLR::scaled( 0x1586C496F1F545, -52 - 1),  // +6.727011631152569615e-01
        FLR::scaled( 0x1586C496F1F545, -52 - 1),  // +6.727011631152569615e-01
        FLR::scaled( 0x158D5A3F8C3D1C, -52 - 1),  // +6.735049477737535817e-01
        FLR::scaled( 0x158D5A3F8C3D1C, -52 - 1),  // +6.735049477737535817e-01
        FLR::scaled( 0x15A82508D4973F, -52 - 1),  // +6.767754719228163962e-01
        FLR::scaled( 0x15A82508D4973F, -52 - 1),  // +6.767754719228163962e-01
        FLR::scaled( 0x15B18833DBB0DB, -52 - 1),  // +6.779213917593794880e-01
        FLR::scaled( 0x15B18833DBB0DB, -52 - 1),  // +6.779213917593794880e-01
        FLR::scaled( 0x15AD492A690C8F, -52 - 1),  // +6.774030521704775820e-01
        FLR::scaled( 0x15AD492A690C8F, -52 - 1),  // +6.774030521704775820e-01
        FLR::scaled( 0x15B659F3EDA545, -52 - 1),  // +6.785096897339505384e-01
        FLR::scaled( 0x15B659F3EDA545, -52 - 1),  // +6.785096897339505384e-01
        FLR::scaled( 0x15FCB39A987BDE, -52 - 1),  // +6.870973605581374155e-01
        FLR::scaled( 0x15FCB39A987BDE, -52 - 1),  // +6.870973605581374155e-01
        FLR::scaled( 0x15FE668D0130BB, -52 - 1),  // +6.873047594067637212e-01
        FLR::scaled( 0x15FE668D0130BB, -52 - 1),  // +6.873047594067637212e-01
        FLR::scaled( 0x1602FAEDE1E7C9, -52 - 1),  // +6.878637930051293425e-01
        FLR::scaled( 0x1602FAEDE1E7C9, -52 - 1),  // +6.878637930051293425e-01
        FLR::scaled( 0x1604A84950ED92, -52 - 1),  // +6.880685264545027824e-01
        FLR::scaled( 0x1604A84950ED92, -52 - 1),  // +6.880685264545027824e-01
        FLR::scaled( 0x162A0886A93F00, -52 - 1),  // +6.926310186481430264e-01
        FLR::scaled( 0x162A0886A93F00, -52 - 1),  // +6.926310186481430264e-01
        FLR::scaled( 0x162D2164ECEC30, -52 - 1),  // +6.930090876770744757e-01
        FLR::scaled( 0x162D2164ECEC30, -52 - 1),  // +6.930090876770744757e-01
        FLR::scaled( 0x16302A85243502, -52 - 1),  // +6.933796501558904257e-01
        FLR::scaled( 0x16302A85243502, -52 - 1),  // +6.933796501558904257e-01
        FLR::scaled( 0x1633599054DB6B, -52 - 1),  // +6.937682932828982407e-01
        FLR::scaled( 0x1633599054DB6B, -52 - 1),  // +6.937682932828982407e-01
        FLR::scaled( 0x1631AB0E698E7D, -52 - 1),  // +6.935630113116101336e-01
        FLR::scaled( 0x1631AB0E698E7D, -52 - 1),  // +6.935630113116101336e-01
        FLR::scaled( 0x1632141B0410EE, -52 - 1),  // +6.936131026891680929e-01
        FLR::scaled( 0x1632141B0410EE, -52 - 1),  // +6.936131026891680929e-01
        FLR::scaled( 0x16379E676BC248, -52 - 1),  // +6.942894000949957345e-01
        FLR::scaled( 0x16379E676BC248, -52 - 1),  // +6.942894000949957345e-01
        FLR::scaled( 0x16380CFC838E3E, -52 - 1),  // +6.943421298896692573e-01
        FLR::scaled( 0x16380CFC838E3E, -52 - 1),  // +6.943421298896692573e-01
        FLR::scaled( 0x1668B418CCFA94, -52 - 1),  // +7.002811893833773560e-01
        FLR::scaled( 0x1668B418CCFA94, -52 - 1),  // +7.002811893833773560e-01
        FLR::scaled( 0x16698FAB048B8E, -52 - 1),  // +7.003858890715137786e-01
        FLR::scaled( 0x16698FAB048B8E, -52 - 1),  // +7.003858890715137786e-01
        FLR::scaled( 0x166E33CB806A86, -52 - 1),  // +7.009524321213838061e-01
        FLR::scaled( 0x166E33CB806A86, -52 - 1),  // +7.009524321213838061e-01
        FLR::scaled( 0x166F2CADBA1C1C, -52 - 1),  // +7.010711091141987872e-01
        FLR::scaled( 0x166F2CADBA1C1C, -52 - 1),  // +7.010711091141987872e-01
        FLR::scaled( 0x16526705063200, -52 - 1),  // +6.975588892105974992e-01
        FLR::scaled( 0x16526705063200, -52 - 1),  // +6.975588892105974992e-01
        FLR::scaled( 0x165402DE6CDE56, -52 - 1),  // +6.977552742236621253e-01
        FLR::scaled( 0x165402DE6CDE56, -52 - 1),  // +6.977552742236621253e-01
        FLR::scaled( 0x1659CD536E99E5, -52 - 1),  // +6.984621648342083100e-01
        FLR::scaled( 0x1659CD536E99E5, -52 - 1),  // +6.984621648342083100e-01
        FLR::scaled( 0x165B36016B5F9B, -52 - 1),  // +6.986341502879328536e-01
        FLR::scaled( 0x165B36016B5F9B, -52 - 1),  // +6.986341502879328536e-01
        FLR::scaled( 0x1683A1DF34455D, -52 - 1),  // +7.035683974701602006e-01
        FLR::scaled( 0x1683A1DF34455D, -52 - 1),  // +7.035683974701602006e-01
        FLR::scaled( 0x16867C3F797EBF, -52 - 1),  // +7.039166679132548010e-01
        FLR::scaled( 0x16867C3F797EBF, -52 - 1),  // +7.039166679132548010e-01
        FLR::scaled( 0x1689E04C0851AB, -52 - 1),  // +7.043305859574976457e-01
        FLR::scaled( 0x1689E04C0851AB, -52 - 1),  // +7.043305859574976457e-01
        FLR::scaled( 0x168C936695435F, -52 - 1),  // +7.046601298880935671e-01
        FLR::scaled( 0x168C936695435F, -52 - 1),  // +7.046601298880935671e-01
        FLR::scaled( 0x1699DD0D53D032, -52 - 1),  // +7.062821636486715793e-01
        FLR::scaled( 0x1699DD0D53D032, -52 - 1),  // +7.062821636486715793e-01
        FLR::scaled( 0x169A0B7454C4DC, -52 - 1),  // +7.063042900173530647e-01
        FLR::scaled( 0x169A0B7454C4DC, -52 - 1),  // +7.063042900173530647e-01
        FLR::scaled( 0x16A17B4FA4AABD, -52 - 1),  // +7.072121196300354962e-01
        FLR::scaled( 0x16A17B4FA4AABD, -52 - 1),  // +7.072121196300354962e-01
        FLR::scaled( 0x16A19B2E94B563, -52 - 1),  // +7.072273168356953965e-01
        FLR::scaled( 0x16A19B2E94B563, -52 - 1),  // +7.072273168356953965e-01
        FLR::scaled( 0x16D7A248EA025D, -52 - 1),  // +7.138225006202209011e-01
        FLR::scaled( 0x16D7A248EA025D, -52 - 1),  // +7.138225006202209011e-01
        FLR::scaled( 0x16D7FDF963A193, -52 - 1),  // +7.138662215120795684e-01
        FLR::scaled( 0x16D7FDF963A193, -52 - 1),  // +7.138662215120795684e-01
        FLR::scaled( 0x16DD2C280BC024, -52 - 1),  // +7.144985944887634055e-01
        FLR::scaled( 0x16DD2C280BC024, -52 - 1),  // +7.144985944887634055e-01
        FLR::scaled( 0x16DD82F7D50A2A, -52 - 1),  // +7.145399895164861181e-01
        FLR::scaled( 0x16DD82F7D50A2A, -52 - 1),  // +7.145399895164861181e-01
        FLR::scaled( 0x16FAD4502AD8A1, -52 - 1),  // +7.181188169258981846e-01
        FLR::scaled( 0x16FAD4502AD8A1, -52 - 1),  // +7.181188169258981846e-01
        FLR::scaled( 0x16FB5AD5972376, -52 - 1),  // +7.181829616248325276e-01
        FLR::scaled( 0x16FB5AD5972376, -52 - 1),  // +7.181829616248325276e-01
        FLR::scaled( 0x16FE704FD472EB, -52 - 1),  // +7.185594138314547186e-01
        FLR::scaled( 0x16FE704FD472EB, -52 - 1),  // +7.185594138314547186e-01
        FLR::scaled( 0x16FEFB8EE4B98A, -52 - 1),  // +7.186258116615118485e-01
        FLR::scaled( 0x16FEFB8EE4B98A, -52 - 1),  // +7.186258116615118485e-01
        FLR::scaled( 0x172BB4E09B59D8, -52 - 1),  // +7.240852724888169334e-01
        FLR::scaled( 0x172BB4E09B59D8, -52 - 1),  // +7.240852724888169334e-01
        FLR::scaled( 0x172DD4DE7E346F, -52 - 1),  // +7.243446679655231035e-01
        FLR::scaled( 0x172DD4DE7E346F, -52 - 1),  // +7.243446679655231035e-01
        FLR::scaled( 0x173263F2A6AAA5, -52 - 1),  // +7.249011744764471965e-01
        FLR::scaled( 0x173263F2A6AAA5, -52 - 1),  // +7.249011744764471965e-01
        FLR::scaled( 0x1734C25BD5D816, -52 - 1),  // +7.251903337153204898e-01
        FLR::scaled( 0x1734C25BD5D816, -52 - 1),  // +7.251903337153204898e-01
        FLR::scaled( 0x173BCD1FA3F297, -52 - 1),  // +7.260499589898071759e-01
        FLR::scaled( 0x173BCD1FA3F297, -52 - 1),  // +7.260499589898071759e-01
        FLR::scaled( 0x173BD0F1ACF3D7, -52 - 1),  // +7.260517807222822695e-01
        FLR::scaled( 0x173BD0F1ACF3D7, -52 - 1),  // +7.260517807222822695e-01
        FLR::scaled( 0x1740307877C214, -52 - 1),  // +7.265856125723666459e-01
        FLR::scaled( 0x1740307877C214, -52 - 1),  // +7.265856125723666459e-01
        FLR::scaled( 0x1740356F213622, -52 - 1),  // +7.265879793646414786e-01
        FLR::scaled( 0x1740356F213622, -52 - 1),  // +7.265879793646414786e-01
        FLR::scaled( 0x1774C5E5198360, -52 - 1),  // +7.330045199015380319e-01
        FLR::scaled( 0x1774C5E5198360, -52 - 1),  // +7.330045199015380319e-01
        FLR::scaled( 0x17756D4775F852, -52 - 1),  // +7.330843349188944646e-01
        FLR::scaled( 0x17756D4775F852, -52 - 1),  // +7.330843349188944646e-01
        FLR::scaled( 0x177CCCF23AD938, -52 - 1),  // +7.339844447185788212e-01
        FLR::scaled( 0x177CCCF23AD938, -52 - 1),  // +7.339844447185788212e-01
        FLR::scaled( 0x177DA323D689E6, -52 - 1),  // +7.340865802728415712e-01
        FLR::scaled( 0x177DA323D689E6, -52 - 1),  // +7.340865802728415712e-01
        FLR::scaled( 0x1777D4479E7CCE, -52 - 1),  // +7.333775900659931235e-01
        FLR::scaled( 0x1777D4479E7CCE, -52 - 1),  // +7.333775900659931235e-01
        FLR::scaled( 0x17784DE2488DB5, -52 - 1),  // +7.334355754468818711e-01
        FLR::scaled( 0x17784DE2488DB5, -52 - 1),  // +7.334355754468818711e-01
        FLR::scaled( 0x177D2B5FBEE55C, -52 - 1),  // +7.340294714005426435e-01
        FLR::scaled( 0x177D2B5FBEE55C, -52 - 1),  // +7.340294714005426435e-01
        FLR::scaled( 0x177D9BC2DF4C93, -52 - 1),  // +7.340830617998953533e-01
        FLR::scaled( 0x177D9BC2DF4C93, -52 - 1),  // +7.340830617998953533e-01
        FLR::scaled( 0x17B638785004B3, -52 - 1),  // +7.409937238554874517e-01
        FLR::scaled( 0x17B638785004B3, -52 - 1),  // +7.409937238554874517e-01
        FLR::scaled( 0x17B8962765B4EC, -52 - 1),  // +7.412825364569051168e-01
        FLR::scaled( 0x17B8962765B4EC, -52 - 1),  // +7.412825364569051168e-01
        FLR::scaled( 0x17BF0FB48A4C66, -52 - 1),  // +7.420729185272534334e-01
        FLR::scaled( 0x17BF0FB48A4C66, -52 - 1),  // +7.420729185272534334e-01
        FLR::scaled( 0x17C1A0AB55CD19, -52 - 1),  // +7.423861833944186417e-01
        FLR::scaled( 0x17C1A0AB55CD19, -52 - 1),  // +7.423861833944186417e-01
        FLR::scaled( 0x17D8B7B6C37635, -52 - 1),  // +7.452047891235397126e-01
        FLR::scaled( 0x17D8B7B6C37635, -52 - 1),  // +7.452047891235397126e-01
        FLR::scaled( 0x17D8B8B1FCE8CF, -52 - 1),  // +7.452052570654589259e-01
        FLR::scaled( 0x17D8B8B1FCE8CF, -52 - 1),  // +7.452052570654589259e-01
        FLR::scaled( 0x17E14C5A15FF23, -52 - 1),  // +7.462522277346333999e-01
        FLR::scaled( 0x17E14C5A15FF23, -52 - 1),  // +7.462522277346333999e-01
        FLR::scaled( 0x17E14C6A922F8F, -52 - 1),  // +7.462522584405507642e-01
        FLR::scaled( 0x17E14C6A922F8F, -52 - 1),  // +7.462522584405507642e-01
        FLR::scaled( 0x18273281C922BB, -52 - 1),  // +7.547848257900889868e-01
        FLR::scaled( 0x18273281C922BB, -52 - 1),  // +7.547848257900889868e-01
        FLR::scaled( 0x182808EFC486FF, -52 - 1),  // +7.548870737993808033e-01
        FLR::scaled( 0x182808EFC486FF, -52 - 1),  // +7.548870737993808033e-01
        FLR::scaled( 0x183512E5FBE10C, -52 - 1),  // +7.564787380097484082e-01
        FLR::scaled( 0x183512E5FBE10C, -52 - 1),  // +7.564787380097484082e-01
        FLR::scaled( 0x18361D49D1D960, -52 - 1),  // +7.566057626525370949e-01
        FLR::scaled( 0x18361D49D1D960, -52 - 1),  // +7.566057626525370949e-01
        FLR::scaled( 0x12EBF3EA927C1E, -52 - 1),  // +5.913028317917257137e-01
        FLR::scaled( 0x12EBF3EA927C1E, -52 - 1),  // +5.913028317917257137e-01
        FLR::scaled( 0x12ECC423F53399, -52 - 1),  // +5.914021208096641447e-01
        FLR::scaled( 0x12ECC423F53399, -52 - 1),  // +5.914021208096641447e-01
        FLR::scaled( 0x12F6FB343A8A4C, -52 - 1),  // +5.926490802851929196e-01
        FLR::scaled( 0x12F6FB343A8A4C, -52 - 1),  // +5.926490802851929196e-01
        FLR::scaled( 0x12F7A3926770CF, -52 - 1),  // +5.927293643431087444e-01
        FLR::scaled( 0x12F7A3926770CF, -52 - 1),  // +5.927293643431087444e-01
        FLR::scaled( 0x132F2865AFC2E7, -52 - 1),  // +5.995065675798202376e-01
        FLR::scaled( 0x132F2865AFC2E7, -52 - 1),  // +5.995065675798202376e-01
        FLR::scaled( 0x132F2872EE13E2, -52 - 1),  // +5.995065922476181530e-01
        FLR::scaled( 0x132F2872EE13E2, -52 - 1),  // +5.995065922476181530e-01
        FLR::scaled( 0x13360ED27AD8FD, -52 - 1),  // +6.003488646445301891e-01
        FLR::scaled( 0x13360ED27AD8FD, -52 - 1),  // +6.003488646445301891e-01
        FLR::scaled( 0x13360F9CDEC971, -52 - 1),  // +6.003492416260042264e-01
        FLR::scaled( 0x13360F9CDEC971, -52 - 1),  // +6.003492416260042264e-01
        FLR::scaled( 0x1348BBBA410A4A, -52 - 1),  // +6.026285779738114190e-01
        FLR::scaled( 0x1348BBBA410A4A, -52 - 1),  // +6.026285779738114190e-01
        FLR::scaled( 0x134AD13D7F9F80, -52 - 1),  // +6.028829766409984359e-01
        FLR::scaled( 0x134AD13D7F9F80, -52 - 1),  // +6.028829766409984359e-01
        FLR::scaled( 0x135015526F8A03, -52 - 1),  // +6.035257921287783267e-01
        FLR::scaled( 0x135015526F8A03, -52 - 1),  // +6.035257921287783267e-01
        FLR::scaled( 0x135202A3F50BD7, -52 - 1),  // +6.037610246934218550e-01
        FLR::scaled( 0x135202A3F50BD7, -52 - 1),  // +6.037610246934218550e-01
        FLR::scaled( 0x13809274099772, -52 - 1),  // +6.094448343617229202e-01
        FLR::scaled( 0x13809274099772, -52 - 1),  // +6.094448343617229202e-01
        FLR::scaled( 0x1380EFC3ED2716, -52 - 1),  // +6.094893290221274906e-01
        FLR::scaled( 0x1380EFC3ED2716, -52 - 1),  // +6.094893290221274906e-01
        FLR::scaled( 0x1384FAC6674A50, -52 - 1),  // +6.099828600948260515e-01
        FLR::scaled( 0x1384FAC6674A50, -52 - 1),  // +6.099828600948260515e-01
        FLR::scaled( 0x13855FEB2A7441, -52 - 1),  // +6.100310891230337207e-01
        FLR::scaled( 0x13855FEB2A7441, -52 - 1),  // +6.100310891230337207e-01
        FLR::scaled( 0x13808C53CD5F72, -52 - 1),  // +6.094419132959798535e-01
        FLR::scaled( 0x13808C53CD5F72, -52 - 1),  // +6.094419132959798535e-01
        FLR::scaled( 0x13813E2D3D6EB7, -52 - 1),  // +6.095267184823204287e-01
        FLR::scaled( 0x13813E2D3D6EB7, -52 - 1),  // +6.095267184823204287e-01
        FLR::scaled( 0x13875FAFE93D5D, -52 - 1),  // +6.102751193774725857e-01
        FLR::scaled( 0x13875FAFE93D5D, -52 - 1),  // +6.102751193774725857e-01
        FLR::scaled( 0x1387EB0BB15DF8, -52 - 1),  // +6.103415706992896261e-01
        FLR::scaled( 0x1387EB0BB15DF8, -52 - 1),  // +6.103415706992896261e-01
        FLR::scaled( 0x13B4129D61FE1C, -52 - 1),  // +6.157315324671261969e-01
        FLR::scaled( 0x13B4129D61FE1C, -52 - 1),  // +6.157315324671261969e-01
        FLR::scaled( 0x13B416D22E8547, -52 - 1),  // +6.157335381614438274e-01
        FLR::scaled( 0x13B416D22E8547, -52 - 1),  // +6.157335381614438274e-01
        FLR::scaled( 0x13B7CC3E63BEB9, -52 - 1),  // +6.161862581775131575e-01
        FLR::scaled( 0x13B7CC3E63BEB9, -52 - 1),  // +6.161862581775131575e-01
        FLR::scaled( 0x13B7CF7C6E73F4, -52 - 1),  // +6.161878042508974751e-01
        FLR::scaled( 0x13B7CF7C6E73F4, -52 - 1),  // +6.161878042508974751e-01
        FLR::scaled( 0x13BDCB4786BCB2, -52 - 1),  // +6.169182202337621934e-01
        FLR::scaled( 0x13BDCB4786BCB2, -52 - 1),  // +6.169182202337621934e-01
        FLR::scaled( 0x13BFCF5BA00152, -52 - 1),  // +6.171643056441473707e-01
        FLR::scaled( 0x13BFCF5BA00152, -52 - 1),  // +6.171643056441473707e-01
        FLR::scaled( 0x13C3B1BED877CA, -52 - 1),  // +6.176384665920917616e-01
        FLR::scaled( 0x13C3B1BED877CA, -52 - 1),  // +6.176384665920917616e-01
        FLR::scaled( 0x13C581C4074575, -52 - 1),  // +6.178597286872632433e-01
        FLR::scaled( 0x13C581C4074575, -52 - 1),  // +6.178597286872632433e-01
        FLR::scaled( 0x13EBF5A7CCE527, -52 - 1),  // +6.225536610938079418e-01
        FLR::scaled( 0x13EBF5A7CCE527, -52 - 1),  // +6.225536610938079418e-01
        FLR::scaled( 0x13EC6E4C1BA174, -52 - 1),  // +6.226111875994733147e-01
        FLR::scaled( 0x13EC6E4C1BA174, -52 - 1),  // +6.226111875994733147e-01
        FLR::scaled( 0x13EF1AB72DC67F, -52 - 1),  // +6.229375436507352815e-01
        FLR::scaled( 0x13EF1AB72DC67F, -52 - 1),  // +6.229375436507352815e-01
        FLR::scaled( 0x13EF8F682DE093, -52 - 1),  // +6.229931864500194427e-01
        FLR::scaled( 0x13EF8F682DE093, -52 - 1),  // +6.229931864500194427e-01
        FLR::scaled( 0x14091F2AF73662, -52 - 1),  // +6.261134947942077478e-01
        FLR::scaled( 0x14091F2AF73662, -52 - 1),  // +6.261134947942077478e-01
        FLR::scaled( 0x14096B3D9E7D1E, -52 - 1),  // +6.261497691629391849e-01
        FLR::scaled( 0x14096B3D9E7D1E, -52 - 1),  // +6.261497691629391849e-01
        FLR::scaled( 0x140DF677D1F27A, -52 - 1),  // +6.267044391857574670e-01
        FLR::scaled( 0x140DF677D1F27A, -52 - 1),  // +6.267044391857574670e-01
        FLR::scaled( 0x140E46F79C3D36, -52 - 1),  // +6.267428241862151861e-01
        FLR::scaled( 0x140E46F79C3D36, -52 - 1),  // +6.267428241862151861e-01
        FLR::scaled( 0x143E280D0E89C7, -52 - 1),  // +6.325874571814943392e-01
        FLR::scaled( 0x143E280D0E89C7, -52 - 1),  // +6.325874571814943392e-01
        FLR::scaled( 0x143E448F114836, -52 - 1),  // +6.326010507857577903e-01
        FLR::scaled( 0x143E448F114836, -52 - 1),  // +6.326010507857577903e-01
        FLR::scaled( 0x1444EDBF3F30DB, -52 - 1),  // +6.334141478814915294e-01
        FLR::scaled( 0x1444EDBF3F30DB, -52 - 1),  // +6.334141478814915294e-01
        FLR::scaled( 0x1445175CADCAA6, -52 - 1),  // +6.334339914449926834e-01
        FLR::scaled( 0x1445175CADCAA6, -52 - 1),  // +6.334339914449926834e-01
        FLR::scaled( 0x1451092DC81CBB, -52 - 1),  // +6.348920721219636354e-01
        FLR::scaled( 0x1451092DC81CBB, -52 - 1),  // +6.348920721219636354e-01
        FLR::scaled( 0x14537825E63CD1, -52 - 1),  // +6.351891269895536540e-01
        FLR::scaled( 0x14537825E63CD1, -52 - 1),  // +6.351891269895536540e-01
        FLR::scaled( 0x14568771C0824F, -52 - 1),  // +6.355626317709467399e-01
        FLR::scaled( 0x14568771C0824F, -52 - 1),  // +6.355626317709467399e-01
        FLR::scaled( 0x14591B39340520, -52 - 1),  // +6.358772389650404477e-01
        FLR::scaled( 0x14591B39340520, -52 - 1),  // +6.358772389650404477e-01
        FLR::scaled( 0x147DE58FC610FA, -52 - 1),  // +6.403682525711069662e-01
        FLR::scaled( 0x147DE58FC610FA, -52 - 1),  // +6.403682525711069662e-01
        FLR::scaled( 0x147F303DF8AABD, -52 - 1),  // +6.405259333017380152e-01
        FLR::scaled( 0x147F303DF8AABD, -52 - 1),  // +6.405259333017380152e-01
        FLR::scaled( 0x1484811BF25C5F, -52 - 1),  // +6.411748452982343194e-01
        FLR::scaled( 0x1484811BF25C5F, -52 - 1),  // +6.411748452982343194e-01
        FLR::scaled( 0x1485FBAB1C9AA7, -52 - 1),  // +6.413553564096518000e-01
        FLR::scaled( 0x1485FBAB1C9AA7, -52 - 1),  // +6.413553564096518000e-01
        FLR::scaled( 0x146BA96690DCD7, -52 - 1),  // +6.381422999610560920e-01
        FLR::scaled( 0x146BA96690DCD7, -52 - 1),  // +6.381422999610560920e-01
        FLR::scaled( 0x146C8BFB8F94AE, -52 - 1),  // +6.382503426836103610e-01
        FLR::scaled( 0x146C8BFB8F94AE, -52 - 1),  // +6.382503426836103610e-01
        FLR::scaled( 0x1470C6B4183C61, -52 - 1),  // +6.387666242097901348e-01
        FLR::scaled( 0x1470C6B4183C61, -52 - 1),  // +6.387666242097901348e-01
        FLR::scaled( 0x14718EFCA811C4, -52 - 1),  // +6.388621267984082586e-01
        FLR::scaled( 0x14718EFCA811C4, -52 - 1),  // +6.388621267984082586e-01
        FLR::scaled( 0x149E52E5A3C252, -52 - 1),  // +6.443266377592158367e-01
        FLR::scaled( 0x149E52E5A3C252, -52 - 1),  // +6.443266377592158367e-01
        FLR::scaled( 0x149EB9858A865B, -52 - 1),  // +6.443755729889731887e-01
        FLR::scaled( 0x149EB9858A865B, -52 - 1),  // +6.443755729889731887e-01
        FLR::scaled( 0x14A3DF23AA38A8, -52 - 1),  // +6.450038620548825818e-01
        FLR::scaled( 0x14A3DF23AA38A8, -52 - 1),  // +6.450038620548825818e-01
        FLR::scaled( 0x14A440D5689BBE, -52 - 1),  // +6.450504463326678373e-01
        FLR::scaled( 0x14A440D5689BBE, -52 - 1),  // +6.450504463326678373e-01
        FLR::scaled( 0x14A2B08EA88968, -52 - 1),  // +6.448595796867211405e-01
        FLR::scaled( 0x14A2B08EA88968, -52 - 1),  // +6.448595796867211405e-01
        FLR::scaled( 0x14A5A6913B54FD, -52 - 1),  // +6.452210270460053687e-01
        FLR::scaled( 0x14A5A6913B54FD, -52 - 1),  // +6.452210270460053687e-01
        FLR::scaled( 0x14A87A1AC8D7AB, -52 - 1),  // +6.455660365233958364e-01
        FLR::scaled( 0x14A87A1AC8D7AB, -52 - 1),  // +6.455660365233958364e-01
        FLR::scaled( 0x14AB5D18BDC02A, -52 - 1),  // +6.459184153773140924e-01
        FLR::scaled( 0x14AB5D18BDC02A, -52 - 1),  // +6.459184153773140924e-01
        FLR::scaled( 0x14CE7333093AC8, -52 - 1),  // +6.502014157102502523e-01
        FLR::scaled( 0x14CE7333093AC8, -52 - 1),  // +6.502014157102502523e-01
        FLR::scaled( 0x14D0090C4E7C1F, -52 - 1),  // +6.503949394572180465e-01
        FLR::scaled( 0x14D0090C4E7C1F, -52 - 1),  // +6.503949394572180465e-01
        FLR::scaled( 0x14D45E7795BADF, -52 - 1),  // +6.509239516870727327e-01
        FLR::scaled( 0x14D45E7795BADF, -52 - 1),  // +6.509239516870727327e-01
        FLR::scaled( 0x14D5FA83F90D4D, -52 - 1),  // +6.511204316706568074e-01
        FLR::scaled( 0x14D5FA83F90D4D, -52 - 1),  // +6.511204316706568074e-01
        FLR::scaled( 0x15197D2CBD5754, -52 - 1),  // +6.593614457912999605e-01
        FLR::scaled( 0x15197D2CBD5754, -52 - 1),  // +6.593614457912999605e-01
        FLR::scaled( 0x15225026BA9DD9, -52 - 1),  // +6.604386097359863372e-01
        FLR::scaled( 0x15225026BA9DD9, -52 - 1),  // +6.604386097359863372e-01
        FLR::scaled( 0x151E2D25D3B0D6, -52 - 1),  // +6.599336375052426984e-01
        FLR::scaled( 0x151E2D25D3B0D6, -52 - 1),  // +6.599336375052426984e-01
        FLR::scaled( 0x15275483139C89, -52 - 1),  // +6.610510406579958032e-01
        FLR::scaled( 0x15275483139C89, -52 - 1),  // +6.610510406579958032e-01
        FLR::scaled( 0x1541A0789E64C0, -52 - 1),  // +6.642610889276951980e-01
        FLR::scaled( 0x1541A0789E64C0, -52 - 1),  // +6.642610889276951980e-01
        FLR::scaled( 0x154820FB07759F, -52 - 1),  // +6.650547888672696528e-01
        FLR::scaled( 0x154820FB07759F, -52 - 1),  // +6.650547888672696528e-01
        FLR::scaled( 0x1544DB6CAE2D5F, -52 - 1),  // +6.646554110206287502e-01
        FLR::scaled( 0x1544DB6CAE2D5F, -52 - 1),  // +6.646554110206287502e-01
        FLR::scaled( 0x154BAC6693158D, -52 - 1),  // +6.654874804886944384e-01
        FLR::scaled( 0x154BAC6693158D, -52 - 1),  // +6.654874804886944384e-01
        FLR::scaled( 0x153F927ADA498D, -52 - 1),  // +6.640102767435550613e-01
        FLR::scaled( 0x153F927ADA498D, -52 - 1),  // +6.640102767435550613e-01
        FLR::scaled( 0x1549A9CD688629, -52 - 1),  // +6.652421008950045733e-01
        FLR::scaled( 0x1549A9CD688629, -52 - 1),  // +6.652421008950045733e-01
        FLR::scaled( 0x1543C172D52EEE, -52 - 1),  // +6.645209544016930092e-01
        FLR::scaled( 0x1543C172D52EEE, -52 - 1),  // +6.645209544016930092e-01
        FLR::scaled( 0x154E328F25BBEC, -52 - 1),  // +6.657955928657179889e-01
        FLR::scaled( 0x154E328F25BBEC, -52 - 1),  // +6.657955928657179889e-01
        FLR::scaled( 0x1566F252693941, -52 - 1),  // +6.688167199697901966e-01
        FLR::scaled( 0x1566F252693941, -52 - 1),  // +6.688167199697901966e-01
        FLR::scaled( 0x156E92A8E2322C, -52 - 1),  // +6.697476671702751183e-01
        FLR::scaled( 0x156E92A8E2322C, -52 - 1),  // +6.697476671702751183e-01
        FLR::scaled( 0x156A15CECF87A6, -52 - 1),  // +6.691998519202015938e-01
        FLR::scaled( 0x156A15CECF87A6, -52 - 1),  // +6.691998519202015938e-01
        FLR::scaled( 0x15720DF6DC8836, -52 - 1),  // +6.701726743233453742e-01
        FLR::scaled( 0x15720DF6DC8836, -52 - 1),  // +6.701726743233453742e-01
        FLR::scaled( 0x1558F498659FAB, -52 - 1),  // +6.671088196280740013e-01
        FLR::scaled( 0x1558F498659FAB, -52 - 1),  // +6.671088196280740013e-01
        FLR::scaled( 0x155F838F44A8DF, -52 - 1),  // +6.679094122130456723e-01
        FLR::scaled( 0x155F838F44A8DF, -52 - 1),  // +6.679094122130456723e-01
        FLR::scaled( 0x155C8DD10A9A7D, -52 - 1),  // +6.675480921592932271e-01
        FLR::scaled( 0x155C8DD10A9A7D, -52 - 1),  // +6.675480921592932271e-01
        FLR::scaled( 0x156334AC9C35F0, -52 - 1),  // +6.683600779812746140e-01
        FLR::scaled( 0x156334AC9C35F0, -52 - 1),  // +6.683600779812746140e-01
        FLR::scaled( 0x157AE0AF801025, -52 - 1),  // +6.712497165431200452e-01
        FLR::scaled( 0x157AE0AF801025, -52 - 1),  // +6.712497165431200452e-01
        FLR::scaled( 0x157FB941E901FC, -52 - 1),  // +6.718412673290568016e-01
        FLR::scaled( 0x157FB941E901FC, -52 - 1),  // +6.718412673290568016e-01
        FLR::scaled( 0x157D1B7D1D255C, -52 - 1),  // +6.715218967084797264e-01
        FLR::scaled( 0x157D1B7D1D255C, -52 - 1),  // +6.715218967084797264e-01
        FLR::scaled( 0x158216A6A7CA74, -52 - 1),  // +6.721299414624142265e-01
        FLR::scaled( 0x158216A6A7CA74, -52 - 1),  // +6.721299414624142265e-01
        FLR::scaled( 0x157B5A68C19A1D, -52 - 1),  // +6.713077589054737837e-01
        FLR::scaled( 0x157B5A68C19A1D, -52 - 1),  // +6.713077589054737837e-01
        FLR::scaled( 0x15837169D51397, -52 - 1),  // +6.722952906644533710e-01
        FLR::scaled( 0x15837169D51397, -52 - 1),  // +6.722952906644533710e-01
        FLR::scaled( 0x157E9C7C276910, -52 - 1),  // +6.717054772264265949e-01
        FLR::scaled( 0x157E9C7C276910, -52 - 1),  // +6.717054772264265949e-01
        FLR::scaled( 0x1586CA8125ECB3, -52 - 1),  // +6.727039835381191102e-01
        FLR::scaled( 0x1586CA8125ECB3, -52 - 1),  // +6.727039835381191102e-01
        FLR::scaled( 0x159DB1C1FAF154, -52 - 1),  // +6.754998005558641161e-01
        FLR::scaled( 0x159DB1C1FAF154, -52 - 1),  // +6.754998005558641161e-01
        FLR::scaled( 0x15A3DEFF8199CC, -52 - 1),  // +6.762537947041038500e-01
        FLR::scaled( 0x15A3DEFF8199CC, -52 - 1),  // +6.762537947041038500e-01
        FLR::scaled( 0x159FC66185E3AD, -52 - 1),  // +6.757537750955769917e-01
        FLR::scaled( 0x159FC66185E3AD, -52 - 1),  // +6.757537750955769917e-01
        FLR::scaled( 0x15A619AC2DABBD, -52 - 1),  // +6.765259135112199340e-01
        FLR::scaled( 0x15A619AC2DABBD, -52 - 1),  // +6.765259135112199340e-01
        FLR::scaled( 0x161DAD4A65C66E, -52 - 1),  // +6.911226704671216137e-01
        FLR::scaled( 0x161DAD4A65C66E, -52 - 1),  // +6.911226704671216137e-01
        FLR::scaled( 0x1627ACB31F8F9E, -52 - 1),  // +6.923430918218291819e-01
        FLR::scaled( 0x1627ACB31F8F9E, -52 - 1),  // +6.923430918218291819e-01
        FLR::scaled( 0x161DB820BDC3BC, -52 - 1),  // +6.911278380849732450e-01
        FLR::scaled( 0x161DB820BDC3BC, -52 - 1),  // +6.911278380849732450e-01
        FLR::scaled( 0x1627B738DAD0BB, -52 - 1),  // +6.923481092876707654e-01
        FLR::scaled( 0x1627B738DAD0BB, -52 - 1),  // +6.923481092876707654e-01
        FLR::scaled( 0x163CB739984614, -52 - 1),  // +6.949115872286619755e-01
        FLR::scaled( 0x163CB739984614, -52 - 1),  // +6.949115872286619755e-01
        FLR::scaled( 0x16453681663AD4, -52 - 1),  // +6.959488417940868921e-01
        FLR::scaled( 0x16453681663AD4, -52 - 1),  // +6.959488417940868921e-01
        FLR::scaled( 0x163CBCB70BB6AE, -52 - 1),  // +6.949142050850320995e-01
        FLR::scaled( 0x163CBCB70BB6AE, -52 - 1),  // +6.949142050850320995e-01
        FLR::scaled( 0x16453BEF80B71E, -52 - 1),  // +6.959514310635517287e-01
        FLR::scaled( 0x16453BEF80B71E, -52 - 1),  // +6.959514310635517287e-01
        FLR::scaled( 0x1650E2EF808AD4, -52 - 1),  // +6.973738363052128797e-01
        FLR::scaled( 0x1650E2EF808AD4, -52 - 1),  // +6.973738363052128797e-01
        FLR::scaled( 0x165DD8FEAF51E6, -52 - 1),  // +6.989560102761600557e-01
        FLR::scaled( 0x165DD8FEAF51E6, -52 - 1),  // +6.989560102761600557e-01
        FLR::scaled( 0x1650F9C24B8548, -52 - 1),  // +6.973847193550364310e-01
        FLR::scaled( 0x1650F9C24B8548, -52 - 1),  // +6.973847193550364310e-01
        FLR::scaled( 0x165DF245C10D55, -52 - 1),  // +6.989680635819391918e-01
        FLR::scaled( 0x165DF245C10D55, -52 - 1),  // +6.989680635819391918e-01
        FLR::scaled( 0x166D22C9159F9A, -52 - 1),  // +7.008222510748851608e-01
        FLR::scaled( 0x166D22C9159F9A, -52 - 1),  // +7.008222510748851608e-01
        FLR::scaled( 0x1677F6EF271D70, -52 - 1),  // +7.021441145852076460e-01
        FLR::scaled( 0x1677F6EF271D70, -52 - 1),  // +7.021441145852076460e-01
        FLR::scaled( 0x166D511446EDBB, -52 - 1),  // +7.008443256412911770e-01
        FLR::scaled( 0x166D511446EDBB, -52 - 1),  // +7.008443256412911770e-01
        FLR::scaled( 0x16782A00D236DD, -52 - 1),  // +7.021684661901549385e-01
        FLR::scaled( 0x16782A00D236DD, -52 - 1),  // +7.021684661901549385e-01
        FLR::scaled( 0x164E3FB75D6B50, -52 - 1),  // +6.970518666597431690e-01
        FLR::scaled( 0x164E3FB75D6B50, -52 - 1),  // +6.970518666597431690e-01
        FLR::scaled( 0x1655213D3E7FAE, -52 - 1),  // +6.978918262648130533e-01
        FLR::scaled( 0x1655213D3E7FAE, -52 - 1),  // +6.978918262648130533e-01
        FLR::scaled( 0x164ED3EA84DCD7, -52 - 1),  // +6.971225338410488304e-01
        FLR::scaled( 0x164ED3EA84DCD7, -52 - 1),  // +6.971225338410488304e-01
        FLR::scaled( 0x1655A7F12C258A, -52 - 1),  // +6.979560575866099459e-01
        FLR::scaled( 0x1655A7F12C258A, -52 - 1),  // +6.979560575866099459e-01
        FLR::scaled( 0x166B62A3507F0C, -52 - 1),  // +7.006085576758507294e-01
        FLR::scaled( 0x166B62A3507F0C, -52 - 1),  // +7.006085576758507294e-01
        FLR::scaled( 0x16710C665EAA5B, -52 - 1),  // +7.012998580369854684e-01
        FLR::scaled( 0x16710C665EAA5B, -52 - 1),  // +7.012998580369854684e-01
        FLR::scaled( 0x166BE73DAEFE8B, -52 - 1),  // +7.006717877156501961e-01
        FLR::scaled( 0x166BE73DAEFE8B, -52 - 1),  // +7.006717877156501961e-01
        FLR::scaled( 0x167188D8215097, -52 - 1),  // +7.013591977397649613e-01
        FLR::scaled( 0x167188D8215097, -52 - 1),  // +7.013591977397649613e-01
        FLR::scaled( 0x167DE61F0C7628, -52 - 1),  // +7.028685194415560389e-01
        FLR::scaled( 0x167DE61F0C7628, -52 - 1),  // +7.028685194415560389e-01
        FLR::scaled( 0x16871C47E86A54, -52 - 1),  // +7.039929775667794765e-01
        FLR::scaled( 0x16871C47E86A54, -52 - 1),  // +7.039929775667794765e-01
        FLR::scaled( 0x167E4F8DEB92BE, -52 - 1),  // +7.029187938574847916e-01
        FLR::scaled( 0x167E4F8DEB92BE, -52 - 1),  // +7.029187938574847916e-01
        FLR::scaled( 0x168783E12D3E91, -52 - 1),  // +7.040423772795795232e-01
        FLR::scaled( 0x168783E12D3E91, -52 - 1),  // +7.040423772795795232e-01
        FLR::scaled( 0x169863AE6D373A, -52 - 1),  // +7.061022192735670888e-01
        FLR::scaled( 0x169863AE6D373A, -52 - 1),  // +7.061022192735670888e-01
        FLR::scaled( 0x169FEB581A94C5, -52 - 1),  // +7.070214005258540491e-01
        FLR::scaled( 0x169FEB581A94C5, -52 - 1),  // +7.070214005258540491e-01
        FLR::scaled( 0x1698D4C472FBF5, -52 - 1),  // +7.061561428926085293e-01
        FLR::scaled( 0x1698D4C472FBF5, -52 - 1),  // +7.061561428926085293e-01
        FLR::scaled( 0x16A05F9344EADC, -52 - 1),  // +7.070768238403064565e-01
        FLR::scaled( 0x16A05F9344EADC, -52 - 1),  // +7.070768238403064565e-01
        FLR::scaled( 0x16120E16FD5E00, -52 - 1),  // +6.897039841668970439e-01
        FLR::scaled( 0x16120E16FD5E00, -52 - 1),  // +6.897039841668970439e-01
        FLR::scaled( 0x161579962964FC, -52 - 1),  // +6.901214535565993735e-01
        FLR::scaled( 0x161579962964FC, -52 - 1),  // +6.901214535565993735e-01
        FLR::scaled( 0x16186A9ED99AFE, -52 - 1),  // +6.904805281199910549e-01
        FLR::scaled( 0x16186A9ED99AFE, -52 - 1),  // +6.904805281199910549e-01
        FLR::scaled( 0x161BDE4A854C47, -52 - 1),  // +6.909018950922324320e-01
        FLR::scaled( 0x161BDE4A854C47, -52 - 1),  // +6.909018950922324320e-01
        FLR::scaled( 0x163E69F03D408B, -52 - 1),  // +6.951188747571149795e-01
        FLR::scaled( 0x163E69F03D408B, -52 - 1),  // +6.951188747571149795e-01
        FLR::scaled( 0x164211DAF55B28, -52 - 1),  // +6.955651546985324174e-01
        FLR::scaled( 0x164211DAF55B28, -52 - 1),  // +6.955651546985324174e-01
        FLR::scaled( 0x164297C348D485, -52 - 1),  // +6.956290067816018885e-01
        FLR::scaled( 0x164297C348D485, -52 - 1),  // +6.956290067816018885e-01
        FLR::scaled( 0x164631EB4DDF34, -52 - 1),  // +6.960687251839545731e-01
        FLR::scaled( 0x164631EB4DDF34, -52 - 1),  // +6.960687251839545731e-01
        FLR::scaled( 0x164D1C38186630, -52 - 1),  // +6.969128699885853706e-01
        FLR::scaled( 0x164D1C38186630, -52 - 1),  // +6.969128699885853706e-01
        FLR::scaled( 0x16544FE7831BC4, -52 - 1),  // +6.977920076104671132e-01
        FLR::scaled( 0x16544FE7831BC4, -52 - 1),  // +6.977920076104671132e-01
        FLR::scaled( 0x1651180AD43D7C, -52 - 1),  // +6.973991595749988726e-01
        FLR::scaled( 0x1651180AD43D7C, -52 - 1),  // +6.973991595749988726e-01
        FLR::scaled( 0x1658223812D8FD, -52 - 1),  // +6.982585044086416781e-01
        FLR::scaled( 0x1658223812D8FD, -52 - 1),  // +6.982585044086416781e-01
        FLR::scaled( 0x1674518B53B136, -52 - 1),  // +7.016990395764313160e-01
        FLR::scaled( 0x1674518B53B136, -52 - 1),  // +7.016990395764313160e-01
        FLR::scaled( 0x167B4EFC54E94D, -52 - 1),  // +7.025523117402286966e-01
        FLR::scaled( 0x167B4EFC54E94D, -52 - 1),  // +7.025523117402286966e-01
        FLR::scaled( 0x16773B211FD248, -52 - 1),  // +7.020545622786551476e-01
        FLR::scaled( 0x16773B211FD248, -52 - 1),  // +7.020545622786551476e-01
        FLR::scaled( 0x167E0A613C750D, -52 - 1),  // +7.028858088630457468e-01
        FLR::scaled( 0x167E0A613C750D, -52 - 1),  // +7.028858088630457468e-01
        FLR::scaled( 0x1651183ED976CF, -52 - 1),  // +6.973992564705556729e-01
        FLR::scaled( 0x1651183ED976CF, -52 - 1),  // +6.973992564705556729e-01
        FLR::scaled( 0x16541FF549D2DF, -52 - 1),  // +6.977691450871040812e-01
        FLR::scaled( 0x16541FF549D2DF, -52 - 1),  // +6.977691450871040812e-01
        FLR::scaled( 0x16581E6538119F, -52 - 1),  // +6.982566811498606141e-01
        FLR::scaled( 0x16581E6538119F, -52 - 1),  // +6.982566811498606141e-01
        FLR::scaled( 0x165B23311B9312, -52 - 1),  // +6.986251792082802670e-01
        FLR::scaled( 0x165B23311B9312, -52 - 1),  // +6.986251792082802670e-01
        FLR::scaled( 0x16790054141ABC, -52 - 1),  // +7.022706644209715243e-01
        FLR::scaled( 0x16790054141ABC, -52 - 1),  // +7.022706644209715243e-01
        FLR::scaled( 0x167C343C1399BB, -52 - 1),  // +7.026616261835479937e-01
        FLR::scaled( 0x167C343C1399BB, -52 - 1),  // +7.026616261835479937e-01
        FLR::scaled( 0x167DD8D2A097E0, -52 - 1),  // +7.028621782126229789e-01
        FLR::scaled( 0x167DD8D2A097E0, -52 - 1),  // +7.028621782126229789e-01
        FLR::scaled( 0x168100DE5F1FA6, -52 - 1),  // +7.032474845118386053e-01
        FLR::scaled( 0x168100DE5F1FA6, -52 - 1),  // +7.032474845118386053e-01
        FLR::scaled( 0x1684F42838C551, -52 - 1),  // +7.037297044354692277e-01
        FLR::scaled( 0x1684F42838C551, -52 - 1),  // +7.037297044354692277e-01
        FLR::scaled( 0x168B2940999A4C, -52 - 1),  // +7.044874440878827748e-01
        FLR::scaled( 0x168B2940999A4C, -52 - 1),  // +7.044874440878827748e-01
        FLR::scaled( 0x168A0AB264B0C4, -52 - 1),  // +7.043508037800383370e-01
        FLR::scaled( 0x168A0AB264B0C4, -52 - 1),  // +7.043508037800383370e-01
        FLR::scaled( 0x16900C567D97F4, -52 - 1),  // +7.050840081471947407e-01
        FLR::scaled( 0x16900C567D97F4, -52 - 1),  // +7.050840081471947407e-01
        FLR::scaled( 0x16A983F3E92C0B, -52 - 1),  // +7.081928027995457731e-01
        FLR::scaled( 0x16A983F3E92C0B, -52 - 1),  // +7.081928027995457731e-01
        FLR::scaled( 0x16AFA9D13BD384, -52 - 1),  // +7.089432798953656523e-01
        FLR::scaled( 0x16AFA9D13BD384, -52 - 1),  // +7.089432798953656523e-01
        FLR::scaled( 0x16AD38E0CF4523, -52 - 1),  // +7.086452856839610126e-01
        FLR::scaled( 0x16AD38E0CF4523, -52 - 1),  // +7.086452856839610126e-01
        FLR::scaled( 0x16B330CF76A75D, -52 - 1),  // +7.093738605519593898e-01
        FLR::scaled( 0x16B330CF76A75D, -52 - 1),  // +7.093738605519593898e-01
        FLR::scaled( 0x16D016D230B240, -52 - 1),  // +7.129015069272739424e-01
        FLR::scaled( 0x16D016D230B240, -52 - 1),  // +7.129015069272739424e-01
        FLR::scaled( 0x16D61020130106, -52 - 1),  // +7.136307360124483079e-01
        FLR::scaled( 0x16D61020130106, -52 - 1),  // +7.136307360124483079e-01
        FLR::scaled( 0x16D25E27590121, -52 - 1),  // +7.131796616086242269e-01
        FLR::scaled( 0x16D25E27590121, -52 - 1),  // +7.131796616086242269e-01
        FLR::scaled( 0x16D84D63A142A6, -52 - 1),  // +7.139040895363748529e-01
        FLR::scaled( 0x16D84D63A142A6, -52 - 1),  // +7.139040895363748529e-01
        FLR::scaled( 0x16F857A03D8841, -52 - 1),  // +7.178152208036935322e-01
        FLR::scaled( 0x16F857A03D8841, -52 - 1),  // +7.178152208036935322e-01
        FLR::scaled( 0x16FF2D3B72489B, -52 - 1),  // +7.186494980872056848e-01
        FLR::scaled( 0x16FF2D3B72489B, -52 - 1),  // +7.186494980872056848e-01
        FLR::scaled( 0x16FA4079D2D466, -52 - 1),  // +7.180483226171758826e-01
        FLR::scaled( 0x16FA4079D2D466, -52 - 1),  // +7.180483226171758826e-01
        FLR::scaled( 0x1700EF2736332E, -52 - 1),  // +7.188640371183276923e-01
        FLR::scaled( 0x1700EF2736332E, -52 - 1),  // +7.188640371183276923e-01
        FLR::scaled( 0x1711788C1D6BB9, -52 - 1),  // +7.208826767558697002e-01
        FLR::scaled( 0x1711788C1D6BB9, -52 - 1),  // +7.208826767558697002e-01
        FLR::scaled( 0x171DE255670FC7, -52 - 1),  // +7.223979633349636442e-01
        FLR::scaled( 0x171DE255670FC7, -52 - 1),  // +7.223979633349636442e-01
        FLR::scaled( 0x1712E03FF906CC, -52 - 1),  // +7.210541963069885263e-01
        FLR::scaled( 0x1712E03FF906CC, -52 - 1),  // +7.210541963069885263e-01
        FLR::scaled( 0x171F1F5AC583AA, -52 - 1),  // +7.225491307145734954e-01
        FLR::scaled( 0x171F1F5AC583AA, -52 - 1),  // +7.225491307145734954e-01
        FLR::scaled( 0x1730FE260F4CF0, -52 - 1),  // +7.247305625300253240e-01
        FLR::scaled( 0x1730FE260F4CF0, -52 - 1),  // +7.247305625300253240e-01
        FLR::scaled( 0x173D451AAF39E5, -52 - 1),  // +7.262292405301279397e-01
        FLR::scaled( 0x173D451AAF39E5, -52 - 1),  // +7.262292405301279397e-01
        FLR::scaled( 0x1732E6CB9323EA, -52 - 1),  // +7.249635673589385210e-01
        FLR::scaled( 0x1732E6CB9323EA, -52 - 1),  // +7.249635673589385210e-01
        FLR::scaled( 0x173EFD94D3BF5B, -52 - 1),  // +7.264392763881731829e-01
        FLR::scaled( 0x173EFD94D3BF5B, -52 - 1),  // +7.264392763881731829e-01
        FLR::scaled( 0x1707B6473E369D, -52 - 1),  // +7.196914092507601390e-01
        FLR::scaled( 0x1707B6473E369D, -52 - 1),  // +7.196914092507601390e-01
        FLR::scaled( 0x170CD07B6945DA, -52 - 1),  // +7.203142557502204557e-01
        FLR::scaled( 0x170CD07B6945DA, -52 - 1),  // +7.203142557502204557e-01
        FLR::scaled( 0x170B467308E87C, -52 - 1),  // +7.201263663075816446e-01
        FLR::scaled( 0x170B467308E87C, -52 - 1),  // +7.201263663075816446e-01
        FLR::scaled( 0x171040DC34075C, -52 - 1),  // +7.207340527386167928e-01
        FLR::scaled( 0x171040DC34075C, -52 - 1),  // +7.207340527386167928e-01
        FLR::scaled( 0x172DAA37F53722, -52 - 1),  // +7.243243306090543232e-01
        FLR::scaled( 0x172DAA37F53722, -52 - 1),  // +7.243243306090543232e-01
        FLR::scaled( 0x173369FB0E88AA, -52 - 1),  // +7.250261214687914180e-01
        FLR::scaled( 0x173369FB0E88AA, -52 - 1),  // +7.250261214687914180e-01
        FLR::scaled( 0x1730AF29BCB9B8, -52 - 1),  // +7.246928992442951412e-01
        FLR::scaled( 0x1730AF29BCB9B8, -52 - 1),  // +7.246928992442951412e-01
        FLR::scaled( 0x1736380C4F9882, -52 - 1),  // +7.253685226867363500e-01
        FLR::scaled( 0x1736380C4F9882, -52 - 1),  // +7.253685226867363500e-01
        FLR::scaled( 0x17431624768735, -52 - 1),  // +7.269392692726116545e-01
        FLR::scaled( 0x17431624768735, -52 - 1),  // +7.269392692726116545e-01
        FLR::scaled( 0x174DAB86100DD3, -52 - 1),  // +7.282312029278109611e-01
        FLR::scaled( 0x174DAB86100DD3, -52 - 1),  // +7.282312029278109611e-01
        FLR::scaled( 0x1745C3EAEA626E, -52 - 1),  // +7.272662723726861511e-01
        FLR::scaled( 0x1745C3EAEA626E, -52 - 1),  // +7.272662723726861511e-01
        FLR::scaled( 0x17500E12E1BDB9, -52 - 1),  // +7.285223358903102353e-01
        FLR::scaled( 0x17500E12E1BDB9, -52 - 1),  // +7.285223358903102353e-01
        FLR::scaled( 0x17618BE77C28C9, -52 - 1),  // +7.306575318518976347e-01
        FLR::scaled( 0x17618BE77C28C9, -52 - 1),  // +7.306575318518976347e-01
        FLR::scaled( 0x176C0F66E3C336, -52 - 1),  // +7.319409379543688754e-01
        FLR::scaled( 0x176C0F66E3C336, -52 - 1),  // +7.319409379543688754e-01
        FLR::scaled( 0x17646D402EEFFD, -52 - 1),  // +7.310091260510486189e-01
        FLR::scaled( 0x17646D402EEFFD, -52 - 1),  // +7.310091260510486189e-01
        FLR::scaled( 0x176EA2C2A1335D, -52 - 1),  // +7.322553445206768652e-01
        FLR::scaled( 0x176EA2C2A1335D, -52 - 1),  // +7.322553445206768652e-01
        FLR::scaled( 0x17698509B51F3D, -52 - 1),  // +7.316308202361835322e-01
        FLR::scaled( 0x17698509B51F3D, -52 - 1),  // +7.316308202361835322e-01
        FLR::scaled( 0x176D69586C29CB, -52 - 1),  // +7.321058966638757104e-01
        FLR::scaled( 0x176D69586C29CB, -52 - 1),  // +7.321058966638757104e-01
        FLR::scaled( 0x176FA1EA8D48AA, -52 - 1),  // +7.323770123569108836e-01
        FLR::scaled( 0x176FA1EA8D48AA, -52 - 1),  // +7.323770123569108836e-01
        FLR::scaled( 0x1773F6D5D2B66E, -52 - 1),  // +7.329057861549708175e-01
        FLR::scaled( 0x1773F6D5D2B66E, -52 - 1),  // +7.329057861549708175e-01
        FLR::scaled( 0x1789D91DCDFD2D, -52 - 1),  // +7.355771619913064052e-01
        FLR::scaled( 0x1789D91DCDFD2D, -52 - 1),  // +7.355771619913064052e-01
        FLR::scaled( 0x178E939C48A956, -52 - 1),  // +7.361543705385809044e-01
        FLR::scaled( 0x178E939C48A956, -52 - 1),  // +7.361543705385809044e-01
        FLR::scaled( 0x178F89790D1471, -52 - 1),  // +7.362716068534053138e-01
        FLR::scaled( 0x178F89790D1471, -52 - 1),  // +7.362716068534053138e-01
        FLR::scaled( 0x1794BBB4993AEA, -52 - 1),  // +7.369059111896067993e-01
        FLR::scaled( 0x1794BBB4993AEA, -52 - 1),  // +7.369059111896067993e-01
        FLR::scaled( 0x179AB66ED21A1F, -52 - 1),  // +7.376358189074528893e-01
        FLR::scaled( 0x179AB66ED21A1F, -52 - 1),  // +7.376358189074528893e-01
        FLR::scaled( 0x17A1201F7A51C4, -52 - 1),  // +7.384186377335528739e-01
        FLR::scaled( 0x17A1201F7A51C4, -52 - 1),  // +7.384186377335528739e-01
        FLR::scaled( 0x179EDB33B9198D, -52 - 1),  // +7.381416330543274507e-01
        FLR::scaled( 0x179EDB33B9198D, -52 - 1),  // +7.381416330543274507e-01
        FLR::scaled( 0x17A59EBAE2987C, -52 - 1),  // +7.389672899341941381e-01
        FLR::scaled( 0x17A59EBAE2987C, -52 - 1),  // +7.389672899341941381e-01
        FLR::scaled( 0x17BD5D90E8F59D, -52 - 1),  // +7.418659048341172957e-01
        FLR::scaled( 0x17BD5D90E8F59D, -52 - 1),  // +7.418659048341172957e-01
        FLR::scaled( 0x17C4ECE3725C7D, -52 - 1),  // +7.427887384718726560e-01
        FLR::scaled( 0x17C4ECE3725C7D, -52 - 1),  // +7.427887384718726560e-01
        FLR::scaled( 0x17C0FE6C7E2305, -52 - 1),  // +7.423088187216256850e-01
        FLR::scaled( 0x17C0FE6C7E2305, -52 - 1),  // +7.423088187216256850e-01
        FLR::scaled( 0x17C8E96B026846, -52 - 1),  // +7.432753648784078404e-01
        FLR::scaled( 0x17C8E96B026846, -52 - 1),  // +7.432753648784078404e-01
        FLR::scaled( 0x17978F72FD7225, -52 - 1),  // +7.372510190867315183e-01
        FLR::scaled( 0x17978F72FD7225, -52 - 1),  // +7.372510190867315183e-01
        FLR::scaled( 0x179A40304F8EF2, -52 - 1),  // +7.375794356889555647e-01
        FLR::scaled( 0x179A40304F8EF2, -52 - 1),  // +7.375794356889555647e-01
        FLR::scaled( 0x179D05372F488A, -52 - 1),  // +7.379175260378059154e-01
        FLR::scaled( 0x179D05372F488A, -52 - 1),  // +7.379175260378059154e-01
        FLR::scaled( 0x17A00ACEF66A5A, -52 - 1),  // +7.382864038693910391e-01
        FLR::scaled( 0x17A00ACEF66A5A, -52 - 1),  // +7.382864038693910391e-01
        FLR::scaled( 0x17B4F6C0B639C7, -52 - 1),  // +7.408403171446530378e-01
        FLR::scaled( 0x17B4F6C0B639C7, -52 - 1),  // +7.408403171446530378e-01
        FLR::scaled( 0x17B8673C6CB559, -52 - 1),  // +7.412601642769615085e-01
        FLR::scaled( 0x17B8673C6CB559, -52 - 1),  // +7.412601642769615085e-01
        FLR::scaled( 0x17BA52A7873288, -52 - 1),  // +7.414944908174030402e-01
        FLR::scaled( 0x17BA52A7873288, -52 - 1),  // +7.414944908174030402e-01
        FLR::scaled( 0x17BE24412E12B3, -52 - 1),  // +7.419606469198555265e-01
        FLR::scaled( 0x17BE24412E12B3, -52 - 1),  // +7.419606469198555265e-01
        FLR::scaled( 0x17C569849942EF, -52 - 1),  // +7.428481664483949087e-01
        FLR::scaled( 0x17C569849942EF, -52 - 1),  // +7.428481664483949087e-01
        FLR::scaled( 0x17CA16B0FAD9F7, -52 - 1),  // +7.434190231932110704e-01
        FLR::scaled( 0x17CA16B0FAD9F7, -52 - 1),  // +7.434190231932110704e-01
        FLR::scaled( 0x17C9305ED9810C, -52 - 1),  // +7.433091976672883128e-01
        FLR::scaled( 0x17C9305ED9810C, -52 - 1),  // +7.433091976672883128e-01
        FLR::scaled( 0x17CE245946AC30, -52 - 1),  // +7.439138168023244901e-01
        FLR::scaled( 0x17CE245946AC30, -52 - 1),  // +7.439138168023244901e-01
        FLR::scaled( 0x17E5271BF05AEB, -52 - 1),  // +7.467227502519028226e-01
        FLR::scaled( 0x17E5271BF05AEB, -52 - 1),  // +7.467227502519028226e-01
        FLR::scaled( 0x17EAECF7E53FEB, -52 - 1),  // +7.474274484356987491e-01
        FLR::scaled( 0x17EAECF7E53FEB, -52 - 1),  // +7.474274484356987491e-01
        FLR::scaled( 0x17E8A0DD328B35, -52 - 1),  // +7.471470184576448625e-01
        FLR::scaled( 0x17E8A0DD328B35, -52 - 1),  // +7.471470184576448625e-01
        FLR::scaled( 0x17EEB45586EE29, -52 - 1),  // +7.478887243700614862e-01
        FLR::scaled( 0x17EEB45586EE29, -52 - 1),  // +7.478887243700614862e-01
        FLR::scaled( 0x18410C805D5A94, -52 - 1),  // +7.579405314562159823e-01
        FLR::scaled( 0x18410C805D5A94, -52 - 1),  // +7.579405314562159823e-01
        FLR::scaled( 0x18483D7D658263, -52 - 1),  // +7.588183831358715770e-01
        FLR::scaled( 0x18483D7D658263, -52 - 1),  // +7.588183831358715770e-01
        FLR::scaled( 0x184284745A651D, -52 - 1),  // +7.581197998544301209e-01
        FLR::scaled( 0x184284745A651D, -52 - 1),  // +7.581197998544301209e-01
        FLR::scaled( 0x1849D52133CDEE, -52 - 1),  // +7.590127609714139023e-01
        FLR::scaled( 0x1849D52133CDEE, -52 - 1),  // +7.590127609714139023e-01
        FLR::scaled( 0x185AEC8AC255E7, -52 - 1),  // +7.610991201533438000e-01
        FLR::scaled( 0x185AEC8AC255E7, -52 - 1),  // +7.610991201533438000e-01
        FLR::scaled( 0x1862E7367745DA, -52 - 1),  // +7.620731414592072372e-01
        FLR::scaled( 0x1862E7367745DA, -52 - 1),  // +7.620731414592072372e-01
        FLR::scaled( 0x185C08EEB835C1, -52 - 1),  // +7.612347280971151209e-01
        FLR::scaled( 0x185C08EEB835C1, -52 - 1),  // +7.612347280971151209e-01
        FLR::scaled( 0x18641E3DE56F5B, -52 - 1),  // +7.622214516554594033e-01
        FLR::scaled( 0x18641E3DE56F5B, -52 - 1),  // +7.622214516554594033e-01
        FLR::scaled( 0x1877711C3221BD, -52 - 1),  // +7.645803023051979119e-01
        FLR::scaled( 0x1877711C3221BD, -52 - 1),  // +7.645803023051979119e-01
        FLR::scaled( 0x18823CCD02D875, -52 - 1),  // +7.658981327174517739e-01
        FLR::scaled( 0x18823CCD02D875, -52 - 1),  // +7.658981327174517739e-01
        FLR::scaled( 0x1877DFBA7AEA45, -52 - 1),  // +7.646330492201022233e-01
        FLR::scaled( 0x1877DFBA7AEA45, -52 - 1),  // +7.646330492201022233e-01
        FLR::scaled( 0x1882AE179B295F, -52 - 1),  // +7.659521542603150435e-01
        FLR::scaled( 0x1882AE179B295F, -52 - 1),  // +7.659521542603150435e-01
        FLR::scaled( 0x1890C3AFB4A84A, -52 - 1),  // +7.676714355232061582e-01
        FLR::scaled( 0x1890C3AFB4A84A, -52 - 1),  // +7.676714355232061582e-01
        FLR::scaled( 0x189C4BAC99030F, -52 - 1),  // +7.690790530251393475e-01
        FLR::scaled( 0x189C4BAC99030F, -52 - 1),  // +7.690790530251393475e-01
        FLR::scaled( 0x1891110779A034, -52 - 1),  // +7.677083154676496157e-01
        FLR::scaled( 0x1891110779A034, -52 - 1),  // +7.677083154676496157e-01
        FLR::scaled( 0x189C9AFE8908C1, -52 - 1),  // +7.691168757812861800e-01
        FLR::scaled( 0x189C9AFE8908C1, -52 - 1),  // +7.691168757812861800e-01
        FLR::scaled( 0x1870885F6410EF, -52 - 1),  // +7.637369025328818450e-01
        FLR::scaled( 0x1870885F6410EF, -52 - 1),  // +7.637369025328818450e-01
        FLR::scaled( 0x1875E50DDB3D80, -52 - 1),  // +7.643914480812981083e-01
        FLR::scaled( 0x1875E50DDB3D80, -52 - 1),  // +7.643914480812981083e-01
        FLR::scaled( 0x1871B1E70293BB, -52 - 1),  // +7.638787757792820932e-01
        FLR::scaled( 0x1871B1E70293BB, -52 - 1),  // +7.638787757792820932e-01
        FLR::scaled( 0x18772769AB0014, -52 - 1),  // +7.645451606586015636e-01
        FLR::scaled( 0x18772769AB0014, -52 - 1),  // +7.645451606586015636e-01
        FLR::scaled( 0x18898971AEAB3C, -52 - 1),  // +7.667891712529590897e-01
        FLR::scaled( 0x18898971AEAB3C, -52 - 1),  // +7.667891712529590897e-01
        FLR::scaled( 0x188F87DCC75620, -52 - 1),  // +7.675208389361536376e-01
        FLR::scaled( 0x188F87DCC75620, -52 - 1),  // +7.675208389361536376e-01
        FLR::scaled( 0x188A81D30C3789, -52 - 1),  // +7.669076082254245863e-01
        FLR::scaled( 0x188A81D30C3789, -52 - 1),  // +7.669076082254245863e-01
        FLR::scaled( 0x189096CF79C5A3, -52 - 1),  // +7.676500370272844043e-01
        FLR::scaled( 0x189096CF79C5A3, -52 - 1),  // +7.676500370272844043e-01
        FLR::scaled( 0x18A2FBC6E0525E, -52 - 1),  // +7.698954471876040540e-01
        FLR::scaled( 0x18A2FBC6E0525E, -52 - 1),  // +7.698954471876040540e-01
        FLR::scaled( 0x18AB60A73D4561, -52 - 1),  // +7.709201113122327031e-01
        FLR::scaled( 0x18AB60A73D4561, -52 - 1),  // +7.709201113122327031e-01
        FLR::scaled( 0x18A3358F0AD623, -52 - 1),  // +7.699229997439868134e-01
        FLR::scaled( 0x18A3358F0AD623, -52 - 1),  // +7.699229997439868134e-01
        FLR::scaled( 0x18AB9EAB821139, -52 - 1),  // +7.709496831671805994e-01
        FLR::scaled( 0x18AB9EAB821139, -52 - 1),  // +7.709496831671805994e-01
        FLR::scaled( 0x18BB67FCDFBC82, -52 - 1),  // +7.728767336792687903e-01
        FLR::scaled( 0x18BB67FCDFBC82, -52 - 1),  // +7.728767336792687903e-01
        FLR::scaled( 0x18C474D6F963EE, -52 - 1),  // +7.739814947809671164e-01
        FLR::scaled( 0x18C474D6F963EE, -52 - 1),  // +7.739814947809671164e-01
        FLR::scaled( 0x18BB9515B56BA6, -52 - 1),  // +7.728982376096282803e-01
        FLR::scaled( 0x18BB9515B56BA6, -52 - 1),  // +7.728982376096282803e-01
        FLR::scaled( 0x18C4A5C549852B, -52 - 1),  // +7.740048268571276813e-01
        FLR::scaled( 0x18C4A5C549852B, -52 - 1)   // +7.740048268571276813e-01
    ];

    pub(crate) const KAT_SAMPLER_512_OUT: [i16; 1024] = [
         -78,   13,  -42,  -51,  -23,  -29,  -57,  -37,  -25,    7,  -51,  -90,
         -53, -117,  -39,   -5,  -83,    3,  -54,  -82,   24,  -67,   -7,  -61,
         -85,  -41,  -34,  -95,  -11,  -60,  -18,  -34,  -60,    0,  -38,  -39,
          -7,   19,  -26,  -84,  -97,  -31,    1,    4,    7,  -30,  -10,  -55,
        -101,   67,  -23,  -68,  -66,  -40,    0,  -56,  -55,  -87,  -42, -104,
          -8,  -87,  -20,  -59,  -40,  -28,  -21,  -66,  -45,  -96,  -64, -102,
         -59,   35,  -12,   20,  -79,  -63,  -14,  -29,  -54,   72,  -24,  -55,
         -32,  -15,  -12,  -29,  -43,   -6,  -34, -107,  -53,    3,  -23,  -60,
        -110,   59,  -40,  -24,  -19,  -51,  -23,  -58,  -56,   24,  -42,   -8,
         -66,  -74,   12,  -63,  -68,  -50,  -61,  -79,  -36,  -73,  -43, -100,
         -62,  -49,  -79,  -48,   14,  -57,  -24,  -30,    7,   44,  -12,  -80,
         -65, -111,  -81, -104,  -18,   13,  -12,  -39,  -53,  -48,    7,  -52,
          -7,    9,  -11,  -27,   -1,  -67,    5,  -38,  -22,  -34,  -15,  -57,
         -22,  -28,  -45,  -36,  -80,  -27, -102,  -19,  -18,  -34,  -21,  -87,
         -24,  -26,  -63,  -71,  -20,  -78,  -33,  -36,  -45,   73,  -93,  -41,
         -42,  -40,  -15, -107,  -46,  -91,  -87,  -62,  -29,  -44,  -76,  -64,
         -42,  -15,  -32,  -57,  -39,    0,  -33,  -36,  -42,  -32,  -31,  -36,
         -48, -125,  -68,  -95,  -59,    3,  -26,  -44,  -19,  -75,  -12,  -85,
           0,  -22,  -58, -162,  -63,  -76,  -10,  -92, -106,  -15,  -64, -105,
         -23,  -53,    4,  -48,  -68,   -5,  -91,  -38,  -18,  -19,  -35,  -45,
         -26,   14,  -47,  -28,  -17,  -77,   23,  -46,  -21,  -55,  -91,  -66,
         -62,  -44,  -82,  -23,  -60,   41,  -15,  -75,  -36,  -42,  -65, -101,
         -68,   -6,  -14,   -8,  -48,  -83,   -1,  -73,  -51,    9,  -76,  -63,
          -2,  -72,  -12,  -38,  -17,  -14,  -37,  -62,  -35,  -76,  -75,  -21,
         -35,   26,   13,  -71,   23,  -38,  -24,  -43,  -94,    0,  -55,  -15,
         -54,  -35,   24,  -90,  -30,   15,  -78,  -14,    9,  -63,  -38,  -54,
         -22,  -77,  -63, -114,  -51,  -22,  -37,  -40,  -66,    1,   -6,  -72,
         -40,  -52,  -81,  -64,  -90,  -60,  -76,   13,  -13,  -11,   66,  -34,
         -22,    5,  -69,    1,  -18,  -32,  -44,  -15,  -18,  -26,  -51,  -96,
         -45, -108,  -45,  -79,  -71,   35,  -33,    3,    4,  -71,  -94,  -53,
         -64,   32,   -5,  -43,  -59,  -38,    4,  -37,  -84,   28,  -43,  -61,
         -23,  -97,    8,  -76,   12,  -49,  -52, -102,  -31,  -84,  -16,  -66,
        -132,   72,  -54,    3, -117,  -58,    6,  -66,  -39,   46,  -13,  -59,
         -31,  -94,   -4,  -41,  -65,   21,  -20,  -58,  -36,    5,  -33,  -39,
         -58,  -24,  -61,  -89,  -59,  -15,  -16,  -34,  -18,   38,  -29,  -42,
         -91,  -46,  -45,  -74,   52,   11,  -67,  -80,  -39,  -67,    7,  -63,
         -57,   20,  -37,  -47,  -39,  -59,  -18,  -30,  -20,  -95,  -85,  -75,
         -50,  -19,   -6,   -6,  -79,   39,  -28,   13,  -50,  -50,  -24,  -65,
         -58,   21,  -31,  -59,   -1,  -54,  -45, -111,  -79,   21,   -9,  -76,
          -8,  -47,  -33,    2,  -38,  -22,  -77,  -84,  -51,  -83,   17,  -15,
        -101,    3,  -33,  -65,  -37,  -28,  -49,  -78,  -55,  -22,  -26, -108,
         -66, -109,  -21,  -18,  -50,   -8,  -61,  -60,    2,  -62,   -5,  -46,
         -73,  -37,  -55,  -97,  -73,   -9,   -7,  -55,  612,   72,  225,  869,
         819,  439, -393,  548,  664,  287,   36,  635,  228,  639, -517,  496,
         462,  518, -169,  494,  365,  383, -401,  461,  813,  423,  -78,  266,
         310,  789, -306,  362,  457,  406,   68,  181,  246,  545,   72,  640,
         371,  597, -199,  521,  252,  755, -341,  450,  804,  609,   60,  254,
         366,  304,   26,  465,  258,  314, -139,  502,  323,  668, -308,  628,
         348,  180,  194,  789,  143,  578,   16,  377,  576,  344, -258,  584,
         214,  468, -201,  716,  681,  316, -113,  425,  343,  555, -466,  283,
         802,  582, -223,  347,  395,  638, -168,  713,  542,  759,  358,  427,
         344,  404, -296, 1011,  244,  763, -138,   89,  296, 1155, -183,  438,
         716,  191,    3,  545,  489,  752, -466,  464,  284,  388, -116,  260,
          63,  459, -320,  621,  644,  220,  126,  453,  464,  268, -388,  703,
         506,  542,   26,  371,  345,  438, -154,  672,  594,  263, -182,  382,
         735,  582, -250,  489,  389,  554, -294,  468,  525,  297, -320,  548,
         413,  342,  386,  562,  335,  533, -433,  906,  449,  446,  -35,  569,
         280,  862, -106,  783,  743,  424, -292,  817,  741,  337, -321,  607,
         287,  527, -435, 1056,  244,  725, -140,  553,  723,   85,   30,  491,
          51,  533, -460,  629,  280,  370,  322,  695,  547,  850, -702,  468,
         522,  421, -324,  166,  496,  373, -353,  198,  203,  634, -204,  517,
         155,  743, -219,  621,  784,  579,  310,  463,  139,  643, -310,  672,
         689,  358, -295,  685,  746,  860, -168,  674,  789,  281,    4,  499,
         256,  504, -105,  938,  603,  272,  -20,  552,  228,  710,  136,  557,
         355,  370,  314,  794,  180,  556, -133,  806,  776,  592, -124,  538,
         460,  906, -579,  891,  642,  393, -193,  374,  413,  348, -428,  556,
         192,  406, -172,  819,  448,  674, -589,  354,  849,  306,  -46,  302,
         329,  463, -326,  332,  607,  346, -205,  368,  234,  440, -121,  680,
         291,  200,  236,  495,  581,  431,  -92,  500,  556,  583, -253,  452,
          25,  488,  -74,  690,  730,  109,  303,  890,  566,  430, -266,  645,
         438,   87,  188,  500,  354,  861, -113,  474,  582,  384,  270,  446,
         294,  552, -194,  491,  241,  605, -311,  730,  354,  565, -110,  447,
         966,  564,   92,  359,  478,  464, -616,  525,  180,  690,  216,  378,
          15,  360, -698,  889,  606,  184,  117,  226,  451,  580, -377,  602,
          66,  650, -357,  414,  232,  945,  -99,  587,  525,  286,  265,  456,
         483,  499, -329,  785,  271,  560, -300,  413,  485,  511, -148,  449,
         881,  344, -323,  479,  223,  542, -416,  537,  375,  474, -300,  558,
         395,  769, -209,  802,  665,  277,   22,  652,  396,  375,  -30,  584,
         552,  452, -176,  491,  611,  397, -246,  321,  630,  340,  -74,  335,
         582,  377, -219,  590,  339,  459, -430,  658,  -57,  886, -321,  327,
         309,  476,  112,  647,  567,  514, -116,  699,  609,  823, -226,  373,
         410,  762, -256,  641,  693,  108, -203,  479,   21,  389, -287,  482,
         515,  250,   54,  404,  231,  631,  -68,  366,  808,  318,   44,  693,
         527,  437, -565,  435,  225,  312, -239,  655,  247,  351, -555,  517,
         821,  355, -182,  415,  557, 1074,  -36,  352,  199,  557, -408,  871,
         159,  351, -501,  759
    ];
}
