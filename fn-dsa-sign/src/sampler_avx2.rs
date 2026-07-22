#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use crate::flr::FLR;
use super::poly_avx2::*;
use fn_dsa_comm::PRNG;

// ========================================================================
// Gaussian sampling, AVX2 specialization
// ========================================================================

// This file follows the same API as sampler.rs, but uses AVX2 intrinsics.
// Its use is ultimately gated by a runtime check of AVX2 support in the
// current CPU.

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

    // Sample the next small integer, using the proper Gaussian
    // distribution with centre mu and inverse of the standard
    // deviation isigma.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn next(&mut self, mu: FLR, isigma: FLR) -> i32 {

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

    // Sample a value from a given half-Gaussian centred on zero; only
    // non-negative values are returned. 72 bits from the random source
    // are used.
    #[target_feature(enable = "avx2")]
    unsafe fn gaussian0(&mut self) -> (i32, i32) {
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
    #[target_feature(enable = "avx2")]
    unsafe fn ber_exp(&mut self, x: FLR, ccs: FLR) -> bool {
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
        let z = (r.expm_p63(ccs) << 1).wrapping_sub(1) >> s;

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

    // Fast Fourier Sampling.
    // The target vector is t, provided as two polynomials t0 and t1.
    // The Gram matrix is provided (G = [[g00, g01], [adj(g01), g11]]).
    // The sampled vector is written over (t0,t1) and the Gram matrix
    // is also modified. The temporary buffer (tmp) must have room for
    // four extra polynomials. All polynomials are in FFT representation.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn ffsamp_fft(&mut self,
        t0: &mut [FLR], t1: &mut [FLR],
        g00: &mut [FLR], g01: &mut [FLR], g11: &mut [FLR], tmp: &mut [FLR])
    {
        self.ffsamp_fft_inner(self.logn, t0, t1, g00, g01, g11, tmp);
    }

    // Inner function for Fast Fourier Sampling (recursive). The
    // degree at this level is provided as the 'logn' parameter (the
    // overall degree is in self.logn).
    #[target_feature(enable = "avx2")]
    unsafe fn ffsamp_fft_inner(&mut self, logn: u32,
        t0: &mut [FLR], t1: &mut [FLR],
        g00: &mut [FLR], g01: &mut [FLR], g11: &mut [FLR], tmp: &mut [FLR])
    {
        // When logn = 1, arrays have length 2; we unroll the last steps.
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
mod tests {

    use super::*;
    use fn_dsa_comm::shake::SHAKE256_PRNG;

    use crate::sampler::tests::{
        KAT_SAMPLER_512_SEED,
        KAT_SAMPLER_512_NONCE,
        KAT_SAMPLER_512_MU,
        KAT_SAMPLER_512_INVSIGMA,
        KAT_SAMPLER_512_OUT,
    };

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
            let x = unsafe { samp.next(mu, isigma) };
            assert!(x == r);
        }
    }

}
