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

// Distribution for gaussian0() (this is the RCDT table from the
// specification, expressed in base 2^24).
const GAUSS0: [[u32; 4]; 18] = [
    [ 10745844,  3068844,  3741698, 0 ],
    [  5559083,  1580863,  8248194, 0 ],
    [  2260429, 13669192,  2736639, 0 ],
    [   708981,  4421575, 10046180, 0 ],
    [   169348,  7122675,  4136815, 0 ],
    [    30538, 13063405,  7650655, 0 ],
    [     4132, 14505003,  7826148, 0 ],
    [      417, 16768101, 11363290, 0 ],
    [       31,  8444042,  8086568, 0 ],
    [        1, 12844466,   265321, 0 ],
    [        0,  1232676, 13644283, 0 ],
    [        0,    38047,  9111839, 0 ],
    [        0,      870,  6138264, 0 ],
    [        0,       14, 12545723, 0 ],
    [        0,        0,  3104126, 0 ],
    [        0,        0,    28824, 0 ],
    [        0,        0,      198, 0 ],
    [        0,        0,        1, 0 ],
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
            let z0 = self.gaussian0();
            let b = (self.rng.next_u8() as i32) & 1;
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
    unsafe fn gaussian0(&mut self) -> i32 {
        // C code includes an AVX2-optimized variant, but it does not
        // seem to improve performance.

        // Get a random 72-bit value, into three 24-bit limbs v0..v2.
        let lo = self.rng.next_u64();
        let hi = self.rng.next_u8();
        let v0 = (lo as u32) & 0xFFFFFF;
        let v1 = ((lo >> 24) as u32) & 0xFFFFFF;
        let v2 = ((lo >> 48) as u32) | ((hi as u32) << 16);

        // Sampled value is z, such that v0..v2 is lower than the first
        // z elements of the table.
        let mut z = 0;
        for i in 0..GAUSS0.len() {
            let cc = v0.wrapping_sub(GAUSS0[i][2]) >> 31;
            let cc = v1.wrapping_sub(GAUSS0[i][1]).wrapping_sub(cc) >> 31;
            let cc = v2.wrapping_sub(GAUSS0[i][0]).wrapping_sub(cc) >> 31;
            z += cc as i32;
        }
        z
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
    use crate::flr::FLR;
    use fn_dsa_comm::PRNG;

    // A custom PRNG that outputs a predefined sequence of bytes; this
    // is for test purposes only.
    #[derive(Clone, Copy, Debug)]
    struct NotARealRNG {
        buf: [u8; 25000],
        ptr: usize,
        len: usize,
    }

    impl NotARealRNG {
        fn new(seed: &[u8]) -> Self {
            let mut buf = [0u8; 25000];
            buf[..seed.len()].copy_from_slice(seed);
            Self {
                buf: buf,
                ptr: 0,
                len: seed.len(),
            }
        }

        fn next_u8(&mut self) -> u8 {
            assert!(self.ptr < self.len);
            let x = self.buf[self.ptr];
            self.ptr += 1;
            x
        }

        fn next_u16(&mut self) -> u16 {
            let mut x = 0;
            for _ in 0..2 {
                // big-endian to match test vector conventions
                x = (x << 8) | (self.next_u8() as u16);
            }
            x
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = 0;
            for _ in 0..8 {
                // big-endian to match test vector conventions
                x = (x << 8) | (self.next_u8() as u64);
            }
            x
        }
    }

    impl PRNG for NotARealRNG {
        fn new(seed: &[u8]) -> Self { NotARealRNG::new(seed) }
        fn next_u8(&mut self) -> u8 { NotARealRNG::next_u8(self) }
        fn next_u16(&mut self) -> u16 { NotARealRNG::next_u16(self) }
        fn next_u64(&mut self) -> u64 { NotARealRNG::next_u64(self) }
    }

    fn sampler_inner(logn: u32, hrnd: &str, mu: FLR, isigma: FLR, r: i32) {
        unsafe {
            let rndb = hex::decode(hrnd).unwrap();
            let mut samp = Sampler::<NotARealRNG>::new(logn, &rndb);
            assert!(r == samp.next(mu, isigma));
            assert!(samp.rng.ptr == samp.rng.len);
        }
    }

    #[test]
    fn sampler() {
        if fn_dsa_comm::has_avx2() {
            sampler_inner(
                9,
                "C5442FF043D66E910FD1EAC64EA5450A22941ECADC6C",
                FLR::scaled(-6467219134421412, -46), // -0x1.6F9E6CB3119A4p+6
                FLR::scaled(5286538515094332, -53),  // +0x1.2C8142A489B3Cp-1
                -92);
            sampler_inner(
                9,
                "DA0F8D8444D1A772F465C26F98BBBB4BEE7DB8EFD9B3",
                FLR::scaled(-4685187520230944, -49), // -0x1.0A52739D97620p+3
                FLR::scaled(5286538515094332, -53),  // +0x1.2C8142A489B3Cp-1
                -8);
            sampler_inner(
                9,
                "41B4F5209665C74DAE00DCA8168A7BB516B319C10CB41DED26CD52AED7702CECA7334E0547BCC3C163DDCE0B",
                FLR::scaled(-6381343956910445, -49), // -0x1.6ABCC6BBDC16Dp+3
                FLR::scaled(5287211078925528, -53),  // +0x1.2C8B0C2363CD8p-1
                -12);
        }
    }

    // KAT512 tests are from the submission package, file
    // test-vector-sampler-Falcon512.txt.gz. There are 1024 sampling
    // instances, each with specific values for mu and 1/sigma which
    // are provided in array KAT512_MU_INVSIGMA. The aggregate random
    // bytes obtained from the generator are in KAT512_RND. The 1024
    // outputs are in KAT512_OUT.

    const KAT512_RND: &str = concat!(
        "C5442FF043D66E910FD1EAC64EA5450A22941ECADC6CDA0F8D8444D1A772F465",
        "C26F98BBBB4BEE7DB8EFD9B347F6D7FB9B19F25CDB36D6334D477A8BC0BE68B9",
        "145D41B4F5209665C74DAE00DCA8168A7BB516B319C10CB41DED26CD52AED770",
        "2CECA7334E0547BCC3C163DDCE0B054166C1012780C63103AE833CEC73F2F41C",
        "A59B807C9C92158834632F9BC815557E9D68A50A06DBBC7364778DDD14BF0BF2",
        "2061A9D632BF6818A68F7AB9993C15148633F5BFA5D268486F668E5DDD46958E",
        "9763043D10587C2BC6C25F5C5EE53F2783C4361FBC7CC91DC7833AE20A443C59",
        "574C2C3B0745E2E1071E6D133DBE3275D94B0AC116ED60C258E2CB6AAEAB8C48",
        "23E6DA36E18D7208DA0CC104E21CC7FD1F5D5CA8DBB675266C928448D9059E16",
        "3BC1E2CBF3E18E687426A1B51D76222A705AD60259523BFAA8A394BF4EF0A5C1",
        "842366FDE286D6A30F0803BD87E63374CEE6218727FC31104AAB64F136A06948",
        "5B2EADBC08EA77ED1CE7282332C29BEF5FF255BB36BA7DE8FBAD926A8748EF11",
        "BD3D5D7EEC0DEC4AB54775669AD5113B6D846510284427BBFAD1B91B1F32C7D6",
        "685CF27A2DE77F5B02549FB27829B2BD367EE80FCCF30135AEFDF86C0EF4AD07",
        "6D8F7854042F67F18F2A49BA99EEA6BA65EF008BE154FDCD9DFD32C97F885D20",
        "EEFEEE41005C53D4AD1BCF824AF04ABB1814BD9CB8B37171705ACECFDC88A5AF",
        "541F303A6E003FEA2DB82A9A0D81D3CEC75358A2E97B4B914E45C392A04D64BB",
        "3CA6D69E5DC4F3310EDF97FA43CEEF87749029C9018B2C3C8645D2BD71F090CD",
        "B2164B558493CA95523A0D9B5AE3BE8197553F931FCD0C760FC8512B5A2A589B",
        "7A9393883DCD258D907377DDA60733A941BA6E5B88370DCF1FDBAA9C014F3530",
        "88667ECE607ACFA1BC8549696CA5C36E9F23DE369321597B689CE8331DB0C0B9",
        "41F88B411CCFC83128389E779855BA7B184BE0D1C03A24B1CA69009622CC74E5",
        "E52D7BAE980D8E331B8E5EE508BE54FBAA2C09E23A0BA4A8B036131EC9D03B20",
        "7668DD51CBE96252AA2375591F42E7D9071A96C300815D4EAB4E6C623C69D5B0",
        "A9E1F4C3E59C19A576F8A4F1BB5A4ADEE1868AF2F3352233E02C27FEA9CBB820",
        "F65C67482A09F06E3F304DCADB1579CC8A58ED342527B5A6CC24B5149C9A1BAE",
        "3C77F82D908A57BEF11ECEAEF75A28E8C909140D7CC7D5C159E2051DC785E3EE",
        "F2319869D464F6B30780976DBAED25113D9DC13CE5B29092A4010584350DCC58",
        "C4B5858C2DB163E7DD76B7092D6586FEAEAE373E00474055E8397C39B4768721",
        "FB7497FA916F9B1935F8CB4A941E9B177F4E299DBD044C399283E58BE8EF23BC",
        "CDF3BCBFB1DA977B036C805EE9FC087B8098BDD8244CED89DD579AB259DE98FD",
        "58603B4270CF0186840CA7AF7436A6A6B41D902D4C745B26DFC474378C94830E",
        "2D5FBD4238ACC6224100967DD69D95274177EE26A4C8B453DE4D0794FA54F057",
        "46EDCA3B0CE5774B857FAA1CE9CCF64E01977CB9F487C6E7FF9CFFF29C70593B",
        "C5AA7A2728AD4FC9FE953EDF15DD5117502A2DE75A1AAFAA56BE6873776E6BE7",
        "D2431E49486850C527C424480EB92CF9CF81A9FBB2638E0B051DA0DE9AF4D6D9",
        "9785DA6D5651B7349B294FAB4725F80CD4E89D76D22E4BF54312F77F60C4674C",
        "56CFEEA449B42854D3B06AE14303197C0E7131689F61A91FDE68CCB5B99FED12",
        "70014640A8F9F26C5516124A5979459ADAF7249A4364C4DF21C0F289C4A5E40A",
        "EBF11AD86CBD455505EF98D423B029442E38D986D1561936CC10625CA81BFE33",
        "07C3A02D20197908F7A03125EFD5DF5001ECE4CAA5D6BE1588C18E5EA9DA933F",
        "E003A3E8E3FB950DCC618A2CC588C94B6E32998A5A61B259C71974F5956A770C",
        "6D850D63B803218831DC82EFA88A6A57C6C082F331F210135E575750E28F2E7B",
        "1720DD89E6978D867B2101FB31307C7A7BD222E49D5615F89C0DCF8089FE03A8",
        "21E704E811F70D10DB8E2506AFC5D8BB09171B098FFB32FE4159B2E6D93E7F31",
        "C750C88D421B77F971617ED0BA5F401220ECF51B833EA576426F0642397C19F3",
        "C1ECECDEE9C03A211667A3C1A4351B6EDAAF0CF32DE2041EF995F3DD2ED528C1",
        "5409EF3948B7DEF5AC906AE40F6BD47FCF930BE4A248C59CE9BAFF0A5055AF27",
        "4AA5E475FB2C4E82AC38EE2EBAC201BEDD7992B65EE45E1A3FB5CE86F25AA60F",
        "7E21C77FF3D064687E61036E78B678B429010D9E1F3B98D178F202B4253571CB",
        "7DB8264A6F4F4B4EA299E0A6F25571F1F49FDFCAD66AD93ED1ED5869F915A348",
        "DDFED1D2791246DB71465B51049901C099FE505E5AFF8FCDEA6D579A220D708F",
        "D1141D05EB3A35CBB8DB91928B549FE500EC8A722EB983C2108954F26E2CC625",
        "6A10FBC51BB2DDACB6BFC22C032C968272117F49FAF2B59B6161FD952811D4FA",
        "7F3DDA25D1A61FD4BF0EF393E0C1BF8B764F0DF03E4170AB4099CDF24669BCB7",
        "87AB821C924CB7D06CF9FFB93854C779F815D8AB626A537754E306421B260757",
        "F4446FB78365576564C349CFA748E6061809FFE7F9653BF37CC86FCEC3226944",
        "9C06BD473FDB8D2B5CA81F4DB0A52399B7ED04DF21FDF7F2451AA814CBA3645E",
        "D29D94A181370CD3D3452818C203622DBA092D6C1FFC83BF23B815C93C628A94",
        "593DC6F27902A87DF10D6D6CB57356C5393172630F19864B2F53154D0B23A7A6",
        "61A2FC6C984C6341AD81477162497B8B57E150AE0CEE767A1936E71837771FC7",
        "ECE3983BCEA474D534E2FAACC72B21C26071BD8D00FC254626D177A7B13FC420",
        "2D133FEB1AFA6898BF1B74B40EF342893F3585BBB3E5A15F2320604D8FF33886",
        "72C5AC1D6D7EEA6E1625591EC5A1A079D578C94941FDFFFF7C26081352D22963",
        "0E8F5C9380C28BFD6D3B74BF858D58383B3354AE4D648713326228163948CADE",
        "9A89BD0078CCE2A032B30BEF7C947C8EE3424BD61E16C0E8B37F0EC7A86FD34A",
        "64134D65360C8E16FA5AF6D913CD5A79B2BFDD0FCAA5F81394D9FB3B84137FCD",
        "E34B21EEE3E2779860D38BB6AE940877EA8702E5E3EC47135F9BB6BAE0240A68",
        "838932474E71FC8DEB294F2914D6DA9B847D48A41CEB26D3BD35759A3BC20AE1",
        "732A62D61D3690EADF46DAC9D5C397E96313801826F98A8ECD5212D31F7DAF33",
        "AC1B56B9ECECD61BAFCD214424FD29A5329294BF8620A1E2A3DC58D94BE6A7AD",
        "24C0C1DABCD2B5E4BCAF2888D947EAAF106F91502A43D394A427ECA108366AE7",
        "5E13575C197B71D3E920C142C09A40281DB783720D01A1A544AFDB33C8F955E8",
        "2CAF4F17B37505D7FA479A6D04052B90ADBF5B5D55C30BE4C14F3B281EE712F8",
        "5676AA190EE12B2B91133B8E523D98502E85E50DC620E32267813C9A8E09C0A2",
        "957682E169E1A8AD4619424FB13EA76BF5C96BB38F631CBA19254FA02F2A2EBC",
        "B750E3993859FE8DF9EF6FBA244A979282A359E075292F56FA7570F778CFC6E6",
        "9DF26048823CB2DDC1354D26398028F83C3A96A9ADF2F9BDAFCD9159F9D02B28",
        "3EB33151CAA30064909B3CAB732CA05BFE9487051FC80183A056AC51AF5D6F29",
        "B7A5AC8587345E6C3FC9BCD69B0FB2F995E0D2E926EC5DCD4332E5AE222463B9",
        "4405D4308E26208997A82CEDA0A3D4A3C9AC9EEFC7DFD41999B9A22B8363F937",
        "F95E2E53A1E6BEFC8DEF49AF49744CEC1650180FB76EC07B4074C08B9DF4400D",
        "842A259D1A138B367B67C6DBCB806898B1C31546F93641FCC143AA05F0DCF521",
        "5D27B4EFC9407E1B5A80686B7CCC9DA65594CA16C2198F335751EB510ED3D9A5",
        "0CC056B1E70350FC6B59A019A02E199CD5985A51FD39BE01014633E09A589DE0",
        "28533398F4122B02433FD71D0DA1944829C710C4F1F712EA9F5585F765B1022C",
        "B5769B78CAB4FF8C8E53ABD0699592DCED62DEAC5A219833F6A5DCC4B71B11CD",
        "7B72030AEEE1003C7E9522B57DC3DAB17E76027B663744D5FC280CBD664E0BF5",
        "EA4AEABCED8636240FF224E2AC168A527AF7E8CF31AA9EED04DA37621E0F24EB",
        "9516397F44339ABB17C3431C4B219BAD88C8110429AC7EDB82192A9CDCAA9124",
        "7B43B0E1AACBEC7D0344A7DBD23C8D98D44CFCE3DE069B33B18A3E0A145B3DD4",
        "EA327FD278217081FE1956C99372DE347CEB624A386EEC75D7E833CE3964DB29",
        "15BF647C43881B2780A41A15F5E009F297B7D21918426DF5D348A3F81AD31C5D",
        "CEB9FA51748E1409FF4CD2A90C01C52F106EC9B397FA6DCF7BAFC0EA818A478D",
        "C9E63C3F506960C91DF8ACCB572381A3F48ABE5CD385045C71C0E4E06824D814",
        "C5F61A80AC87775575CB83170F81182AE4156EF5D6D297E1327AF29D0EC3561B",
        "E988BD6B7B211DF719F1475F47B913889B0CC548C4C51C65B554D2CECAB2CCD4",
        "FE4FE1157C93F7FB7B26FD4AD70D9899310DC8A19DC89E7196471BAF0B7B85F6",
        "3C50C0720938CDDF32630BFB99BBC0CDC7D85AF27E9452ECEE57C711664BC0E0",
        "2EDEA50C7DD2C2A2432286BD98E9B80C1734660AC0356437E6A512356EE55BDB",
        "9D6D2EF6BE80DED4C239D0BE18429E9C65375381C6348DABC3CE0157B12A30E6",
        "61B47795C20924754E1398B3AEA1E62C01C3F477CE420602BEEA81864721E7A8",
        "51E39C369FA233D4E68BF4D2094203BA6BC251D10B4A2A58BF7D8C6898BBE97D",
        "CEC0FF949918E18B5101E7EB90B9B1AB9BE477FE01B7E01ADE07B8B3382B356B",
        "6569FD3A79AFC58A32C392C44AF0F9B20E13FAE805EF8FA8F57D386EC42B9F4C",
        "CC0AC810922A5971519407E2C23DFC11C742FA6F47F5C26A8E31CFA4CD642B37",
        "784E17DDE31B14822BA79A3D07B3604727C8AD885CB28DF316A49D61FF9267A5",
        "6431F7712DB5708C0EA66D7A0DD7BA8F7E8EC4CBD9A2E2E7423F573A2723EC01",
        "3CA36FF7293EE29D42681518BF569AE7E1F78C5C4573A04D08F5B55698B90B2D",
        "20593DDA0D867AEF6DDB92FB5146474EAC40BAC1E5E9749BCF67640072F9F53F",
        "DA39D223E9D2F7902A76152D5DA597B4830D6464D114ED78AF8EFBC534EC1A25",
        "DADA05204076A71DB7B32D6ECAA8D89D8EDF5F0DFECF8B955929922D1A721544",
        "B42D162531F375C5AC2DCDFBA4A8CF75B4C7ED0D06020D80535C6ED145948859",
        "25099AB23E9F46CA6093270C84F90177CF452BD6690A667A27419A4FAAD4D279",
        "2D9E4912C914198A3B066DB6F47D5D931AEEE05D95B2C38AD498DAC544624935",
        "6BDA1E1680B15EE9EC987B4A979F050744CD17B1DCFFA64BD80B589916A062B9",
        "05A28ACF31E3602A3F7C42C71FCDC8F0DFE5405F8AC225621147163D377D38D0",
        "3CBE70055589F8FFCA784422D292338513B8D666C119FD14F3FE9CE7E1788C0B",
        "F65220C7F11521EFBF724D4C8D6994C6362ABB1FE040428D5822F7459184D540",
        "5F9DEBF1B9BA08931E1A85FB563A0C2CE50FBF6C20A8B3B258393E22409856DD",
        "820AE7B52C74F352A096D2EC3F87D25BB6095808E52330F80E285F5B1646EA6E",
        "A81A8E6EAD115C6DDDB7FF3D0C939226CB3438A7B07A71A23492452938DA3687",
        "F28A45EE0E79DB570D78B07CF0735F4CCFA8DD8742D109834735D41110A161D9",
        "2EB61043E955774D858022A203B5DE874190DD3F0776576A327A619211701DC6",
        "70244A19B6282C6548D55A5926AD167D397C9A59ED2FD8091A546739200352E7",
        "2BF248ABD3CBF5DC5A936531EA0D2B8FDEBB4F495083EE8D96884B3ECCCE32BB",
        "3774690F58B64442B307310DE254B434A02956F9541F67E192DB945BFE2CD00A",
        "36D2F48ECE524A9159989400DCC4D9D6F1A87746584543C0D36AA5CB8F2D11B5",
        "317D64A383BB2540C50EB41A8F1DFD7C29EAD8B8D0B5A534090442F1BAF17B40",
        "9CF464BB389591E8966234E253D08C938D02E984AC7987DC201F274633EF7A43",
        "D8441FDE4168F80376B61C38379D3EF6A184C9C249362A7E8FC7EAF21809AF34",
        "5B7FED238886D11863801843279BA9BD4E209A5049DC6E6C4A7EEF810EADBBE8",
        "287F4BB825498F6676E4E228D224950216EDD62085A81749CF6C12C234739B3A",
        "86338C2F6D90511244CFBA795661BB5EE8C080DE77EE1F02BBE208658DCA34EE",
        "773A7ADC6478DA951BD1F6738E116D78BBAAC491DAB7200B92C5D8DDF18DC7B8",
        "4628B28DFEBF8D3FAB508D296212ACF9AF60B1EAAB267A29618CFD7EB1476AEF",
        "642B3D64B1C62723B85B796BDBFE763FFA97515B1DB583FEA369BDDB8BB2F13E",
        "CDA16C5AFE91076A66E78CC71C5113C11E6AFD3FBA91E5A039E6B88AC6D7AD05",
        "CC0B02EF4A1F762601B81F3870FB232B2556F4A33B199160E29B9BDBD3BDD2C5",
        "2776D1FFD4FA44C70F69552713397B6687F8B2A992E14D749953506D2D884659",
        "1A8ED780398C8978A0E197FCDA642DF1E5FFD130D19CFA33CC1A6DB0B35C6117",
        "6CE0934B0A1C6DB036413669E0A756380DE984FA22DA1EC6331F66C8B10DDA21",
        "A26F2E906A5AED62A3C3F85AD993E5216F105E13F6CC50ECFF44732D6B287E0B",
        "DFF0DF0A6AFE8CF78231D81AEC31E3B7D36C953A928107883D093EFE8F8AA84A",
        "BB8FFAB5119ACFC0AF8D26857A31F09A961DE47176345FA33789EFC5496B484C",
        "677841DDB385A2EE18A94B325B739B1DCCC7FCB314386D1F966864593D6875F7",
        "ED9E5C116A57BECBD824D9F796DD0705CA6EE0D1BFC185A968D92B48CD3F1195",
        "8CF3CDDE2D7A8D085FFC5ACE66463DDA7562B6AA6C2091B613022A64C9FE8D1E",
        "8B1838DD3584A9DAE4ED4141102DC4A337431D0648DED026B5BB37C059727FF3",
        "CB30680111AF483E8758E1E547C976656D968FC50D9B0580D7142E77227BEFBB",
        "D000D976DB88F217E7F668387C8F0C6CBA468C597328172F6A468C8EEF1DD571",
        "EDF78ED142104ADE10576FDDF789B15A27420978ED1926328A4F25F58C238F5F",
        "EDE9A88CE1F62F1972012F02DE6E25DE4CC1A0D677BB689530960215F4D95C0A",
        "4ED227438887F2BEC9C5CD957CF787D1CA6CA723743E55581437BF2035AA8C73",
        "2630361406AEFE0E1D7D1D180E4E54D6FF213C828812D4B79AC0082FB73D68BA",
        "164B504AB249A073FBB82233C404A2B36CEF00E5DA8276BC012EE3C3FB1F2AC8",
        "A100D17F416FDE67CE5B078235A998D5FEEB1CA7195BF7136259529BD9FA2E56",
        "111B6BE7836627D235D79CADF1BED42E3E5008A50F22BFA8A7D1B9C1A58AE1D8",
        "79450619396C9ACB9293F23614249D80B953B9D911D30B229C0179DD8411DD87",
        "399E4B7FE688B77A60002DFC63E56647797BC5A453D432C463938AB70EA8B68E",
        "8F875C29B8370F80BBB43DFE82DDFF1C097384316A0AA6B0012BA7B2F8EF998A",
        "1EBF3B35E8793C49CE8AB5779AF89BB8F35CD87A4A9AA6D917E612EC021D2F9D",
        "701D540C62548596D182C08F05A074A59B57EE9ED322D06DFA4F44B8E91ABD13",
        "B592C2722794AC34F2AC450387E467BBE1BC430B982FB58AE7B028263AD152A5",
        "09100648A6DBD7DB5D20691216CD59AEAC393DDC96F7C2BE22BE5FC8242D00C2",
        "0DEBB434A031E87B453EBF7FFFA64F4EBD7A51301FBC438FDB7ABDA0C1495D13",
        "16A88EF9F275FB505485B07DFE5F1C327DB615C735EEF50D719D5B6DBD88B145",
        "024BCC17198E127F4B348FBF14E500C99F8882D4424A451151D2BA1944ACF0BD",
        "D68A3A2B49D18B4707B91870C0C1F1800ED558B698DFEDA62E0F708B8A9DD1B4",
        "33DD8ABDBE9BD401EEF709D578EDF06F8B7C26DC5BF4CA580F06265B25AE1752",
        "CC44BBE7E9C988273DC6770B54CB4CBE29FAB6F82A64F89311D558170F53A2AF",
        "04E8DA5E7C3E06DDFA5137161164FE66EE35943228841D762E328FEBBC6F73E4",
        "39281F1D47F35682915A66BB97A0369A69C37667FF32DCA400342C4657625FB1",
        "77902D80585E5DB15E3B51609F4D4C40BCE42FE563F30130773DD3483DD8A9BA",
        "3ADE0D639FF4A0A69DFAF82D70928BE67C3D0B86903D791A92E65B04F4143C56",
        "DC632355DC9AB9A275AD1BC49688F85F388A0887C05A78B982E1DC80FBCC1AC5",
        "170D7D6ABF9A42A85F826334720D586ECBA9DD6B315ABE3D6980906CB88E1DF6",
        "E288E40381A927E62A3F7A13A78BCB0F9F1510100E9C42AFE5E20651A3ECB54C",
        "50530A1DED07C641DC644660E17A36DD8CE2D49F3188BF7319AA56CE88B52011",
        "164E2E9C0A45B6CDC73EA17E200D6744A4459AD65D4D8D0DDE62650251153F08",
        "2A1AB3B6FEFA37F8979306EA596D0E0B8066A0823176AC8E48BFD9F0E537B0B9",
        "DFBF7FE206D2247CFC5AB4B7D16FC56239515426229A808514247A10048C7E11",
        "37C8492F8E69DE22556617458096EB4686098D10555BB6701BC3004FD073D1B3",
        "5B3DD32E5CBAF2820B099CAD0D62F23AC6AA766187421EFA77AA5CB6CF63A831",
        "D87DCCF0401228C76BD2D19DFCBC62B7DB5601B6B531084043B9FC80CC773A0E",
        "FFC3CA43697D7BF7BB7D8CEBDBCB247DD5DF08F12723BB3F1B0D4F91AB522681",
        "79CD65841BB49ADC2A0F2D14AF88E2E4A9D38A064F1BE0638F2B239CF4069DE5",
        "2C613FDBF32BF12B4A9B33C38CFAAEDE5D23820C5C3846FC9B37E50B00F0E6EA",
        "B810DF51F84883EA09F666EF8A0B72B584144AEFDF528958C2D7C5618F248FA0",
        "0FE7EB82A43F57EB00C05BACD36F2FD5E922124D24DCDB25A969499981A6AB90",
        "6951012095D7726A5C6C5C4CBF75C6C482F9FD4C6CDD9D15FE74C27B7C40009F",
        "E3B9E84DA4E91E06AF5E8936D2F112D2A71575015B1F909D04A31A08D02B8428",
        "F3C418D6C4223499FA13395D4B6FD7C15760D630EEB6FAEDE00E90F35A505A6F",
        "27B867AC59DE03AE8BC61C25D519D517690E982F5180B05B81CFE61D5E81C275",
        "C2A1EEA77D78192E6AAC336A599C6C23FCA91D7ED54516597B7D402B6A28BAC7",
        "5F5287470E413766357B3B5064C3140AA8C22D062F50557EB8CA69D971FD2B21",
        "F6C669A6E44A9B2681A13BFC75E3A726ABB55D4601A2E23AB186504AF3F35894",
        "92872C040EBBE8E1F44CE9E620255FA175FAFE0F47BA230DAECCFECB6B235F2A",
        "6A4E3998DE94B4F7AE93D4A8D50E5064091AD80AF28EFFD45575E790D6B670E2",
        "7C0F8EF96387C35AE19B84378E751501071F0C69C4F2414822F1BC1219EA6082",
        "257F3440281D0F27ED7DF92EFCC568FE1AA327183A4541C35B6B85B6E4F1FEEE",
        "F099B2C6E29329A6434C64E4DF1CFB9D1F2A764DFE92F51B685AC9C7C55F4127",
        "B2476196BE45D2276E078D929A22901A7C1B0136E926AE243B453BCC7CFC488B",
        "7F764D1D221F89A91E2F54875F86EAABFCA7C5669B5C993670E4A4116447CC9C",
        "C7D0F873D3BA4523749F5405CD1370EA5D9B30A8687DBED10C15A380907BB819",
        "D4F8BBE75B205FCF78F8114E9D4901C9085C5FF68E5B92325132FDE4A4B322B6",
        "DD3A6081732E5C864BAD6429D7643FA8ECBD5F1F48A66293AE0E6BD49AB90A74",
        "8E9F88E6847C9386E6BABD8F4208093313CC9C1CDE10A66D2816A0EEF5E59669",
        "94560AD252069849FDCF4809DD32F14F7B3669A3EA72FB69E36E2FB486307BE8",
        "C9312B79CE3FEFCDEE73B59AEEE5B0C0470DB1348D81F6EE08B09331DCCBF382",
        "49FA0EBC6AB154BC132EEF0DAA33E995587E354C1DF8EB990290A78E7919A8D3",
        "E590BE90C6DBBA61F9594E928B8CB223D3602FBD12B68DA9179E3D64014D22AA",
        "2E1F959D0F30534B67136BB40698B12D642C0E23E8AA27BEF423FEEB6C039395",
        "BD35B897417B272D9F072B0D31A1EBB1772516D1B930F1452FB2F4D582A8D1F4",
        "FF13738249CBDBB469E05F175942CD062A20CEB8358F4A732165FAF6F8877D32",
        "C44D989623088037D0F1299CDAFF68299D1AF6F2F4221F3CE32C7FFA9B2F54A6",
        "265C4EED37CA6AE19D6FC0314AC83089003760C2E870E013D281E8EAF6D25ADA",
        "9A29686467567518AD70218083BDC9F382E130B0CC780DA828CDA2D4AFF4F723",
        "628D6768914080A9E9037E026B64E95321C6C79554A4C98006E2BD6EC1C60E38",
        "5E5285407BD5F5B0085F2FECBD0087EB04950B8519CA0BAB8F8A56E0F7E3AB31",
        "1291E84BAFF2573B7E23DF72071EAC3FA779301500BAEC0E2E861A6246F0EC78",
        "E81AEB97ABA25B053A6313766370A774E96D9DDFCBFBB2E337A608349A8CBB11",
        "ABF04B4FB2AA0CAFA8A0738B2D4B931E482B0E099FFB41B7FF1F1DB9EB5439FD",
        "D8CE4E2D03B877AC7750DEC363C145FC8C5A1B0CCDF487FE459321AB9F38E8EB",
        "5C6A23CA0EFB057C5C273AA0BC0308954C39FFF757863BF54F71DC55E5D02069",
        "16DEB6AFDDB65B359EA92155E23F8343DFE681AB0F1CB6724CB81809A0BCA723",
        "3CECEBB40BE4F172FF402CF581140B247AB6505B79DE813D45CCA3B6775E492D",
        "B7F4869E524B19BDF0A2B21C093167E23261695D897DFDF6A236D6E895DA892C",
        "1BA9F714F5DB7E48C074994E0002B3046DB6025DB235D63187B983B0759AF602",
        "EA59BA446ECDF137ED764EFBB6620D1FB17EA963F1F2F470AB602FA7626C0909",
        "AA29D08F316320D8DB07EC84991E37B9EEF19D9940F08A3DCE806D4F849F4F74",
        "BC9A7F9A8878BD9375F09ADF068245B0EC263A93992803346B87CC7114A999A4",
        "9E567F2906A5AF8523FC845E42DA5560E1B8A791BB324190B5937C7C2EB1C4FB",
        "AAAC516CF430E9BDEB628B81842773C203745ABB610119484B8CF4924229FC00",
        "6C21DAED711FDD09C3955D657984F9FD8FD3D0CD66C8697A8ADEE05BE09D2445",
        "8A5197FC1E9CD066368CE79BB1EF998E08882B6A339E6BD29596EA298E6D8A13",
        "70AA178B5E0650B97BF4046C4DA3DB4C53E51C61E8A93B182A5441D1A919AD2F",
        "A3AE43B06273BEF2585B2A9F33F5D36ECA646958310C077912A55D4E9A2BC22C",
        "061C2434A4251107E841E20697BF9E815111621B36BA60E342F815807882A241",
        "CF1ACA401D1AA9C4E420267CEDD39C96C288FF8969D2D8FD3D404F0EF827B984",
        "2BD2BF1F11E1A8C23D88C16085E7359F6C2DD021DEE6134D32F4A214F4D59B3F",
        "C9033B2318C1895C11E0D779D7D7E751610F0C9373E3A8D5FDB1A021BCB39544",
        "6FE50E9ABBD51C3CD32ADB6B036DBD44E3E47ED1792E475F557DD8C0F02A76DE",
        "885573451434CC28E9AF733FF2B328600F1488C4FEBE2183CF44BE69C09C0876",
        "48ECD14301951DFBAD85FD7579DC4ECAF32A1A9BBCBDE6B1B3D22EECDE8BDCA2",
        "C5E25920D1022675E4913C6B4E26C115B1079DBCCE8DEF2748BEB080FE9BB016",
        "7C200018BC37D7B58FFF94E4A6886063DDD1153DE9B08C135AF420AD2E17CF1B",
        "360E59F3613E9D5404D39F1E814DF4D920AFCA43449C9EF8E00A1AAB0EC9705B",
        "83095B3DE8F701BEFB59EA1E3E7D52E870CFD8D399A4457ACCCADD1F06C0D540",
        "DBE8F4138011355AF903D0CBF6564EA96E898EA30C73BE8867F902252F9ECF83",
        "A2487D120B0B8C6517F1C8072A6E4CEFD8B4B658F09248DAE35E04A9030BCFFF",
        "643E0ACEBD53C503CF7255EEF9B34AC264FF724040E0BB0252CC3A0D554119E3",
        "DAD88036709F84E37FF61DB9C3332CA3C590828F35511A685D705156AF6C4D97",
        "74EE39A3D362F3250249E70E58A3DE2CBCA3C35539CD4A55564318CB591B208F",
        "A012A26A80FAE814D93E2F15A4C66F2D7CCDCAD54D0F4701769047F4DA4A1040",
        "8AE95FCA0EBC11CA92863DECFBDBB8E887B86829CDF922835869609F337C3EBC",
        "F089EE3ED09B93ECEB03EB474DC6E05466A170DDF9FD95875017731A25AC9984",
        "7BE211A5766D3E4B5402E26496A3F1268041601425F7E378967CA8B702CCAEBF",
        "9E86D712FBE3CD1D9CCB4BA39F418C3C0482626B9ADD78DC6B6BB6FA52A5DB73",
        "27709A384D9AFA5ADD29DFF272E2DF9DD4CF0C05A56CC0C1C06F80645A75FE13",
        "A993F7B87D32091869195480880D71DA29C223D19B106D9C5129769F4D9D903D",
        "7A1C44445A35F347244E0CF17AC255E96E49FFF3CBF8FFFC967D125726BF7715",
        "2003052CCEC8206B47E8DF66682B72D5916A2257942C6C526F62A9F958DBF59F",
        "7391233FDE8BDCF5161B9D083288364F641B7A4902DFF59341B831205B5A2AB5",
        "0B9F47245C88629A8A6EB0D2CD0DAED6F64410045EF161E1F6F98F190993DE5B",
        "F4693671242B1E24847D7EEAB0CB714D6066BC49333F0031C6D73FB0B04FEEEB",
        "FF3194628D0695ACC8D35B402CFE74DA0E5AF9871217A1B8ADF6FC9DC02F2DAE",
        "1ECA2B5D218A81B23403C45567F9D1FD52F01FA5A07580953CBC28D0DA18E258",
        "A0DA6561A11D54793FD95CE404A0A334046F86BF0B418B015B360E9F9017B511",
        "6E582C474A288ED1A07184147C23555E08555BAFD3FFBF54EEEB2DE90A6B501C",
        "E3EB09D24CBA3E40BD40FC8DFE64C02BCBB66E52804C717EBAFC2CB9B7E10CA9",
        "288A6775BF475ABACB98EDEA106B655FC15AE0A62B9A31FD55F64876FCFE5146",
        "84532FB1B8BD372BA5BA96E2FD9BE5F72BDDAAA7831C78090E77A99FBCCD4BB3",
        "AA5AA842E51138B9B2BB21C36A3C994B8D92FF206572FF3CC56C143EC53623AC",
        "E534D22853D2F5FF828341A4E62DDB94BC47402A41262292F18A398321083B1E",
        "2130EDA45EF1DABA59B92BC51D91D52CC0E6FD07A7A29744682D67A5165F8091",
        "E90BD998FB27FC4A164B530D781D2CA577131560804BB118201D1B7B5B425B51",
        "FB76B603488092439BF1108AD7E59393F6F379D2A1CB61EAAA3559254FC434AA",
        "DF3F472915EE9C0A223106546F8472E135A3AB93E5D4F07E3AA1A56EFA1AB2AE",
        "F75C9037C5D9D33A579E83926B989A90FE8E8AAFC01149F15DF86A4957AFB889",
        "B27AE2EC4601B9A097A89E623D310E215D347AA305AA58CF6A353BAD7A2042C9",
        "9262F0567B8351A222B796581FAC1161ECBE10EBD50B47C4FA4AD8B09C3667A2",
        "12DB0710121F569766EA1FA54710E7E8D7B1278628A3801DA6104C52F287E0EE",
        "2ABD92484AAFB66D2AF2F168D268A06AC70C9CB3605F718959D366819B69CF4C",
        "6BF2CA727BE30067E6A53DBAF31DE3BB2BD2627798B23EE8BC54316A09DA8453",
        "9478C528679A8C6BB7B6906EE6F991ADF9224FF2063E1271CADB00B7A4EB4D7E",
        "B8D11837E4A61CFF74F6D655B0D2D9ED7F57EB25B9B3B1887AF141150BC5A35F",
        "0CA95509A2CB209DEFF44BAC234287F8C5CFBD54262C7581FBE72129B749922D",
        "303ED55AB8102FEB8D0CDBA57ECA48C8304BE07173F97FDF7BFD7FE81B72AD38",
        "92C1A7449C70B47F742CA8BC92B21D5FDCB3B8315E9A3912648F32A640FFF8D9",
        "9C17C9CAC88D72AFCB6D3E25E9E3755CA4E420602AB872FEDAC7BC19BBC74335",
        "D21DB5BAF10E18316F7F35E583E55E4D1A998507658A3D9384EB5FC0E9CCDF3B",
        "701D9EE8BD66A88BDA05EB81B11AF0508A4DCE95FB86E6B53AB5D59912721471",
        "562002F1BD44A4205C26F672D459C87BCCFEA26325153FDE87D6682A1F789E0F",
        "DF43DA0CA036DAFFEF8069CA784786905467F7F711E04B42BAB56AE92AEEC326",
        "F6CCAD7F4450E28638AC37B75A58A24469449A056859C8812A9AE3B0C74A134D",
        "303B9926FB31B297A8D843ACABDCBB29990BE0073DBFE6947B02A414EAFDE82D",
        "66F8C097C93A8CAA21AA753A9802C26C03960E4F994AF035DC41002EBAB5F1D9",
        "69B3F437AD52C553090DA13ABA7D5591C21CDEA918E5EFB91C255E0160C1BFF2",
        "9ED929CBFD318AE912A4B44C3E2466F02A2796D3066282C192168C706700FD17",
        "3478F3F902A5DBBE4ED3CFDEED54D577DB8CF94CDA65857069436C09D29F0247",
        "A86A9B976F285AB1D347D59F67D06368491566C248F685A7F3D5F25FC58E086C",
        "FB19DDBC830B8DD7C4DAD74B311C9F9B69C32D28B85F5CAF80A42B65C8963409",
        "D2153A9674C09F20F2B1770767B719B10BA8C762DD65FDB596F9AE39DC9132A5",
        "E5CB4BA1151E6882BEE5860D9385C68A063C15770E9C40457FDA4BA36033A857",
        "A5BD45B7D1E51F681B777E388737F85B097C4DC3DFBE8EC0453FB3FB1ACA12AA",
        "2230A1844416DBB5E4A3F6C472FF567251EC0C0122B2362AED99E71A4D901EA9",
        "CE3BE5B1061E8AD9873095CC5E53F98BD84256F8BDD0A62786B9A3E340C5C68B",
        "F93739DCE7BCDC4D480EA830BBC83975EC98B0324EF23B9BEC6521ACCC52DA82",
        "045BA925E8216CEC1ED681EB98514AF7EB747F3609215620616ADFBFDE8C1641",
        "3F547F19E6050B72B851CC114AAF7BB05684AC65EDCF831AD8DA2A09E4750952",
        "B910FE8E95E4C1065BF806165D7322FDB137642719140A3764C1EA9C89DE3FA8",
        "3EDCC6DDE9B4E2A030665D31378BF31665A15DD87BC13D3ECE1F9ABF319800B6",
        "4D974675480EE3F7B547E23354907A7B3C8A093E94B23E42359F2D1E3B46351F",
        "E55ACB9D6D4AB816651A3D0D08A6B992B6998A6596DAED00701127055C06CC40",
        "C0ECCD290DCD3EE7447EA5FE9EDB9EC3A89585C4DE857FF538716146E3713325",
        "0395BDA5867F3320B8A2973877D2F0B650F87CE6AA4B7E3B0B9BBD861C74F30A",
        "185B2026720416065641862F21521646716936D1ECC78606113644BC4BF2A6E0",
        "D27E42DE63E8F3D0FCA496ED91E7AACDCEC19876B2DDB2C2858FE1FD9FD2F18B",
        "398301F1E287ADF103BF77DF7A91BA5C7E868A79E19D143B11AC752ADE471C73",
        "611E96C7DCCCB9BDEC61580A701B598040DF890AD30070BB64F7D29AB72F8605",
        "431325728BFF7A3A074F56BF9E56301CFB9AE4206D9DA49BA385DC25398BC80C",
        "39159DD7441FE05331A2731E19E8573795484863FBFB17A6212DC59B5A3FA5A5",
        "F2D994BB798954911A212C748325C4CB8C8AFEE33B76056F21F11C9DA4F63E12",
        "F82E15CDE22B71724499AF5F5585DC795BE37AE2B4A96D2A9F86C332DCE03352",
        "A80FCE0B191B246507A4AF68E1C4E725719CB1C7183DD18CDFED98415FF773EB",
        "6E50FF874A8EBE634AC5D3EBAC040F6B38379A435DD71ADB1AE1903562C77139",
        "88920526928386747FCDC2B08EA795E6C1A8A3BCC809816A2DEF296F3011B90E",
        "23579BDDDBD4A2D1745048EA6BE7F62CFBD2177CAE3C6D0735DA1E4894FFB140",
        "D0C58939AF5AC87A4B41E3DB9CB12EFB66BA181130C834F8A66D9344C6938293",
        "A59C62656C6CF1598FAFC4691F3F657846CBE1B9E65D221FF4498DBB6DD51695",
        "7E0F83C4B8E7BD4DA5DB98C2BCE776AF0F6D28BDC245BE6D8C443426E6630EEE",
        "9152EB8D4F7054239D4F32CAD95EDD88B8D22189E3D2BDAE09A3E154900604F0",
        "602B52FE5501DC253AC6038DA1EA2D34DEB61929EF882B1C3069724264AFB03A",
        "C6CF98BA9296771728811003E03C36BC978A7E430388DFE24D789EE76F4ACB5C",
        "2F257E2F65B7641F07D1295477B29AA21C8362919D14D6DA26089CA77D9BC238",
        "F7871962C762E5BA346BFC3172A5D1C6DA7500010F926691F383094C1FEC3866",
        "1EDD4787B1AFCCBBC3A601BC2E7B6E2CA19CA1224DF83029E98C60B6DC051A6A",
        "41C6E9E3647F1056D5CFDF17F2592B05F59FFD4F797F1135959DB3EA4E0890D5",
        "EAC61C05DE4F45B30BC90425F11E1D2B9686504FA23797B16F47C20EE92C4631",
        "3B70022CDD71ED3FC90D12FA07A973976B8F4D2863CB83622E972EFE728C31C1",
        "BC02C2FBAE9020CF6F25685CC0F561670617D51BD881347FA32A388EC06C8300",
        "67ED4A27197A16558813D4650229C1ACD3B4B19F9BCF268A69C24957B3117C50",
        "445DFFB3EBB2BB66FC92327F05076FBC7B822879564815AF1846C0EA2995D037",
        "07F1673121C33CD113291C1131F055A60593B218AF84E63E2E8CC0C77AECEE1F",
        "15625E137A6CB8BE12C7096F1AB8E0458308A0667295F1D739BC95F307E44FF2",
        "CBB524DD7AF50269D0928604039D5CD62D7F05D0B44903FAE21B6F36B65B9100",
        "C49B2F7B0967F299BC2B7B97D89371456F831CD5B486BB050A3D50EFC87A5A03",
        "7CD1A9F2F3D59D447471E1021D5B9B1DAC2FA7FCAB94AC7401AFB7E54027754E",
        "13EDB18A6A4F1C4951AA40D82302F3938B8AAC1EA1D2345E53361D89D44DFF21",
        "D9EE5D03340A50B08E9DC9CA45FCAACD829E48CEE34CDC8DE0A6916593D4645B",
        "ABE33187682919FAC03CA57738A0DBB4B65E17494DB8731258EFB6024B39FBEA",
        "A57A3FA2B973206ECEE5D02D923F778A13597D03A53A1E183BFF5C42783A9554",
        "9D4FE76E700CB283D44DCE8E87B1EB0B03FA13ADE98850C35BEA2C8C2D80EB69",
        "94C1EC9C4D24FFC17924698DF71D35DA15603D3AA7ADD759CB89EEFD0C095F18",
        "7FD80ED61BCEB3886D5E2AF2D2890180EB23A027C091F8B729F9E4F7D149C968",
        "D43B7364D04E306BBA341D167C930831900BC632097CEED0780EA4952572B134",
        "9084B5CC4D54EF1B33656C4A585B18C2D3F82777A57BE852A9B9342E9BD20B0A",
        "39E91DCC08B082E633D54BA8BFE3A57A4BDB74D176FC728A27C57129A17416C4",
        "8BB44A34BBFB2BBE16DD8589584F9F92795E2189AE18650E5518D2E648413669",
        "1D8A40B75B1FB6CD3A185F4A668E38D3AA35D24A364D5274EC4DBC7B8D96B63A",
        "49E53DA17EBF52FE8C67F40DB1E650ABD24992E9A3FA5F537D8A54EA773EEC74",
        "48006F6736EA5767D22DAB79B38AF307A4619948085B18A81FDE5DE19FFD2D0B",
        "6C480188A06847554EA4E3C9CEB368975A3C74F8ACB3AA32326F9B57709D0B0C",
        "69345388492DC566A2F77870DCADA7276138E4085E2EC0B80CD1F6971A908232",
        "0FF9FB2EAA58DFE6CBF5D879A585A6B7E902DE1C9D3A1AA0728B2E15CD64D595",
        "976C6471A8E93548440FF9CF26906871AE589BD9ABCCFEA3C76994A3C7089622",
        "7986B818A6C4FE14B587B8D6E6C0E5E44A43C955C20429D40EE02DF2B47831B2",
        "996EE784EAEAC9B5387FD81C03AA67A2983D9B0ED874B915ED8F0CBED8CF17AB",
        "1B00027F32D738D093C416973EDFC1A1557CAF814AF0D4FFCF2205C20D0DD2B2",
        "C8AA7DFB6AB5BFDE511C4830B8BE0DF28C4232A446EEE178B2E4F288280F8935",
        "CBA3B3AC18CD172F39402D44FBBB650C044B5A3DAA115CFAC323F62E00832ED4",
        "8CEB678EC0AAB2AB6F49E4CB82B7C4026E3E39DA0C89BEAEF837A637D846CA78",
        "A3AB4040343EEFD5D4A495E6018A38D384D7C65D226FF06A012031D6D17D1078",
        "07E071EEAFC09EA6F5189B01A88F6F7A7790F6D9C41D4CFA12881E8A8D8F2FF0",
        "747D7EB5FDB9559C7260A5933763D37AAC44FF7938E9129CA23B2F43B4F11FD9",
        "C11011FECDBAFB20538214064274C0917F3D34BF953B971C1B894FDAB705DF12",
        "6BBE4B3748316228876D44CB6EA1AE51189DB491FB6A6E438BE5CEAFC09D9CE3",
        "6E9E379B877B13CB9FD8C318DCB503E8D886DC5654E68A149F4542E04026351E",
        "936FEDA97D3874E1E46F358EF6DC409F02BB11DC7FC42307BDE062732EF5416C",
        "FB235F55D45433EB5D056CD8455AB84BB27222F3B28C6CCC0DA7FCEEF7E2D911",
        "1A00DABC6015D3F0C5AEEFA23DA4EBFCC6BF6FB5FE4869843C22AA5E6D601EA1",
        "27EC7A416AAD8ED8F4E46CC9137DA02E9455EB5977C25896F4665E2B9F7DD22D",
        "C3C34028AE4DB91A8B31691FFC4934E5CB4CB82ACB27E50CD367FCD2DCC3ED6E",
        "36F19C26361D5CF7BDEA2F60585D5866EE5C340C9A547BFCBB88CB8DB26FB9B2",
        "82CD69165E18B5C39F493C37E0252448B5D4209C53937E33BEDFD9A85C15C045",
        "DDEC8AABD47A37F0F5033369759CD6119CBD62D07748A0321618D8F01215492C",
        "957ADA92667A661695784B907689FA473B721F1FB607C2A8F32237C14ABE64AE",
        "3EF7DFE247B0877783A02F0974569A09CFCFBE7C7E8E658D4CC5C6E6DAEBDBCA",
        "7221AC1EF595C8CAD192C0199EECA1AFAB3277F9C5E928D99E6E4B31A733BE7C",
        "6168B6B737112BDFAA886A9FF7B41742BBD5E6482FBD72F772997A5E97506AE2",
        "373DBF51039525D92E5059F55F06730C06E0FF6C354FC40F71253A4CF5BB670A",
        "F9C5BAAEF8F74730F6D7B06A62E149159C3A0925B505362712471290ADDBBE2A",
        "FA131FF6892769B1B8947FC6C4794ECCF8F807F1EEBCB95581141D5FC41A4080",
        "1759B0A3ABC33ED45C5C2CC15BBB6D03A320692F756D4D6EA31CAE65A9F25112",
        "D2FAD95A87FE41564CF35827D7BFD67CABF2ED162632929F24F3BE0E147B150E",
        "2CB71AD03BE86F37A2B989F0FFB52DA6C276D2E02465B48BF8353565CA8DDDB9",
        "A7C953335C50C8B60363957E886D7EBD089A19403C004AE1AD0DB8C287347736",
        "6EA8964B6836F70CE8515807FA22157DB8D02BE4D60D70811B6671F9179468A2",
        "8B2E6D15E4A427ED770B8C70321E2EC677EF99E7C0C62EFC1BD46B441915C9B3",
        "23452F45494A02776FD16E320ECE92EB1B0FE81AF742F352C29796512A8CF9A9",
        "5BFA54C36D34AD7427FA000363ADA8B188D73CC922A166793DEB482BB68E3F8D",
        "CBBA61D2874476D8763CD740F4CBD1F70E7E7A3098921EC43D12F407CE5274BA",
        "DC6DAA4D4698B7B31B2D1ADCF1DA72449756A2513860B5479806FC4FEAF68821",
        "A94D6A62F33AD0D46DDBB2B0EB029D97A981F3BD5903A93552D3A81ECF6806CE",
        "1AE4BF72E6816CAECE250BD97850A5017B1338CE2E042A72084F9B21BBF225F0",
        "0272A390496D8AC130A803EA4CF7A48F8C218B01A72F3D5A09903F25E5691321",
        "6654D8ED48964237AB3351D32F5FFEA2B1A5314EC2D7CD47D7B23AC53719388A",
        "54E85C4A0ADB1199DD51DE6A4B1F8E6E7A4C13DD3BE5D6A01D3F670283DC9F80",
        "1B8FE51C17F81CCEE9C0C607F556D7FA9E2FDCE92C5AB9C351D12DE76A244415",
        "54408E12D6055376373B4C51D88FC06849EAF1512827F51140264A528208AD04",
        "62FDCAC2383E0B745D48234C37304F4D50A08AE76AE5F63E79C1C5C39EE01646",
        "6AC17D237E1895C0E48AA8B6F2E7119831E7631BAB0DD650472AE53D674C530E",
        "BFED11DD05D152520EEEF7DA5F320F96B68D4EA2967442E55DA8F9BB7D5B0D95",
        "4B9AE75EF2F73DD1A85611B6061F5BE3015C7F7AEA39926E65E05B093FB2CA6D",
        "D8AE46DE2D631531EC67F5606F6479275F23EBB8A3AF0BB4CAB00D9B96EF15B3",
        "EE08EDA2A314B4C7789153C47ED1C3D39E70DD5C188B8CBBD34BA238013C670F",
        "71391BCDD2CBCD6F2CC1D53267864AC98564AAEAE253ACF99A66365E3DCC10F0",
        "5A0054EE115965B71625FC6AE14E26538D4014032669B6E67B4CEDA32A2352C9",
        "AE7C994B08D53DC4301BE31D59DF2BF17ACCBF4260A053FCB914E37973F4169A",
        "6F98E7B12BC9AABEE2B8F7853CA5E4A230042F753A954B1C9D13385685415C34",
        "BB3BE3E23CE3A388B02B36C8EFE91247E652E70ED89D05CCE6D76FF98348E038",
        "BE3634F5C9305B019DA09BB7113DD7965A9AF3E7B41C790EF811008877C1E329",
        "9010C9E70CD506155167D28F8CB0FDCBA7B2BCE760061E4DFFBAE6582B6E4C74",
        "D85570D8AA722673F8321B5C5640C3A920C68EE395C7B46BF42AB73848F248F3",
        "2B1571897529CF44C2F1C44A68A9EE3CCCEE8FD512E04A36C421602F88912A7E",
        "0154DD5147918D4CA76BFD0D28649615732BF1E30C76899500455F944889EB35",
        "FC0873F81AAB8C2503836EB6596753940AF61D5208775E9CC2A348F3D4F01562",
        "608C2E65F2B4D147CB6AFAFE953332BAA726767013598862F7C01B882CC2E259",
        "6F17D60237C3E41B6C380C9F80228D19502EA74ABB212C5163DCA438EEB78931",
        "19CE6F37775E1296B49909DC8F70E3823C4AE05D9EF86AFB20A0BCAA55B34E1B",
        "09E11178159E876ADCBC21CB617D85F3CFBF0197D53E93AFB3943A91B638ACD4",
        "7F08C9584BF7C63ABE3289C888E6A5945D822F0380EC1AD458A9F524546B283D",
        "0E7BAC9A0C12070A47D1A3AB810D5B37B4EF9254A1DBB26528F1F24C104DDC7A",
        "C666607B95FE188D60D2599B765430941F040CAA6BB59C477D23D2E65FEBB2C0",
        "CFB33F806C5F9E3057D856B1662716D3586DC102E6564617F520F269F9482DE1",
        "5360D4C9862B0250A823B411805B5CE40E45EE61196B74448B32ED84FA196F34",
        "D0A097AD942362AF1438F1664E612266E66E90CEC0B730FCE0E5E19AC1C75DF6",
        "BD2562CD6F4EC7D2E9B2F222566FB2142ECF17F031AE85DC0F90595A20B5795A",
        "718A27485C9AF892C732C792123AF49C567AD48441826A7C1226E8A713958634",
        "1C6D4249B98B115936D3F29CE5E473B837110F3A4014553B9D8C5898825B7DFC",
        "5473FC44539E0CAABC82CB4CFB08A16E3CD06C9FA92683A5FFE116DEDD14CE81",
        "F355CB24E4D8DC62A41A8F53C2067B4B4355342202BAD55662F36A37234520A9",
        "18405AFFA762533523430FE954239277F566C70615B761B8DF9B2048DB984772",
        "D6AF4FC81477432713F16A3A928DBC478662B497D944005780F51A000A974F3E",
        "EF25E623528FC1A8F2CD8F18DCEFCCF2D62178AB7B41BE3A58C9B7BD206C3BF7",
        "C42963DAB93E5037A20CB4C7E0F07596162A294340D30A61F5A0696D7B2E1193",
        "B83074C3EFF8D4B1868AA7C87ED69FAA56A358F6DB3AD5B5B238AE82EF253810",
        "982105DB74B60142578C874E1F0CFB59F54B108AD3ADB32B36CC500DDF3EE091",
        "173306978F5A8D08A56073514C93F41D169CB0651B590A2D2C13363A285F2E41",
        "B510E705298CAC70B70826B99A36C066EA4CC1D53163EE2554E9B87E1315AC7D",
        "53677D6B0E5BDA430E04226E2765ED701B6502336AEACF8DE7D7029B06F7B0C8",
        "B44CB94A6A359376561D7853F411E96A6F84A7F962977B3D5EDADF7036473A08",
        "C4D4F150F543364F92C5FCC34E91921D0425B81D00C1772EFBF71F48577F8309",
        "76D603365CA99A5A92D0E55BAEDB81A454A1901556D60393487E2A4196D04BEE",
        "A83EE56A26036AE5EE61FEC16DEC364DE13FF37F1E75A5FAB63B8BED76568A67",
        "45799FBDD92CBB7ACACF3BE7335C0DBC64AC8D11D66242D8EA411E6606016D16",
        "DEF683D2B7BAB6131220E6926D6F0B34DB93AB185FFD40CF806103AB8FC79F4C",
        "CA3C61294B70B1CD4F05E49CD5818C9B44378494DB2FDA261B100921CC2A3238",
        "A59FD7748D7943014BCA0B8C7F4179D44B131BCAFFD39AD8CCB535B1D5662611",
        "348BA2B1C241B0C28B1B00521E92A21662C9937C42714390751DFE1E8534FDA7",
        "6BF398B511E4EDEF873BD08EDB1FC9352DAAA97D68627876A89B6A4DF446F066",
        "7BC2EEFBA3C7A0DEBE36C83788FB598FAEC37AB1F2CC27319AA414B72E02C304",
        "6B1CF35322D7529B1563F31F522EFCC3DBD38276E9AB271A8A2386FB2C47BEE8",
        "8D41D21CD0886049548283224D4752C560E148604E61A5E5750E4A21E19838DE",
        "D066E0648B0A795B129B644FDE6CAACEE511D100A16821BA0DF487D00AD1BECD",
        "27C6EB183C708B774E05278A07AE8BAF3D014FFBBD6F8C163CA246120CF3ED7E",
        "6F69914851582F55ACCE15967D78698863E6ABE94E1EF95B9654041D18B564FE",
        "D2889C50B2F8DCC0B4FDD1AF38B97DF329ECC1341E48F6B0AD596955441B62B9",
        "CF2E575797CB0682B8474AEDB1490BF8EB80B3E9878856E6CF29860DC1F58357",
        "44FC4B62CF77B5475EA8AB5254D5B9A281502D840722791FF547D0DB405AA0E3",
        "6298D269F607BC10497C6EA82B1F545EBB6769B7B7572A316AC46BC8E98AE4E5",
        "A67421B3BA964ABADC60342B007AC635128CE1DADD93EF20340CF11CE0E605EB",
        "86E322BDB8C4A2608585468CC4CDFA3A9F0CD684DD750EDF4CDECD6DE4C92216",
        "2A3BA81E7EFBE11CBC3F9BEB97549858246C02985857AEC07FDA778B9B6D0F54",
        "58FEA944E843626574E7F318A10C31D83838C515B63735F71E1FB1B8B75A4837",
        "55131B9C486D9B1EE4C921ED98508A20201A6CE7548AEF1B9DD7846E98F4061D",
        "21EC2184AA6D91288DCDAB6B2D55BBA13E362C5B1F6A53CF021EE03E81ED3AE3",
        "267D3F2D4D3C05C6C3946F461E1220805831F694AEE861B29C55C77521B7DE5C",
        "B288171BF87855635369F93ADC2E5DFC48107976EDE5D0300D54D198FF9566C8",
        "6D7F3E2A0F57480949E3F6D7026B4574E4842F0A23BBB79254BE639228BBFCA5",
        "B25FA3992361455551F8A24FA406DFE3F421ED90920FEE546B5CE98A3918AA4F",
        "6F760B11DF6E44F809D49B46D99BF8A1C932D4924CFE2D4B0941ACB68D05A59D",
        "24796B84760D2CEE03D57A5574A3DA3F0EB237D5771B86BD08DABB4E78C42B14",
        "2546CF9524AED808508223AE633BD29F99D17A2E1EF9B6D178E09D9DE7F7B0A2",
        "0DFC49EA656C77D0DF4C4590BF49AED088ACA80E7F239A00C5C679BFB470412F",
        "445CC5BEDF8E541BC9471EB83A5592B249280D6CA756B63F96AABCADE25A92FB",
        "810139A90E35CF81A1EBAEF5825F47FA3E5289E3DEE29FE6CF709639B8ABD5D4",
        "2F7587471814788119662C63537712AC1BE984A39B7023D377856B29863F40EB",
        "ABCE65DD2C38744F3B0530DD5CB7F29055CD5456C45663AAC07876EC35B57CAA",
        "16D0B8069C74E5103241127C4B8C2F52DA4DA2EB47BA46D4B7B258D99D85F15E",
        "35C942A5DA64223B9F9B43A8B8AF9BC2937B2EE0AF7C9DF6FE342050FA6D4C56",
        "CACDA30E7C0289E9C2869DD57D3555B635D060D7E34B6FD8634FE1287BED11FD",
        "C9BC409B35C8D6FA33B7099E53A6BB708C0AB7404F11619BEE14BBACAAED7782",
        "C5BC5E50760DB625C02F968D4DAD8131062AEA35916B5448B3FB42A8E1591B1B",
        "FBA436189AEA611FD94D1EAAE4622201D04F9D518745F2C2AFE7F09BA85D1A1F",
        "77912B14E7EC8913AF19EE6079577E3C24234C30947A6FB22B9423EBA1D80DC0",
        "ADEB42785EF015879CF2C4F390E60CA9BDD722F49A5D354CDEBC8EFB2013BFFC",
        "0BA1F44FF1CB0BB92890BE99870CE41A644765FB2F6B2D5151D8123318B7015B",
        "FC96AA69B97F960647C49FBF263281B0498BC15794466DE94EA7B98EEE261B83",
        "1DBA5D248E91D67A603E2DCE943CD18705EA7A9065F498988754073617030C5C",
        "B7D1237DA982D2FE196FFD9C913F7507BB78CD934E6890D7DFF38A947380F2CA",
        "8AB4C01F0371E7A69ED8EF7E7636610CD0C32628512DC4D04077188DBF019598",
        "38FC4EC7AED06C7E5152937F7BE6A36A1A1DB659CD0943E597CD783DACA1D210",
        "0245D7CA151E99B01911D26412A63F611097284EB9F2F4D9EFF29AC9EB7C7FB3",
        "0A141689631A7025BD5D4C18371F7EDDD7773D3465E704E7FB31CFEB8163A290",
        "357AACBBC68D1BF2448CF110BF1B3175F3F6F59CAB2536D933FD572EE2CB4C22",
        "F594C69039D6FB9B59C815337402B8AD4478FAB81F3DC23F08D0E800EAEDDC0C",
        "377344BC11E90CA5CB71BFC0E07AA6CD2CA07BE28E2FF3EDF646F174B3231116",
        "B6BE02677F8CBD6B7EB6FFD6F8402DA86DE0941F61819804418866E2A9FAB159",
        "8374964C99259A4E4480194CB79A0AF3F57B720E537C9655E5FF894BA438D4D0",
        "31157666554779BA9B5899F7F5085E2A76EBDB4AAF08BC83B218F7407E11CCBA",
        "9E4D75313C2E8121452EAA71A959FCC424A188FEB4BF357E44152C57E43C4CFC",
        "BAE372CB74E011BB21EA7381371A75A98DEB5959E5D822DAD4920E3697072875",
        "1676EC743AF0C23AF9AD35711745FEEBFD8C9B24530B8D9C208B7CD41E541717",
        "C67AD1A7F5BA2F0314F7C542F087B31F6391CBB43A54A91872C8B8ABD7A406D6",
        "8BF498F73BE0B75FDDD53DE11ED2584D2F724EDF46FA8DD5CA1C4154F3937A34",
        "10539B4DF196AC2EEB25AEF995D6069BD3F5A4A21EEFA56B5A2D5253A1D5EAE8",
        "DEAB73F0871F26D0A134AF21712462CE83EA15E795F2EFABB87F8F3020817F3A",
        "4AED3CA42D5EE04D7AFFBDA06E6BBA5FA47F07E63C3FF3DE6A4723003A2F8E0E",
        "B3292967854A404C565E92B3520669FAEBAA49DA1DB15ED9D3AC50459B1847D1",
        "8F3430FF04865964176B03B7F62AB60212F8A348D4B15BE61C095C18C73D2764",
        "055D7DECE64DDF79ADA75BCA09F663CC56461A88ACB1FD5FCE4FDE039E385714",
        "8B3CE78D6FD057D34AAD75C5A17A4CC6EB2276D726BA8E1F68DD8E62A3155CFF",
        "5B09C598D417D80C064B2C5748BE0C6C8E683F5E8D7F53DB90DA0D832AFC3D79",
        "9DD88E05753E75E825D46987A38CF66915B2442F9CC9597DB844E634C1FD9A54",
        "F920DF48252B66E168C6BF32BE9F832C5C799C91D2090D7C8BBC8B57C70F2EA1",
        "18303918993F0F01C4FAEDD10901A6B2129667AAF41B0578A02B814FB407618C",
        "82F6651DCA153C8594FE7FA44E12B14B246C84951983F1315CA768225DB17118",
        "383E2E8C6DD25E072313D8874AD357E609ABACA9C81CBC875C35F4358577CE2B",
        "075B5F52B387833E6211CE5025DCF2C4631A5CA7B3D03481C9C06A71AF5AB9F0",
        "562E4F7F281019B1CA7413415D08BC6CB24B2BC32F2137220E1260C424BEC26C",
        "7F5318DDB052D8A66AA6CF2B8007C668BF49901FFDECB72DB609DA0BEAAB3AEA",
        "4DABE6E6046407EB3F0A03E774F468C14FE3156E0E6477961E6C44BAB0C8A25B",
        "FA4FD2D3606BBBA9149ACCBA5E5E7C32ACA2325384D2A7F3008DFB8453EBE1FE",
        "4B27D2524C1C3FBE9BC6C48FFE5D4F756266E8D5D1023125A1D26A89FD807FCA",
        "C193089F530F4B3B83C9E59914556DFA57C1D21C5D1D3F589DDD45DD6FF02818",
        "C8464CEBB3B36FB0D098D73A08AE05E7CE8D00F9BB190FAC5A207EDBCE525898",
        "42E9B1AF2E4A3CCB7DEDA84B2D3B38310F0CEF43E0A1FABBFD3865A22434F80B",
        "98E8759873659045D3E3A4B2A4AAD60A59770A5EAAC518B49714CF18130B88CE",
        "92E5653B8C264124BCBE28480D490130887FE1AEA1E25842D1800BC722B07CE7",
        "731C7EBEF3BC5033B56B767BB8016EF6A4A1477EA4F4DDA8EDFE29AFD0D1E3ED",
        "9CF313B51B5F3E629FE28403A335F6216464D1B2748B556EB0B8A863AB15DDA8",
        "6CB7486BD4444DAF143BA7C0730DEFD62E54DECB7F34C8D0C65E23E01AEB4D6A",
        "35F4AC6D260A2469FAB2E8D6415DBEEE27231AEF5FA5D2247CAFDCA00D6C8433",
        "8EF294725A201D318C5C233FA50C878BD8D5E2908DC3C459F6055C781C1CED7A",
        "3927F61535732259A0634A5C619F7F3B2A8B4098680841BB5BFF081A39EC1CF3",
        "551760E700A17C4478346D153F27360979FD466E55780CBA416B8089A6AF9593",
        "5A5BBE88E344B5791AF98B4ACFEE6DC7466AA7E82801FBE15140BE6FE8ECB8C2",
        "824A6246085AEE91A9B194A734F3334C0D4E3B3C50E53E84314D87873D7F91A0",
        "9ED6EEB47983B22CC7EF95CF302C725A0A856A730223AA3C0072981852C30AB6",
        "C487EC96B94C32237C531B11855A0917B8C4553D3A87BBE77B30A7FE781504E2",
        "F5836225D5670C23559EEEE94CBF8E819FBF49AAACDC2F0A89EF931313DC2B3D",
        "DE01E738A5A72365ED5F6F340CA8BA2655DA4C812B9419A394E5DA016CA30FDA",
        "A9BCD1B045926C9AC70974EBCDFEFE807C50217C8ED138B7C43B21D4B7AA0CFF",
        "1979B201F5031BBED5DFA2B29D080294D7AA12B794E852714AF379B425A35008",
        "9E5423BD9602ED3D84E12E3E2FFF458AD85E62817079125CD1B71D7F990CC5A0",
        "168BBA614D0310C7D4B8AD8483C826756272124716978785B872B2946595CE81",
        "461060C0D1283B0D389D0E1E6D8A5E03DE872F418D7FF29D26667FE12B76F279",
        "AE43B53D57AC4170B7D6AE4D099131923DF5B05CC1F666F775959CA30C437FEE",
        "706C54A65EF109599D0BF2D6664536DE86F49A957048F7EB709FC1D8292B1256",
        "0E62A7AF61A1A88509B7AD83B8EC5CE2CED3E3DC8BF0E14E8E1D61BDD682BDD7",
        "04F1441905B5CF3A2E0C223F6CFCA31680B3637752B257D8F5C42667BA887392",
        "34905894DF4808022E47F024479FEB37F51D371BF4B2B40DE276C6BD2D8605BC",
        "679EB2FA881AE3FCB533656A6B7A9E931ED1D143863D6B25E8B0727A2D13F873",
        "40A555D8A2F1D96570DC21A5A82CAEDAB9ED3A6FCB06A9339618A758DA26C85E",
        "D8B04C2C982E3392CFED389159F0EF3F3B5964B661AF34AB0286CB1E10E48EF0",
        "AA5ACE0C596A2E699100A15639CE7DA0D190B8DFA46DC394E7D3C9BD5592404F",
        "5B9DE0869302771F463D8CA83CF358EE52A32F98551D88976F3AA7FD94882781",
        "1D7290D4B87B0A665363ECCB627EF68186CCC7BBB2E056DED42E145A84164292",
        "7D125B6755FF2E86969BA5E2EA2487017E677F17C6B5498BC58B0CFE12331099",
        "66D506A83FDEE09D02519482D5897B0832CF10D2D28DAB300C1CD9E6D00FA533",
        "1C5AF9779D623645C6AAEBAB171F3373DAD9053532A0DD11DF22D9D0EC989141",
        "28CE181054B8E2ECA770CDC9359DA6A7214F6C5B20DC875DA350F68FA14560D9",
        "764C02189C22EEF8BCE320A677119D6E0611ACF8A68EC1F3AD13E6F8C9ED3FE0",
        "DDE5305A34664ECE309A3C58947660277C2CE8A7B3ECFA54A6688B5032EA5E28",
        "0922885862E85AB431C0943FD319B7F5F6C4AFE43B136AA0ADF6D19285F652AC",
        "57199CD156584CA3330C6BE1AA27D6F64B001F2F5894DA28A3DD6C6383D4965C",
        "50E5862E369C340CA319505400959CDF85B752CB9AF18087DD62C97B86043890",
        "92CE9EB54AD9583E8A99C337793325F13A19A8E7E8672C691E0063049AA15D6C",
        "91B119AF8026373322D8D0D051CF239314CFD2F513919C53CB28D3FF12F12E26",
        "40F871629FC4BBF64BC628AA371F422FF0F91F69C296147DD75D37CC9BB66EBD",
        "BB64035DD8E05A900E66AC2AAAC6DFB3D8F4CEF3F9DA8F637745814B65BC0C65",
        "FEC26BDAB67A28B5A837818E601381FB472B2922A2C8CB1D4ACAA5A87F40F403",
        "EAC2AF0FAAF6F4F9EB29775B5CE496A0C64DB1F30B79CB8FCE7AF3C2BDF6FF0A",
        "6BC4540F86390B40EB82B4120DB6312C99C11F0F265F343A08D5452BBE39D6B6",
        "BF5D78AD92FEDF934901ADF8526C2047105997D2CEAD569E75F5718B4A88CD15",
        "4508647EB9CB748300D569D40758F5A55C47DE8660270BECA7E0FCF0AAE516AD",
        "0729962DBBAE492A5BDF4DA570B7327AF24F48B9BB4804D085A213F17E465076",
        "925F6B903EC4F9A7BF38BC142BBEE07CF5D15E4A8F5085ED7AC705CDC3A3C593",
        "398844D2F516CA6A6CCFC3DBDE0FD743E8594CFCDD7ED2F125F6A873B89068EF",
        "CB69496CE8AAD7F5475CEF2A4228247683253B53F3A3E5047B7E7F47ED5F1BBF",
        "82C474FEBBF18031EA6A8377D358A96CD12C080DC4828DC9368D61BF2161F11C",
        "FB2B797FA8EB0158C1268AB266C95C77638F2520EAD1183F6A97F60695496821",
        "2B46EEB2F4BFB43D8276719B1073153F812B48B704291260DCE2C3CE90851987",
        "C17C7561B18CEBF80F20B89153F3A6C095181CDE883B929B241C93B9F16EAA70",
        "57B2A076C69A32B2B79C3D40D34403161367D6AF9493344589572DB06C2C4A29",
        "F6C3E0C853BD9AFFF5B72EDC27776476ACC2927CB72B2769CC1C6F839E98ECF8",
        "A33DEC2B157BF9343816F8AE901E2E53614452100514AAB9226F2149A87A7B5E",
        "8E283CC7BBB810A58B276CA18ABE09F5C7CCE757BD6093ED09454E85A6563899",
        "CDB55065A5D1EDF9C74DAF8149EEBE464C4958D470AD7DA9DFA5521A5575112F",
        "228D3AB8FC0E8C7CAF5B3C66A832208751BC99175AFDFE93C90492ED536B1A07",
        "7417F3BF327D4FF1C9D0A1682796A56DF6C2761DF1342826C39F5841F9D4008C",
        "8C4E5F3FD87B7B18E11771D92B37DFD3ACE22A2A56AE2C55DF743C4EA9E6D8F6",
        "044F1C7EFEE34163AE869A7C8D507740A5FEB62197858BC308D4A5E83BD27C9C",
        "701F220583F76976AEF8FBBFE006DE24CBC9220149A2EEEA4637F25461A1C075",
        "B45247312EE2A4E9523B8344961826C44523FA45CC557A382E146B7858C9734D",
        "F390246DAB3D595CE29161F0A63B5100D71A716C3F8FB29DCE644D367227F272",
        "C4D9770097D3D86D934437A69BB05F3C7827E2A899D30CC2019D63B4C74D116B",
        "4297AE8D0F83C76D8B89E89FBC4619E03C13F1780D4A63F64ED7BBEEC7E39C54",
        "CA599292D4D88CD4F931170ECFE0EFEA35E89033ED03BC4F9041BE3E69368309",
        "E8DDC4A0884C4D0EC2E57FA2E00D81999439B9701E6B3DB9D2521590C216326B",
        "7A153B9D8F827B74AE81188D963D07E9E3FDB5146F7D8DEC535DC2B3564128EF",
        "882EFC17BA572572CDC48FCEC367B5FA40F908883E5ADC0BB83518BDCA1EDB6B",
        "E97F27");

    const KAT512_MU_INVSIGMA: [FLR; 2048] = [
        FLR::scaled(-0x16F9E6CB3119A4, -52 + 6),  // -9.190471153063714382e+01
        FLR::scaled( 0x12C8142A489B3C, -52 - 1),  // +5.869236780025413047e-01
        FLR::scaled(-0x10A52739D97620, -52 + 3),  // -8.322564895434936716e+00
        FLR::scaled( 0x12C8142A489B3C, -52 - 1),  // +5.869236780025413047e-01
        FLR::scaled(-0x1318B5479C9F93, -52 + 4),  // -1.909651610921680387e+01
        FLR::scaled( 0x12C8B0C2363CD8, -52 - 1),  // +5.869983475876336954e-01
        FLR::scaled(-0x16ABCC6BBDC16D, -52 + 3),  // -1.133554398242332617e+01
        FLR::scaled( 0x12C8B0C2363CD8, -52 - 1),  // +5.869983475876336954e-01
        FLR::scaled( 0x1FC1339AD7C928, -52 + 2),  // +7.938673419399755460e+00
        FLR::scaled( 0x12D72DE0AA39E9, -52 - 1),  // +5.887669933306912684e-01
        FLR::scaled(-0x1CFDA859EE5568, -52 + 4),  // -2.899085008686725473e+01
        FLR::scaled( 0x12D72DE0AA39E9, -52 - 1),  // +5.887669933306912684e-01
        FLR::scaled(-0x12247BEAD535AD, -52 + 3),  // -9.071257914091654939e+00
        FLR::scaled( 0x12D846F69991F7, -52 - 1),  // +5.889010254291510149e-01
        FLR::scaled(-0x15F19B18DCAEBE, -52 + 5),  // -4.388754568839566161e+01
        FLR::scaled( 0x12D846F69991F7, -52 - 1),  // +5.889010254291510149e-01
        FLR::scaled(-0x1D165147C514E3, -52 + 5),  // -5.817435547946094943e+01
        FLR::scaled( 0x12CFB65140B836, -52 - 1),  // +5.878554903954469335e-01
        FLR::scaled(-0x15CB17510E2B49, -52 + 5),  // -4.358664906684732188e+01
        FLR::scaled( 0x12CFB65140B836, -52 - 1),  // +5.878554903954469335e-01
        FLR::scaled(-0x115A52CE4A54D6, -52 + 5),  // -3.470565203313314839e+01
        FLR::scaled( 0x12D02A021BCF08, -52 - 1),  // +5.879106560882698673e-01
        FLR::scaled(-0x162E179E49B601, -52 + 5),  // -4.436009577368896117e+01
        FLR::scaled( 0x12D02A021BCF08, -52 - 1),  // +5.879106560882698673e-01
        FLR::scaled(-0x15C8751E3758F2, -52 + 4),  // -2.178303707934623645e+01
        FLR::scaled( 0x12DEA485108B5A, -52 - 1),  // +5.896780585211260917e-01
        FLR::scaled(-0x13D8197D0C4AC8, -52 + 5),  // -3.968827784633828060e+01
        FLR::scaled( 0x12DEA485108B5A, -52 - 1),  // +5.896780585211260917e-01
        FLR::scaled(-0x127D155A33D576, -52 + 4),  // -1.848860706105684670e+01
        FLR::scaled( 0x12DF8A09171D70, -52 - 1),  // +5.897875001473220635e-01
        FLR::scaled(-0x1832B3B66806A2, -52 + 5),  // -4.839610939101591214e+01
        FLR::scaled( 0x12DF8A09171D70, -52 - 1),  // +5.897875001473220635e-01
        FLR::scaled(-0x19403F2E9E009C, -52 + 6),  // -1.010038563292495724e+02
        FLR::scaled( 0x12E356386503A3, -52 - 1),  // +5.902510739762089065e-01
        FLR::scaled(-0x1BE2130E237338, -52 + 5),  // -5.576620651942215545e+01
        FLR::scaled( 0x12E356386503A3, -52 - 1),  // +5.902510739762089065e-01
        FLR::scaled( 0x111E89605BF920, -52 + 2),  // +4.279820924390406844e+00
        FLR::scaled( 0x12E4BCA0B93315, -52 - 1),  // +5.904219760064700617e-01
        FLR::scaled(-0x18A7268F0DF2CE, -52 + 2),  // -6.163233027674051456e+00
        FLR::scaled( 0x12E4BCA0B93315, -52 - 1),  // +5.904219760064700617e-01
        FLR::scaled(-0x194617EB39AEA5, -52 + 3),  // -1.263690123633507234e+01
        FLR::scaled( 0x12F157D686CBBE, -52 - 1),  // +5.919608297320946289e-01
        FLR::scaled(-0x1C618B85084099, -52 + 3),  // -1.419051757550941950e+01
        FLR::scaled( 0x12F157D686CBBE, -52 - 1),  // +5.919608297320946289e-01
        FLR::scaled( 0x1FFDF5AE0D51FB, -52 + 3),  // +1.599601501381493129e+01
        FLR::scaled( 0x12F365ADF51754, -52 - 1),  // +5.922115705113619732e-01
        FLR::scaled(-0x1F422B07A0119D, -52 + 5),  // -6.251693816486224620e+01
        FLR::scaled( 0x12F365ADF51754, -52 - 1),  // +5.922115705113619732e-01
        FLR::scaled(-0x13228C8F860D3F, -52 + 4),  // -1.913495728514430638e+01
        FLR::scaled( 0x12ED188D87FDB3, -52 - 1),  // +5.914423717767277600e-01
        FLR::scaled( 0x147C2769A033D0, -52 + 2),  // +5.121244097140291274e+00
        FLR::scaled( 0x12ED188D87FDB3, -52 - 1),  // +5.914423717767277600e-01
        FLR::scaled( 0x1ABF1C156C4B4A, -52 + 2),  // +6.686630568251368700e+00
        FLR::scaled( 0x12EE4A01151D70, -52 - 1),  // +5.915880223409839545e-01
        FLR::scaled(-0x12F115BF3EFF7A, -52 + 5),  // -3.788347616745063817e+01
        FLR::scaled( 0x12EE4A01151D70, -52 - 1),  // +5.915880223409839545e-01
        FLR::scaled(-0x18A775E91A24E8, -52 + 2),  // -6.163535730572426985e+00
        FLR::scaled( 0x12FACC2A4F851F, -52 - 1),  // +5.931149317149538858e-01
        FLR::scaled(-0x19EB3455355504, -52 + 3),  // -1.295938364292170064e+01
        FLR::scaled( 0x12FACC2A4F851F, -52 - 1),  // +5.931149317149538858e-01
        FLR::scaled( 0x17FC12FA797EA2, -52 + 2),  // +5.996166146912999650e+00
        FLR::scaled( 0x12FC9E19F91BDB, -52 - 1),  // +5.933371073996299705e-01
        FLR::scaled(-0x17275CE73947EB, -52 + 6),  // -9.261504536241379526e+01
        FLR::scaled( 0x12FC9E19F91BDB, -52 - 1),  // +5.933371073996299705e-01
        FLR::scaled(-0x11C3709E5B5DED, -52 + 5),  // -3.552687434636377617e+01
        FLR::scaled( 0x132D168619E64C, -52 - 1),  // +5.992539042628748369e-01
        FLR::scaled(-0x1D9BAA8AEE756F, -52 + 3),  // -1.480403551255105121e+01
        FLR::scaled( 0x132D168619E64C, -52 - 1),  // +5.992539042628748369e-01
        FLR::scaled(-0x11BCBB40A76579, -52 + 5),  // -3.547446449445391892e+01
        FLR::scaled( 0x132D1870B24ADB, -52 - 1),  // +5.992548180678015646e-01
        FLR::scaled(-0x15BA4890D3ED8C, -52 + 6),  // -8.691067906089864437e+01
        FLR::scaled( 0x132D1870B24ADB, -52 - 1),  // +5.992548180678015646e-01
        FLR::scaled(-0x195FB2D113D042, -52 + 5),  // -5.074764455287414933e+01
        FLR::scaled( 0x13477720674B5A, -52 - 1),  // +6.024737961655362017e-01
        FLR::scaled(-0x1215AB26D775E7, -52 + 4),  // -1.808464281807200891e+01
        FLR::scaled( 0x13477720674B5A, -52 - 1),  // +6.024737961655362017e-01
        FLR::scaled(-0x136AB99217BE2E, -52 + 4),  // -1.941689408378277193e+01
        FLR::scaled( 0x13477A624A73CA, -52 - 1),  // +6.024753494017371924e-01
        FLR::scaled(-0x12F0F3FBF5CED2, -52 + 6),  // -7.576489161495854319e+01
        FLR::scaled( 0x13477A624A73CA, -52 - 1),  // +6.024753494017371924e-01
        FLR::scaled(-0x169168B34D1B71, -52 + 4),  // -2.256800385124683217e+01
        FLR::scaled( 0x13336F282A31C9, -52 - 1),  // +6.000285896748717152e-01
        FLR::scaled(-0x111FD0674910AC, -52 + 5),  // -3.424854746883042367e+01
        FLR::scaled( 0x13336F282A31C9, -52 - 1),  // +6.000285896748717152e-01
        FLR::scaled(-0x1D338FC54032FC, -52 + 1),  // -3.650176564237311183e+00
        FLR::scaled( 0x133379240A9165, -52 - 1),  // +6.000333503657598877e-01
        FLR::scaled(-0x14F1765B21F790, -52 + 6),  // -8.377284887616247033e+01
        FLR::scaled( 0x133379240A9165, -52 - 1),  // +6.000333503657598877e-01
        FLR::scaled(-0x13583F514B2F7A, -52 + 6),  // -7.737886459677056905e+01
        FLR::scaled( 0x134D201BBE8501, -52 - 1),  // +6.031647245291936743e-01
        FLR::scaled(-0x17E3CC8F561053, -52 + 5),  // -4.777968017294247005e+01
        FLR::scaled( 0x134D201BBE8501, -52 - 1),  // +6.031647245291936743e-01
        FLR::scaled(-0x12D827911D0613, -52 + 5),  // -3.768870748440908613e+01
        FLR::scaled( 0x134D20349F7B6F, -52 - 1),  // +6.031647708694957144e-01
        FLR::scaled(-0x14524D62494F4F, -52 + 2),  // -5.080373321270442055e+00
        FLR::scaled( 0x134D20349F7B6F, -52 - 1),  // +6.031647708694957144e-01
        FLR::scaled(-0x113470360154F2, -52 + 6),  // -6.881934881334362331e+01
        FLR::scaled( 0x134EAA22490621, -52 - 1),  // +6.033526105531487049e-01
        FLR::scaled(-0x1F6D9DB366438A, -52 + 4),  // -3.142818757292437937e+01
        FLR::scaled( 0x134EAA22490621, -52 - 1),  // +6.033526105531487049e-01
        FLR::scaled(-0x115CD695CCEFB3, -52 + 2),  // -4.340662327416725752e+00
        FLR::scaled( 0x134EC758A6EBA4, -52 - 1),  // +6.033665400967618275e-01
        FLR::scaled( 0x116D4F09F3D6E4, -52 - 2),  // +2.722966763679848246e-01
        FLR::scaled( 0x134EC758A6EBA4, -52 - 1),  // +6.033665400967618275e-01
        FLR::scaled(-0x1254556165C496, -52 + 5),  // -3.665885560483108918e+01
        FLR::scaled( 0x13688FD9ED6AA7, -52 - 1),  // +6.065139061350536265e-01
        FLR::scaled(-0x1F9DFB7FA23F12, -52 + 3),  // -1.580855940681025018e+01
        FLR::scaled( 0x13688FD9ED6AA7, -52 - 1),  // +6.065139061350536265e-01
        FLR::scaled( 0x1B23099302CC7C, -52 + 2),  // +6.784216210408995806e+00
        FLR::scaled( 0x1368D92B2B8E4F, -52 - 1),  // +6.065488665739823260e-01
        FLR::scaled(-0x181E364EB89F95, -52 + 5),  // -4.823603233351528985e+01
        FLR::scaled( 0x1368D92B2B8E4F, -52 - 1),  // +6.065488665739823260e-01
        FLR::scaled( 0x1D3E3228915F72, -52 + 4),  // +2.924295285748616635e+01
        FLR::scaled( 0x135695B67D083A, -52 - 1),  // +6.043194355227179404e-01
        FLR::scaled(-0x101775E48AE658, -52 + 5),  // -3.218328530103889307e+01
        FLR::scaled( 0x135695B67D083A, -52 - 1),  // +6.043194355227179404e-01
        FLR::scaled( 0x1FE63E93322E11, -52 + 1),  // +3.987424039811010790e+00
        FLR::scaled( 0x1356A34933636A, -52 - 1),  // +6.043259076787823592e-01
        FLR::scaled(-0x1BE06E29C48673, -52 + 4),  // -2.787668095634439780e+01
        FLR::scaled( 0x1356A34933636A, -52 - 1),  // +6.043259076787823592e-01
        FLR::scaled(-0x1C92AA9707ADE8, -52 + 5),  // -5.714583099245993481e+01
        FLR::scaled( 0x136F8E7CD05D71, -52 - 1),  // +6.073677480480182966e-01
        FLR::scaled(-0x17613CCAE527D4, -52 + 6),  // -9.351933548334574198e+01
        FLR::scaled( 0x136F8E7CD05D71, -52 - 1),  // +6.073677480480182966e-01
        FLR::scaled(-0x1074A8C90F81DF, -52 + 2),  // -4.113925115176669145e+00
        FLR::scaled( 0x136FC0E2B034BF, -52 - 1),  // +6.073917796617464004e-01
        FLR::scaled(-0x1A03695444998B, -52 + 3),  // -1.300666297280692696e+01
        FLR::scaled( 0x136FC0E2B034BF, -52 - 1),  // +6.073917796617464004e-01
        FLR::scaled(-0x127F1E5C31C578, -52 + 6),  // -7.398622803554997063e+01
        FLR::scaled( 0x1321EC9C10BF43, -52 - 1),  // +5.978911445763305244e-01
        FLR::scaled( 0x183E49315DCE04, -52 + 3),  // +1.212165216703488824e+01
        FLR::scaled( 0x1321EC9C10BF43, -52 - 1),  // +5.978911445763305244e-01
        FLR::scaled(-0x174E8606A7C587, -52 + 4),  // -2.330673257442461122e+01
        FLR::scaled( 0x132220A199478A, -52 - 1),  // +5.979159504151863036e-01
        FLR::scaled(-0x109DF0997BB3F6, -52 + 1),  // -2.077119063460936665e+00
        FLR::scaled( 0x132220A199478A, -52 - 1),  // +5.979159504151863036e-01
        FLR::scaled(-0x194212BCDFD18F, -52 + 4),  // -2.525809841598816874e+01
        FLR::scaled( 0x132CFE21D4348F, -52 - 1),  // +5.992422733994703377e-01
        FLR::scaled(-0x1BCADFCB8EC62E, -52 + 5),  // -5.558495468589204336e+01
        FLR::scaled( 0x132CFE21D4348F, -52 - 1),  // +5.992422733994703377e-01
        FLR::scaled( 0x1D3DD0AAA924CB, -52 + 4),  // +2.924146525029645360e+01
        FLR::scaled( 0x132D72B6BA8830, -52 - 1),  // +5.992978638571511141e-01
        FLR::scaled(-0x154C1405BE06DE, -52 + 6),  // -8.518872207219416737e+01
        FLR::scaled( 0x132D72B6BA8830, -52 - 1),  // +5.992978638571511141e-01
        FLR::scaled(-0x1CB812E2CB5000, -52 + 1),  // -3.589879772023778060e+00
        FLR::scaled( 0x132A913BCB8E42, -52 - 1),  // +5.989462058900658636e-01
        FLR::scaled( 0x1649803351BCC4, -52 + 1),  // +2.785889054233480877e+00
        FLR::scaled( 0x132A913BCB8E42, -52 - 1),  // +5.989462058900658636e-01
        FLR::scaled( 0x1192E182B5FA3C, -52 + 4),  // +1.757375351851281664e+01
        FLR::scaled( 0x132AB3306F853A, -52 - 1),  // +5.989623971947033443e-01
        FLR::scaled(-0x112F3579790EB3, -52 + 4),  // -1.718440970616820707e+01
        FLR::scaled( 0x132AB3306F853A, -52 - 1),  // +5.989623971947033443e-01
        FLR::scaled(-0x18AC79D47829FD, -52 + 5),  // -4.934746795527824048e+01
        FLR::scaled( 0x13358803C6CCF4, -52 - 1),  // +6.002845834504157985e-01
        FLR::scaled(-0x12D472B2B6584D, -52 + 5),  // -3.765975030807076251e+01
        FLR::scaled( 0x13358803C6CCF4, -52 - 1),  // +6.002845834504157985e-01
        FLR::scaled(-0x19C66D80FD8599, -52 + 4),  // -2.577510839643000295e+01
        FLR::scaled( 0x1335E06F6D47E9, -52 - 1),  // +6.003267456346722541e-01
        FLR::scaled(-0x1C965BF86DC82C, -52 + 5),  // -5.717468171463437443e+01
        FLR::scaled( 0x1335E06F6D47E9, -52 - 1),  // +6.003267456346722541e-01
        FLR::scaled(-0x13D10F1AAD16E2, -52 + 6),  // -7.926654688742885924e+01
        FLR::scaled( 0x13388C0A5708F4, -52 - 1),  // +6.006527139618627054e-01
        FLR::scaled( 0x1C10A24133ECA0, -52 + 0),  // +1.754060988138725463e+00
        FLR::scaled( 0x13388C0A5708F4, -52 - 1),  // +6.006527139618627054e-01
        FLR::scaled(-0x1B2D72AC177002, -52 + 3),  // -1.358876550470450084e+01
        FLR::scaled( 0x13390F71B119C0, -52 - 1),  // +6.007153721373512667e-01
        FLR::scaled(-0x1146E92CAA2FB7, -52 + 4),  // -1.727699546008053844e+01
        FLR::scaled( 0x13390F71B119C0, -52 - 1),  // +6.007153721373512667e-01
        FLR::scaled(-0x16567245F22E23, -52 + 6),  // -8.935072468424236547e+01
        FLR::scaled( 0x134350E2DD3D07, -52 - 1),  // +6.019672804776811104e-01
        FLR::scaled(-0x10BD8B0CB6A21C, -52 + 5),  // -3.348080595891607913e+01
        FLR::scaled( 0x134350E2DD3D07, -52 - 1),  // +6.019672804776811104e-01
        FLR::scaled(-0x1E41B9E9790365, -52 + 4),  // -3.025674304203439036e+01
        FLR::scaled( 0x13443140CEA49F, -52 - 1),  // +6.020742669835675853e-01
        FLR::scaled(-0x114416574CF156, -52 + 6),  // -6.906386358751237253e+01
        FLR::scaled( 0x13443140CEA49F, -52 - 1),  // +6.020742669835675853e-01
        FLR::scaled( 0x11E1A95A294BBE, -52 + 5),  // +3.576298071876907159e+01
        FLR::scaled( 0x1342ED4548370B, -52 - 1),  // +6.019197800794428010e-01
        FLR::scaled( 0x105D33756D074E, -52 + 5),  // +3.272813289474161991e+01
        FLR::scaled( 0x1342ED4548370B, -52 - 1),  // +6.019197800794428010e-01
        FLR::scaled( 0x17F9435B669C26, -52 + 0),  // +1.498355252298787743e+00
        FLR::scaled( 0x13435C66E913C0, -52 - 1),  // +6.019727716417193619e-01
        FLR::scaled(-0x1EF7D6B3A4787E, -52 + 2),  // -7.742029959596150590e+00
        FLR::scaled( 0x13435C66E913C0, -52 - 1),  // +6.019727716417193619e-01
        FLR::scaled(-0x119A4578FF258F, -52 + 6),  // -7.041049027363463608e+01
        FLR::scaled( 0x134D78D87B7C0A, -52 - 1),  // +6.032070377513047976e-01
        FLR::scaled(-0x14C9B2656D26BA, -52 + 5),  // -4.157575671987201815e+01
        FLR::scaled( 0x134D78D87B7C0A, -52 - 1),  // +6.032070377513047976e-01
        FLR::scaled(-0x14E73A0128B452, -52 + 1),  // -2.612903603605936986e+00
        FLR::scaled( 0x134E3CEF360455, -52 - 1),  // +6.033005401697076886e-01
        FLR::scaled(-0x159E6D75D233CB, -52 + 5),  // -4.323771546138558364e+01
        FLR::scaled( 0x134E3CEF360455, -52 - 1),  // +6.033005401697076886e-01
        FLR::scaled(-0x1E7B59B75E8653, -52 + 5),  // -6.096367542376960813e+01
        FLR::scaled( 0x138BCEFEBE1E0C, -52 - 1),  // +6.108164763872436787e-01
        FLR::scaled(-0x1C895994C5FBAD, -52 + 5),  // -5.707304629962104769e+01
        FLR::scaled( 0x138BCEFEBE1E0C, -52 - 1),  // +6.108164763872436787e-01
        FLR::scaled( 0x11EFA40BC987C7, -52 + 3),  // +8.968048446989895339e+00
        FLR::scaled( 0x138BF73E2747CF, -52 - 1),  // +6.108356679853786941e-01
        FLR::scaled(-0x144D8A1D78995B, -52 + 4),  // -2.030288871950447671e+01
        FLR::scaled( 0x138BF73E2747CF, -52 - 1),  // +6.108356679853786941e-01
        FLR::scaled(-0x103DC912A26AD1, -52 + 5),  // -3.248269875460176337e+01
        FLR::scaled( 0x139F3127EB8DFA, -52 - 1),  // +6.131826190652980291e-01
        FLR::scaled(-0x1C9852FFCDC439, -52 + 5),  // -5.719003293559257628e+01
        FLR::scaled( 0x139F3127EB8DFA, -52 - 1),  // +6.131826190652980291e-01
        FLR::scaled(-0x1B7E3C93E9D2AC, -52 + 5),  // -5.498622368733535382e+01
        FLR::scaled( 0x139F39BBEEC689, -52 - 1),  // +6.131867094574811050e-01
        FLR::scaled(-0x115ADC75DB96DC, -52 + 6),  // -6.941970583385722193e+01
        FLR::scaled( 0x139F39BBEEC689, -52 - 1),  // +6.131867094574811050e-01
        FLR::scaled(-0x1966CC18AAEBEA, -52 + 3),  // -1.270077588163799831e+01
        FLR::scaled( 0x1393BFC56B126B, -52 - 1),  // +6.117857795548621302e-01
        FLR::scaled(-0x17A6F0E5E102DE, -52 + 5),  // -4.730422662245631216e+01
        FLR::scaled( 0x1393BFC56B126B, -52 - 1),  // +6.117857795548621302e-01
        FLR::scaled(-0x1AC6571FF2C1A7, -52 + 0),  // -1.673422932432097943e+00
        FLR::scaled( 0x139400C2F2B96C, -52 - 1),  // +6.118167693692107001e-01
        FLR::scaled(-0x120191953941FF, -52 + 4),  // -1.800612766883750382e+01
        FLR::scaled( 0x139400C2F2B96C, -52 - 1),  // +6.118167693692107001e-01
        FLR::scaled(-0x12D837193EA31D, -52 + 6),  // -7.537836295239362983e+01
        FLR::scaled( 0x13A668DF3E5CCE, -52 - 1),  // +6.140636787630684434e-01
        FLR::scaled(-0x15509BFC5236E6, -52 + 5),  // -4.262976030363442703e+01
        FLR::scaled( 0x13A668DF3E5CCE, -52 - 1),  // +6.140636787630684434e-01
        FLR::scaled(-0x13DC65A3AEC533, -52 + 4),  // -1.986092589394429453e+01
        FLR::scaled( 0x13A67CCEF2276C, -52 - 1),  // +6.140731851494201088e-01
        FLR::scaled(-0x10C2C8EBE4F205, -52 + 4),  // -1.676087831820952445e+01
        FLR::scaled( 0x13A67CCEF2276C, -52 - 1),  // +6.140731851494201088e-01
        FLR::scaled(-0x1F293535ADB5A6, -52 + 4),  // -3.116096816531139524e+01
        FLR::scaled( 0x13A7E3388465E6, -52 - 1),  // +6.142440894938629992e-01
        FLR::scaled( 0x103BB19E0A9071, -52 + 5),  // +3.246635795131522428e+01
        FLR::scaled( 0x13A7E3388465E6, -52 - 1),  // +6.142440894938629992e-01
        FLR::scaled(-0x1984B560900DFD, -52 + 5),  // -5.103678519281309178e+01
        FLR::scaled( 0x13A7E650BF3AAC, -52 - 1),  // +6.142455651368741165e-01
        FLR::scaled(-0x17544CC621247A, -52 + 4),  // -2.332929647740500201e+01
        FLR::scaled( 0x13A7E650BF3AAC, -52 - 1),  // +6.142455651368741165e-01
        FLR::scaled(-0x1FD931BE1AA810, -52 + 3),  // -1.592420763087650926e+01
        FLR::scaled( 0x13BB8E137ADDB8, -52 - 1),  // +6.166448955981911340e-01
        FLR::scaled(-0x1C92A83BDDCD4A, -52 + 4),  // -2.857287954487882331e+01
        FLR::scaled( 0x13BB8E137ADDB8, -52 - 1),  // +6.166448955981911340e-01
        FLR::scaled(-0x18C426DABA0355, -52 + 2),  // -6.191554467776616555e+00
        FLR::scaled( 0x13BB9147D3A26D, -52 - 1),  // +6.166464236130885235e-01
        FLR::scaled(-0x1051DFEED787EB, -52 + 5),  // -3.263964639209719820e+01
        FLR::scaled( 0x13BB9147D3A26D, -52 - 1),  // +6.166464236130885235e-01
        FLR::scaled( 0x123AAFA74FEDDE, -52 + 5),  // +3.645848552134314957e+01
        FLR::scaled( 0x13B16501A0A74B, -52 - 1),  // +6.154046088970316353e-01
        FLR::scaled(-0x19CBC9006AE996, -52 + 3),  // -1.289801789574702795e+01
        FLR::scaled( 0x13B16501A0A74B, -52 - 1),  // +6.154046088970316353e-01
        FLR::scaled(-0x1ACDA067F5D56B, -52 + 5),  // -5.360645770553204414e+01
        FLR::scaled( 0x13B16FBAB6C0D7, -52 - 1),  // +6.154097220187634276e-01
        FLR::scaled(-0x1121B907D9D2EA, -52 + 5),  // -3.426345918785030165e+01
        FLR::scaled( 0x13B16FBAB6C0D7, -52 - 1),  // +6.154097220187634276e-01
        FLR::scaled(-0x1BBA13AFC17B6E, -52 + 3),  // -1.386343144642679803e+01
        FLR::scaled( 0x13C41AFAC4C608, -52 - 1),  // +6.176886461091166680e-01
        FLR::scaled(-0x1E67038FF3D9CE, -52 + 5),  // -6.080479621321465800e+01
        FLR::scaled( 0x13C41AFAC4C608, -52 - 1),  // +6.176886461091166680e-01
        FLR::scaled(-0x1D8FCE15F87763, -52 + 3),  // -1.478086918504749825e+01
        FLR::scaled( 0x13C41B237E3AA2, -52 - 1),  // +6.176887219642888116e-01
        FLR::scaled(-0x1A85ADF88B00C0, -52 + 5),  // -5.304437166964771677e+01
        FLR::scaled( 0x13C41B237E3AA2, -52 - 1),  // +6.176887219642888116e-01
        FLR::scaled(-0x1BD7F5B70E622C, -52 + 5),  // -5.568718612863844442e+01
        FLR::scaled( 0x1380FF3674B611, -52 - 1),  // +6.094966949073655771e-01
        FLR::scaled(-0x1759E6A276BDC0, -52 + 5),  // -4.670235091016684237e+01
        FLR::scaled( 0x1380FF3674B611, -52 - 1),  // +6.094966949073655771e-01
        FLR::scaled(-0x1148956BA3E735, -52 + 6),  // -6.913411990171591981e+01
        FLR::scaled( 0x138344CC9754C0, -52 - 1),  // +6.097740169449465952e-01
        FLR::scaled(-0x1EA8B12B0B2FA6, -52 + 3),  // -1.532947668563413046e+01
        FLR::scaled( 0x138344CC9754C0, -52 - 1),  // +6.097740169449465952e-01
        FLR::scaled( 0x1205A63C66B1D3, -52 + 2),  // +4.505516952293379340e+00
        FLR::scaled( 0x13927367017072, -52 - 1),  // +6.116272937611155758e-01
        FLR::scaled( 0x1FC6BE8C870B00, -52 - 1),  // +9.930107826879464028e-01
        FLR::scaled( 0x13927367017072, -52 - 1),  // +6.116272937611155758e-01
        FLR::scaled( 0x1D7860523C4533, -52 + 4),  // +2.947021974536364652e+01
        FLR::scaled( 0x1395E9FDF4D2CF, -52 - 1),  // +6.120500526509092820e-01
        FLR::scaled(-0x190529E8BDF5CB, -52 + 5),  // -5.004034146571537889e+01
        FLR::scaled( 0x1395E9FDF4D2CF, -52 - 1),  // +6.120500526509092820e-01
        FLR::scaled(-0x10C7164A16CF94, -52 + 6),  // -6.711073543765661498e+01
        FLR::scaled( 0x138861B418581F, -52 - 1),  // +6.103981511576000996e-01
        FLR::scaled(-0x193F6C3DC6B97E, -52 + 4),  // -2.524774538137125290e+01
        FLR::scaled( 0x138861B418581F, -52 - 1),  // +6.103981511576000996e-01
        FLR::scaled(-0x153FE0E9356BA8, -52 + 6),  // -8.499810247628067827e+01
        FLR::scaled( 0x138A960645C8EA, -52 - 1),  // +6.106672403823527606e-01
        FLR::scaled(-0x1580BA877B574B, -52 + 5),  // -4.300569242022046268e+01
        FLR::scaled( 0x138A960645C8EA, -52 - 1),  // +6.106672403823527606e-01
        FLR::scaled(-0x125D1FA124B141, -52 + 5),  // -3.672752775470372200e+01
        FLR::scaled( 0x139A8EDEE05E38, -52 - 1),  // +6.126169541411803365e-01
        FLR::scaled(-0x163D9D0651D03F, -52 + 5),  // -4.448135451311872401e+01
        FLR::scaled( 0x139A8EDEE05E38, -52 - 1),  // +6.126169541411803365e-01
        FLR::scaled(-0x13A53D5FBA263D, -52 + 5),  // -3.929093548383068679e+01
        FLR::scaled( 0x139E020389FC69, -52 - 1),  // +6.130380696412319752e-01
        FLR::scaled(-0x1740526DA8A708, -52 + 5),  // -4.650251551375373538e+01
        FLR::scaled( 0x139E020389FC69, -52 - 1),  // +6.130380696412319752e-01
        FLR::scaled(-0x1C33DF4AF3EB9A, -52 + 3),  // -1.410131296374838783e+01
        FLR::scaled( 0x13A8565C5CD611, -52 - 1),  // +6.142989925344314317e-01
        FLR::scaled(-0x1693AF2F23057E, -52 + 3),  // -1.128844592382915479e+01
        FLR::scaled( 0x13A8565C5CD611, -52 - 1),  // +6.142989925344314317e-01
        FLR::scaled(-0x1641671CBF03BD, -52 + 5),  // -4.451095923735508819e+01
        FLR::scaled( 0x13AC45CBB85BF2, -52 - 1),  // +6.147793749722707535e-01
        FLR::scaled(-0x1694853FE02831, -52 + 4),  // -2.258015822622855140e+01
        FLR::scaled( 0x13AC45CBB85BF2, -52 - 1),  // +6.147793749722707535e-01
        FLR::scaled( 0x1402B0F243E5DD, -52 + 5),  // +4.002102497401549641e+01
        FLR::scaled( 0x13BB071B944784, -52 - 1),  // +6.165805376679007743e-01
        FLR::scaled(-0x196D34D4F3C122, -52 + 4),  // -2.542658739996944206e+01
        FLR::scaled( 0x13BB071B944784, -52 - 1),  // +6.165805376679007743e-01
        FLR::scaled( 0x1150D4CB31F5E9, -52 + 5),  // +3.463149394931298986e+01
        FLR::scaled( 0x13C0A69802824C, -52 - 1),  // +6.172669381085795770e-01
        FLR::scaled(-0x1B34C5CDA75836, -52 + 6),  // -1.088245729574417453e+02
        FLR::scaled( 0x13C0A69802824C, -52 - 1),  // +6.172669381085795770e-01
        FLR::scaled(-0x1B891A59C4AD34, -52 + 4),  // -2.753555832912134349e+01
        FLR::scaled( 0x13B2B829807950, -52 - 1),  // +6.155663309653309767e-01
        FLR::scaled(-0x1262F7ECCD6899, -52 + 6),  // -7.354638214168006982e+01
        FLR::scaled( 0x13B2B829807950, -52 - 1),  // +6.155663309653309767e-01
        FLR::scaled(-0x1CB62BCD46AB91, -52 + 3),  // -1.435580293166802512e+01
        FLR::scaled( 0x13B6B0C180D65F, -52 - 1),  // +6.160510806427729191e-01
        FLR::scaled(-0x16550EE5F4EA53, -52 + 5),  // -4.466451715906864450e+01
        FLR::scaled( 0x13B6B0C180D65F, -52 - 1),  // +6.160510806427729191e-01
        FLR::scaled(-0x1E5C656FB4AA96, -52 + 5),  // -6.072184559175109086e+01
        FLR::scaled( 0x13C68BF8646710, -52 - 1),  // +6.179866649065122175e-01
        FLR::scaled(-0x1272481519203F, -52 + 4),  // -1.844641239036013403e+01
        FLR::scaled( 0x13C68BF8646710, -52 - 1),  // +6.179866649065122175e-01
        FLR::scaled(-0x12E0378113E11E, -52 + 5),  // -3.775169385405227729e+01
        FLR::scaled( 0x13CC57B2A184AC, -52 - 1),  // +6.186941613088001723e-01
        FLR::scaled( 0x112594A447D416, -52 + 3),  // +8.573399671333429950e+00
        FLR::scaled( 0x13CC57B2A184AC, -52 - 1),  // +6.186941613088001723e-01
        FLR::scaled(-0x1D99CEE1FA6CE0, -52 + 4),  // -2.960081302989863161e+01
        FLR::scaled( 0x14058856311F0A, -52 - 1),  // +6.256753619609025652e-01
        FLR::scaled( 0x1CA698DC99E369, -52 + 3),  // +1.432538499239463370e+01
        FLR::scaled( 0x14058856311F0A, -52 - 1),  // +6.256753619609025652e-01
        FLR::scaled(-0x139B3BE7418ECC, -52 + 4),  // -1.960638280249149545e+01
        FLR::scaled( 0x14058ADFFF6BF8, -52 - 1),  // +6.256765723186381578e-01
        FLR::scaled(-0x17AB3BCCCD009E, -52 + 5),  // -4.733776245126612991e+01
        FLR::scaled( 0x14058ADFFF6BF8, -52 - 1),  // +6.256765723186381578e-01
        FLR::scaled(-0x11976B5A0D2980, -52 - 2),  // -2.748669032486290575e-01
        FLR::scaled( 0x1420D4EC6A7FEF, -52 - 1),  // +6.290077798366818795e-01
        FLR::scaled(-0x1940D3B2F5E67F, -52 + 5),  // -5.050646054274420038e+01
        FLR::scaled( 0x1420D4EC6A7FEF, -52 - 1),  // +6.290077798366818795e-01
        FLR::scaled( 0x109394D5546BED, -52 + 5),  // +3.315297953245303830e+01
        FLR::scaled( 0x14210550AAD071, -52 - 1),  // +6.290308547527400096e-01
        FLR::scaled(-0x188D65E4A5C14A, -52 + 1),  // -3.069042002018396609e+00
        FLR::scaled( 0x14210550AAD071, -52 - 1),  // +6.290308547527400096e-01
        FLR::scaled(-0x113DA8F3123750, -52 + 5),  // -3.448171842946487686e+01
        FLR::scaled( 0x140CAE3C8BF9E0, -52 - 1),  // +6.265479261926962806e-01
        FLR::scaled(-0x1AD698414CA14E, -52 + 5),  // -5.367652145616249015e+01
        FLR::scaled( 0x140CAE3C8BF9E0, -52 - 1),  // +6.265479261926962806e-01
        FLR::scaled(-0x15F9088ADE9678, -52 + 5),  // -4.394557319515746485e+01
        FLR::scaled( 0x140CB0E5038281, -52 - 1),  // +6.265491936611199408e-01
        FLR::scaled( 0x10574DC2FE18B0, -52 - 1),  // +5.106571968506354864e-01
        FLR::scaled( 0x140CB0E5038281, -52 - 1),  // +6.265491936611199408e-01
        FLR::scaled( 0x122DC79AE3EE93, -52 + 4),  // +1.817882698120827101e+01
        FLR::scaled( 0x1428F7D9DBEE17, -52 - 1),  // +6.300009970722751929e-01
        FLR::scaled(-0x13965BAA9630A6, -52 + 5),  // -3.917467243512628272e+01
        FLR::scaled( 0x1428F7D9DBEE17, -52 - 1),  // +6.300009970722751929e-01
        FLR::scaled(-0x1B758C9427D3AE, -52 + 5),  // -5.491835262245818683e+01
        FLR::scaled( 0x14292E89F98745, -52 - 1),  // +6.300270743197208256e-01
        FLR::scaled(-0x14D45307E2B293, -52 + 5),  // -4.165878389901367740e+01
        FLR::scaled( 0x14292E89F98745, -52 - 1),  // +6.300270743197208256e-01
        FLR::scaled(-0x1378E11978CB34, -52 + 6),  // -7.788873898311868516e+01
        FLR::scaled( 0x1435910AABD339, -52 - 1),  // +6.315388878270830064e-01
        FLR::scaled(-0x139FD31DBEE5AC, -52 + 3),  // -9.812157563736796817e+00
        FLR::scaled( 0x1435910AABD339, -52 - 1),  // +6.315388878270830064e-01
        FLR::scaled(-0x10271509212E5A, -52 + 6),  // -6.461065891495073288e+01
        FLR::scaled( 0x1435C08D0C5DD8, -52 - 1),  // +6.315615420198197327e-01
        FLR::scaled(-0x14FABBD0375CF5, -52 + 1),  // -2.622428538026378764e+00
        FLR::scaled( 0x1435C08D0C5DD8, -52 - 1),  // +6.315615420198197327e-01
        FLR::scaled(-0x1076033B18B2C2, -52 + 6),  // -6.584394719516697592e+01
        FLR::scaled( 0x1451900FB4BBC4, -52 - 1),  // +6.349563891179674791e-01
        FLR::scaled(-0x1D604BBB6FF41B, -52 + 4),  // -2.937615558131447457e+01
        FLR::scaled( 0x1451900FB4BBC4, -52 - 1),  // +6.349563891179674791e-01
        FLR::scaled(-0x11C2DEF1E5CECC, -52 + 4),  // -1.776121436939756393e+01
        FLR::scaled( 0x145236625C07A0, -52 - 1),  // +6.350356980403724094e-01
        FLR::scaled(-0x1AD05968BB4C69, -52 + 4),  // -2.681386427471844414e+01
        FLR::scaled( 0x145236625C07A0, -52 - 1),  // +6.350356980403724094e-01
        FLR::scaled(-0x1341EB38E75E94, -52 + 4),  // -1.925749545715969191e+01
        FLR::scaled( 0x143E518C40622D, -52 - 1),  // +6.326072444235869563e-01
        FLR::scaled( 0x121AD38D764F76, -52 + 4),  // +1.810479053629338608e+01
        FLR::scaled( 0x143E518C40622D, -52 - 1),  // +6.326072444235869563e-01
        FLR::scaled(-0x1A43BB3A004C3D, -52 + 3),  // -1.313228780034671139e+01
        FLR::scaled( 0x143E820A793845, -52 - 1),  // +6.326303677140080461e-01
        FLR::scaled(-0x191F1EF000AB2A, -52 + 4),  // -2.512156581894229390e+01
        FLR::scaled( 0x143E820A793845, -52 - 1),  // +6.326303677140080461e-01
        FLR::scaled( 0x1C51D673151AAE, -52 + 2),  // +7.079919622576808180e+00
        FLR::scaled( 0x145B815A634E75, -52 - 1),  // +6.361700787915213207e-01
        FLR::scaled(-0x1D162D16D093D0, -52 + 4),  // -2.908662550537320612e+01
        FLR::scaled( 0x145B815A634E75, -52 - 1),  // +6.361700787915213207e-01
        FLR::scaled(-0x18ED3E785521D5, -52 + 3),  // -1.246336723365031141e+01
        FLR::scaled( 0x145C3590B0BC46, -52 - 1),  // +6.362560106262058479e-01
        FLR::scaled(-0x170FAD3C5E041F, -52 + 5),  // -4.612247423735265528e+01
        FLR::scaled( 0x145C3590B0BC46, -52 - 1),  // +6.362560106262058479e-01
        FLR::scaled(-0x119C94578E8112, -52 + 6),  // -7.044655407825874249e+01
        FLR::scaled( 0x13F42FB6B049C2, -52 - 1),  // +6.235579078805175701e-01
        FLR::scaled(-0x1CDB8331CB2818, -52 + 4),  // -2.885747061929586721e+01
        FLR::scaled( 0x13F42FB6B049C2, -52 - 1),  // +6.235579078805175701e-01
        FLR::scaled(-0x13FE29C4FC9F1A, -52 + 4),  // -1.999282485167996271e+01
        FLR::scaled( 0x13F617788C6569, -52 - 1),  // +6.237904886685728956e-01
        FLR::scaled(-0x11C199FD79FB59, -52 + 5),  // -3.551251190620559584e+01
        FLR::scaled( 0x13F617788C6569, -52 - 1),  // +6.237904886685728956e-01
        FLR::scaled(-0x1B1182A7BFA26C, -52 + 3),  // -1.353419994558608863e+01
        FLR::scaled( 0x13FF81BBCCBA49, -52 - 1),  // +6.249397914851410052e-01
        FLR::scaled( 0x11F28FAFDAEABA, -52 + 3),  // +8.973752494309668037e+00
        FLR::scaled( 0x13FF81BBCCBA49, -52 - 1),  // +6.249397914851410052e-01
        FLR::scaled(-0x183CB8291E0273, -52 + 4),  // -2.423718506796508265e+01
        FLR::scaled( 0x14020ED921B037, -52 - 1),  // +6.252512207843271552e-01
        FLR::scaled(-0x1E69703C66529A, -52 + 5),  // -6.082373766895507572e+01
        FLR::scaled( 0x14020ED921B037, -52 - 1),  // +6.252512207843271552e-01
        FLR::scaled(-0x1EEC7F12C3E838, -52 + 4),  // -3.092381398470772069e+01
        FLR::scaled( 0x13FB229ED43B9D, -52 - 1),  // +6.244061567430098103e-01
        FLR::scaled(-0x1793834F10343E, -52 + 4),  // -2.357622236390692905e+01
        FLR::scaled( 0x13FB229ED43B9D, -52 - 1),  // +6.244061567430098103e-01
        FLR::scaled(-0x121DFAAEBDF9AC, -52 + 5),  // -3.623421272541176563e+01
        FLR::scaled( 0x13FD094D25082B, -52 - 1),  // +6.246382242900428983e-01
        FLR::scaled(-0x19E18F2611E5AE, -52 + 3),  // -1.294054526298972618e+01
        FLR::scaled( 0x13FD094D25082B, -52 - 1),  // +6.246382242900428983e-01
        FLR::scaled(-0x1D572B10C6483C, -52 + 5),  // -5.868100175554033626e+01
        FLR::scaled( 0x140700093034BB, -52 - 1),  // +6.258545093020509986e-01
        FLR::scaled(-0x1E8F0C3F75DCF4, -52 + 4),  // -3.055878063800351185e+01
        FLR::scaled( 0x140700093034BB, -52 - 1),  // +6.258545093020509986e-01
        FLR::scaled(-0x12AA09C2AD2A98, -52 + 5),  // -3.732842286544217814e+01
        FLR::scaled( 0x140990F289CA72, -52 - 1),  // +6.261677491259673989e-01
        FLR::scaled(-0x15F47A80E06794, -52 + 5),  // -4.390998850781684837e+01
        FLR::scaled( 0x140990F289CA72, -52 - 1),  // +6.261677491259673989e-01
        FLR::scaled(-0x16ED918BAE1BC6, -52 + 5),  // -4.585600419999495614e+01
        FLR::scaled( 0x141943E5FBE7E5, -52 - 1),  // +6.280841342806949834e-01
        FLR::scaled(-0x107E489C449876, -52 + 5),  // -3.298659089421646229e+01
        FLR::scaled( 0x141943E5FBE7E5, -52 - 1),  // +6.280841342806949834e-01
        FLR::scaled(-0x1101594D835DB9, -52 + 6),  // -6.802107560948105913e+01
        FLR::scaled( 0x141C19297F0A80, -52 - 1),  // +6.284299669717512415e-01
        FLR::scaled( 0x18E5BD045BEF00, -52 + 3),  // +1.244870771047817470e+01
        FLR::scaled( 0x141C19297F0A80, -52 - 1),  // +6.284299669717512415e-01
        FLR::scaled(-0x18279A750305B2, -52 + 3),  // -1.207735028898136775e+01
        FLR::scaled( 0x1426AADCED14E5, -52 - 1),  // +6.297201456988231749e-01
        FLR::scaled( 0x1399A5CED20A5A, -52 + 3),  // +9.800093138827993045e+00
        FLR::scaled( 0x1426AADCED14E5, -52 - 1),  // +6.297201456988231749e-01
        FLR::scaled(-0x16FFE1C68703AE, -52 + 3),  // -1.149976940534710579e+01
        FLR::scaled( 0x142A6753D6EEE5, -52 - 1),  // +6.301762235156870284e-01
        FLR::scaled(-0x13866BD7BEE28E, -52 + 5),  // -3.905016609974437358e+01
        FLR::scaled( 0x142A6753D6EEE5, -52 - 1),  // +6.301762235156870284e-01
        FLR::scaled( 0x1804A6C74FA744, -52 + 1),  // +3.002271229856804169e+00
        FLR::scaled( 0x142277A3F9F321, -52 - 1),  // +6.292074396766090816e-01
        FLR::scaled(-0x1060218ECBC615, -52 + 5),  // -3.275102410268679165e+01
        FLR::scaled( 0x142277A3F9F321, -52 - 1),  // +6.292074396766090816e-01
        FLR::scaled(-0x1571AF9BB7F77E, -52 + 1),  // -2.680510727454872288e+00
        FLR::scaled( 0x142575219BDE7B, -52 - 1),  // +6.295724541113963957e-01
        FLR::scaled(-0x11070DFD8FC196, -52 + 6),  // -6.811022891081515240e+01
        FLR::scaled( 0x142575219BDE7B, -52 - 1),  // +6.295724541113963957e-01
        FLR::scaled(-0x1489C95BF41235, -52 + 6),  // -8.215291498980589324e+01
        FLR::scaled( 0x1430BAC1DEB2DC, -52 - 1),  // +6.309484278222856624e-01
        FLR::scaled(-0x1164A8F2CEE824, -52 + 5),  // -3.478640589812155781e+01
        FLR::scaled( 0x1430BAC1DEB2DC, -52 - 1),  // +6.309484278222856624e-01
        FLR::scaled( 0x17F32492338478, -52 + 3),  // +1.197488839033961483e+01
        FLR::scaled( 0x1434B0D1E3524D, -52 - 1),  // +6.314319705366614466e-01
        FLR::scaled(-0x1087D9B083BE85, -52 + 6),  // -6.612266171327253517e+01
        FLR::scaled( 0x1434B0D1E3524D, -52 - 1),  // +6.314319705366614466e-01
        FLR::scaled(-0x11C65689B998E8, -52 + 5),  // -3.554951592981689146e+01
        FLR::scaled( 0x14792AB6162C1C, -52 - 1),  // +6.397908741358864226e-01
        FLR::scaled( 0x1D38F5D204749A, -52 + 2),  // +7.305625230333271602e+00
        FLR::scaled( 0x14792AB6162C1C, -52 - 1),  // +6.397908741358864226e-01
        FLR::scaled( 0x17FDFBDA561231, -52 + 3),  // +1.199606210995361444e+01
        FLR::scaled( 0x14792D39FE7135, -52 - 1),  // +6.397920735067034181e-01
        FLR::scaled(-0x14F3C30F58F7F4, -52 + 5),  // -4.190439025730293565e+01
        FLR::scaled( 0x14792D39FE7135, -52 - 1),  // +6.397920735067034181e-01
        FLR::scaled( 0x16FF4C1B9E0B72, -52 + 3),  // +1.149862753204590504e+01
        FLR::scaled( 0x1489F21D0FDFD9, -52 - 1),  // +6.418390815369959812e-01
        FLR::scaled( 0x190C4F0293A498, -52 + 3),  // +1.252404029896051441e+01
        FLR::scaled( 0x1489F21D0FDFD9, -52 - 1),  // +6.418390815369959812e-01
        FLR::scaled( 0x108FE999D0C46D, -52 + 4),  // +1.656215821596963522e+01
        FLR::scaled( 0x1489F9A75975BD, -52 - 1),  // +6.418426769775390506e-01
        FLR::scaled(-0x1CC5489213B7DE, -52 + 5),  // -5.754127717936329134e+01
        FLR::scaled( 0x1489F9A75975BD, -52 - 1),  // +6.418426769775390506e-01
        FLR::scaled(-0x1AF2F0D58D239D, -52 + 4),  // -2.694898733802584800e+01
        FLR::scaled( 0x1480314DC46A58, -52 - 1),  // +6.406485098735386075e-01
        FLR::scaled(-0x16F48AC6B4EA11, -52 + 4),  // -2.295524255673268854e+01
        FLR::scaled( 0x1480314DC46A58, -52 - 1),  // +6.406485098735386075e-01
        FLR::scaled(-0x12272CFE03D686, -52 + 5),  // -3.630606055438424562e+01
        FLR::scaled( 0x14803398A0DAB7, -52 - 1),  // +6.406496029875005105e-01
        FLR::scaled(-0x14206A855208BF, -52 + 3),  // -1.006331268907922372e+01
        FLR::scaled( 0x14803398A0DAB7, -52 - 1),  // +6.406496029875005105e-01
        FLR::scaled(-0x184A4CD4ED9C72, -52 + 5),  // -4.858046971895318222e+01
        FLR::scaled( 0x14917E0E0AED33, -52 - 1),  // +6.427603029509668664e-01
        FLR::scaled(-0x1566522D2D8CA7, -52 + 6),  // -8.559876565406976567e+01
        FLR::scaled( 0x14917E0E0AED33, -52 - 1),  // +6.427603029509668664e-01
        FLR::scaled( 0x1524F7F929CF79, -52 + 3),  // +1.057220438609486912e+01
        FLR::scaled( 0x14918773F1E5C0, -52 - 1),  // +6.427647842930852562e-01
        FLR::scaled(-0x14F793B1ABAF5A, -52 + 5),  // -4.193419476397566825e+01
        FLR::scaled( 0x14918773F1E5C0, -52 - 1),  // +6.427647842930852562e-01
        FLR::scaled(-0x117F2A0FACDEB3, -52 + 5),  // -3.499347110691942220e+01
        FLR::scaled( 0x14A5DE8B985302, -52 - 1),  // +6.452477194276016181e-01
        FLR::scaled(-0x152F5A382B4EC6, -52 + 2),  // -5.296242597239773531e+00
        FLR::scaled( 0x14A5DE8B985302, -52 - 1),  // +6.452477194276016181e-01
        FLR::scaled(-0x1F32F2C7B81EA7, -52 + 5),  // -6.239803406229230376e+01
        FLR::scaled( 0x14A5DFC1587FBC, -52 - 1),  // +6.452482963832077978e-01
        FLR::scaled(-0x19F0147304B5AA, -52 + 5),  // -5.187562406282388849e+01
        FLR::scaled( 0x14A5DFC1587FBC, -52 - 1),  // +6.452482963832077978e-01
        FLR::scaled(-0x159A9BC9CD130A, -52 + 5),  // -4.320787928117177046e+01
        FLR::scaled( 0x14B8156189EF9F, -52 - 1),  // +6.474711327605183753e-01
        FLR::scaled(-0x14FA5267ACAF9C, -52 + 5),  // -4.195563980037624674e+01
        FLR::scaled( 0x14B8156189EF9F, -52 - 1),  // +6.474711327605183753e-01
        FLR::scaled(-0x1A1D38AF75B5D1, -52 + 3),  // -1.305707310020344103e+01
        FLR::scaled( 0x14B83B60CDC9F5, -52 - 1),  // +6.474892512035795855e-01
        FLR::scaled(-0x13C238B4BE4822, -52 + 4),  // -1.975867776532698628e+01
        FLR::scaled( 0x14B83B60CDC9F5, -52 - 1),  // +6.474892512035795855e-01
        FLR::scaled( 0x18234949164B22, -52 + 2),  // +6.034459249482809540e+00
        FLR::scaled( 0x14AE7252838508, -52 - 1),  // +6.462947475048688162e-01
        FLR::scaled( 0x1DA517B6F36860, -52 + 1),  // +3.705611638358320192e+00
        FLR::scaled( 0x14AE7252838508, -52 - 1),  // +6.462947475048688162e-01
        FLR::scaled( 0x1E66792087CB8D, -52 + 2),  // +7.600071438110615141e+00
        FLR::scaled( 0x14AE746F4505D9, -52 - 1),  // +6.462957547411704029e-01
        FLR::scaled( 0x14E9AA2A267EDF, -52 + 3),  // +1.045637637824932931e+01
        FLR::scaled( 0x14AE746F4505D9, -52 - 1),  // +6.462957547411704029e-01
        FLR::scaled(-0x113BAB9361A77E, -52 + 4),  // -1.723308678754937517e+01
        FLR::scaled( 0x14C1506BA5EBE4, -52 - 1),  // +6.485979177954246389e-01
        FLR::scaled(-0x1CB74CD6F11440, -52 + 6),  // -1.148640649179733373e+02
        FLR::scaled( 0x14C1506BA5EBE4, -52 - 1),  // +6.485979177954246389e-01
        FLR::scaled( 0x1E1A5CA36D9BE5, -52 + 4),  // +3.010297604967117380e+01
        FLR::scaled( 0x14C17E68B92F95, -52 - 1),  // +6.486198468569336351e-01
        FLR::scaled(-0x1175317F7149D4, -52 + 6),  // -6.983114610732383198e+01
        FLR::scaled( 0x14C17E68B92F95, -52 - 1),  // +6.486198468569336351e-01
        FLR::scaled(-0x1E4E21BE006395, -52 + 5),  // -6.061040473002427831e+01
        FLR::scaled( 0x15395D59FB49AF, -52 - 1),  // +6.632525212719907470e-01
        FLR::scaled( 0x182A02DD35347E, -52 + 4),  // +2.416410620259238584e+01
        FLR::scaled( 0x15395D59FB49AF, -52 - 1),  // +6.632525212719907470e-01
        FLR::scaled(-0x1F8F53E6383E9B, -52 + 4),  // -3.155987395165594123e+01
        FLR::scaled( 0x154DDE0E2F9FDF, -52 - 1),  // +6.657552983351670006e-01
        FLR::scaled(-0x17245E56E028A9, -52 + 5),  // -4.628412900872474012e+01
        FLR::scaled( 0x154DDE0E2F9FDF, -52 - 1),  // +6.657552983351670006e-01
        FLR::scaled(-0x164BE6C9DA7945, -52 + 1),  // -2.787061287860668646e+00
        FLR::scaled( 0x154AE978844552, -52 - 1),  // +6.653945306626758427e-01
        FLR::scaled(-0x10B2589E5FF7B5, -52 + 3),  // -8.348332356657786946e+00
        FLR::scaled( 0x154AE978844552, -52 - 1),  // +6.653945306626758427e-01
        FLR::scaled(-0x125E33CCC9C60A, -52 + 4),  // -1.836797790456879653e+01
        FLR::scaled( 0x15600EE83F232E, -52 - 1),  // +6.679758583132746619e-01
        FLR::scaled(-0x1A1F1A91611A58, -52 + 5),  // -5.224299828759529873e+01
        FLR::scaled( 0x15600EE83F232E, -52 - 1),  // +6.679758583132746619e-01
        FLR::scaled(-0x14910DCE6AE3D4, -52 + 5),  // -4.113323383540378586e+01
        FLR::scaled( 0x15491B089DD5B9, -52 - 1),  // +6.651740234653323869e-01
        FLR::scaled( 0x126836DEAC4B18, -52 + 3),  // +9.203543623477841606e+00
        FLR::scaled( 0x15491B089DD5B9, -52 - 1),  // +6.651740234653323869e-01
        FLR::scaled(-0x163BD6DFFE386D, -52 + 1),  // -2.779218435235682794e+00
        FLR::scaled( 0x155CFB6ECFA0C7, -52 - 1),  // +6.676003612783681929e-01
        FLR::scaled(-0x1286DD284C9546, -52 + 6),  // -7.410724837759798334e+01
        FLR::scaled( 0x155CFB6ECFA0C7, -52 - 1),  // +6.676003612783681929e-01
        FLR::scaled(-0x1407D441D0B022, -52 + 4),  // -2.003058253617212614e+01
        FLR::scaled( 0x1558D1C6B552B7, -52 - 1),  // +6.670922165891032263e-01
        FLR::scaled(-0x11FF7221964EBD, -52 + 5),  // -3.599567050780522237e+01
        FLR::scaled( 0x1558D1C6B552B7, -52 - 1),  // +6.670922165891032263e-01
        FLR::scaled(-0x107C4301FCC37F, -52 + 4),  // -1.648539745732295714e+01
        FLR::scaled( 0x156D5C7ACBF94D, -52 - 1),  // +6.695997618078678437e-01
        FLR::scaled(-0x105C948701A1E6, -52 + 6),  // -6.544656539115348437e+01
        FLR::scaled( 0x156D5C7ACBF94D, -52 - 1),  // +6.695997618078678437e-01
        FLR::scaled(-0x15EFB3E6136016, -52 + 6),  // -8.774535514728663088e+01
        FLR::scaled( 0x154876E6206DD2, -52 - 1),  // +6.650957579290042165e-01
        FLR::scaled(-0x128B01DBCB455C, -52 + 3),  // -9.271498554766985478e+00
        FLR::scaled( 0x154876E6206DD2, -52 - 1),  // +6.650957579290042165e-01
        FLR::scaled( 0x1BFE7D3B7EA0DB, -52 + 3),  // +1.399704919739490627e+01
        FLR::scaled( 0x155E715B8FC2E3, -52 - 1),  // +6.677786625205864857e-01
        FLR::scaled( 0x16970EB057149A, -52 + 4),  // +2.259006788373935848e+01
        FLR::scaled( 0x155E715B8FC2E3, -52 - 1),  // +6.677786625205864857e-01
        FLR::scaled(-0x12D3904B71035F, -52 + 6),  // -7.530568204914514752e+01
        FLR::scaled( 0x155AA2844BE6A8, -52 - 1),  // +6.673138221660410707e-01
        FLR::scaled(-0x116E8EC0E09EED, -52 + 6),  // -6.972746297774911284e+01
        FLR::scaled( 0x155AA2844BE6A8, -52 - 1),  // +6.673138221660410707e-01
        FLR::scaled(-0x171B5C5D596C9D, -52 + 5),  // -4.621375624529284920e+01
        FLR::scaled( 0x15718A3DA472B1, -52 - 1),  // +6.701098636582029089e-01
        FLR::scaled(-0x1E6B2ACE414DA7, -52 + 3),  // -1.520931095645103248e+01
        FLR::scaled( 0x15718A3DA472B1, -52 - 1),  // +6.701098636582029089e-01
        FLR::scaled( 0x19D4A8279C9A33, -52 + 3),  // +1.291534541880273501e+01
        FLR::scaled( 0x1559DC259B0AA4, -52 - 1),  // +6.672192320332510640e-01
        FLR::scaled(-0x104F0B59C15BFC, -52 + 4),  // -1.630876694651304604e+01
        FLR::scaled( 0x1559DC259B0AA4, -52 - 1),  // +6.672192320332510640e-01
        FLR::scaled(-0x1044D95AFD4F07, -52 + 5),  // -3.253788316124524016e+01
        FLR::scaled( 0x156F36C1B97E4B, -52 - 1),  // +6.698259147341983910e-01
        FLR::scaled(-0x1CEAAC58254DE6, -52 + 5),  // -5.783338453122614453e+01
        FLR::scaled( 0x156F36C1B97E4B, -52 - 1),  // +6.698259147341983910e-01
        FLR::scaled(-0x18C2949B8106EA, -52 + 5),  // -4.952016013908526304e+01
        FLR::scaled( 0x156A11DA40C049, -52 - 1),  // +6.691979658844583456e-01
        FLR::scaled(-0x1277CF1399BE84, -52 + 6),  // -7.387201395048219865e+01
        FLR::scaled( 0x156A11DA40C049, -52 - 1),  // +6.691979658844583456e-01
        FLR::scaled(-0x128889B734D117, -52 + 5),  // -3.706670274809783194e+01
        FLR::scaled( 0x1580604485A6B7, -52 - 1),  // +6.719209039994983312e-01
        FLR::scaled(-0x16414B5F1BCCB5, -52 + 5),  // -4.451011265618709700e+01
        FLR::scaled( 0x1580604485A6B7, -52 - 1),  // +6.719209039994983312e-01
        FLR::scaled(-0x1FE6ED333EBC4B, -52 + 4),  // -3.190205688745144741e+01
        FLR::scaled( 0x15D93B5A0EE5B7, -52 - 1),  // +6.827675589512897103e-01
        FLR::scaled(-0x151F77D91C4FC8, -52 + 5),  // -4.224584497339634481e+01
        FLR::scaled( 0x15D93B5A0EE5B7, -52 - 1),  // +6.827675589512897103e-01
        FLR::scaled( 0x18E25B1E2DC342, -52 + 4),  // +2.488420284859899567e+01
        FLR::scaled( 0x15E4A2DA112623, -52 - 1),  // +6.841596850510466288e-01
        FLR::scaled(-0x10A5838403C020, -52 + 5),  // -3.329307604010705290e+01
        FLR::scaled( 0x15E4A2DA112623, -52 - 1),  // +6.841596850510466288e-01
        FLR::scaled(-0x1212E5B02E07F6, -52 + 5),  // -3.614763452766048601e+01
        FLR::scaled( 0x160575E1C33A65, -52 - 1),  // +6.881665620256397498e-01
        FLR::scaled( 0x1CBE777EA526AE, -52 + 2),  // +7.186002711133978593e+00
        FLR::scaled( 0x160575E1C33A65, -52 - 1),  // +6.881665620256397498e-01
        FLR::scaled(-0x16454DE6D03728, -52 + 3),  // -1.113535996715252452e+01
        FLR::scaled( 0x160E7AFE77B6A9, -52 - 1),  // +6.892676324911991559e-01
        FLR::scaled(-0x107DB5DD62587B, -52 + 6),  // -6.596422514537873383e+01
        FLR::scaled( 0x160E7AFE77B6A9, -52 - 1),  // +6.892676324911991559e-01
        FLR::scaled(-0x1A2BDA091C08ED, -52 + 5),  // -5.234259141796960790e+01
        FLR::scaled( 0x15EA9350948A8D, -52 - 1),  // +6.848846982796473748e-01
        FLR::scaled(-0x1F42EC7F0F3E02, -52 + 4),  // -3.126142114755749191e+01
        FLR::scaled( 0x15EA9350948A8D, -52 - 1),  // +6.848846982796473748e-01
        FLR::scaled(-0x11A392916D9C77, -52 + 6),  // -7.055582080558984615e+01
        FLR::scaled( 0x15F56043F5508E, -52 - 1),  // +6.862031295118116159e-01
        FLR::scaled( 0x1F38E2B102A301, -52 + 1),  // +3.902776129620520340e+00
        FLR::scaled( 0x15F56043F5508E, -52 - 1),  // +6.862031295118116159e-01
        FLR::scaled(-0x1E91C5E9BF009E, -52 + 6),  // -1.222777046551950377e+02
        FLR::scaled( 0x1613BD1996025C, -52 - 1),  // +6.899095058179898210e-01
        FLR::scaled(-0x10D63708935A12, -52 + 4),  // -1.683677724454361879e+01
        FLR::scaled( 0x1613BD1996025C, -52 - 1),  // +6.899095058179898210e-01
        FLR::scaled(-0x16CAFEB467846C, -52 + 1),  // -2.849118623169990983e+00
        FLR::scaled( 0x161C570BFC7BF3, -52 - 1),  // +6.909594759089244809e-01
        FLR::scaled(-0x1F3EE3375032FD, -52 + 3),  // -1.562282727102273761e+01
        FLR::scaled( 0x161C570BFC7BF3, -52 - 1),  // +6.909594759089244809e-01
        FLR::scaled(-0x1E3C947AF512EE, -52 + 4),  // -3.023664062960863674e+01
        FLR::scaled( 0x15F122CF697165, -52 - 1),  // +6.856855441106232130e-01
        FLR::scaled( 0x122474201362F4, -52 + 4),  // +1.814239693139366238e+01
        FLR::scaled( 0x15F122CF697165, -52 - 1),  // +6.856855441106232130e-01
        FLR::scaled(-0x17547DDAA3A6C6, -52 + 5),  // -4.666009076109689602e+01
        FLR::scaled( 0x15FCB60935F372, -52 - 1),  // +6.870985202691441973e-01
        FLR::scaled(-0x1CFFA86142A81C, -52 + 5),  // -5.799732604746552056e+01
        FLR::scaled( 0x15FCB60935F372, -52 - 1),  // +6.870985202691441973e-01
        FLR::scaled(-0x1389587ED0BF7A, -52 + 6),  // -7.814602632890264999e+01
        FLR::scaled( 0x162079EB44D639, -52 - 1),  // +6.914643855186063393e-01
        FLR::scaled(-0x1094DFD3E2A504, -52 + 6),  // -6.632616135724316564e+01
        FLR::scaled( 0x162079EB44D639, -52 - 1),  // +6.914643855186063393e-01
        FLR::scaled(-0x17B23DB792DDC2, -52 + 1),  // -2.962031778497220991e+00
        FLR::scaled( 0x16299BE44FA6A9, -52 - 1),  // +6.925792178346529271e-01
        FLR::scaled(-0x1F777D737D6FA3, -52 + 2),  // -7.866689495593081283e+00
        FLR::scaled( 0x16299BE44FA6A9, -52 - 1),  // +6.925792178346529271e-01
        FLR::scaled( 0x1BC70649B24990, -52 - 1),  // +8.680449904807563399e-01
        FLR::scaled( 0x160497629B8082, -52 - 1),  // +6.880604673315391384e-01
        FLR::scaled(-0x175EBBE5C89DB0, -52 + 4),  // -2.337005458972788574e+01
        FLR::scaled( 0x160497629B8082, -52 - 1),  // +6.880604673315391384e-01
        FLR::scaled(-0x122B6B8C257920, -52 + 5),  // -3.633921958760970483e+01
        FLR::scaled( 0x160F55E1335CA6, -52 - 1),  // +6.893720053148129079e-01
        FLR::scaled(-0x1E819E9AD3EA51, -52 + 2),  // -7.626581591781886438e+00
        FLR::scaled( 0x160F55E1335CA6, -52 - 1),  // +6.893720053148129079e-01
        FLR::scaled(-0x18E1C25697BCCB, -52 + 4),  // -2.488187161640670908e+01
        FLR::scaled( 0x1630CD1207EAB5, -52 - 1),  // +6.934571602026468051e-01
        FLR::scaled(-0x104D17E936C055, -52 + 4),  // -1.630114610277844989e+01
        FLR::scaled( 0x1630CD1207EAB5, -52 - 1),  // +6.934571602026468051e-01
        FLR::scaled( 0x1B98AB14FEEBF1, -52 + 4),  // +2.759636050437615395e+01
        FLR::scaled( 0x1639507D77CB2F, -52 - 1),  // +6.944963884874136850e-01
        FLR::scaled(-0x13462D6300A558, -52 + 5),  // -3.854826009303604906e+01
        FLR::scaled( 0x1639507D77CB2F, -52 - 1),  // +6.944963884874136850e-01
        FLR::scaled(-0x1642D63FBF8932, -52 + 6),  // -8.904432672218970879e+01
        FLR::scaled( 0x15C91D19AA49E8, -52 - 1),  // +6.808000088952299578e-01
        FLR::scaled( 0x16029ED124F9D0, -52 + 4),  // +2.201023585465173937e+01
        FLR::scaled( 0x15C91D19AA49E8, -52 - 1),  // +6.808000088952299578e-01
        FLR::scaled( 0x1E72FA1A6F435F, -52 + 3),  // +1.522456438644593213e+01
        FLR::scaled( 0x15DA6C39AAA925, -52 - 1),  // +6.829129339505796148e-01
        FLR::scaled(-0x18D5EF2F6C0212, -52 + 4),  // -2.483568092715183440e+01
        FLR::scaled( 0x15DA6C39AAA925, -52 - 1),  // +6.829129339505796148e-01
        FLR::scaled(-0x179256340D628B, -52 + 4),  // -2.357162785841732600e+01
        FLR::scaled( 0x15D6D57E3534F4, -52 - 1),  // +6.824748482701168406e-01
        FLR::scaled(-0x1AAB2F4EFB8F68, -52 + 5),  // -5.333738124163829752e+01
        FLR::scaled( 0x15D6D57E3534F4, -52 - 1),  // +6.824748482701168406e-01
        FLR::scaled( 0x14F9541A7A9D3B, -52 + 5),  // +4.194787913310070593e+01
        FLR::scaled( 0x15E91738FB7EEB, -52 - 1),  // +6.847034562051396156e-01
        FLR::scaled(-0x147E72DC245276, -52 + 4),  // -2.049394012343187654e+01
        FLR::scaled( 0x15E91738FB7EEB, -52 - 1),  // +6.847034562051396156e-01
        FLR::scaled(-0x15CFD609C3A2D5, -52 + 2),  // -5.452964928212812090e+00
        FLR::scaled( 0x15DCE3EC9E6EA5, -52 - 1),  // +6.832141515219133376e-01
        FLR::scaled(-0x163470679225E8, -52 + 3),  // -1.110242007884058069e+01
        FLR::scaled( 0x15DCE3EC9E6EA5, -52 - 1),  // +6.832141515219133376e-01
        FLR::scaled(-0x1F41A908B8B9A5, -52 + 5),  // -6.251297101039680371e+01
        FLR::scaled( 0x15ECD058907577, -52 - 1),  // +6.851579408427558304e-01
        FLR::scaled(-0x11DA1D924DDE06, -52 + 6),  // -7.140805490116335363e+01
        FLR::scaled( 0x15ECD058907577, -52 - 1),  // +6.851579408427558304e-01
        FLR::scaled(-0x145456FC46698E, -52 + 4),  // -2.032945229262400488e+01
        FLR::scaled( 0x15E8D1BDD58136, -52 - 1),  // +6.846703250594490253e-01
        FLR::scaled(-0x1139CCAA0BF3F2, -52 + 4),  // -1.722577917854136587e+01
        FLR::scaled( 0x15E8D1BDD58136, -52 - 1),  // +6.846703250594490253e-01
        FLR::scaled(-0x196EA412D76115, -52 + 2),  // -6.358047766109184984e+00
        FLR::scaled( 0x15F9BBE9A1E489, -52 - 1),  // +6.867351115353282909e-01
        FLR::scaled(-0x15B3AE91F41BFC, -52 + 5),  // -4.340376495761299225e+01
        FLR::scaled( 0x15F9BBE9A1E489, -52 - 1),  // +6.867351115353282909e-01
        FLR::scaled(-0x1182B5F322642C, -52 + 6),  // -7.004235533102536237e+01
        FLR::scaled( 0x15D911C052144D, -52 - 1),  // +6.827477222692636127e-01
        FLR::scaled( 0x131274D3BD6096, -52 + 3),  // +9.536047570102066828e+00
        FLR::scaled( 0x15D911C052144D, -52 - 1),  // +6.827477222692636127e-01
        FLR::scaled(-0x12204939E45F69, -52 + 6),  // -7.250446936895390593e+01
        FLR::scaled( 0x15EC6266019108, -52 - 1),  // +6.851055137927071215e-01
        FLR::scaled( 0x104F1A0E93960F, -52 + 4),  // +1.630899134734323397e+01
        FLR::scaled( 0x15EC6266019108, -52 - 1),  // +6.851055137927071215e-01
        FLR::scaled(-0x11D29BFC5E9516, -52 + 5),  // -3.564538530939368854e+01
        FLR::scaled( 0x15E7EB7A9D8E7B, -52 - 1),  // +6.845605273087608245e-01
        FLR::scaled(-0x177FDB8B6D63A4, -52 + 5),  // -4.699888747063894812e+01
        FLR::scaled( 0x15E7EB7A9D8E7B, -52 - 1),  // +6.845605273087608245e-01
        FLR::scaled( 0x1A0BC83E979488, -52 + 5),  // +5.209204847718598330e+01
        FLR::scaled( 0x15FC7398BB4A6F, -52 - 1),  // +6.870668395079756463e-01
        FLR::scaled(-0x16621A9EE83660, -52 + 6),  // -8.953287480046265046e+01
        FLR::scaled( 0x15FC7398BB4A6F, -52 - 1),  // +6.870668395079756463e-01
        FLR::scaled(-0x135E7F8CD99540, -52 + 0),  // -1.210570860095074863e+00
        FLR::scaled( 0x15EE87E4853F67, -52 - 1),  // +6.853675330439558122e-01
        FLR::scaled(-0x1FA7B66EB1FFD0, -52 + 5),  // -6.331025489512796867e+01
        FLR::scaled( 0x15EE87E4853F67, -52 - 1),  // +6.853675330439558122e-01
        FLR::scaled( 0x1B9A5A8C81BF44, -52 + 4),  // +2.760294416587500166e+01
        FLR::scaled( 0x16008584B7A62E, -52 - 1),  // +6.875636665474240683e-01
        FLR::scaled(-0x1295E2F7A308E7, -52 + 5),  // -3.717098899326975214e+01
        FLR::scaled( 0x16008584B7A62E, -52 - 1),  // +6.875636665474240683e-01
        FLR::scaled(-0x1875470A4E2F15, -52 + 5),  // -4.891623047654699263e+01
        FLR::scaled( 0x15FB8AF4EDD853, -52 - 1),  // +6.869559081812987023e-01
        FLR::scaled(-0x1260E163DA2DDE, -52 + 4),  // -1.837843917919769154e+01
        FLR::scaled( 0x15FB8AF4EDD853, -52 - 1),  // +6.869559081812987023e-01
        FLR::scaled( 0x1CAC8DAAD2882C, -52 + 3),  // +1.433701833553285354e+01
        FLR::scaled( 0x160ECC988F07D2, -52 - 1),  // +6.893065433180203261e-01
        FLR::scaled(-0x15EAD6E52EE93B, -52 + 6),  // -8.766936616498144019e+01
        FLR::scaled( 0x160ECC988F07D2, -52 - 1),  // +6.893065433180203261e-01
        FLR::scaled(-0x1AF868B7B15D63, -52 + 6),  // -1.078813914520338102e+02
        FLR::scaled( 0x167467A0E01EB9, -52 - 1),  // +7.017095701312064948e-01
        FLR::scaled(-0x158AC35B2015C8, -52 + 3),  // -1.077102169768012629e+01
        FLR::scaled( 0x167467A0E01EB9, -52 - 1),  // +7.017095701312064948e-01
        FLR::scaled(-0x101347F1B55B95, -52 + 6),  // -6.430126612387387297e+01
        FLR::scaled( 0x167F9EC6B12B86, -52 - 1),  // +7.030786400513171497e-01
        FLR::scaled(-0x162CF51AC5E595, -52 + 4),  // -2.217561499911751710e+01
        FLR::scaled( 0x167F9EC6B12B86, -52 - 1),  // +7.030786400513171497e-01
        FLR::scaled(-0x1B56B4FE692148, -52 + 2),  // -6.834674811522127413e+00
        FLR::scaled( 0x1698E371FD548C, -52 - 1),  // +7.061631418570342156e-01
        FLR::scaled(-0x18508BB2B3FC34, -52 + 5),  // -4.862926324642504028e+01
        FLR::scaled( 0x1698E371FD548C, -52 - 1),  // +7.061631418570342156e-01
        FLR::scaled(-0x1B5683093598D7, -52 + 5),  // -5.467587390057604324e+01
        FLR::scaled( 0x16A2FBF4B5A892, -52 - 1),  // +7.073955325588647813e-01
        FLR::scaled(-0x13A43ADBD42F27, -52 + 5),  // -3.928304622517162414e+01
        FLR::scaled( 0x16A2FBF4B5A892, -52 - 1),  // +7.073955325588647813e-01
        FLR::scaled( 0x16A44EE7D6DFD1, -52 + 3),  // +1.132091450212456785e+01
        FLR::scaled( 0x168B2D0EC8523F, -52 - 1),  // +7.044892586441803273e-01
        FLR::scaled(-0x141C95047A41D8, -52 + 5),  // -4.022329765290822934e+01
        FLR::scaled( 0x168B2D0EC8523F, -52 - 1),  // +7.044892586441803273e-01
        FLR::scaled(-0x1D7C8BFF7781C2, -52 + 5),  // -5.897302239737793172e+01
        FLR::scaled( 0x1694E4C132F61F, -52 - 1),  // +7.056754849833771770e-01
        FLR::scaled( 0x1CD4B8B3CBF520, -52 + 3),  // +1.441547166695323767e+01
        FLR::scaled( 0x1694E4C132F61F, -52 - 1),  // +7.056754849833771770e-01
        FLR::scaled(-0x118FD0C0A16CFF, -52 + 5),  // -3.512355811960332375e+01
        FLR::scaled( 0x16ABA09F0466BB, -52 - 1),  // +7.084506135754148337e-01
        FLR::scaled(-0x1E3F38ABAEE726, -52 + 4),  // -3.024695847530451687e+01
        FLR::scaled( 0x16ABA09F0466BB, -52 - 1),  // +7.084506135754148337e-01
        FLR::scaled(-0x12BAD76BF09355, -52 + 4),  // -1.872984957335878065e+01
        FLR::scaled( 0x16B48EF5DF962E, -52 - 1),  // +7.095408251013333167e-01
        FLR::scaled(-0x16D07298D18A4E, -52 + 5),  // -4.562849722129304553e+01
        FLR::scaled( 0x16B48EF5DF962E, -52 - 1),  // +7.095408251013333167e-01
        FLR::scaled(-0x1376855366657C, -52 + 6),  // -7.785188755988741605e+01
        FLR::scaled( 0x169094E68B577A, -52 - 1),  // +7.051491263216427274e-01
        FLR::scaled(-0x155D8CD3C03EA4, -52 + 6),  // -8.546172040723701002e+01
        FLR::scaled( 0x169094E68B577A, -52 - 1),  // +7.051491263216427274e-01
        FLR::scaled(-0x1E1CAFD4FB323F, -52 + 4),  // -3.011205798275682000e+01
        FLR::scaled( 0x169CDAB04327CF, -52 - 1),  // +7.066472475646551343e-01
        FLR::scaled(-0x12597602E71F18, -52 + 5),  // -3.669891392026164567e+01
        FLR::scaled( 0x169CDAB04327CF, -52 - 1),  // +7.066472475646551343e-01
        FLR::scaled( 0x1D4320146811AD, -52 + 4),  // +2.926220824757335848e+01
        FLR::scaled( 0x16B9AB15E4C6A4, -52 - 1),  // +7.101645877466649104e-01
        FLR::scaled(-0x1625B6C1E77B86, -52 + 5),  // -4.429463981440407849e+01
        FLR::scaled( 0x16B9AB15E4C6A4, -52 - 1),  // +7.101645877466649104e-01
        FLR::scaled(-0x152C63A0A2AA90, -52 + 1),  // -2.646674399341755191e+00
        FLR::scaled( 0x16C4CF70B3F797, -52 - 1),  // +7.115246964674381003e-01
        FLR::scaled(-0x1326276EB233EE, -52 + 4),  // -1.914903919077544714e+01
        FLR::scaled( 0x16C4CF70B3F797, -52 - 1),  // +7.115246964674381003e-01
        FLR::scaled( 0x12F2D43328B4D4, -52 + 6),  // +7.579420165038328605e+01
        FLR::scaled( 0x16A96763AB859A, -52 - 1),  // +7.081791826896506326e-01
        FLR::scaled(-0x18D6746090EC09, -52 + 5),  // -4.967542655063886770e+01
        FLR::scaled( 0x16A96763AB859A, -52 - 1),  // +7.081791826896506326e-01
        FLR::scaled( 0x1FC9EE20FEEB60, -52 + 0),  // +1.986799363031160226e+00
        FLR::scaled( 0x16B3F1CA618E04, -52 - 1),  // +7.094658806567513132e-01
        FLR::scaled(-0x10CDDF6569066E, -52 + 5),  // -3.360838000896625033e+01
        FLR::scaled( 0x16B3F1CA618E04, -52 - 1),  // +7.094658806567513132e-01
        FLR::scaled(-0x11F67E9676E3C5, -52 + 5),  // -3.592573815159952488e+01
        FLR::scaled( 0x16CE601D061756, -52 - 1),  // +7.126923148032158206e-01
        FLR::scaled(-0x1ABC65141C9BC3, -52 + 5),  // -5.347183467289826098e+01
        FLR::scaled( 0x16CE601D061756, -52 - 1),  // +7.126923148032158206e-01
        FLR::scaled( 0x1762B39CEF7778, -52 + 3),  // +1.169277658866097624e+01
        FLR::scaled( 0x16D8225C7B259D, -52 - 1),  // +7.138835722227444558e-01
        FLR::scaled(-0x105C412482D407, -52 + 6),  // -6.544147599006838334e+01
        FLR::scaled( 0x16D8225C7B259D, -52 - 1),  // +7.138835722227444558e-01
        FLR::scaled(-0x142C26D5DD348E, -52 + 5),  // -4.034493516255416523e+01
        FLR::scaled( 0x1669E6DE814124, -52 - 1),  // +7.004274698065597882e-01
        FLR::scaled(-0x1ACB65B81CF537, -52 + 4),  // -2.679452086169223080e+01
        FLR::scaled( 0x1669E6DE814124, -52 - 1),  // +7.004274698065597882e-01
        FLR::scaled(-0x1ACE38169F425D, -52 + 2),  // -6.701385835142528613e+00
        FLR::scaled( 0x16897F911F6765, -52 - 1),  // +7.042844614436317707e-01
        FLR::scaled(-0x1CA4681D6113E1, -52 + 4),  // -2.864221366519985068e+01
        FLR::scaled( 0x16897F911F6765, -52 - 1),  // +7.042844614436317707e-01
        FLR::scaled( 0x1783753FEFCC3E, -52 + 4),  // +2.351350783924521437e+01
        FLR::scaled( 0x167E497EBADD2C, -52 - 1),  // +7.029159045404518302e-01
        FLR::scaled(-0x17A6205C58EB1D, -52 + 5),  // -4.729786257116050052e+01
        FLR::scaled( 0x167E497EBADD2C, -52 - 1),  // +7.029159045404518302e-01
        FLR::scaled(-0x144CC4B1A1A2BA, -52 + 4),  // -2.029987631031210782e+01
        FLR::scaled( 0x16A095BA7DF63E, -52 - 1),  // +7.071026461050633483e-01
        FLR::scaled(-0x1197DCC378B7BA, -52 + 6),  // -7.037284933842502710e+01
        FLR::scaled( 0x16A095BA7DF63E, -52 - 1),  // +7.071026461050633483e-01
        FLR::scaled(-0x10CAD326B0D118, -52 + 4),  // -1.679228441063705191e+01
        FLR::scaled( 0x16792BEE1A3F00, -52 - 1),  // +7.022914553108137170e-01
        FLR::scaled(-0x1A564B999F1188, -52 + 5),  // -5.267418213145271011e+01
        FLR::scaled( 0x16792BEE1A3F00, -52 - 1),  // +7.022914553108137170e-01
        FLR::scaled(-0x1243BEFF4A35A5, -52 + 5),  // -3.652926627276909954e+01
        FLR::scaled( 0x1698D6107993F9, -52 - 1),  // +7.061567613387743636e-01
        FLR::scaled(-0x1645F0EAE5CCA2, -52 + 2),  // -5.568301840091551824e+00
        FLR::scaled( 0x1698D6107993F9, -52 - 1),  // +7.061567613387743636e-01
        FLR::scaled( 0x13846FD5C9E380, -52 + 0),  // +1.219833216773821505e+00
        FLR::scaled( 0x168B7EB005D2DB, -52 - 1),  // +7.045281827873525193e-01
        FLR::scaled(-0x10B98A3586049F, -52 + 5),  // -3.344953030628061441e+01
        FLR::scaled( 0x168B7EB005D2DB, -52 - 1),  // +7.045281827873525193e-01
        FLR::scaled( 0x12E6C7B7F92276, -52 + 3),  // +9.450742482339801853e+00
        FLR::scaled( 0x16ADB30EE4D644, -52 - 1),  // +7.087035456558585800e-01
        FLR::scaled(-0x129DDA8D2B90CB, -52 + 5),  // -3.723323216082788889e+01
        FLR::scaled( 0x16ADB30EE4D644, -52 - 1),  // +7.087035456558585800e-01
        FLR::scaled(-0x1EB0194D551301, -52 + 5),  // -6.137577215818419774e+01
        FLR::scaled( 0x16862D60DE6D59, -52 - 1),  // +7.038790599794239045e-01
        FLR::scaled(-0x142E5C94CEABB7, -52 + 5),  // -4.036220035640092618e+01
        FLR::scaled( 0x16862D60DE6D59, -52 - 1),  // +7.038790599794239045e-01
        FLR::scaled(-0x1B2BB54AAFC39C, -52 + 5),  // -5.434147008497458842e+01
        FLR::scaled( 0x16A8E05BDEB220, -52 - 1),  // +7.081147951444712874e-01
        FLR::scaled(-0x1D5DCBA28A6A3F, -52 + 3),  // -1.468319423617970010e+01
        FLR::scaled( 0x16A8E05BDEB220, -52 - 1),  // +7.081147951444712874e-01
        FLR::scaled( 0x11EB1A3DDCB344, -52 + 2),  // +4.479592291446184760e+00
        FLR::scaled( 0x169CF4B0D6FB57, -52 - 1),  // +7.066596464063462646e-01
        FLR::scaled(-0x1681ECEED909F8, -52 + 5),  // -4.501504312131504548e+01
        FLR::scaled( 0x169CF4B0D6FB57, -52 - 1),  // +7.066596464063462646e-01
        FLR::scaled( 0x1D28773021E229, -52 + 3),  // +1.457903433240524471e+01
        FLR::scaled( 0x16C387ECFF41F8, -52 - 1),  // +7.113685253953567766e-01
        FLR::scaled(-0x1F912003B6EA05, -52 + 5),  // -6.313378950530390199e+01
        FLR::scaled( 0x16C387ECFF41F8, -52 - 1),  // +7.113685253953567766e-01
        FLR::scaled( 0x1291036A9DC196, -52 + 3),  // +9.283229190595005065e+00
        FLR::scaled( 0x16981037155C28, -52 - 1),  // +7.060624194954288058e-01
        FLR::scaled(-0x108A22B6EE2584, -52 + 5),  // -3.307918440464257515e+01
        FLR::scaled( 0x16981037155C28, -52 - 1),  // +7.060624194954288058e-01
        FLR::scaled(-0x154BAAF42A15CB, -52 + 5),  // -4.259115459494531564e+01
        FLR::scaled( 0x16BAA8237FF6FA, -52 - 1),  // +7.102852528912244612e-01
        FLR::scaled(-0x1A3FF5E1561089, -52 - 2),  // -4.101538372563103274e-01
        FLR::scaled( 0x16BAA8237FF6FA, -52 - 1),  // +7.102852528912244612e-01
        FLR::scaled(-0x127A290F26540A, -52 + 6),  // -7.390875605338092669e+01
        FLR::scaled( 0x16AC6D111A1B45, -52 - 1),  // +7.085481008551616222e-01
        FLR::scaled(-0x150F53756CF1A8, -52 + 2),  // -5.264966807150280204e+00
        FLR::scaled( 0x16AC6D111A1B45, -52 - 1),  // +7.085481008551616222e-01
        FLR::scaled(-0x1192EC3DC5E1E5, -52 + 5),  // -3.514783451235033596e+01
        FLR::scaled( 0x16D2AA8EAD7FD2, -52 - 1),  // +7.132160936998792611e-01
        FLR::scaled(-0x15A94576BA1893, -52 + 6),  // -8.664486473248898335e+01
        FLR::scaled( 0x16D2AA8EAD7FD2, -52 - 1),  // +7.132160936998792611e-01
        FLR::scaled(-0x136869ACB18327, -52 + 6),  // -7.763144986472308062e+01
        FLR::scaled( 0x1755CB16C5CD35, -52 - 1),  // +7.292228169230045021e-01
        FLR::scaled(-0x1766A81D0FFE30, -52 + 5),  // -4.680200541764168065e+01
        FLR::scaled( 0x1755CB16C5CD35, -52 - 1),  // +7.292228169230045021e-01
        FLR::scaled( 0x107C4EBC454DC7, -52 + 5),  // +3.297115281471229054e+01
        FLR::scaled( 0x176A6CAA8CB781, -52 - 1),  // +7.317412692116108675e-01
        FLR::scaled(-0x12F3B5F295873A, -52 + 1),  // -2.368999381244887736e+00
        FLR::scaled( 0x176A6CAA8CB781, -52 - 1),  // +7.317412692116108675e-01
        FLR::scaled( 0x17E4640F60D712, -52 + 0),  // +1.493259487220204296e+00
        FLR::scaled( 0x177C2D46CE6C2E, -52 - 1),  // +7.339083083092015070e-01
        FLR::scaled( 0x1D29B3AA1DEA44, -52 + 2),  // +7.290724428249237832e+00
        FLR::scaled( 0x177C2D46CE6C2E, -52 - 1),  // +7.339083083092015070e-01
        FLR::scaled( 0x1DFBDEE5F3B2B1, -52 + 3),  // +1.499193495368794693e+01
        FLR::scaled( 0x178F90D96FF972, -52 - 1),  // +7.362751242469995905e-01
        FLR::scaled(-0x10F83887E0FF4B, -52 + 6),  // -6.787845036480318583e+01
        FLR::scaled( 0x178F90D96FF972, -52 - 1),  // +7.362751242469995905e-01
        FLR::scaled(-0x14F018594C4C8C, -52 + 3),  // -1.046893576675781645e+01
        FLR::scaled( 0x1764231753D7AF, -52 - 1),  // +7.309737640014101201e-01
        FLR::scaled(-0x14BED3495F1EEC, -52 + 4),  // -2.074541147777829053e+01
        FLR::scaled( 0x1764231753D7AF, -52 - 1),  // +7.309737640014101201e-01
        FLR::scaled( 0x1E7054628CFBAC, -52 + 3),  // +1.521939380618081117e+01
        FLR::scaled( 0x1778E21711059C, -52 - 1),  // +7.335062456624430460e-01
        FLR::scaled(-0x16BC8213D60D2B, -52 + 6),  // -9.094543929961643869e+01
        FLR::scaled( 0x1778E21711059C, -52 - 1),  // +7.335062456624430460e-01
        FLR::scaled(-0x18718A818E638A, -52 + 5),  // -4.888703937008456535e+01
        FLR::scaled( 0x17885DB489A9DB, -52 - 1),  // +7.353962446334735281e-01
        FLR::scaled(-0x1204DABA5167DA, -52 + 5),  // -3.603792504286657561e+01
        FLR::scaled( 0x17885DB489A9DB, -52 - 1),  // +7.353962446334735281e-01
        FLR::scaled(-0x158368A8659B6A, -52 + 5),  // -4.302663140260013108e+01
        FLR::scaled( 0x179BEAAC4884AD, -52 - 1),  // +7.377827992351250197e-01
        FLR::scaled(-0x1097271CB435DF, -52 + 4),  // -1.659044055366200254e+01
        FLR::scaled( 0x179BEAAC4884AD, -52 - 1),  // +7.377827992351250197e-01
        FLR::scaled(-0x15C1C7EED38515, -52 + 4),  // -2.175695698417719726e+01
        FLR::scaled( 0x177A6174C5ECC8, -52 - 1),  // +7.336890488362763918e-01
        FLR::scaled( 0x11311A69F19A17, -52 + 5),  // +3.438361858651131087e+01
        FLR::scaled( 0x177A6174C5ECC8, -52 - 1),  // +7.336890488362763918e-01
        FLR::scaled(-0x103CAB559444A4, -52 + 4),  // -1.623698935384585695e+01
        FLR::scaled( 0x178F32D160FF97, -52 - 1),  // +7.362302865440025768e-01
        FLR::scaled(-0x1CCEAD9492F79C, -52 + 4),  // -2.880733612621371265e+01
        FLR::scaled( 0x178F32D160FF97, -52 - 1),  // +7.362302865440025768e-01
        FLR::scaled(-0x11CF1D0BDD733E, -52 + 6),  // -7.123614784837715774e+01
        FLR::scaled( 0x17A0F8AFA853D5, -52 - 1),  // +7.383998328028790192e-01
        FLR::scaled(-0x129C629D08795A, -52 + 6),  // -7.444351888492147395e+01
        FLR::scaled( 0x17A0F8AFA853D5, -52 - 1),  // +7.383998328028790192e-01
        FLR::scaled(-0x1A169A1C510073, -52 + 5),  // -5.217657808261073882e+01
        FLR::scaled( 0x17B509476D7755, -52 - 1),  // +7.408491511412004238e-01
        FLR::scaled(-0x13569D8CB6A674, -52 + 5),  // -3.867668303411929287e+01
        FLR::scaled( 0x17B509476D7755, -52 - 1),  // +7.408491511412004238e-01
        FLR::scaled( 0x17FD861D4A1A48, -52 + 2),  // +5.997581918380610944e+00
        FLR::scaled( 0x178AAFA2AE2978, -52 - 1),  // +7.356794526433949599e-01
        FLR::scaled(-0x1B6AC8FD68F437, -52 + 1),  // -3.427141170278015903e+00
        FLR::scaled( 0x178AAFA2AE2978, -52 - 1),  // +7.356794526433949599e-01
        FLR::scaled(-0x17223350E76AB8, -52 + 0),  // -1.445849720030919272e+00
        FLR::scaled( 0x179F1AA7BC8A99, -52 - 1),  // +7.381718898871724166e-01
        FLR::scaled(-0x17381F8025CB72, -52 + 3),  // -1.160961533032761750e+01
        FLR::scaled( 0x179F1AA7BC8A99, -52 - 1),  // +7.381718898871724166e-01
        FLR::scaled( 0x1054409EE37100, -52 - 4),  // +6.378558997261407626e-02
        FLR::scaled( 0x17AE9ECF9F86C0, -52 - 1),  // +7.400659613742490706e-01
        FLR::scaled(-0x1C44BF0531AF58, -52 + 5),  // -5.653707947660467426e+01
        FLR::scaled( 0x17AE9ECF9F86C0, -52 - 1),  // +7.400659613742490706e-01
        FLR::scaled( 0x11B18C5A9F3A2B, -52 + 4),  // +1.769354788195975559e+01
        FLR::scaled( 0x17C26081FC72AD, -52 - 1),  // +7.424776591102123513e-01
        FLR::scaled(-0x13A795D5CD2F71, -52 + 3),  // -9.827315026566539657e+00
        FLR::scaled( 0x17C26081FC72AD, -52 - 1),  // +7.424776591102123513e-01
        FLR::scaled(-0x17E3B788FBA209, -52 + 5),  // -4.777903854643597725e+01
        FLR::scaled( 0x17338F18FD7C55, -52 - 1),  // +7.250438201989576337e-01
        FLR::scaled(-0x128207D0326025, -52 + 5),  // -3.701586344203705181e+01
        FLR::scaled( 0x17338F18FD7C55, -52 - 1),  // +7.250438201989576337e-01
        FLR::scaled(-0x1BBB90A4D08ACD, -52 + 4),  // -2.773267583934175562e+01
        FLR::scaled( 0x174C76BB18C524, -52 - 1),  // +7.280839590295369312e-01
        FLR::scaled( 0x1638C59E3AC9CA, -52 + 2),  // +5.555441353166722607e+00
        FLR::scaled( 0x174C76BB18C524, -52 - 1),  // +7.280839590295369312e-01
        FLR::scaled( 0x103B8E2963B998, -52 + 4),  // +1.623263796505634105e+01
        FLR::scaled( 0x1749D8BC8ED90B, -52 - 1),  // +7.277644808553146438e-01
        FLR::scaled(-0x1F73EA49670300, -52 + 4),  // -3.145279368176397838e+01
        FLR::scaled( 0x1749D8BC8ED90B, -52 - 1),  // +7.277644808553146438e-01
        FLR::scaled(-0x16044978224941, -52 + 5),  // -4.403349210428360294e+01
        FLR::scaled( 0x1765E5B7348D8D, -52 - 1),  // +7.311886385181637360e-01
        FLR::scaled(-0x16B08E802091D5, -52 + 6),  // -9.075869754009848123e+01
        FLR::scaled( 0x1765E5B7348D8D, -52 - 1),  // +7.311886385181637360e-01
        FLR::scaled(-0x1B4357270A9FBC, -52 + 4),  // -2.726304859170316774e+01
        FLR::scaled( 0x17467E865B9A0F, -52 - 1),  // +7.273552536178743422e-01
        FLR::scaled(-0x184E9D846D026F, -52 + 3),  // -1.215354551153833818e+01
        FLR::scaled( 0x17467E865B9A0F, -52 - 1),  // +7.273552536178743422e-01
        FLR::scaled(-0x1FCF88D89D79E2, -52 + 5),  // -6.362136371316206862e+01
        FLR::scaled( 0x175ED136526531, -52 - 1),  // +7.303243695234070687e-01
        FLR::scaled(-0x124E0D86936111, -52 + 5),  // -3.660978777118919680e+01
        FLR::scaled( 0x175ED136526531, -52 - 1),  // +7.303243695234070687e-01
        FLR::scaled( 0x195554BB5709CA, -52 + 3),  // +1.266666207730749605e+01
        FLR::scaled( 0x175A6BCFA94A4F, -52 - 1),  // +7.297877365002224392e-01
        FLR::scaled(-0x19FCB1DA86FD10, -52 + 0),  // -1.624193051931630549e+00
        FLR::scaled( 0x175A6BCFA94A4F, -52 - 1),  // +7.297877365002224392e-01
        FLR::scaled(-0x1597ACC07A2FA4, -52 + 5),  // -4.318495946851842859e+01
        FLR::scaled( 0x1775C0E0F8C375, -52 - 1),  // +7.331241983393811390e-01
        FLR::scaled(-0x186089A428B767, -52 + 3),  // -1.218855011937166744e+01
        FLR::scaled( 0x1775C0E0F8C375, -52 - 1),  // +7.331241983393811390e-01
        FLR::scaled(-0x1990E23DDF5911, -52 + 5),  // -5.113190434842739052e+01
        FLR::scaled( 0x175144DBD48FA9, -52 - 1),  // +7.286705297051315755e-01
        FLR::scaled(-0x134CBC3B2E7DE6, -52 + 6),  // -7.719898871937002127e+01
        FLR::scaled( 0x175144DBD48FA9, -52 - 1),  // +7.286705297051315755e-01
        FLR::scaled(-0x15C0BB9B51A5B8, -52 + 5),  // -4.350572530256926029e+01
        FLR::scaled( 0x176DAAAB728FAF, -52 - 1),  // +7.321370457252579511e-01
        FLR::scaled(-0x1FBFBE3EE7A0D6, -52 + 0),  // -1.984312291833750574e+00
        FLR::scaled( 0x176DAAAB728FAF, -52 - 1),  // +7.321370457252579511e-01
        FLR::scaled(-0x16CBD4DFB6A092, -52 + 3),  // -1.139810847381912495e+01
        FLR::scaled( 0x176BB71B84DF87, -52 - 1),  // +7.318988358956496354e-01
        FLR::scaled(-0x11A9B29A653BC1, -52 + 4),  // -1.766288151713866128e+01
        FLR::scaled( 0x176BB71B84DF87, -52 - 1),  // +7.318988358956496354e-01
        FLR::scaled(-0x14973CA2C8C996, -52 + 5),  // -4.118153796009134737e+01
        FLR::scaled( 0x178C669BFC1E74, -52 - 1),  // +7.358887716845416982e-01
        FLR::scaled(-0x15060FD5FD03F2, -52 + 6),  // -8.409471654614006297e+01
        FLR::scaled( 0x178C669BFC1E74, -52 - 1),  // +7.358887716845416982e-01
        FLR::scaled( 0x102CCCFD3F27BE, -52 + 3),  // +8.087501443824177016e+00
        FLR::scaled( 0x1765DDBB6F744A, -52 - 1),  // +7.311848317000422259e-01
        FLR::scaled(-0x19F64B4BDFB35A, -52 + 5),  // -5.192417286322479697e+01
        FLR::scaled( 0x1765DDBB6F744A, -52 - 1),  // +7.311848317000422259e-01
        FLR::scaled(-0x1ACBC8E91A8E5A, -52 + 5),  // -5.359206880375559479e+01
        FLR::scaled( 0x1781E574562BD4, -52 - 1),  // +7.346064827155438515e-01
        FLR::scaled(-0x1ADCF719A80015, -52 + 5),  // -5.372629090026035925e+01
        FLR::scaled( 0x1781E574562BD4, -52 - 1),  // +7.346064827155438515e-01
        FLR::scaled(-0x1B587B58AD1424, -52 + 3),  // -1.367281605828072344e+01
        FLR::scaled( 0x177DB1CE2216C6, -52 - 1),  // +7.340935731924325136e-01
        FLR::scaled(-0x109598E0949068, -52 + 6),  // -6.633745588787280667e+01
        FLR::scaled( 0x177DB1CE2216C6, -52 - 1),  // +7.340935731924325136e-01
        FLR::scaled(-0x19678E49783C7C, -52 + 3),  // -1.270225743859031553e+01
        FLR::scaled( 0x179DD439886803, -52 - 1),  // +7.380162357032989950e-01
        FLR::scaled(-0x12451D8BB8DAFE, -52 + 5),  // -3.653996416593689389e+01
        FLR::scaled( 0x179DD439886803, -52 - 1),  // +7.380162357032989950e-01
        FLR::scaled(-0x1644BE399D5E9E, -52 + 6),  // -8.907411041610836833e+01
        FLR::scaled( 0x182D490AD7E9F8, -52 - 1),  // +7.555279933724809993e-01
        FLR::scaled( 0x1CC09A0F612D60, -52 + 0),  // +1.797021923138196087e+00
        FLR::scaled( 0x182D490AD7E9F8, -52 - 1),  // +7.555279933724809993e-01
        FLR::scaled(-0x1EDE3F66192C32, -52 + 4),  // -3.086815488924566608e+01
        FLR::scaled( 0x184015D5FF9988, -52 - 1),  // +7.578229121834718640e-01
        FLR::scaled(-0x1974E565DF2486, -52 + 4),  // -2.545662533471888622e+01
        FLR::scaled( 0x184015D5FF9988, -52 - 1),  // +7.578229121834718640e-01
        FLR::scaled( 0x11FABF1E683270, -52 + 2),  // +4.494869685277635085e+00
        FLR::scaled( 0x18567574514F4D, -52 - 1),  // +7.605540534809535069e-01
        FLR::scaled(-0x1CA7E2AAF3969E, -52 + 5),  // -5.731160485166513752e+01
        FLR::scaled( 0x18567574514F4D, -52 - 1),  // +7.605540534809535069e-01
        FLR::scaled( 0x11A6FAD2CEE039, -52 + 0),  // +1.103266547650504359e+00
        FLR::scaled( 0x186A011D95FB3E, -52 - 1),  // +7.629399850701259478e-01
        FLR::scaled(-0x127CD074546182, -52 + 5),  // -3.697511152382050170e+01
        FLR::scaled( 0x186A011D95FB3E, -52 - 1),  // +7.629399850701259478e-01
        FLR::scaled(-0x11C2A9CEBD8D66, -52 + 4),  // -1.776040355804197901e+01
        FLR::scaled( 0x184378F02489E0, -52 - 1),  // +7.582363786971733077e-01
        FLR::scaled(-0x1302D3BFD7EDE6, -52 + 4),  // -1.901104353925429535e+01
        FLR::scaled( 0x184378F02489E0, -52 - 1),  // +7.582363786971733077e-01
        FLR::scaled(-0x11A20A431038B5, -52 + 5),  // -3.526593817035737999e+01
        FLR::scaled( 0x18555AD57D44AD, -52 - 1),  // +7.604192895616016523e-01
        FLR::scaled( 0x1D10D0543164A0, -52 + 2),  // +7.266419711603845144e+00
        FLR::scaled( 0x18555AD57D44AD, -52 - 1),  // +7.604192895616016523e-01
        FLR::scaled(-0x1C2C3422BE5CF8, -52 + 5),  // -5.634534105582309849e+01
        FLR::scaled( 0x18695C8F2D8CAB, -52 - 1),  // +7.628615185207271443e-01
        FLR::scaled(-0x163F400781B582, -52 + 5),  // -4.449414151986549371e+01
        FLR::scaled( 0x18695C8F2D8CAB, -52 - 1),  // +7.628615185207271443e-01
        FLR::scaled( 0x1C31C1F8449C59, -52 + 3),  // +1.409718299710782397e+01
        FLR::scaled( 0x187C1AFD3FC073, -52 - 1),  // +7.651495882291911022e-01
        FLR::scaled(-0x104485B98BE6CC, -52 + 6),  // -6.507066191351185580e+01
        FLR::scaled( 0x187C1AFD3FC073, -52 - 1),  // +7.651495882291911022e-01
        FLR::scaled(-0x1980E979D7BFBE, -52 + 3),  // -1.275178128012327861e+01
        FLR::scaled( 0x1847EBD478657F, -52 - 1),  // +7.587794446764489775e-01
        FLR::scaled(-0x172DAE0791B369, -52 + 4),  // -2.317843673045300434e+01
        FLR::scaled( 0x1847EBD478657F, -52 - 1),  // +7.587794446764489775e-01
        FLR::scaled(-0x1711064B30C0D7, -52 + 5),  // -4.613300456886798173e+01
        FLR::scaled( 0x185C9F17C0852D, -52 - 1),  // +7.613063300997616745e-01
        FLR::scaled(-0x145FBD484B8E5E, -52 + 3),  // -1.018699098512950840e+01
        FLR::scaled( 0x185C9F17C0852D, -52 - 1),  // +7.613063300997616745e-01
        FLR::scaled(-0x15B1868E418DFE, -52 + 4),  // -2.169345940685706609e+01
        FLR::scaled( 0x18732BA2DA3DC9, -52 - 1),  // +7.640588932717317094e-01
        FLR::scaled(-0x1B4F25E3CC9393, -52 + 5),  // -5.461834380616269158e+01
        FLR::scaled( 0x18732BA2DA3DC9, -52 - 1),  // +7.640588932717317094e-01
        FLR::scaled(-0x109620E7ECCA06, -52 + 5),  // -3.317287921010942853e+01
        FLR::scaled( 0x1889340C814C3C, -52 - 1),  // +7.667484516372335968e-01
        FLR::scaled( 0x1AAA0FEDDE83F0, -52 + 3),  // +1.333215277997257431e+01
        FLR::scaled( 0x1889340C814C3C, -52 - 1),  // +7.667484516372335968e-01
        FLR::scaled(-0x19439737E158A0, -52 + 1),  // -3.158003269733924867e+00
        FLR::scaled( 0x185DDF5BFD8460, -52 - 1),  // +7.614590450940674771e-01
        FLR::scaled(-0x176F4A1DB65B99, -52 + 5),  // -4.686944934276761643e+01
        FLR::scaled( 0x185DDF5BFD8460, -52 - 1),  // +7.614590450940674771e-01
        FLR::scaled(-0x15741C7A1FD596, -52 + 3),  // -1.072677976263620891e+01
        FLR::scaled( 0x18716C2F3C3397, -52 - 1),  // +7.638455317079316798e-01
        FLR::scaled(-0x12B45792ABFA07, -52 + 5),  // -3.740892251393602663e+01
        FLR::scaled( 0x18716C2F3C3397, -52 - 1),  // +7.638455317079316798e-01
        FLR::scaled(-0x1E6321CD7AC626, -52 + 4),  // -3.038723453757679493e+01
        FLR::scaled( 0x1885A24413ED52, -52 - 1),  // +7.663127259869872976e-01
        FLR::scaled(-0x1190E0D1D6BD82, -52 + 6),  // -7.026372190447548860e+01
        FLR::scaled( 0x1885A24413ED52, -52 - 1),  // +7.663127259869872976e-01
        FLR::scaled( 0x12D2A2E5A81417, -52 + 3),  // +9.411399056212799152e+00
        FLR::scaled( 0x189A941551CDA5, -52 - 1),  // +7.688694397351595322e-01
        FLR::scaled(-0x1C7EFCCE1D191A, -52 + 5),  // -5.699209000035098427e+01
        FLR::scaled( 0x189A941551CDA5, -52 - 1),  // +7.688694397351595322e-01
        FLR::scaled( 0x1028EADF459094, -52 + 8),  // +2.585573418347714778e+02
        FLR::scaled( 0x129EB0C014ACEC, -52 - 1),  // +5.818713904931462899e-01
        FLR::scaled(-0x1169E652EA3186, -52 + 6),  // -6.965468285437063400e+01
        FLR::scaled( 0x129EB0C014ACEC, -52 - 1),  // +5.818713904931462899e-01
        FLR::scaled( 0x14445AC5F3CA09, -52 + 6),  // +8.106804035956896826e+01
        FLR::scaled( 0x12AE980C95DEA1, -52 - 1),  // +5.838127370652338444e-01
        FLR::scaled(-0x1FFA61A7583217, -52 + 6),  // -1.279122103081975723e+02
        FLR::scaled( 0x12AE980C95DEA1, -52 - 1),  // +5.838127370652338444e-01
        FLR::scaled( 0x11D1A7F252E63C, -52 + 9),  // +5.702070051647674518e+02
        FLR::scaled( 0x12BE0AA3335B70, -52 - 1),  // +5.856984317314140043e-01
        FLR::scaled(-0x15DB0015633137, -52 + 8),  // -3.496875203966805543e+02
        FLR::scaled( 0x12BE0AA3335B70, -52 - 1),  // +5.856984317314140043e-01
        FLR::scaled( 0x105E87616CEF63, -52 + 6),  // +6.547701297414964472e+01
        FLR::scaled( 0x12CD143EA7B81E, -52 - 1),  // +5.875340675099811616e-01
        FLR::scaled( 0x152196C4EFC049, -52 + 8),  // +3.380993089070585143e+02
        FLR::scaled( 0x12CD143EA7B81E, -52 - 1),  // +5.875340675099811616e-01
        FLR::scaled( 0x1BA45FC9067764, -52 + 6),  // +1.105683462680004254e+02
        FLR::scaled( 0x12ABE04849B0A6, -52 - 1),  // +5.834809696075538010e-01
        FLR::scaled(-0x1D1093C839107A, -52 + 7),  // -2.325180398096597969e+02
        FLR::scaled( 0x12ABE04849B0A6, -52 - 1),  // +5.834809696075538010e-01
        FLR::scaled( 0x13B6813E95D47A, -52 + 9),  // +6.308131076531856252e+02
        FLR::scaled( 0x12BCB3A35CB95F, -52 - 1),  // +5.855348768871343479e-01
        FLR::scaled( 0x1C59F4EF6CEC1F, -52 + 7),  // +2.268111493232144937e+02
        FLR::scaled( 0x12BCB3A35CB95F, -52 - 1),  // +5.855348768871343479e-01
        FLR::scaled( 0x12AC1DA94C7017, -52 + 9),  // +5.975144830676753145e+02
        FLR::scaled( 0x12CE0B68A3244D, -52 - 1),  // +5.876519244858485758e-01
        FLR::scaled(-0x15214A8FFBA620, -52 + 4),  // -2.113004398244640925e+01
        FLR::scaled( 0x12CE0B68A3244D, -52 - 1),  // +5.876519244858485758e-01
        FLR::scaled( 0x1AE596E3152E08, -52 + 8),  // +4.303493376567207633e+02
        FLR::scaled( 0x12DE13876410CC, -52 - 1),  // +5.896089214661741629e-01
        FLR::scaled( 0x1CB569F508A1AB, -52 + 8),  // +4.593383684479874205e+02
        FLR::scaled( 0x12DE13876410CC, -52 - 1),  // +5.896089214661741629e-01
        FLR::scaled( 0x1F28ED6B8CFA1A, -52 + 6),  // +1.246394909741142385e+02
        FLR::scaled( 0x12B5DD3A8F11B1, -52 - 1),  // +5.847002166488463049e-01
        FLR::scaled( 0x12746C3E84959C, -52 + 5),  // +3.690955335115287994e+01
        FLR::scaled( 0x12B5DD3A8F11B1, -52 - 1),  // +5.847002166488463049e-01
        FLR::scaled( 0x1957B8468650E5, -52 + 6),  // +1.013706222831420547e+02
        FLR::scaled( 0x12C43B04522E33, -52 - 1),  // +5.864539226908561664e-01
        FLR::scaled( 0x160A7779F72F27, -52 + 5),  // +4.408177113122501822e+01
        FLR::scaled( 0x12C43B04522E33, -52 - 1),  // +5.864539226908561664e-01
        FLR::scaled( 0x17AAEF30319C84, -52 + 7),  // +1.893416977852795071e+02
        FLR::scaled( 0x12D3A9043A9983, -52 - 1),  // +5.883374292941855321e-01
        FLR::scaled( 0x13764175811760, -52 + 7),  // +1.556954906007113095e+02
        FLR::scaled( 0x12D3A9043A9983, -52 - 1),  // +5.883374292941855321e-01
        FLR::scaled(-0x1420663236EC3D, -52 + 7),  // -1.610124751160346079e+02
        FLR::scaled( 0x12E189233FF1A1, -52 - 1),  // +5.900312126610068875e-01
        FLR::scaled( 0x16DD2001830189, -52 + 5),  // +4.572753924271371062e+01
        FLR::scaled( 0x12E189233FF1A1, -52 - 1),  // +5.900312126610068875e-01
        FLR::scaled( 0x1A00333D3E761E, -52 + 8),  // +4.160125095786951306e+02
        FLR::scaled( 0x12C3BC86BF5EEE, -52 - 1),  // +5.863936073100981528e-01
        FLR::scaled(-0x1C3CC529496470, -52 + 7),  // -2.258990675385898612e+02
        FLR::scaled( 0x12C3BC86BF5EEE, -52 - 1),  // +5.863936073100981528e-01
        FLR::scaled( 0x1FA3C8092D694F, -52 + 5),  // +6.327954210965491910e+01
        FLR::scaled( 0x12D2CE6436E0C9, -52 - 1),  // +5.882331807433952564e-01
        FLR::scaled( 0x19D371E326F09D, -52 + 7),  // +2.066076522598786198e+02
        FLR::scaled( 0x12D2CE6436E0C9, -52 - 1),  // +5.882331807433952564e-01
        FLR::scaled( 0x1247F09032295A, -52 + 8),  // +2.924962312659678219e+02
        FLR::scaled( 0x12E42C4096F439, -52 - 1),  // +5.903531323925853558e-01
        FLR::scaled( 0x17485FA0470444, -52 + 6),  // +9.313083655295582730e+01
        FLR::scaled( 0x12E42C4096F439, -52 - 1),  // +5.903531323925853558e-01
        FLR::scaled( 0x1A3C4548CBBBC1, -52 + 7),  // +2.098834575633209454e+02
        FLR::scaled( 0x12F2DCDD4DBC95, -52 - 1),  // +5.921463320099912275e-01
        FLR::scaled( 0x10A247BDCA2A6B, -52 + 9),  // +5.322850299638934075e+02
        FLR::scaled( 0x12F2DCDD4DBC95, -52 - 1),  // +5.921463320099912275e-01
        FLR::scaled( 0x164C366BE6A6D3, -52 + 8),  // +3.567632864961462360e+02
        FLR::scaled( 0x1365F6F8EE4E3D, -52 - 1),  // +6.061968671733165559e-01
        FLR::scaled( 0x1FFBE005749FFF, -52 + 7),  // +2.558710963514167531e+02
        FLR::scaled( 0x1365F6F8EE4E3D, -52 - 1),  // +6.061968671733165559e-01
        FLR::scaled( 0x16BDE60CFD51DB, -52 + 6),  // +9.096716618288284906e+01
        FLR::scaled( 0x13808026FFE47A, -52 - 1),  // +6.094361077986285569e-01
        FLR::scaled(-0x14DB20AA6952F8, -52 + 6),  // -8.342386875424915615e+01
        FLR::scaled( 0x13808026FFE47A, -52 - 1),  // +6.094361077986285569e-01
        FLR::scaled( 0x10674E47829956, -52 + 9),  // +5.249132223322910704e+02
        FLR::scaled( 0x137D03C8BC0B15, -52 - 1),  // +6.090105934711994573e-01
        FLR::scaled(-0x14367781B5CB3F, -52 + 7),  // -1.617020882177984902e+02
        FLR::scaled( 0x137D03C8BC0B15, -52 - 1),  // +6.090105934711994573e-01
        FLR::scaled(-0x10C529A2A05A0C, -52 + 5),  // -3.354033310727763251e+01
        FLR::scaled( 0x13945C8268F03C, -52 - 1),  // +6.118605181759515510e-01
        FLR::scaled( 0x1FB81114352BD5, -52 + 8),  // +5.075041696621895539e+02
        FLR::scaled( 0x13945C8268F03C, -52 - 1),  // +6.118605181759515510e-01
        FLR::scaled( 0x1C4AA3CDBFCB82, -52 + 8),  // +4.526649911396017387e+02
        FLR::scaled( 0x137452479219BC, -52 - 1),  // +6.079493902077994782e-01
        FLR::scaled(-0x194630FD4605AE, -52 + 6),  // -1.010967400726137555e+02
        FLR::scaled( 0x137452479219BC, -52 - 1),  // +6.079493902077994782e-01
        FLR::scaled( 0x155839605CC1A8, -52 + 6),  // +8.537850197847603795e+01
        FLR::scaled( 0x138F78B7C0158D, -52 - 1),  // +6.112636174081430562e-01
        FLR::scaled( 0x10C29FBED2E399, -52 + 6),  // +6.704100008577951542e+01
        FLR::scaled( 0x138F78B7C0158D, -52 - 1),  // +6.112636174081430562e-01
        FLR::scaled( 0x17DD291A4527A9, -52 + 8),  // +3.818225348187793884e+02
        FLR::scaled( 0x138DD7A1B33238, -52 - 1),  // +6.110647352412064137e-01
        FLR::scaled(-0x1E929CE6718452, -52 + 7),  // -2.445816528527380456e+02
        FLR::scaled( 0x138DD7A1B33238, -52 - 1),  // +6.110647352412064137e-01
        FLR::scaled( 0x1B3C474CB6CF4B, -52 + 7),  // +2.178837035723211955e+02
        FLR::scaled( 0x13A5A81C84D096, -52 - 1),  // +6.139717633254970774e-01
        FLR::scaled( 0x12957DEEC583D3, -52 + 8),  // +2.973432452884127883e+02
        FLR::scaled( 0x13A5A81C84D096, -52 - 1),  // +6.139717633254970774e-01
        FLR::scaled( 0x188FFB6EA2A3D0, -52 + 5),  // +4.912486060086632733e+01
        FLR::scaled( 0x13871A18A2B110, -52 - 1),  // +6.102419358408344152e-01
        FLR::scaled( 0x17A80D7DBBA6E8, -52 + 7),  // +1.892516468682363211e+02
        FLR::scaled( 0x13871A18A2B110, -52 - 1),  // +6.102419358408344152e-01
        FLR::scaled( 0x17A8CB1C7C4C5E, -52 + 8),  // +3.785495877128031452e+02
        FLR::scaled( 0x139DF4FB2F3489, -52 - 1),  // +6.130318551964971663e-01
        FLR::scaled( 0x199A9B90C225CB, -52 + 3),  // +1.280196812028852626e+01
        FLR::scaled( 0x139DF4FB2F3489, -52 - 1),  // +6.130318551964971663e-01
        FLR::scaled( 0x15048FEECEC780, -52 + 8),  // +3.362851398541752133e+02
        FLR::scaled( 0x139A4452C418A8, -52 - 1),  // +6.125814072154485146e-01
        FLR::scaled(-0x1620FECD264010, -52 + 5),  // -4.425777592055976584e+01
        FLR::scaled( 0x139A4452C418A8, -52 - 1),  // +6.125814072154485146e-01
        FLR::scaled(-0x18F971166B2771, -52 + 6),  // -9.989752731765999272e+01
        FLR::scaled( 0x13AEC076A66C8D, -52 - 1),  // +6.150820081123967720e-01
        FLR::scaled( 0x1CECB7AF29527E, -52 + 7),  // +2.313974223906588463e+02
        FLR::scaled( 0x13AEC076A66C8D, -52 - 1),  // +6.150820081123967720e-01
        FLR::scaled( 0x1A8CB7957885C1, -52 + 8),  // +4.247948202808293559e+02
        FLR::scaled( 0x139455D42D93B7, -52 - 1),  // +6.118573326208353036e-01
        FLR::scaled( 0x136BF23FC858F0, -52 + 6),  // +7.768666071477105106e+01
        FLR::scaled( 0x139455D42D93B7, -52 - 1),  // +6.118573326208353036e-01
        FLR::scaled( 0x1DEFF86C4BFE67, -52 + 8),  // +4.789981501549249856e+02
        FLR::scaled( 0x13ABEB21C19061, -52 - 1),  // +6.147361430453309739e-01
        FLR::scaled( 0x14739987BED426, -52 + 4),  // +2.045156143578437735e+01
        FLR::scaled( 0x13ABEB21C19061, -52 - 1),  // +6.147361430453309739e-01
        FLR::scaled( 0x11D836365640E2, -52 + 8),  // +2.855132354134822208e+02
        FLR::scaled( 0x13A9B571276E4F, -52 - 1),  // +6.144664011039341345e-01
        FLR::scaled(-0x12754DA269CC42, -52 + 7),  // -1.476657268587460408e+02
        FLR::scaled( 0x13A9B571276E4F, -52 - 1),  // +6.144664011039341345e-01
        FLR::scaled( 0x1A9CA4424F0531, -52 + 8),  // +4.257901022993783613e+02
        FLR::scaled( 0x13BED0B7FF79E4, -52 - 1),  // +6.170428842268020908e-01
        FLR::scaled( 0x120DB1D64F5885, -52 + 8),  // +2.888559172725147732e+02
        FLR::scaled( 0x13BED0B7FF79E4, -52 - 1),  // +6.170428842268020908e-01
        FLR::scaled( 0x1CD79987966C9E, -52 + 7),  // +2.307374914110159239e+02
        FLR::scaled( 0x13482005D1ED58, -52 - 1),  // +6.025543321297091026e-01
        FLR::scaled( 0x124990E629D13A, -52 + 5),  // +3.657473446885929036e+01
        FLR::scaled( 0x13482005D1ED58, -52 - 1),  // +6.025543321297091026e-01
        FLR::scaled( 0x17E07C602F842A, -52 + 2),  // +5.969224455738222801e+00
        FLR::scaled( 0x135835F2F2FC58, -52 - 1),  // +6.045179123974646629e-01
        FLR::scaled(-0x1013164CDF770E, -52 + 6),  // -6.429823610136756429e+01
        FLR::scaled( 0x135835F2F2FC58, -52 - 1),  // +6.045179123974646629e-01
        FLR::scaled( 0x1F72287CCF0B9A, -52 + 6),  // +1.257837211629797878e+02
        FLR::scaled( 0x1364EAE73843BC, -52 - 1),  // +6.060690418254277567e-01
        FLR::scaled(-0x170E032BD0023B, -52 + 7),  // -1.844378871023817226e+02
        FLR::scaled( 0x1364EAE73843BC, -52 - 1),  // +6.060690418254277567e-01
        FLR::scaled( 0x1B084B75743F0A, -52 + 4),  // +2.703240140998881458e+01
        FLR::scaled( 0x1375BD09B6E253, -52 - 1),  // +6.081223668798635407e-01
        FLR::scaled( 0x1F6D2B3E6D2247, -52 + 8),  // +5.028230575812380607e+02
        FLR::scaled( 0x1375BD09B6E253, -52 - 1),  // +6.081223668798635407e-01
        FLR::scaled( 0x1C539F86A69076, -52 + 6),  // +1.133066116930584428e+02
        FLR::scaled( 0x1352F9BA7797F9, -52 - 1),  // +6.038788453995486138e-01
        FLR::scaled( 0x16040268F09EC5, -52 + 5),  // +4.403132354496987233e+01
        FLR::scaled( 0x1352F9BA7797F9, -52 - 1),  // +6.038788453995486138e-01
        FLR::scaled( 0x112CCC6A182FBD, -52 + 8),  // +2.747999058670791896e+02
        FLR::scaled( 0x1363628AA5206E, -52 - 1),  // +6.058819492254892136e-01
        FLR::scaled(-0x1733B35D1FABA3, -52 + 7),  // -1.856156449907840340e+02
        FLR::scaled( 0x1363628AA5206E, -52 - 1),  // +6.058819492254892136e-01
        FLR::scaled( 0x1F279C146044B6, -52 + 7),  // +2.492378026848070363e+02
        FLR::scaled( 0x137202DD01FB61, -52 - 1),  // +6.076673809583149621e-01
        FLR::scaled( 0x1D2E8BC95E43AC, -52 + 6),  // +1.167272818966436603e+02
        FLR::scaled( 0x137202DD01FB61, -52 - 1),  // +6.076673809583149621e-01
        FLR::scaled( 0x15508961F5B457, -52 + 8),  // +3.410335406873541046e+02
        FLR::scaled( 0x138340D49303A8, -52 - 1),  // +6.097721244660663231e-01
        FLR::scaled( 0x12DCE1876D41DB, -52 + 9),  // +6.036101215873453611e+02
        FLR::scaled( 0x138340D49303A8, -52 - 1),  // +6.097721244660663231e-01
        FLR::scaled(-0x13B109EDE33820, -52 + 8),  // -3.150649241328956123e+02
        FLR::scaled( 0x13678936050672, -52 - 1),  // +6.063886694975748615e-01
        FLR::scaled( 0x188ED3EDC284B9, -52 + 7),  // +1.964633702086628375e+02
        FLR::scaled( 0x13678936050672, -52 - 1),  // +6.063886694975748615e-01
        FLR::scaled( 0x1360D23D396C34, -52 + 9),  // +6.201026558385988210e+02
        FLR::scaled( 0x1377A82D7809BA, -52 - 1),  // +6.083565605225011996e-01
        FLR::scaled(-0x191AD8EB875C1E, -52 + 7),  // -2.008389794963595136e+02
        FLR::scaled( 0x1377A82D7809BA, -52 - 1),  // +6.083565605225011996e-01
        FLR::scaled( 0x1282209B3A1BCE, -52 + 8),  // +2.961329605359904917e+02
        FLR::scaled( 0x13847F86E58599, -52 - 1),  // +6.099240908335331612e-01
        FLR::scaled( 0x1A4188AC3B8FAE, -52 + 7),  // +2.100479336894326821e+02
        FLR::scaled( 0x13847F86E58599, -52 - 1),  // +6.099240908335331612e-01
        FLR::scaled(-0x1D6E2CBAD65209, -52 + 4),  // -2.943037002308304650e+01
        FLR::scaled( 0x1395CF057DF205, -52 - 1),  // +6.120371920838471036e-01
        FLR::scaled( 0x1DE76147D56569, -52 + 8),  // +4.784612501464640104e+02
        FLR::scaled( 0x1395CF057DF205, -52 - 1),  // +6.120371920838471036e-01
        FLR::scaled( 0x182682F04A47BF, -52 + 7),  // +1.932034837199007313e+02
        FLR::scaled( 0x1371B541B31B74, -52 - 1),  // +6.076303752132461433e-01
        FLR::scaled(-0x1A99340AE248A7, -52 + 7),  // -2.127876028461080011e+02
        FLR::scaled( 0x1371B541B31B74, -52 - 1),  // +6.076303752132461433e-01
        FLR::scaled( 0x1F941530140299, -52 + 7),  // +2.526275864020178972e+02
        FLR::scaled( 0x1381C2C929BBBC, -52 - 1),  // +6.095899514165163957e-01
        FLR::scaled( 0x127400C0548798, -52 + 7),  // +1.476250917101831419e+02
        FLR::scaled( 0x1381C2C929BBBC, -52 - 1),  // +6.095899514165163957e-01
        FLR::scaled( 0x1D2CBEF969C3EA, -52 + 8),  // +4.667966245776611913e+02
        FLR::scaled( 0x13908CC0E5C0A8, -52 - 1),  // +6.113952415016870034e-01
        FLR::scaled( 0x162754A8E7D928, -52 + 7),  // +1.772290844467436273e+02
        FLR::scaled( 0x13908CC0E5C0A8, -52 - 1),  // +6.113952415016870034e-01
        FLR::scaled( 0x1BB68A5F88D3C0, -52 + 8),  // +4.434087825150309072e+02
        FLR::scaled( 0x13A1D8EF6FB769, -52 - 1),  // +6.135067631237066665e-01
        FLR::scaled( 0x16EAC9EF237A30, -52 + 9),  // +7.333486006518996874e+02
        FLR::scaled( 0x13A1D8EF6FB769, -52 - 1),  // +6.135067631237066665e-01
        FLR::scaled( 0x11D50D379E2E9B, -52 + 8),  // +2.853157268694864683e+02
        FLR::scaled( 0x1412A481559BBB, -52 - 1),  // +6.272757078230520866e-01
        FLR::scaled(-0x1E0168E5468005, -52 + 6),  // -1.200220273197629268e+02
        FLR::scaled( 0x1412A481559BBB, -52 - 1),  // +6.272757078230520866e-01
        FLR::scaled( 0x138A80D0CD163A, -52 + 7),  // +1.563282245641328814e+02
        FLR::scaled( 0x14347F1D548201, -52 - 1),  // +6.314082692006764974e-01
        FLR::scaled( 0x1F174F21C48601, -52 + 2),  // +7.772762801761474272e+00
        FLR::scaled( 0x14347F1D548201, -52 - 1),  // +6.314082692006764974e-01
        FLR::scaled( 0x119AAEA5812BD6, -52 + 8),  // +2.816676383062125524e+02
        FLR::scaled( 0x1427D89AD6E63F, -52 - 1),  // +6.298640274246237736e-01
        FLR::scaled( 0x10A8734871F306, -52 + 7),  // +1.332640726304600207e+02
        FLR::scaled( 0x1427D89AD6E63F, -52 - 1),  // +6.298640274246237736e-01
        FLR::scaled(-0x1E0F937F16A401, -52 + 8),  // -4.809735098728561411e+02
        FLR::scaled( 0x1446B4CB9DC607, -52 - 1),  // +6.336311318283954774e-01
        FLR::scaled( 0x1EB7EBDE83E574, -52 + 4),  // +3.071844282837032836e+01
        FLR::scaled( 0x1446B4CB9DC607, -52 - 1),  // +6.336311318283954774e-01
        FLR::scaled( 0x17CF87F172203A, -52 + 8),  // +3.809706892450373061e+02
        FLR::scaled( 0x141FFD1B2235B5, -52 - 1),  // +6.289048700288534244e-01
        FLR::scaled(-0x1A6CED69B870E2, -52 + 6),  // -1.057019905377560747e+02
        FLR::scaled( 0x141FFD1B2235B5, -52 - 1),  // +6.289048700288534244e-01
        FLR::scaled( 0x190179BDF2DEEF, -52 + 7),  // +2.000461110824175819e+02
        FLR::scaled( 0x144251C132F03C, -52 - 1),  // +6.330956242959540070e-01
        FLR::scaled(-0x17068D21C6EB77, -52 + 6),  // -9.210236401010284624e+01
        FLR::scaled( 0x144251C132F03C, -52 - 1),  // +6.330956242959540070e-01
        FLR::scaled( 0x1031A6B3170696, -52 + 7),  // +1.295515990686150758e+02
        FLR::scaled( 0x1437A96300EF68, -52 - 1),  // +6.317946370759104369e-01
        FLR::scaled( 0x119928F97B958F, -52 + 6),  // +7.039312588757296396e+01
        FLR::scaled( 0x1437A96300EF68, -52 - 1),  // +6.317946370759104369e-01
        FLR::scaled( 0x1EAFE65396C62C, -52 + 7),  // +2.454968660301977934e+02
        FLR::scaled( 0x1456CEA8B78D8F, -52 - 1),  // +6.355965895894984952e-01
        FLR::scaled( 0x1B2C22D167DA92, -52 + 6),  // +1.086896251215169116e+02
        FLR::scaled( 0x1456CEA8B78D8F, -52 - 1),  // +6.355965895894984952e-01
        FLR::scaled( 0x16C24D77E5CFA7, -52 + 5),  // +4.551798914643523375e+01
        FLR::scaled( 0x14335CAD7CDC9F, -52 - 1),  // +6.312697781021546772e-01
        FLR::scaled(-0x15FF2FAE139AF6, -52 + 6),  // -8.798728515543538720e+01
        FLR::scaled( 0x14335CAD7CDC9F, -52 - 1),  // +6.312697781021546772e-01
        FLR::scaled( 0x1DD948CDDCB3B5, -52 + 7),  // +2.387901372252069052e+02
        FLR::scaled( 0x1452028A9A98A7, -52 - 1),  // +6.350109774691831133e-01
        FLR::scaled( 0x1FFE0377570286, -52 + 6),  // +1.279689615583139073e+02
        FLR::scaled( 0x1452028A9A98A7, -52 - 1),  // +6.350109774691831133e-01
        FLR::scaled( 0x13451506889D2A, -52 + 9),  // +6.166352663681948343e+02
        FLR::scaled( 0x1446034427FBC3, -52 - 1),  // +6.335464793372626024e-01
        FLR::scaled( 0x18ACB47BD95734, -52 + 6),  // +9.869851585602447130e+01
        FLR::scaled( 0x1446034427FBC3, -52 - 1),  // +6.335464793372626024e-01
        FLR::scaled( 0x1402D616D11B03, -52 + 7),  // +1.600886339267818528e+02
        FLR::scaled( 0x146293EAFFCAFC, -52 - 1),  // +6.370334234073591340e-01
        FLR::scaled( 0x1091A944E861CB, -52 + 8),  // +2.651038254811689399e+02
        FLR::scaled( 0x146293EAFFCAFC, -52 - 1),  // +6.370334234073591340e-01
        FLR::scaled( 0x1474ACDAF06980, -52 + 9),  // +6.545844019682117505e+02
        FLR::scaled( 0x143F11F3C653EA, -52 - 1),  // +6.326989899849853050e-01
        FLR::scaled( 0x1F5F31A28AE724, -52 + 6),  // +1.254874044758294644e+02
        FLR::scaled( 0x143F11F3C653EA, -52 - 1),  // +6.326989899849853050e-01
        FLR::scaled( 0x1594C7D800D291, -52 + 7),  // +1.726493949905457441e+02
        FLR::scaled( 0x145DF1185ABD07, -52 - 1),  // +6.364675021813192002e-01
        FLR::scaled(-0x1E905B77E2905E, -52 + 7),  // -2.445111655640675394e+02
        FLR::scaled( 0x145DF1185ABD07, -52 - 1),  // +6.364675021813192002e-01
        FLR::scaled( 0x1AD59ECAF5663C, -52 + 8),  // +4.293512677751457431e+02
        FLR::scaled( 0x1453CF63641381, -52 - 1),  // +6.352307263592679165e-01
        FLR::scaled( 0x1403304F629585, -52 + 7),  // +1.600996472287626204e+02
        FLR::scaled( 0x1453CF63641381, -52 - 1),  // +6.352307263592679165e-01
        FLR::scaled( 0x1A7DA14D9C2AD5, -52 + 4),  // +2.649074254095724612e+01
        FLR::scaled( 0x1470772DD090B2, -52 - 1),  // +6.387287039583695591e-01
        FLR::scaled( 0x13B7B1E6AF7E73, -52 + 7),  // +1.577404664447418270e+02
        FLR::scaled( 0x1470772DD090B2, -52 - 1),  // +6.387287039583695591e-01
        FLR::scaled( 0x18CE84476FDD73, -52 + 7),  // +1.984536473450530991e+02
        FLR::scaled( 0x140DD68648710F, -52 - 1),  // +6.266892073358877324e-01
        FLR::scaled(-0x141CEFE03BD851, -52 + 7),  // -1.609042817276809103e+02
        FLR::scaled( 0x140DD68648710F, -52 - 1),  // +6.266892073358877324e-01
        FLR::scaled( 0x114ABE3761FC55, -52 + 8),  // +2.766714395358624756e+02
        FLR::scaled( 0x14166B4CCC9BFC, -52 - 1),  // +6.277367115006877718e-01
        FLR::scaled(-0x13EEC0A5A0E78C, -52 + 7),  // -1.594610164778390526e+02
        FLR::scaled( 0x14166B4CCC9BFC, -52 - 1),  // +6.277367115006877718e-01
        FLR::scaled( 0x1F77175A58ECF7, -52 + 8),  // +5.034432013963373151e+02
        FLR::scaled( 0x142DCE27A314F0, -52 - 1),  // +6.305914663468268344e-01
        FLR::scaled( 0x174403518B35CC, -52 + 6),  // +9.306270254702320699e+01
        FLR::scaled( 0x142DCE27A314F0, -52 - 1),  // +6.305914663468268344e-01
        FLR::scaled( 0x11A15E5B9C5DD7, -52 + 8),  // +2.820855365856236290e+02
        FLR::scaled( 0x143730EBB3F8D8, -52 - 1),  // +6.317371944021727970e-01
        FLR::scaled( 0x140497879DF780, -52 + 7),  // +1.601434972844399454e+02
        FLR::scaled( 0x143730EBB3F8D8, -52 - 1),  // +6.317371944021727970e-01
        FLR::scaled( 0x1F0D2DD43BF35E, -52 + 8),  // +4.968236887304136644e+02
        FLR::scaled( 0x141EDB9F12D3CE, -52 - 1),  // +6.287668330102123004e-01
        FLR::scaled( 0x12E8E790B21CF0, -52 + 8),  // +3.025565344769993317e+02
        FLR::scaled( 0x141EDB9F12D3CE, -52 - 1),  // +6.287668330102123004e-01
        FLR::scaled( 0x1A5852D79A85BD, -52 + 7),  // +2.107601125734344407e+02
        FLR::scaled( 0x1428B90B62586A, -52 - 1),  // +6.299710485789209446e-01
        FLR::scaled( 0x180EE6695E14AF, -52 + 7),  // +1.924656264150157483e+02
        FLR::scaled( 0x1428B90B62586A, -52 - 1),  // +6.299710485789209446e-01
        FLR::scaled( 0x11A607D5C8D89D, -52 + 7),  // +1.411884564326072962e+02
        FLR::scaled( 0x1442690CEC9C27, -52 - 1),  // +6.331067325999172324e-01
        FLR::scaled( 0x1A31D74D1E0598, -52 + 8),  // +4.191150637791374720e+02
        FLR::scaled( 0x1442690CEC9C27, -52 - 1),  // +6.331067325999172324e-01
        FLR::scaled( 0x19A1A8FC047CE4, -52 + 8),  // +4.101037559676462934e+02
        FLR::scaled( 0x144D6DDA9D935A, -52 - 1),  // +6.344517965159000017e-01
        FLR::scaled( 0x1E6EFF1608ABD2, -52 + 8),  // +4.869372768725125979e+02
        FLR::scaled( 0x144D6DDA9D935A, -52 - 1),  // +6.344517965159000017e-01
        FLR::scaled( 0x1E5900A3168196, -52 + 7),  // +2.427813277663778422e+02
        FLR::scaled( 0x142D427913BF4B, -52 - 1),  // +6.305248608386845310e-01
        FLR::scaled(-0x1C28D759B68454, -52 + 6),  // -1.126381439478294055e+02
        FLR::scaled( 0x142D427913BF4B, -52 - 1),  // +6.305248608386845310e-01
        FLR::scaled( 0x1129435B67DCF7, -52 + 6),  // +6.864473614828953885e+01
        FLR::scaled( 0x14353553C5530E, -52 - 1),  // +6.314951549671563580e-01
        FLR::scaled(-0x10AEEAC1CA7088, -52 + 8),  // -2.669323137195392519e+02
        FLR::scaled( 0x14353553C5530E, -52 - 1),  // +6.314951549671563580e-01
        FLR::scaled( 0x1421323F0704F2, -52 + 9),  // +6.441495342777618589e+02
        FLR::scaled( 0x14498D696060BA, -52 - 1),  // +6.339785631307883751e-01
        FLR::scaled( 0x1D19E414AE8364, -52 + 8),  // +4.656181837860988253e+02
        FLR::scaled( 0x14498D696060BA, -52 - 1),  // +6.339785631307883751e-01
        FLR::scaled( 0x1793E05C122F80, -52 + 7),  // +1.886211376528917754e+02
        FLR::scaled( 0x14524C1EE98D2A, -52 - 1),  // +6.350460628276881625e-01
        FLR::scaled( 0x1B9C32D3DCCD74, -52 + 8),  // +4.417624090790843638e+02
        FLR::scaled( 0x14524C1EE98D2A, -52 - 1),  // +6.350460628276881625e-01
        FLR::scaled( 0x139E62C2F1D769, -52 + 7),  // +1.569495558474984875e+02
        FLR::scaled( 0x143CEC955A00E8, -52 - 1),  // +6.324370305083251154e-01
        FLR::scaled(-0x12A2C2F6905940, -52 + 6),  // -7.454314960571809934e+01
        FLR::scaled( 0x143CEC955A00E8, -52 - 1),  // +6.324370305083251154e-01
        FLR::scaled( 0x1D9C691A6B78E6, -52 + 6),  // +1.184439149903806481e+02
        FLR::scaled( 0x1445F742E57DAC, -52 - 1),  // +6.335407549449221243e-01
        FLR::scaled(-0x17119F0E89172B, -52 + 6),  // -9.227533305537933472e+01
        FLR::scaled( 0x1445F742E57DAC, -52 - 1),  // +6.335407549449221243e-01
        FLR::scaled( 0x1E735A3E8FB1EA, -52 + 6),  // +1.218023830798407801e+02
        FLR::scaled( 0x145CBC25D0BE74, -52 - 1),  // +6.363201845724248962e-01
        FLR::scaled(-0x10D531961211E3, -52 + 7),  // -1.346623030045439862e+02
        FLR::scaled( 0x145CBC25D0BE74, -52 - 1),  // +6.363201845724248962e-01
        FLR::scaled( 0x1579B16E42A1CB, -52 + 8),  // +3.436058180430233620e+02
        FLR::scaled( 0x1466E7BEC3437E, -52 - 1),  // +6.375616765818532539e-01
        FLR::scaled( 0x11D7314192E432, -52 + 7),  // +1.427247627133343144e+02
        FLR::scaled( 0x1466E7BEC3437E, -52 - 1),  // +6.375616765818532539e-01
        FLR::scaled(-0x1BA30347983DE3, -52 + 5),  // -5.527353758748702006e+01
        FLR::scaled( 0x14C4E22E6CE2FB, -52 - 1),  // +6.490336329216853661e-01
        FLR::scaled(-0x16D9FD32DBE93E, -52 + 6),  // -9.140607902026837905e+01
        FLR::scaled( 0x14C4E22E6CE2FB, -52 - 1),  // +6.490336329216853661e-01
        FLR::scaled( 0x15F129DB713B1E, -52 + 8),  // +3.510727190421183650e+02
        FLR::scaled( 0x14D713B01884F6, -52 - 1),  // +6.512545050974540839e-01
        FLR::scaled( 0x17CBA8AF70C5D9, -52 + 6),  // +9.518217073452923671e+01
        FLR::scaled( 0x14D713B01884F6, -52 - 1),  // +6.512545050974540839e-01
        FLR::scaled( 0x19D5BF97429203, -52 + 8),  // +4.133592751121906872e+02
        FLR::scaled( 0x14D25C6F0E189D, -52 - 1),  // +6.506788414997292103e-01
        FLR::scaled(-0x1670987398D066, -52 + 7),  // -1.795186098084115542e+02
        FLR::scaled( 0x14D25C6F0E189D, -52 - 1),  // +6.506788414997292103e-01
        FLR::scaled( 0x14A2334ADAB733, -52 + 7),  // +1.650687612792767993e+02
        FLR::scaled( 0x14E370F42C433A, -52 - 1),  // +6.527638215066879912e-01
        FLR::scaled( 0x1646B6145FF4A0, -52 + 8),  // +3.564194530246986687e+02
        FLR::scaled( 0x14E370F42C433A, -52 - 1),  // +6.527638215066879912e-01
        FLR::scaled(-0x10D65BF3490E9E, -52 + 7),  // -1.346987244059463933e+02
        FLR::scaled( 0x14D6372C8CF75B, -52 - 1),  // +6.511493559007520693e-01
        FLR::scaled(-0x1888E4A3608090, -52 + 7),  // -1.962779099354561367e+02
        FLR::scaled( 0x14D6372C8CF75B, -52 - 1),  // +6.511493559007520693e-01
        FLR::scaled( 0x11F6DBD29B42DF, -52 + 9),  // +5.748573352937490881e+02
        FLR::scaled( 0x14E9BEC1F6C019, -52 - 1),  // +6.535333431584177122e-01
        FLR::scaled( 0x1CB2A849D6F4F8, -52 + 8),  // +4.591660860440019860e+02
        FLR::scaled( 0x14E9BEC1F6C019, -52 - 1),  // +6.535333431584177122e-01
        FLR::scaled( 0x1B972706CA3D66, -52 + 8),  // +4.414470279598230036e+02
        FLR::scaled( 0x14E57C82124D76, -52 - 1),  // +6.530134716471553968e-01
        FLR::scaled(-0x14D5CC9621E98A, -52 + 6),  // -8.334061196624512036e+01
        FLR::scaled( 0x14E57C82124D76, -52 - 1),  // +6.530134716471553968e-01
        FLR::scaled(-0x13F09DF9EDEEED, -52 + 7),  // -1.595192842147002068e+02
        FLR::scaled( 0x14F7F5CFC908AB, -52 - 1),  // +6.552685793215194954e-01
        FLR::scaled( 0x1B7504CC2B2B10, -52 + 7),  // +2.196568356364373358e+02
        FLR::scaled( 0x14F7F5CFC908AB, -52 - 1),  // +6.552685793215194954e-01
        FLR::scaled(-0x1D02256BC1DF44, -52 + 5),  // -5.801676699606335319e+01
        FLR::scaled( 0x14D8CACEFBFA67, -52 - 1),  // +6.514638941442399966e-01
        FLR::scaled(-0x104C48228B5035, -52 + 7),  // -1.303838055344546376e+02
        FLR::scaled( 0x14D8CACEFBFA67, -52 - 1),  // +6.514638941442399966e-01
        FLR::scaled( 0x11BD39F85B1E4E, -52 + 9),  // +5.676533057325957543e+02
        FLR::scaled( 0x14E8E2F781FB49, -52 - 1),  // +6.534285387168462522e-01
        FLR::scaled( 0x15B4F4797B319F, -52 + 8),  // +3.473096861660250738e+02
        FLR::scaled( 0x14E8E2F781FB49, -52 - 1),  // +6.534285387168462522e-01
        FLR::scaled( 0x1E88E298CC09FC, -52 + 8),  // +4.885553214998506064e+02
        FLR::scaled( 0x14E513B80551F0, -52 - 1),  // +6.529635042339219098e-01
        FLR::scaled(-0x12BB8CFCD024D2, -52 + 6),  // -7.493048019720598063e+01
        FLR::scaled( 0x14E513B80551F0, -52 - 1),  // +6.529635042339219098e-01
        FLR::scaled( 0x1B5296405A1509, -52 + 7),  // +2.185808412322442393e+02
        FLR::scaled( 0x14F44BA61FE86B, -52 - 1),  // +6.548212284681204087e-01
        FLR::scaled( 0x15AF3671EF52C4, -52 + 8),  // +3.469507922504965336e+02
        FLR::scaled( 0x14F44BA61FE86B, -52 - 1),  // +6.548212284681204087e-01
        FLR::scaled( 0x11D6CDDF36C85C, -52 + 6),  // +7.135631542539471184e+01
        FLR::scaled( 0x14E8A0A8D0CA04, -52 - 1),  // +6.533969208888383839e-01
        FLR::scaled(-0x10593620149033, -52 + 8),  // -2.615757141879323058e+02
        FLR::scaled( 0x14E8A0A8D0CA04, -52 - 1),  // +6.533969208888383839e-01
        FLR::scaled( 0x1BA1A92B1EC44E, -52 + 6),  // +1.105259502220589809e+02
        FLR::scaled( 0x14FA1B41E0AD1F, -52 - 1),  // +6.555305754349410874e-01
        FLR::scaled( 0x129534B7837534, -52 + 9),  // +5.946507406492369228e+02
        FLR::scaled( 0x14FA1B41E0AD1F, -52 - 1),  // +6.555305754349410874e-01
        FLR::scaled( 0x10101ED5BFEC7D, -52 + 8),  // +2.570075280663511990e+02
        FLR::scaled( 0x14F6A95CE9B455, -52 - 1),  // +6.551100554185135261e-01
        FLR::scaled(-0x10E71252768777, -52 + 8),  // -2.704419731740994735e+02
        FLR::scaled( 0x14F6A95CE9B455, -52 - 1),  // +6.551100554185135261e-01
        FLR::scaled( 0x14004658883C9A, -52 + 7),  // +1.600085871373055966e+02
        FLR::scaled( 0x15075147988D81, -52 - 1),  // +6.571432493550873888e-01
        FLR::scaled( 0x188E0A3EFA0AE8, -52 + 5),  // +4.910968768319236233e+01
        FLR::scaled( 0x15075147988D81, -52 - 1),  // +6.571432493550873888e-01
        FLR::scaled( 0x12E524DB5380D3, -52 + 8),  // +3.023214982282490269e+02
        FLR::scaled( 0x149D26C34D7CF8, -52 - 1),  // +6.441835226541163806e-01
        FLR::scaled( 0x139A3A980F55A3, -52 + 6),  // +7.840982629296790662e+01
        FLR::scaled( 0x149D26C34D7CF8, -52 - 1),  // +6.441835226541163806e-01
        FLR::scaled( 0x12BD5593A62F61, -52 + 8),  // +2.998333927623371551e+02
        FLR::scaled( 0x14A50F52E3DA23, -52 - 1),  // +6.451489085146174807e-01
        FLR::scaled(-0x1BF051AD5EF614, -52 + 6),  // -1.117549851825099836e+02
        FLR::scaled( 0x14A50F52E3DA23, -52 - 1),  // +6.451489085146174807e-01
        FLR::scaled( 0x13F332D901EFA2, -52 + 8),  // +3.191999139857890668e+02
        FLR::scaled( 0x14C460EE42A8EC, -52 - 1),  // +6.489720014117472680e-01
        FLR::scaled(-0x1056A4FF05B218, -52 + 7),  // -1.307076411353343701e+02
        FLR::scaled( 0x14C460EE42A8EC, -52 - 1),  // +6.489720014117472680e-01
        FLR::scaled( 0x1182C69598127E, -52 + 8),  // +2.801734825077363666e+02
        FLR::scaled( 0x14CE832BAD481F, -52 - 1),  // +6.502090313972564983e-01
        FLR::scaled( 0x189AB2C57265E7, -52 + 7),  // +1.968343226656281502e+02
        FLR::scaled( 0x14CE832BAD481F, -52 - 1),  // +6.502090313972564983e-01
        FLR::scaled( 0x11FD19CC09686A, -52 + 8),  // +2.878187981002325841e+02
        FLR::scaled( 0x14ABC269702266, -52 - 1),  // +6.459667262398169907e-01
        FLR::scaled( 0x120FF6FF0DF430, -52 + 8),  // +2.889978018326828533e+02
        FLR::scaled( 0x14ABC269702266, -52 - 1),  // +6.459667262398169907e-01
        FLR::scaled( 0x147A50B6B0D7B3, -52 + 8),  // +3.276447054775155152e+02
        FLR::scaled( 0x14B44A8C663547, -52 - 1),  // +6.470082037136898334e-01
        FLR::scaled( 0x1142FD98F3BE06, -52 + 9),  // +5.523738268892636825e+02
        FLR::scaled( 0x14B44A8C663547, -52 - 1),  // +6.470082037136898334e-01
        FLR::scaled( 0x1B42DF00E85D10, -52 + 8),  // +4.361794442249965869e+02
        FLR::scaled( 0x14D5F835F59748, -52 - 1),  // +6.511193326848365714e-01
        FLR::scaled( 0x1A700112AA068C, -52 + 5),  // +5.287503274251966445e+01
        FLR::scaled( 0x14D5F835F59748, -52 - 1),  // +6.511193326848365714e-01
        FLR::scaled( 0x1F900FB946B96F, -52 + 7),  // +2.525019194012961350e+02
        FLR::scaled( 0x14E0F60E8F3E34, -52 - 1),  // +6.524610790601799160e-01
        FLR::scaled( 0x1C667A772D16CA, -52 + 6),  // +1.136012247028658351e+02
        FLR::scaled( 0x14E0F60E8F3E34, -52 - 1),  // +6.524610790601799160e-01
        FLR::scaled( 0x1E0C495B20C484, -52 + 6),  // +1.201919772930141903e+02
        FLR::scaled( 0x14B82A1118B6F9, -52 - 1),  // +6.474809965054354466e-01
        FLR::scaled( 0x12E28F15A7D250, -52 + 6),  // +7.553998319042989351e+01
        FLR::scaled( 0x14B82A1118B6F9, -52 - 1),  // +6.474809965054354466e-01
        FLR::scaled( 0x16F05BD25095DA, -52 + 8),  // +3.670224173686852964e+02
        FLR::scaled( 0x14C03C98CD1E0C, -52 - 1),  // +6.484663948439801651e-01
        FLR::scaled( 0x1CAF1564C345F4, -52 + 7),  // +2.294713615240031004e+02
        FLR::scaled( 0x14C03C98CD1E0C, -52 - 1),  // +6.484663948439801651e-01
        FLR::scaled( 0x150B259A83EB01, -52 + 8),  // +3.366966805604025126e+02
        FLR::scaled( 0x14DCEDF9C980C9, -52 - 1),  // +6.519689444212640739e-01
        FLR::scaled(-0x132835D1322EE0, -52 + 4),  // -1.915707118487523530e+01
        FLR::scaled( 0x14DCEDF9C980C9, -52 - 1),  // +6.519689444212640739e-01
        FLR::scaled(-0x188DC69F092444, -52 + 5),  // -4.910762393900270695e+01
        FLR::scaled( 0x14E7360AC790EA, -52 - 1),  // +6.532240114725287317e-01
        FLR::scaled( 0x19185DC7DDD566, -52 + 8),  // +4.015228956857084768e+02
        FLR::scaled( 0x14E7360AC790EA, -52 - 1),  // +6.532240114725287317e-01
        FLR::scaled(-0x166663F9BE8D20, -52 + 2),  // -5.599990751509977827e+00
        FLR::scaled( 0x14C52F051E3031, -52 - 1),  // +6.490702724418097036e-01
        FLR::scaled(-0x141352189218DE, -52 + 8),  // -3.212075429636878425e+02
        FLR::scaled( 0x14C52F051E3031, -52 - 1),  // +6.490702724418097036e-01
        FLR::scaled(-0x150C4EFB0EF2C9, -52 + 6),  // -8.419232059917261779e+01
        FLR::scaled( 0x14CDB0F23EB428, -52 - 1),  // +6.501087886186995846e-01
        FLR::scaled( 0x171815ECF71B79, -52 + 7),  // +1.847526764704050777e+02
        FLR::scaled( 0x14CDB0F23EB428, -52 - 1),  // +6.501087886186995846e-01
        FLR::scaled( 0x1B6C524CDD20DA, -52 + 8),  // +4.387700928342652560e+02
        FLR::scaled( 0x14ECE1C114A6F1, -52 - 1),  // +6.539162417513734171e-01
        FLR::scaled(-0x140E397D052918, -52 + 8),  // -3.208890352441389950e+02
        FLR::scaled( 0x14ECE1C114A6F1, -52 - 1),  // +6.539162417513734171e-01
        FLR::scaled( 0x1FBF821E65AF3B, -52 + 5),  // +6.349615840878546891e+01
        FLR::scaled( 0x14F7CDE2F954CE, -52 - 1),  // +6.552495415768591069e-01
        FLR::scaled( 0x1D7539595891F4, -52 + 6),  // +1.178316253056471510e+02
        FLR::scaled( 0x14F7CDE2F954CE, -52 - 1),  // +6.552495415768591069e-01
        FLR::scaled( 0x114144736C0D52, -52 + 9),  // +5.521584232751431500e+02
        FLR::scaled( 0x154E7494E1B7BF, -52 - 1),  // +6.658270747991464900e-01
        FLR::scaled(-0x19E18C229EBB68, -52 + 5),  // -5.176208908796871810e+01
        FLR::scaled( 0x154E7494E1B7BF, -52 - 1),  // +6.658270747991464900e-01
        FLR::scaled( 0x1E46BAC123C190, -52 + 8),  // +4.844205943485949319e+02
        FLR::scaled( 0x1564A63B6C2EC4, -52 - 1),  // +6.685362969014581047e-01
        FLR::scaled( 0x1313E9C0BF0FEB, -52 + 7),  // +1.526222842914279170e+02
        FLR::scaled( 0x1564A63B6C2EC4, -52 - 1),  // +6.685362969014581047e-01
        FLR::scaled( 0x12D2B67F3DEB51, -52 + 8),  // +3.011695549410551962e+02
        FLR::scaled( 0x155F83DD0601E8, -52 - 1),  // +6.679095570435125140e-01
        FLR::scaled( 0x1DF6E51852BF66, -52 + 7),  // +2.397154656997838060e+02
        FLR::scaled( 0x155F83DD0601E8, -52 - 1),  // +6.679095570435125140e-01
        FLR::scaled(-0x10E92ED9AA1055, -52 + 4),  // -1.691087112810085458e+01
        FLR::scaled( 0x1574E4210EB94A, -52 - 1),  // +6.705189366964898756e-01
        FLR::scaled(-0x1D059B1F97DDF2, -52 + 5),  // -5.804379649081592163e+01
        FLR::scaled( 0x1574E4210EB94A, -52 - 1),  // +6.705189366964898756e-01
        FLR::scaled( 0x1EBB1682743AE5, -52 + 7),  // +2.458464977522009178e+02
        FLR::scaled( 0x155D3255A7CD71, -52 - 1),  // +6.676265404661717584e-01
        FLR::scaled(-0x1486AE40A4436E, -52 + 8),  // -3.284175421158350900e+02
        FLR::scaled( 0x155D3255A7CD71, -52 - 1),  // +6.676265404661717584e-01
        FLR::scaled( 0x1EA6E5DE7C97A0, -52 + 7),  // +2.452155601914828367e+02
        FLR::scaled( 0x15741CCE74F89A, -52 - 1),  // +6.704238922464071937e-01
        FLR::scaled( 0x1DF7A20E7A9C63, -52 + 5),  // +5.993463307368144655e+01
        FLR::scaled( 0x15741CCE74F89A, -52 - 1),  // +6.704238922464071937e-01
        FLR::scaled( 0x1BB5E92C41D00C, -52 + 7),  // +2.216847134862331359e+02
        FLR::scaled( 0x15704A1AA0DD56, -52 - 1),  // +6.699572105489248752e-01
        FLR::scaled( 0x1E5BCDCD4627DD, -52 + 6),  // +1.214344361481775678e+02
        FLR::scaled( 0x15704A1AA0DD56, -52 - 1),  // +6.699572105489248752e-01
        FLR::scaled( 0x1B0D99F4157D81, -52 + 8),  // +4.328500862922156216e+02
        FLR::scaled( 0x15866DB0551F33, -52 - 1),  // +6.726597255701335376e-01
        FLR::scaled( 0x13B3258441EB5C, -52 + 8),  // +3.151966593337035647e+02
        FLR::scaled( 0x15866DB0551F33, -52 - 1),  // +6.726597255701335376e-01
        FLR::scaled( 0x17E88EBBD4096C, -52 + 8),  // +3.825348470957458176e+02
        FLR::scaled( 0x15615CF179BC20, -52 - 1),  // +6.681351391142733576e-01
        FLR::scaled( 0x1C1E217BC11D09, -52 + 7),  // +2.249415873309847314e+02
        FLR::scaled( 0x15615CF179BC20, -52 - 1),  // +6.681351391142733576e-01
        FLR::scaled( 0x16630AF85F0CCE, -52 + 7),  // +1.790950891357846899e+02
        FLR::scaled( 0x1575EFDE3CE96D, -52 - 1),  // +6.706466045937254927e-01
        FLR::scaled( 0x13B46A9CB63899, -52 + 8),  // +3.152760283582697980e+02
        FLR::scaled( 0x1575EFDE3CE96D, -52 - 1),  // +6.706466045937254927e-01
        FLR::scaled( 0x1C58BA3E7ED067, -52 + 7),  // +2.267727348782384240e+02
        FLR::scaled( 0x1571C159519DA2, -52 - 1),  // +6.701361412532842454e-01
        FLR::scaled( 0x1200BF9CC9C323, -52 + 7),  // +1.440233901920956612e+02
        FLR::scaled( 0x1571C159519DA2, -52 - 1),  // +6.701361412532842454e-01
        FLR::scaled( 0x11BA357678CCA5, -52 + 6),  // +7.090951310917678541e+01
        FLR::scaled( 0x1585C7B4FA20E3, -52 - 1),  // +6.725805792530333838e-01
        FLR::scaled( 0x1633C5DC3AC4BC, -52 + 7),  // +1.776179028652021543e+02
        FLR::scaled( 0x1585C7B4FA20E3, -52 - 1),  // +6.725805792530333838e-01
        FLR::scaled(-0x14B7AA7EFE86A1, -52 + 5),  // -4.143489062717458893e+01
        FLR::scaled( 0x156EAB53EA4ECD, -52 - 1),  // +6.697594298334138552e-01
        FLR::scaled(-0x13EF0056542306, -52 + 6),  // -7.973439558235631353e+01
        FLR::scaled( 0x156EAB53EA4ECD, -52 - 1),  // +6.697594298334138552e-01
        FLR::scaled(-0x1B64D92969927C, -52 + 7),  // -2.191515090047795411e+02
        FLR::scaled( 0x1583F446918E88, -52 - 1),  // +6.723576906483268445e-01
        FLR::scaled( 0x12765F3F4BF51C, -52 + 5),  // +3.692478171547756460e+01
        FLR::scaled( 0x1583F446918E88, -52 - 1),  // +6.723576906483268445e-01
        FLR::scaled(-0x1CF3ED03AE0885, -52 + 4),  // -2.895283530234202729e+01
        FLR::scaled( 0x1580F8301718CD, -52 - 1),  // +6.719933451902534438e-01
        FLR::scaled(-0x1C65A1D1ACDDDA, -52 + 3),  // -1.419850020632923204e+01
        FLR::scaled( 0x1580F8301718CD, -52 - 1),  // +6.719933451902534438e-01
        FLR::scaled( 0x14E33809881023, -52 + 8),  // +3.342011809649431484e+02
        FLR::scaled( 0x1595BE10219159, -52 - 1),  // +6.745291056691186116e-01
        FLR::scaled( 0x119CC2184F1427, -52 + 8),  // +2.817973864640247825e+02
        FLR::scaled( 0x1595BE10219159, -52 - 1),  // +6.745291056691186116e-01
        FLR::scaled( 0x1CDC2B125C2222, -52 + 8),  // +4.617605155562361006e+02
        FLR::scaled( 0x161266CD4A9893, -52 - 1),  // +6.897462854001495947e-01
        FLR::scaled(-0x127C0D283B33F8, -52 + 7),  // -1.478766060978230144e+02
        FLR::scaled( 0x161266CD4A9893, -52 - 1),  // +6.897462854001495947e-01
        FLR::scaled( 0x14273445E9C224, -52 + 7),  // +1.612251309934227947e+02
        FLR::scaled( 0x161297B5464046, -52 - 1),  // +6.897696056858044766e-01
        FLR::scaled(-0x128EE0BCB2A17F, -52 + 7),  // -1.484649337281116175e+02
        FLR::scaled( 0x161297B5464046, -52 - 1),  // +6.897696056858044766e-01
        FLR::scaled( 0x140BCA7844ED6B, -52 + 8),  // +3.207369311039425952e+02
        FLR::scaled( 0x1626B874437E90, -52 - 1),  // +6.922266264700329685e-01
        FLR::scaled( 0x1177D3DABF1B28, -52 + 5),  // +3.493615278560019988e+01
        FLR::scaled( 0x1626B874437E90, -52 - 1),  // +6.922266264700329685e-01
        FLR::scaled( 0x1F60ED30D0B76A, -52 + 7),  // +2.510289539410107977e+02
        FLR::scaled( 0x1626BAB77367A1, -52 - 1),  // +6.922277052901685268e-01
        FLR::scaled( 0x1A0A9D2E514FB5, -52 + 6),  // +1.041658435625129897e+02
        FLR::scaled( 0x1626BAB77367A1, -52 - 1),  // +6.922277052901685268e-01
        FLR::scaled( 0x1940CE642F559B, -52 + 7),  // +2.020251942562580041e+02
        FLR::scaled( 0x161C4492BFCB78, -52 - 1),  // +6.909506670184404342e-01
        FLR::scaled( 0x1E384E306F6703, -52 + 7),  // +2.417595445800617142e+02
        FLR::scaled( 0x161C4492BFCB78, -52 - 1),  // +6.909506670184404342e-01
        FLR::scaled( 0x1F18E58EE891C8, -52 + 8),  // +4.975560444912666753e+02
        FLR::scaled( 0x161C6D1F3A54BF, -52 - 1),  // +6.909700021666579373e-01
        FLR::scaled(-0x137781D2E56251, -52 + 7),  // -1.557345976333768078e+02
        FLR::scaled( 0x161C6D1F3A54BF, -52 - 1),  // +6.909700021666579373e-01
        FLR::scaled( 0x1AE8F51620E492, -52 + 8),  // +4.305598355564953863e+02
        FLR::scaled( 0x162FED10F83768, -52 - 1),  // +6.933503467023287570e-01
        FLR::scaled(-0x1CC5B8C322903F, -52 + 7),  // -2.301788039851253131e+02
        FLR::scaled( 0x162FED10F83768, -52 - 1),  // +6.933503467023287570e-01
        FLR::scaled( 0x1FFC650BDEA0E6, -52 + 6),  // +1.279436673807245768e+02
        FLR::scaled( 0x162FEE5DCFD932, -52 - 1),  // +6.933509666694475104e-01
        FLR::scaled( 0x1D4584453BE7E4, -52 + 7),  // +2.341723962945972062e+02
        FLR::scaled( 0x162FEE5DCFD932, -52 - 1),  // +6.933509666694475104e-01
        FLR::scaled( 0x1C07C7F76C5263, -52 + 7),  // +2.242431599727306946e+02
        FLR::scaled( 0x1645DF43067701, -52 - 1),  // +6.960293110930423355e-01
        FLR::scaled( 0x12C1338A7AEA2F, -52 + 9),  // +6.001501664736478006e+02
        FLR::scaled( 0x1645DF43067701, -52 - 1),  // +6.960293110930423355e-01
        FLR::scaled( 0x147BA4B82AD62F, -52 + 6),  // +8.193192867453829820e+01
        FLR::scaled( 0x1645E970514B90, -52 - 1),  // +6.960341638281182242e-01
        FLR::scaled(-0x13F89B38B1A632, -52 + 6),  // -7.988447396610789042e+01
        FLR::scaled( 0x1645E970514B90, -52 - 1),  // +6.960341638281182242e-01
        FLR::scaled( 0x17929466992711, -52 + 8),  // +3.771612306578181801e+02
        FLR::scaled( 0x1658B291492A15, -52 - 1),  // +6.983273351300477438e-01
        FLR::scaled( 0x1045D48854A170, -52 + 7),  // +1.301821939137403206e+02
        FLR::scaled( 0x1658B291492A15, -52 - 1),  // +6.983273351300477438e-01
        FLR::scaled( 0x155278879ADB0E, -52 + 8),  // +3.411544261979150860e+02
        FLR::scaled( 0x1658B510FBAE43, -52 - 1),  // +6.983285266591753304e-01
        FLR::scaled( 0x143F94D3E11787, -52 + 7),  // +1.619869174381567234e+02
        FLR::scaled( 0x1658B510FBAE43, -52 - 1),  // +6.983285266591753304e-01
        FLR::scaled( 0x1C98F205939D9F, -52 + 7),  // +2.287795436747664723e+02
        FLR::scaled( 0x164E1051B73D2C, -52 - 1),  // +6.970292659770271904e-01
        FLR::scaled( 0x10141D9E9E7E22, -52 + 6),  // +6.431430783727458333e+01
        FLR::scaled( 0x164E1051B73D2C, -52 - 1),  // +6.970292659770271904e-01
        FLR::scaled( 0x148E0C0A65DFA1, -52 + 8),  // +3.288779396037517131e+02
        FLR::scaled( 0x164E1881FBE440, -52 - 1),  // +6.970331705807737421e-01
        FLR::scaled(-0x1A6CA8F4B5C86A, -52 + 5),  // -5.284890612484089445e+01
        FLR::scaled( 0x164E1881FBE440, -52 - 1),  // +6.970331705807737421e-01
        FLR::scaled( 0x1EFAA3A153CC76, -52 + 7),  // +2.478324743878071672e+02
        FLR::scaled( 0x16605D78D1FA60, -52 - 1),  // +6.992633209009220252e-01
        FLR::scaled(-0x15A12235E11568, -52 + 3),  // -1.081471413014033089e+01
        FLR::scaled( 0x16605D78D1FA60, -52 - 1),  // +6.992633209009220252e-01
        FLR::scaled( 0x1D514AE88C4CB3, -52 + 8),  // +4.690807881813481686e+02
        FLR::scaled( 0x166060389526E9, -52 - 1),  // +6.992646317605394346e-01
        FLR::scaled( 0x173171F6B2E08A, -52 + 8),  // +3.710903231608759825e+02
        FLR::scaled( 0x166060389526E9, -52 - 1),  // +6.992646317605394346e-01
        FLR::scaled( 0x14DDE3369B521E, -52 + 4),  // +2.086674824993144028e+01
        FLR::scaled( 0x16AC354A81D059, -52 - 1),  // +7.085215048996459375e-01
        FLR::scaled( 0x117FE381A53168, -52 + 6),  // +6.999826089031341780e+01
        FLR::scaled( 0x16AC354A81D059, -52 - 1),  // +7.085215048996459375e-01
        FLR::scaled( 0x1B81C5E0B1EB52, -52 + 8),  // +4.401108099889726191e+02
        FLR::scaled( 0x16B0A80782E1D2, -52 - 1),  // +7.090644976333868588e-01
        FLR::scaled(-0x101AC3481771AC, -52 + 6),  // -6.441816904344040040e+01
        FLR::scaled( 0x16B0A80782E1D2, -52 - 1),  // +7.090644976333868588e-01
        FLR::scaled( 0x18216E91824D02, -52 + 9),  // +7.721789884738684577e+02
        FLR::scaled( 0x16BD5A013429CF, -52 - 1),  // +7.106142066489214981e-01
        FLR::scaled(-0x1179C5AEA88840, -52 + 3),  // -8.737836320946485102e+00
        FLR::scaled( 0x16BD5A013429CF, -52 - 1),  // +7.106142066489214981e-01
        FLR::scaled(-0x13047296365FC4, -52 + 7),  // -1.521389876424783552e+02
        FLR::scaled( 0x16C0BA88D75DA3, -52 - 1),  // +7.110264465981582793e-01
        FLR::scaled( 0x1EC94094DB54D9, -52 + 8),  // +4.925782669608720994e+02
        FLR::scaled( 0x16C0BA88D75DA3, -52 - 1),  // +7.110264465981582793e-01
        FLR::scaled( 0x10CCD2AB1034B8, -52 + 8),  // +2.688014326699299090e+02
        FLR::scaled( 0x16B7C62FC52F8E, -52 - 1),  // +7.099333699238614681e-01
        FLR::scaled( 0x1828B290FD19A0, -52 + 6),  // +9.663589882580572521e+01
        FLR::scaled( 0x16B7C62FC52F8E, -52 - 1),  // +7.099333699238614681e-01
        FLR::scaled(-0x1392F3CCB492DE, -52 + 6),  // -7.829613034853124987e+01
        FLR::scaled( 0x16BBFC7C18EB61, -52 - 1),  // +7.104475425506785458e-01
        FLR::scaled( 0x16565CC6418AE6, -52 + 7),  // +1.786988250045898781e+02
        FLR::scaled( 0x16BBFC7C18EB61, -52 - 1),  // +7.104475425506785458e-01
        FLR::scaled( 0x1048404F3A8DD5, -52 + 9),  // +5.210314011168035222e+02
        FLR::scaled( 0x16C7EF4FCF8575, -52 - 1),  // +7.119061049271936392e-01
        FLR::scaled(-0x1F9E8EA6CF12E0, -52 + 5),  // -6.323872838126203533e+01
        FLR::scaled( 0x16C7EF4FCF8575, -52 - 1),  // +7.119061049271936392e-01
        FLR::scaled( 0x1DFCB55A789FFC, -52 + 7),  // +2.398971378665881957e+02
        FLR::scaled( 0x16CB255DE087EB, -52 - 1),  // +7.122980912720299207e-01
        FLR::scaled( 0x12B6B2C9DA282F, -52 + 5),  // +3.742733119156070387e+01
        FLR::scaled( 0x16CB255DE087EB, -52 - 1),  // +7.122980912720299207e-01
        FLR::scaled( 0x1C6A08FDEB0277, -52 + 6),  // +1.136567988200202848e+02
        FLR::scaled( 0x16DD01216E1D0F, -52 - 1),  // +7.144780781681293602e-01
        FLR::scaled(-0x13C8027C935E37, -52 + 8),  // -3.165006070858539147e+02
        FLR::scaled( 0x16DD01216E1D0F, -52 - 1),  // +7.144780781681293602e-01
        FLR::scaled( 0x17884C14424625, -52 + 6),  // +9.412964350196905627e+01
        FLR::scaled( 0x16DFEF10402CE7, -52 - 1),  // +7.148356740375704232e-01
        FLR::scaled( 0x1156180D8AB7C3, -52 + 8),  // +2.773808722895302594e+02
        FLR::scaled( 0x16DFEF10402CE7, -52 - 1),  // +7.148356740375704232e-01
        FLR::scaled( 0x1239B38DBC28BE, -52 + 7),  // +1.458031681704505331e+02
        FLR::scaled( 0x16EB561F71A5B3, -52 - 1),  // +7.162275900019977604e-01
        FLR::scaled( 0x154B06B75218B4, -52 + 4),  // +2.129307122949894904e+01
        FLR::scaled( 0x16EB561F71A5B3, -52 - 1),  // +7.162275900019977604e-01
        FLR::scaled( 0x18263E7BF91780, -52 + 8),  // +3.863902549486301723e+02
        FLR::scaled( 0x16ED845F4410CF, -52 - 1),  // +7.164937840139148362e-01
        FLR::scaled( 0x105023FB8A78D5, -52 + 8),  // +2.610087848099768166e+02
        FLR::scaled( 0x16ED845F4410CF, -52 - 1),  // +7.164937840139148362e-01
        FLR::scaled( 0x1347567AD56BF8, -52 + 8),  // +3.084586132370745872e+02
        FLR::scaled( 0x16E59586308704, -52 - 1),  // +7.155254002466056029e-01
        FLR::scaled(-0x11907D0DE04A92, -52 + 9),  // -5.620610616228825620e+02
        FLR::scaled( 0x16E59586308704, -52 - 1),  // +7.155254002466056029e-01
        FLR::scaled( 0x1487F8E40A9C03, -52 + 8),  // +3.284982643522673129e+02
        FLR::scaled( 0x16E8814EEE74BE, -52 - 1),  // +7.158819715147257678e-01
        FLR::scaled( 0x110CA96D06AF77, -52 + 8),  // +2.727913637410305796e+02
        FLR::scaled( 0x16E8814EEE74BE, -52 - 1),  // +7.158819715147257678e-01
        FLR::scaled( 0x16D1425243494E, -52 + 8),  // +3.650786917332051189e+02
        FLR::scaled( 0x16F34F6731E235, -52 - 1),  // +7.172009482883995313e-01
        FLR::scaled(-0x1756DE7FAA0662, -52 + 6),  // -9.335733024219510412e+01
        FLR::scaled( 0x16F34F6731E235, -52 - 1),  // +7.172009482883995313e-01
        FLR::scaled( 0x1003C7765B88C3, -52 + 9),  // +5.124723937178717961e+02
        FLR::scaled( 0x16F58068D4DEDB, -52 - 1),  // +7.174684569826824676e-01
        FLR::scaled(-0x1D3524F713BC31, -52 + 4),  // -2.920759529334845084e+01
        FLR::scaled( 0x16F58068D4DEDB, -52 - 1),  // +7.174684569826824676e-01
        FLR::scaled( 0x1E37949764DBFB, -52 + 7),  // +2.417368885965259722e+02
        FLR::scaled( 0x1680337E3F7CF0, -52 - 1),  // +7.031495538502934295e-01
        FLR::scaled( 0x130310F50FA942, -52 + 6),  // +7.604790998963747484e+01
        FLR::scaled( 0x1680337E3F7CF0, -52 - 1),  // +7.031495538502934295e-01
        FLR::scaled( 0x12455582E4D6B6, -52 + 8),  // +2.923333767832767762e+02
        FLR::scaled( 0x1680FAADD2A647, -52 - 1),  // +7.032445330598385835e-01
        FLR::scaled(-0x1C473C8F81FCC8, -52 + 7),  // -2.262261426485840730e+02
        FLR::scaled( 0x1680FAADD2A647, -52 - 1),  // +7.032445330598385835e-01
        FLR::scaled( 0x106C16541D5952, -52 + 9),  // +5.255109026234515568e+02
        FLR::scaled( 0x16A13694B1DFAB, -52 - 1),  // +7.071793464847265787e-01
        FLR::scaled( 0x104D4DB25A810B, -52 + 8),  // +2.608314689193072695e+02
        FLR::scaled( 0x16A13694B1DFAB, -52 - 1),  // +7.071793464847265787e-01
        FLR::scaled( 0x18B1A640D64334, -52 + 7),  // +1.975515445885481540e+02
        FLR::scaled( 0x16A16CCA4FF907, -52 - 1),  // +7.072051955617845165e-01
        FLR::scaled( 0x155587ABC6BCE6, -52 + 7),  // +1.706728114015197093e+02
        FLR::scaled( 0x16A16CCA4FF907, -52 - 1),  // +7.072051955617845165e-01
        FLR::scaled( 0x12CA571CFA3448, -52 + 7),  // +1.503231339346696132e+02
        FLR::scaled( 0x168B452BED8A61, -52 - 1),  // +7.045007570234923522e-01
        FLR::scaled( 0x10B018DBE67B4A, -52 + 7),  // +1.335030345441430768e+02
        FLR::scaled( 0x168B452BED8A61, -52 - 1),  // +7.045007570234923522e-01
        FLR::scaled( 0x11E57FCB38FAEF, -52 + 8),  // +2.863436996675290516e+02
        FLR::scaled( 0x168BFDB60F5CF2, -52 - 1),  // +7.045887523517235795e-01
        FLR::scaled( 0x15BC40FBD1FE1F, -52 + 4),  // +2.173536657215856494e+01
        FLR::scaled( 0x168BFDB60F5CF2, -52 - 1),  // +7.045887523517235795e-01
        FLR::scaled( 0x18C17F6A01D170, -52 + 7),  // +1.980468034778127731e+02
        FLR::scaled( 0x16AB04729D40F2, -52 - 1),  // +7.083761442718510271e-01
        FLR::scaled( 0x1DF1937FFB9C96, -52 + 5),  // +5.988731384072995922e+01
        FLR::scaled( 0x16AB04729D40F2, -52 - 1),  // +7.083761442718510271e-01
        FLR::scaled(-0x177252D7BA2A14, -52 + 6),  // -9.378630631618608504e+01
        FLR::scaled( 0x16AB39BCBF6CBD, -52 - 1),  // +7.084015547256040657e-01
        FLR::scaled( 0x1661C9DAB00EC4, -52 + 7),  // +1.790558904112459686e+02
        FLR::scaled( 0x16AB39BCBF6CBD, -52 - 1),  // +7.084015547256040657e-01
        FLR::scaled( 0x15F9461F5F433B, -52 + 8),  // +3.515796197625347190e+02
        FLR::scaled( 0x16B926A56606C5, -52 - 1),  // +7.101014357033014202e-01
        FLR::scaled( 0x100DACD875080D, -52 + 8),  // +2.568546986171284630e+02
        FLR::scaled( 0x16B926A56606C5, -52 - 1),  // +7.101014357033014202e-01
        FLR::scaled( 0x11DBD3A0ECD237, -52 + 9),  // +5.714783342839863280e+02
        FLR::scaled( 0x16B96449892984, -52 - 1),  // +7.101308284994023445e-01
        FLR::scaled( 0x119BFAE728514B, -52 + 7),  // +1.408743778026058351e+02
        FLR::scaled( 0x16B96449892984, -52 - 1),  // +7.101308284994023445e-01
        FLR::scaled( 0x1679C32A704B83, -52 + 8),  // +3.596101478945276426e+02
        FLR::scaled( 0x16D970EB8EA061, -52 - 1),  // +7.140431023335730432e-01
        FLR::scaled( 0x1038498239E7DB, -52 + 8),  // +2.595179464590016210e+02
        FLR::scaled( 0x16D970EB8EA061, -52 - 1),  // +7.140431023335730432e-01
        FLR::scaled(-0x18D79FD46AF032, -52 + 7),  // -1.987382604683530758e+02
        FLR::scaled( 0x16D973F30C8075, -52 - 1),  // +7.140445467994270823e-01
        FLR::scaled( 0x1E6FB33D634393, -52 + 8),  // +4.869812597157953746e+02
        FLR::scaled( 0x16D973F30C8075, -52 - 1),  // +7.140445467994270823e-01
        FLR::scaled( 0x19BB22B2E874A9, -52 + 8),  // +4.116959714012432983e+02
        FLR::scaled( 0x16C25D21F9CA38, -52 - 1),  // +7.112260497654636637e-01
        FLR::scaled( 0x17504899274E68, -52 + 6),  // +9.325443104589942322e+01
        FLR::scaled( 0x16C25D21F9CA38, -52 - 1),  // +7.112260497654636637e-01
        FLR::scaled( 0x1E07F07275DEC6, -52 + 8),  // +4.804962029079728154e+02
        FLR::scaled( 0x16C293D9822301, -52 - 1),  // +7.112521408281226032e-01
        FLR::scaled( 0x1F7A6C12FAE8DB, -52 + 6),  // +1.259128463220871907e+02
        FLR::scaled( 0x16C293D9822301, -52 - 1),  // +7.112521408281226032e-01
        FLR::scaled( 0x1C728EADF9BCBD, -52 + 8),  // +4.551598338847505261e+02
        FLR::scaled( 0x16E199666143A7, -52 - 1),  // +7.150389670952009835e-01
        FLR::scaled(-0x12CD66DC0B1EA4, -52 + 6),  // -7.520940304838092061e+01
        FLR::scaled( 0x16E199666143A7, -52 - 1),  // +7.150389670952009835e-01
        FLR::scaled( 0x1B6D05DE9C5761, -52 + 8),  // +4.388139330012400592e+02
        FLR::scaled( 0x16E19C4CFEF374, -52 - 1),  // +7.150403503252236170e-01
        FLR::scaled( 0x16613751D95E3B, -52 + 8),  // +3.580760057917538575e+02
        FLR::scaled( 0x16E19C4CFEF374, -52 - 1),  // +7.150403503252236170e-01
        FLR::scaled( 0x10446C6DFDEDEA, -52 + 9),  // +5.205529441679220781e+02
        FLR::scaled( 0x1723B4DAA8811C, -52 - 1),  // +7.231086989086494832e-01
        FLR::scaled( 0x109059CF4BBB83, -52 + 8),  // +2.650219262083339231e+02
        FLR::scaled( 0x1723B4DAA8811C, -52 - 1),  // +7.231086989086494832e-01
        FLR::scaled( 0x1090A9C9162D6C, -52 + 9),  // +5.300829030735599190e+02
        FLR::scaled( 0x172A7CF83D2C32, -52 - 1),  // +7.239365433137037176e-01
        FLR::scaled(-0x132E974D1270FB, -52 + 6),  // -7.672798468399916771e+01
        FLR::scaled( 0x172A7CF83D2C32, -52 - 1),  // +7.239365433137037176e-01
        FLR::scaled( 0x1E6D42E29D4D2C, -52 + 7),  // +2.434144146988195416e+02
        FLR::scaled( 0x173D1F0D038D08, -52 - 1),  // +7.262110952546274589e-01
        FLR::scaled( 0x16C8B75C8B7FFC, -52 + 6),  // +9.113619149802246966e+01
        FLR::scaled( 0x173D1F0D038D08, -52 - 1),  // +7.262110952546274589e-01
        FLR::scaled( 0x13C641555BA74C, -52 + 7),  // +1.581954752721889008e+02
        FLR::scaled( 0x1741CE5F348C7A, -52 - 1),  // +7.267829761007214007e-01
        FLR::scaled( 0x1D21B7499981AC, -52 + 8),  // +4.661072479244564875e+02
        FLR::scaled( 0x1741CE5F348C7A, -52 - 1),  // +7.267829761007214007e-01
        FLR::scaled( 0x137E616FD6F7A9, -52 + 8),  // +3.118987882992901746e+02
        FLR::scaled( 0x1731672E49838C, -52 - 1),  // +7.247806457563554794e-01
        FLR::scaled(-0x1C578C893E076E, -52 + 7),  // -2.267359052859787312e+02
        FLR::scaled( 0x1731672E49838C, -52 - 1),  // +7.247806457563554794e-01
        FLR::scaled( 0x1E63F04C702B45, -52 + 7),  // +2.431230833235551074e+02
        FLR::scaled( 0x173803461AB8D1, -52 - 1),  // +7.255874985910627517e-01
        FLR::scaled(-0x19FEAD5C1D7763, -52 + 7),  // -2.079586620879664167e+02
        FLR::scaled( 0x173803461AB8D1, -52 - 1),  // +7.255874985910627517e-01
        FLR::scaled( 0x1C20217CE3E3EC, -52 + 7),  // +2.250040878725989160e+02
        FLR::scaled( 0x17496D6907E330, -52 - 1),  // +7.277133036978735703e-01
        FLR::scaled(-0x14130BD1244318, -52 + 5),  // -4.014879812498674028e+01
        FLR::scaled( 0x17496D6907E330, -52 - 1),  // +7.277133036978735703e-01
        FLR::scaled( 0x13AA901F05096E, -52 + 8),  // +3.146601858326674801e+02
        FLR::scaled( 0x174E16D786E0E4, -52 - 1),  // +7.282823762425576497e-01
        FLR::scaled( 0x1AB409E29CCBA3, -52 + 8),  // +4.272524133801290986e+02
        FLR::scaled( 0x174E16D786E0E4, -52 - 1),  // +7.282823762425576497e-01
        FLR::scaled( 0x10C1F4ED86D898, -52 + 7),  // +1.340611484178268711e+02
        FLR::scaled( 0x175A5C4BEAA834, -52 - 1),  // +7.297803385492955819e-01
        FLR::scaled( 0x1CDC92545544C0, -52 + 0),  // +1.803850488115401163e+00
        FLR::scaled( 0x175A5C4BEAA834, -52 - 1),  // +7.297803385492955819e-01
        FLR::scaled( 0x1D0437CC5BF7FB, -52 + 8),  // +4.642636226265455548e+02
        FLR::scaled( 0x175E78576A61DF, -52 - 1),  // +7.302819926581455290e-01
        FLR::scaled( 0x103D8037255043, -52 + 6),  // +6.496095064777277628e+01
        FLR::scaled( 0x175E78576A61DF, -52 - 1),  // +7.302819926581455290e-01
        FLR::scaled( 0x1AC1D036366814, -52 + 6),  // +1.070283332377733245e+02
        FLR::scaled( 0x17719217A4E796, -52 - 1),  // +7.326136075782752055e-01
        FLR::scaled( 0x1B639C1FEB4301, -52 + 8),  // +4.382256163778220639e+02
        FLR::scaled( 0x17719217A4E796, -52 - 1),  // +7.326136075782752055e-01
        FLR::scaled(-0x114E5BBE3A35F6, -52 + 6),  // -6.922434955296179737e+01
        FLR::scaled( 0x177437673430B4, -52 - 1),  // +7.329365745258855647e-01
        FLR::scaled( 0x171E9E8EE0FB2F, -52 + 8),  // +3.699137104786231589e+02
        FLR::scaled( 0x177437673430B4, -52 - 1),  // +7.329365745258855647e-01
        FLR::scaled( 0x14E96BC1B7D97E, -52 + 8),  // +3.345888077909111189e+02
        FLR::scaled( 0x176402E14C7E1A, -52 - 1),  // +7.309584045760317839e-01
        FLR::scaled(-0x15C5570B50796C, -52 + 8),  // -3.483337510245826252e+02
        FLR::scaled( 0x176402E14C7E1A, -52 - 1),  // +7.309584045760317839e-01
        FLR::scaled( 0x1CB48BF5B939A0, -52 + 0),  // +1.794078788621483511e+00
        FLR::scaled( 0x1768267279DB7B, -52 - 1),  // +7.314636455401876125e-01
        FLR::scaled(-0x1884500E307D58, -52 + 4),  // -2.451684654887989723e+01
        FLR::scaled( 0x1768267279DB7B, -52 - 1),  // +7.314636455401876125e-01
        FLR::scaled( 0x12F86AEAA434F0, -52 + 6),  // +7.588152566943949751e+01
        FLR::scaled( 0x177A5CAE4967E2, -52 - 1),  // +7.336867717779080866e-01
        FLR::scaled(-0x111362A749D920, -52 + 1),  // -2.134465510312239189e+00
        FLR::scaled( 0x177A5CAE4967E2, -52 - 1),  // +7.336867717779080866e-01
        FLR::scaled( 0x1BD2001A4DBF10, -52 + 6),  // +1.112812562712899762e+02
        FLR::scaled( 0x177D18C539594A, -52 - 1),  // +7.340206005126586053e-01
        FLR::scaled( 0x13DF0752029F40, -52 + 7),  // +1.589696435977184592e+02
        FLR::scaled( 0x177D18C539594A, -52 - 1),  // +7.340206005126586053e-01
        FLR::scaled( 0x15B4F44E80698F, -52 + 8),  // +3.473096451774699176e+02
        FLR::scaled( 0x172D59471CF0D0, -52 - 1),  // +7.242857350279567896e-01
        FLR::scaled(-0x1318781A1D8FC9, -52 + 8),  // -3.055293217806579946e+02
        FLR::scaled( 0x172D59471CF0D0, -52 - 1),  // +7.242857350279567896e-01
        FLR::scaled( 0x1086B77B2FFCB8, -52 + 7),  // +1.322098976075410519e+02
        FLR::scaled( 0x172D5976DD8F69, -52 - 1),  // +7.242858239737702819e-01
        FLR::scaled(-0x14ED7D73B6F8BA, -52 + 8),  // -3.348431279322936689e+02
        FLR::scaled( 0x172D5976DD8F69, -52 - 1),  // +7.242858239737702819e-01
        FLR::scaled( 0x12B1F7FE79E397, -52 + 7),  // +1.495615227108616807e+02
        FLR::scaled( 0x1743523E14AF43, -52 - 1),  // +7.269679272189722985e-01
        FLR::scaled(-0x1640E5DF41B0BF, -52 + 7),  // -1.780280605586067111e+02
        FLR::scaled( 0x1743523E14AF43, -52 - 1),  // +7.269679272189722985e-01
        FLR::scaled(-0x19EE8D1CD9CDE9, -52 + 8),  // -4.149094513423902413e+02
        FLR::scaled( 0x17435EE8CF094D, -52 - 1),  // +7.269739672704332856e-01
        FLR::scaled( 0x1A903B78ACB039, -52 + 8),  // +4.250145193811072772e+02
        FLR::scaled( 0x17435EE8CF094D, -52 - 1),  // +7.269739672704332856e-01
        FLR::scaled(-0x15DA271BB3925E, -52 + 5),  // -4.370431848781730366e+01
        FLR::scaled( 0x173760B0BF7BD4, -52 - 1),  // +7.255099727734610759e-01
        FLR::scaled( 0x1272E17D9A0100, -52 - 2),  // +2.882617689683826256e-01
        FLR::scaled( 0x173760B0BF7BD4, -52 - 1),  // +7.255099727734610759e-01
        FLR::scaled( 0x1F785CE04AEBF2, -52 + 8),  // +5.035226748396518133e+02
        FLR::scaled( 0x17376475EC14CA, -52 - 1),  // +7.255117705505196302e-01
        FLR::scaled( 0x18AF42B89C0385, -52 + 8),  // +3.949537893385207212e+02
        FLR::scaled( 0x17376475EC14CA, -52 - 1),  // +7.255117705505196302e-01
        FLR::scaled( 0x1AE523BEDFC014, -52 + 8),  // +4.303212269535299583e+02
        FLR::scaled( 0x174E9BB05AD7D0, -52 - 1),  // +7.283457226210376945e-01
        FLR::scaled(-0x18C1881DC5B60A, -52 + 6),  // -9.902393287952159540e+01
        FLR::scaled( 0x174E9BB05AD7D0, -52 - 1),  // +7.283457226210376945e-01
        FLR::scaled( 0x1D7A034DC1DA72, -52 + 6),  // +1.179064516442392971e+02
        FLR::scaled( 0x174E9F5BBFB2EF, -52 - 1),  // +7.283474723786563798e-01
        FLR::scaled( 0x16250C3AD5A745, -52 + 9),  // +7.086309715930625543e+02
        FLR::scaled( 0x174E9F5BBFB2EF, -52 - 1),  // +7.283474723786563798e-01
        FLR::scaled(-0x112F99FEABC2A8, -52 + 7),  // -1.374875481943793147e+02
        FLR::scaled( 0x17504877F3DC26, -52 - 1),  // +7.285501807044780787e-01
        FLR::scaled(-0x175C960D6F1170, -52 + 8),  // -3.737866339052770854e+02
        FLR::scaled( 0x17504877F3DC26, -52 - 1),  // +7.285501807044780787e-01
        FLR::scaled( 0x192B052C0BE9E0, -52 + 8),  // +4.026887627091764443e+02
        FLR::scaled( 0x1750601F316BC8, -52 - 1),  // +7.285614594687723766e-01
        FLR::scaled( 0x18C2FD1BAD4B38, -52 + 6),  // +9.904669849322533537e+01
        FLR::scaled( 0x1750601F316BC8, -52 - 1),  // +7.285614594687723766e-01
        FLR::scaled( 0x1CC32F7E5FE77A, -52 + 8),  // +4.601990951296098729e+02
        FLR::scaled( 0x17664B6166B22E, -52 - 1),  // +7.312371160856565577e-01
        FLR::scaled(-0x12ADBEFB7F9E31, -52 + 7),  // -1.494295632832086369e+02
        FLR::scaled( 0x17664B6166B22E, -52 - 1),  // +7.312371160856565577e-01
        FLR::scaled( 0x1262B6800F6443, -52 + 5),  // +3.677119446517510681e+01
        FLR::scaled( 0x1766990F69C71E, -52 - 1),  // +7.312741566695171169e-01
        FLR::scaled( 0x1725486027F53E, -52 + 8),  // +3.703301698265894402e+02
        FLR::scaled( 0x1766990F69C71E, -52 - 1),  // +7.312741566695171169e-01
        FLR::scaled( 0x13B38DB47703C3, -52 + 6),  // +7.880552398321655971e+01
        FLR::scaled( 0x1758E94DF9C5D9, -52 - 1),  // +7.296034357988744334e-01
        FLR::scaled( 0x1A1B3F8B8E5357, -52 + 6),  // +1.044257534875772393e+02
        FLR::scaled( 0x1758E94DF9C5D9, -52 - 1),  // +7.296034357988744334e-01
        FLR::scaled(-0x1D4D6EAF558BFE, -52 + 4),  // -2.930247016752763756e+01
        FLR::scaled( 0x1758F382EE2455, -52 - 1),  // +7.296083028060232900e-01
        FLR::scaled( 0x1B58E5C0BC492E, -52 + 7),  // +2.187780460050066154e+02
        FLR::scaled( 0x1758F382EE2455, -52 - 1),  // +7.296083028060232900e-01
        FLR::scaled( 0x13B36C55404ED5, -52 + 8),  // +3.152139484893826307e+02
        FLR::scaled( 0x176FEA7499C98C, -52 - 1),  // +7.324116017683066637e-01
        FLR::scaled(-0x16F0609847153F, -52 + 8),  // -3.670235827233008763e+02
        FLR::scaled( 0x176FEA7499C98C, -52 - 1),  // +7.324116017683066637e-01
        FLR::scaled( 0x1365AE22739D0C, -52 + 7),  // +1.551775066621852375e+02
        FLR::scaled( 0x17701AB71C11CD, -52 - 1),  // +7.324346138344083323e-01
        FLR::scaled( 0x1378A597C66D8D, -52 + 9),  // +6.230808558942968602e+02
        FLR::scaled( 0x17701AB71C11CD, -52 - 1),  // +7.324346138344083323e-01
        FLR::scaled(-0x11AE6DC2340A8C, -52 + 7),  // -1.414508982674054778e+02
        FLR::scaled( 0x17BADA9507626D, -52 - 1),  // +7.415593062133446489e-01
        FLR::scaled(-0x184CFB228C3780, -52 + 6),  // -9.720282806103750772e+01
        FLR::scaled( 0x17BADA9507626D, -52 - 1),  // +7.415593062133446489e-01
        FLR::scaled(-0x1D7F59FAD29DAC, -52 + 5),  // -5.899493346485118650e+01
        FLR::scaled( 0x17BBCBA5657614, -52 - 1),  // +7.416742544552925587e-01
        FLR::scaled(-0x141F45F2F9F6C2, -52 + 8),  // -3.219545774234976534e+02
        FLR::scaled( 0x17BBCBA5657614, -52 - 1),  // +7.416742544552925587e-01
        FLR::scaled( 0x19CD4CABC9CEEB, -52 + 8),  // +4.128312185176025082e+02
        FLR::scaled( 0x17C840CC06E967, -52 - 1),  // +7.431949601080248824e-01
        FLR::scaled( 0x19B86CCEA50AB4, -52 + 6),  // +1.028816410648094575e+02
        FLR::scaled( 0x17C840CC06E967, -52 - 1),  // +7.431949601080248824e-01
        FLR::scaled(-0x170AC136F686EA, -52 + 6),  // -9.216804288935568934e+01
        FLR::scaled( 0x17C8CA03003C8E, -52 - 1),  // +7.432603891956135467e-01
        FLR::scaled( 0x1573E9A9306A60, -52 + 5),  // +4.290556826461829587e+01
        FLR::scaled( 0x17C8CA03003C8E, -52 - 1),  // +7.432603891956135467e-01
        FLR::scaled( 0x181ADF25F24661, -52 + 8),  // +3.856794795478691071e+02
        FLR::scaled( 0x17C73A0E329575, -52 - 1),  // +7.430696751877535755e-01
        FLR::scaled(-0x10638542780A26, -52 + 7),  // -1.311100170464061989e+02
        FLR::scaled( 0x17C73A0E329575, -52 - 1),  // +7.430696751877535755e-01
        FLR::scaled( 0x18085A676F30A8, -52 + 8),  // +3.845220712989198546e+02
        FLR::scaled( 0x17C84F03B70CCE, -52 - 1),  // +7.432017395552976691e-01
        FLR::scaled(-0x185AA2E4795767, -52 + 5),  // -4.870809608387826728e+01
        FLR::scaled( 0x17C84F03B70CCE, -52 - 1),  // +7.432017395552976691e-01
        FLR::scaled( 0x18D6096D02CA78, -52 + 7),  // +1.986886506132611885e+02
        FLR::scaled( 0x17D4FF326B2BAB, -52 - 1),  // +7.447505936373678415e-01
        FLR::scaled(-0x1B6A4972FC2A2F, -52 + 6),  // -1.096607329809710194e+02
        FLR::scaled( 0x17D4FF326B2BAB, -52 - 1),  // +7.447505936373678415e-01
        FLR::scaled( 0x1F17B8DD7B2EF8, -52 + 7),  // +2.487413165479590589e+02
        FLR::scaled( 0x17D5A21FEC641C, -52 - 1),  // +7.448282836440998089e-01
        FLR::scaled( 0x137A547B693DDB, -52 + 8),  // +3.116456255064965148e+02
        FLR::scaled( 0x17D5A21FEC641C, -52 - 1),  // +7.448282836440998089e-01
        FLR::scaled( 0x141575F3DFC658, -52 + 9),  // +6.426825940592198094e+02
        FLR::scaled( 0x17D8F246E15896, -52 - 1),  // +7.452327141170538294e-01
        FLR::scaled(-0x1466CE376AB910, -52 + 4),  // -2.040158411365069924e+01
        FLR::scaled( 0x17D8F246E15896, -52 - 1),  // +7.452327141170538294e-01
        FLR::scaled( 0x12849AB0DA8C91, -52 + 7),  // +1.481438831585442415e+02
        FLR::scaled( 0x17D9600C43731F, -52 - 1),  // +7.452850570221903892e-01
        FLR::scaled( 0x19A063C3E4088D, -52 + 3),  // +1.281326114805804117e+01
        FLR::scaled( 0x17D9600C43731F, -52 - 1),  // +7.452850570221903892e-01
        FLR::scaled( 0x196BDFE482FA8F, -52 + 9),  // +8.134843225701059737e+02
        FLR::scaled( 0x17E6DA41C3EF98, -52 - 1),  // +7.469302448730443800e-01
        FLR::scaled( 0x102D89DD9CFE52, -52 + 8),  // +2.588461586124950600e+02
        FLR::scaled( 0x17E6DA41C3EF98, -52 - 1),  // +7.469302448730443800e-01
        FLR::scaled( 0x1894A89ECE8664, -52 + 5),  // +4.916139588436342933e+01
        FLR::scaled( 0x17E7049A21A1EE, -52 - 1),  // +7.469504366281947139e-01
        FLR::scaled(-0x104CE1F75F84AA, -52 + 4),  // -1.630032297212589043e+01
        FLR::scaled( 0x17E7049A21A1EE, -52 - 1),  // +7.469504366281947139e-01
        FLR::scaled( 0x1D390D75A588E3, -52 + 8),  // +4.675657860246848827e+02
        FLR::scaled( 0x17E36D6CAB5272, -52 - 1),  // +7.465121385999522463e-01
        FLR::scaled( 0x1097AF412E6B53, -52 + 8),  // +2.654802867711306931e+02
        FLR::scaled( 0x17E36D6CAB5272, -52 - 1),  // +7.465121385999522463e-01
        FLR::scaled( 0x13A0E0C0FD5352, -52 + 8),  // +3.140548715491796656e+02
        FLR::scaled( 0x17E3FEA841745F, -52 - 1),  // +7.465813909763133749e-01
        FLR::scaled(-0x1E7E7E9768E57F, -52 + 4),  // -3.049411913214634851e+01
        FLR::scaled( 0x17E3FEA841745F, -52 - 1),  // +7.465813909763133749e-01
        FLR::scaled( 0x13C666C909C169, -52 + 7),  // +1.582000470343148493e+02
        FLR::scaled( 0x17F18FBFAE90F6, -52 - 1),  // +7.482374900614832125e-01
        FLR::scaled( 0x133BB27483DCEF, -52 + 7),  // +1.538655340743493696e+02
        FLR::scaled( 0x17F18FBFAE90F6, -52 - 1),  // +7.482374900614832125e-01
        FLR::scaled(-0x13EBB04FAE74EC, -52 + 7),  // -1.593652723700864726e+02
        FLR::scaled( 0x17F1D0DA0E6EB6, -52 - 1),  // +7.482685336030587830e-01
        FLR::scaled( 0x17739EDB13EB05, -52 + 8),  // +3.752262831476257929e+02
        FLR::scaled( 0x17F1D0DA0E6EB6, -52 - 1),  // +7.482685336030587830e-01
        FLR::scaled( 0x14B6F1A12EE8B7, -52 + 7),  // +1.657169958034698709e+02
        FLR::scaled( 0x1791EF651D8958, -52 - 1),  // +7.365643477353769342e-01
        FLR::scaled(-0x1C9AA0098E72B9, -52 + 7),  // -2.288320358068647522e+02
        FLR::scaled( 0x1791EF651D8958, -52 - 1),  // +7.365643477353769342e-01
        FLR::scaled( 0x17722345688A1D, -52 + 7),  // +1.875668055574214179e+02
        FLR::scaled( 0x17922C836B786D, -52 - 1),  // +7.365934912484256580e-01
        FLR::scaled(-0x15D5AC574B5AA7, -52 + 6),  // -8.733864385947036624e+01
        FLR::scaled( 0x17922C836B786D, -52 - 1),  // +7.365934912484256580e-01
        FLR::scaled( 0x13F7DC3FA91ED0, -52 + 8),  // +3.194912716490043749e+02
        FLR::scaled( 0x17B08BEAF974FB, -52 - 1),  // +7.403010930389933852e-01
        FLR::scaled(-0x1885F6C9A2287B, -52 + 6),  // -9.809318772159342359e+01
        FLR::scaled( 0x17B08BEAF974FB, -52 - 1),  // +7.403010930389933852e-01
        FLR::scaled( 0x163D9D243D42B3, -52 + 4),  // +2.224067903991335626e+01
        FLR::scaled( 0x17B09C8B8DA546, -52 - 1),  // +7.403090215349628078e-01
        FLR::scaled( 0x13052EE70CC8C7, -52 + 8),  // +3.043239508151422683e+02
        FLR::scaled( 0x17B09C8B8DA546, -52 - 1),  // +7.403090215349628078e-01
        FLR::scaled( 0x141F199491E476, -52 + 8),  // +3.219437452029154656e+02
        FLR::scaled( 0x179A5206E9EDD1, -52 - 1),  // +7.375879416499008245e-01
        FLR::scaled(-0x117985D064F972, -52 + 7),  // -1.397975847217708747e+02
        FLR::scaled( 0x179A5206E9EDD1, -52 - 1),  // +7.375879416499008245e-01
        FLR::scaled( 0x160B8B021A2DFE, -52 + 9),  // +7.054428751035009100e+02
        FLR::scaled( 0x179AAB3063275D, -52 - 1),  // +7.376304574074584730e-01
        FLR::scaled( 0x109BC8C37D129C, -52 + 8),  // +2.657365145574237886e+02
        FLR::scaled( 0x179AAB3063275D, -52 - 1),  // +7.376304574074584730e-01
        FLR::scaled( 0x1F5DE9579A1F66, -52 + 8),  // +5.018694683094421407e+02
        FLR::scaled( 0x17BA30780C4465, -52 - 1),  // +7.414781899152670386e-01
        FLR::scaled(-0x1C4292AFA47978, -52 + 4),  // -2.826005075231066144e+01
        FLR::scaled( 0x17BA30780C4465, -52 - 1),  // +7.414781899152670386e-01
        FLR::scaled( 0x14118553C5FD6C, -52 + 6),  // +8.027376264891580604e+01
        FLR::scaled( 0x17BA545E7022C3, -52 - 1),  // +7.414953083508283305e-01
        FLR::scaled( 0x17BD30AEABF3EB, -52 + 8),  // +3.798243853299051693e+02
        FLR::scaled( 0x17BA545E7022C3, -52 - 1),  // +7.414953083508283305e-01
        FLR::scaled( 0x17299A314ADC5D, -52 + 7),  // +1.853000723325848469e+02
        FLR::scaled( 0x17BC38A42A96B0, -52 - 1),  // +7.417262274145368650e-01
        FLR::scaled( 0x1E5AA8A6C65EF1, -52 + 7),  // +2.428330873369627909e+02
        FLR::scaled( 0x17BC38A42A96B0, -52 - 1),  // +7.417262274145368650e-01
        FLR::scaled( 0x14C17F6FD59E52, -52 + 8),  // +3.320936125130148184e+02
        FLR::scaled( 0x17BC38C2C2A7DE, -52 - 1),  // +7.417262844003251754e-01
        FLR::scaled( 0x1D4C45ED34BDFD, -52 + 6),  // +1.171917679801044443e+02
        FLR::scaled( 0x17BC38C2C2A7DE, -52 - 1),  // +7.417262844003251754e-01
        FLR::scaled( 0x16EE0062CA1169, -52 + 8),  // +3.668750942128449992e+02
        FLR::scaled( 0x17DBEE76B41709, -52 - 1),  // +7.455971067836070221e-01
        FLR::scaled( 0x1577AF3DF01EA0, -52 + 3),  // +1.073375886493823828e+01
        FLR::scaled( 0x17DBEE76B41709, -52 - 1),  // +7.455971067836070221e-01
        FLR::scaled(-0x18C54E961E24DC, -52 + 6),  // -9.908292153304813610e+01
        FLR::scaled( 0x17DBFADEA46DC2, -52 - 1),  // +7.456030224306504639e-01
        FLR::scaled( 0x13A5BE5F8E7170, -52 + 8),  // +3.143589778484520139e+02
        FLR::scaled( 0x17DBFADEA46DC2, -52 - 1),  // +7.456030224306504639e-01
        FLR::scaled( 0x17D02A5A602640, -52 + 8),  // +3.810103400951229560e+02
        FLR::scaled( 0x17C32CA32EE994, -52 - 1),  // +7.425749957249530020e-01
        FLR::scaled( 0x1327EBFE8D8968, -52 + 5),  // +3.831188947592710292e+01
        FLR::scaled( 0x17C32CA32EE994, -52 - 1),  // +7.425749957249530020e-01
        FLR::scaled( 0x179DC3658522EB, -52 + 8),  // +3.778602042389526900e+02
        FLR::scaled( 0x17C330A6FC45A6, -52 - 1),  // +7.425769101557093688e-01
        FLR::scaled( 0x161E4A3BC905BC, -52 + 8),  // +3.538931234219014641e+02
        FLR::scaled( 0x17C330A6FC45A6, -52 - 1),  // +7.425769101557093688e-01
        FLR::scaled(-0x11FA4979E9DA08, -52 + 6),  // -7.191073463284567424e+01
        FLR::scaled( 0x17E3DDE19F9D22, -52 - 1),  // +7.465657622059647114e-01
        FLR::scaled(-0x124213F650581C, -52 + 8),  // -2.921298735750622200e+02
        FLR::scaled( 0x17E3DDE19F9D22, -52 - 1),  // +7.465657622059647114e-01
        FLR::scaled(-0x13E68A9EBC352C, -52 + 7),  // -1.592044213939601605e+02
        FLR::scaled( 0x17E3E044D1D001, -52 - 1),  // +7.465669006473946157e-01
        FLR::scaled( 0x1468E1776AC6AB, -52 + 8),  // +3.265550455256404234e+02
        FLR::scaled( 0x17E3E044D1D001, -52 - 1),  // +7.465669006473946157e-01
        FLR::scaled( 0x17C881CDB6A263, -52 + 5),  // +4.756646129052821692e+01
        FLR::scaled( 0x1820DD2D2A6B4F, -52 - 1),  // +7.540117151396347195e-01
        FLR::scaled(-0x12FC2617F941D4, -52 + 3),  // -9.492478131462952717e+00
        FLR::scaled( 0x1820DD2D2A6B4F, -52 - 1),  // +7.540117151396347195e-01
        FLR::scaled( 0x182450369249FA, -52 + 4),  // +2.414184895583637314e+01
        FLR::scaled( 0x18232D8252FA6C, -52 - 1),  // +7.542941613572344828e-01
        FLR::scaled( 0x164A1CE9820417, -52 + 5),  // +4.457900732849537206e+01
        FLR::scaled( 0x18232D8252FA6C, -52 - 1),  // +7.542941613572344828e-01
        FLR::scaled( 0x1B46ECF868DAE3, -52 + 8),  // +4.364328540893458808e+02
        FLR::scaled( 0x1833205E9E28E6, -52 - 1),  // +7.562410209659702343e-01
        FLR::scaled( 0x1D4D8F32EE7AF9, -52 + 8),  // +4.688474606814993990e+02
        FLR::scaled( 0x1833205E9E28E6, -52 - 1),  // +7.562410209659702343e-01
        FLR::scaled( 0x1820295EDC90D5, -52 + 6),  // +9.650252505817054782e+01
        FLR::scaled( 0x1834A6EE76F478, -52 - 1),  // +7.564272553933184540e-01
        FLR::scaled( 0x1C8964F964CD7A, -52 + 6),  // +1.141467879757309731e+02
        FLR::scaled( 0x1834A6EE76F478, -52 - 1),  // +7.564272553933184540e-01
        FLR::scaled( 0x1D6E5F6073B546, -52 + 7),  // +2.354491426715778175e+02
        FLR::scaled( 0x182C9A7F4EFE0A, -52 - 1),  // +7.554447638030421519e-01
        FLR::scaled( 0x16A07E040F25F0, -52 + 7),  // +1.810153827949393417e+02
        FLR::scaled( 0x182C9A7F4EFE0A, -52 - 1),  // +7.554447638030421519e-01
        FLR::scaled( 0x1231DAD414FFC3, -52 + 8),  // +2.911159249134327069e+02
        FLR::scaled( 0x182F398FF69190, -52 - 1),  // +7.557647525577966263e-01
        FLR::scaled( 0x15E9A0FCAA5009, -52 + 6),  // +8.765045086509793748e+01
        FLR::scaled( 0x182F398FF69190, -52 - 1),  // +7.557647525577966263e-01
        FLR::scaled( 0x17EE12FC0DC7BD, -52 + 7),  // +1.914398174542565414e+02
        FLR::scaled( 0x183F5C86A55FEE, -52 - 1),  // +7.577345495037641765e-01
        FLR::scaled( 0x1105D77BBC6995, -52 + 7),  // +1.361825541191034574e+02
        FLR::scaled( 0x183F5C86A55FEE, -52 - 1),  // +7.577345495037641765e-01
        FLR::scaled( 0x1C2A3F6192DF2F, -52 + 8),  // +4.506404739129238237e+02
        FLR::scaled( 0x184128A1A81D2D, -52 - 1),  // +7.579539449078872559e-01
        FLR::scaled( 0x1C34A8CED65214, -52 + 8),  // +4.512912128803156975e+02
        FLR::scaled( 0x184128A1A81D2D, -52 - 1),  // +7.579539449078872559e-01
        FLR::scaled( 0x109091A6660643, -52 + 8),  // +2.650355590806322539e+02
        FLR::scaled( 0x18460A040EEE15, -52 - 1),  // +7.585496978057927331e-01
        FLR::scaled(-0x11DC77EB31A63F, -52 + 7),  // -1.428896385163988896e+02
        FLR::scaled( 0x18460A040EEE15, -52 - 1),  // +7.585496978057927331e-01
        FLR::scaled( 0x11CADC3D1AA6C5, -52 + 8),  // +2.846787692109176646e+02
        FLR::scaled( 0x1847314299331D, -52 - 1),  // +7.586904812575060442e-01
        FLR::scaled( 0x118F626AD99BD9, -52 + 7),  // +1.404807638406917079e+02
        FLR::scaled( 0x1847314299331D, -52 - 1),  // +7.586904812575060442e-01
        FLR::scaled( 0x188E68333B9072, -52 + 8),  // +3.929004394842842203e+02
        FLR::scaled( 0x1859E076233EF2, -52 - 1),  // +7.609712893845126391e-01
        FLR::scaled( 0x11DF52224ABDC8, -52 + 8),  // +2.859575522346099206e+02
        FLR::scaled( 0x1859E076233EF2, -52 - 1),  // +7.609712893845126391e-01
        FLR::scaled( 0x13B5BAA481D20F, -52 + 8),  // +3.153580670424570940e+02
        FLR::scaled( 0x185A7638C5C0DE, -52 - 1),  // +7.610427006566415908e-01
        FLR::scaled( 0x1F190B7E88CD97, -52 + 8),  // +4.975653062194700738e+02
        FLR::scaled( 0x185A7638C5C0DE, -52 - 1),  // +7.610427006566415908e-01
        FLR::scaled( 0x1532CDA508660C, -52 + 8),  // +3.391752062156745069e+02
        FLR::scaled( 0x184F64A4BC6847, -52 - 1),  // +7.596915452479685582e-01
        FLR::scaled(-0x11902B2C574BCE, -52 + 6),  // -7.025263508343707031e+01
        FLR::scaled( 0x184F64A4BC6847, -52 - 1),  // +7.596915452479685582e-01
        FLR::scaled( 0x1A678C0BC9B442, -52 + 7),  // +2.112358454646619634e+02
        FLR::scaled( 0x1850CF54BB1914, -52 - 1),  // +7.598644881152574193e-01
        FLR::scaled(-0x1648AA03262DE6, -52 + 8),  // -3.565415069095018907e+02
        FLR::scaled( 0x1850CF54BB1914, -52 - 1),  // +7.598644881152574193e-01
        FLR::scaled(-0x118E445B3E2ECB, -52 + 5),  // -3.511146107231396485e+01
        FLR::scaled( 0x186390C132B10C, -52 - 1),  // +7.621539853476249071e-01
        FLR::scaled( 0x1E05B532EA5180, -52 + 6),  // +1.200891845024361828e+02
        FLR::scaled( 0x186390C132B10C, -52 - 1),  // +7.621539853476249071e-01
        FLR::scaled( 0x10B844C7AACB7E, -52 + 6),  // +6.687919799498737916e+01
        FLR::scaled( 0x18645C19AAC49F, -52 - 1),  // +7.622509480771845203e-01
        FLR::scaled( 0x13A5A77569DD5B, -52 + 9),  // +6.287067669172932938e+02
        FLR::scaled( 0x18645C19AAC49F, -52 - 1),  // +7.622509480771845203e-01
    ];

    const KAT512_OUT: [i32; 1024] = [
         -92,   -8,  -20,  -12,    8,  -30,  -10,  -41,  -61,  -46,  -34,  -44,
         -23,  -40,  -22,  -50, -102,  -58,    8,   -7,  -14,  -14,   13,  -64,
         -19,    4,    8,  -40,   -4,  -13,   11,  -94,  -36,  -15,  -36,  -90,
         -49,  -17,  -19,  -74,  -22,  -35,   -3,  -85,  -79,  -45,  -38,   -4,
         -67,  -33,   -3,   -1,  -38,  -14,    8,  -48,   28,  -30,    4,  -26,
         -59,  -93,   -5,  -14,  -72,   10,  -20,    0,  -27,  -54,   28,  -84,
          -3,   -2,   19,  -16,  -47,  -38,  -27,  -56,  -80,    0,  -15,  -18,
         -90,  -33,  -30,  -71,   34,   32,    2,   -8,  -68,  -43,   -1,  -41,
         -61,  -58,   10,  -21,  -33,  -56,  -57,  -69,  -15,  -45,   -2,  -19,
         -75,  -42,  -18,  -16,  -30,   33,  -53,  -23,  -18,  -28,   -4,  -31,
          36,  -12,  -53,  -35,  -11,  -60,  -14,  -53,  -54,  -51,  -71,  -18,
           4,    1,   30,  -51,  -68,  -28,  -85,  -42,  -38,  -45,  -38,  -48,
         -14,  -14,  -45,  -24,   40,  -25,   37, -110,  -28,  -72,  -14,  -41,
         -60,  -18,  -35,    8,  -30,   15,  -19,  -48,   -2,  -51,   33,   -8,
         -33,  -54,  -43,    0,   19,  -43,  -55,  -41,  -77,   -8,  -67,   -1,
         -66,  -30,  -17,  -25,  -16,   19,  -14,  -26,    8,  -27,  -14,  -47,
         -68,  -29,  -20,  -37,  -14,    8,  -25,  -61,  -31,  -25,  -36,  -11,
         -59,  -33,  -41,  -41,  -46,  -31,  -70,   15,  -12,   11,   -9,  -39,
           2,  -34,   -3,  -71,  -80,  -31,   11,  -64,  -38,    5,   13,  -43,
          12,   14,   16,  -57,  -25,  -24,  -36,  -10,  -50,  -84,    8,  -45,
         -38,   -4,  -61,  -53,  -43,  -44,  -13,  -17,    7,    5,    9,   16,
         -16, -114,   28,  -73,  -60,   22,  -32,  -46,   -2,   -7,  -18,  -53,
         -41,   11,   -1,  -75,  -22,  -35,  -17,  -66,  -86,   -9,   14,   23,
         -77,  -70,  -45,  -15,   13,  -17,  -31,  -55,  -50,  -76,  -37,  -43,
         -30,  -43,   24,  -32,  -38,    6,  -14,  -65,  -54,  -31,  -72,    5,
        -123,  -17,   -3,  -14,  -29,   17,  -46,  -61,  -76,  -65,   -3,   -7,
           0,  -25,  -36,   -7,  -25,  -14,   26,  -39,  -89,   21,   16,  -25,
         -22,  -56,   43,  -21,   -5,  -11,  -66,  -71,  -21,  -15,   -6,  -44,
         -72,   11,  -72,   16,  -36,  -48,   52,  -91,    0,  -63,   30,  -37,
         -48,  -18,   14,  -86, -107,  -11,  -65,  -23,   -6,  -53,  -57,  -39,
          13,  -41,  -60,   15,  -33,  -30,  -15,  -47,  -77,  -86,  -31,  -38,
          29,  -43,   -2,  -20,   74,  -50,    1,  -34,  -36,  -52,   13,  -65,
         -40,  -27,   -8,  -28,   26,  -47,  -21,  -69,  -15,  -54,  -37,   -6,
           3,  -34,   12,  -37,  -60,  -39,  -52,  -13,    5,  -44,   15,  -64,
          13,  -33,  -43,    0,  -74,   -4,  -34,  -85,  -79,  -46,   31,    0,
           1,    6,   16,  -68,   -7,  -19,   13,  -90,  -48,  -37,  -44,  -13,
         -23,   32,  -15,  -28,  -73,  -73,  -54,  -38,    9,   -3,   -3,  -11,
          -1,  -57,   19,   -9,  -48,  -36,  -29,    8,   15,  -32,  -44,  -91,
         -29,  -13,  -62,  -37,   12,   -4,  -40,  -10,  -51,  -77,  -44,   -2,
         -13,  -19,  -42,  -84,    8,  -53,  -54,  -54,  -13,  -68,  -15,  -39,
         -90,    3,  -31,  -27,    3,  -56,    0,  -37,  -18,  -19,  -34,    8,
         -58,  -43,   15,  -66,  -13,  -23,  -46,  -12,  -22,  -55,  -34,   13,
          -3,  -47,  -10,  -38,  -32,  -70,    6,  -58,  258,  -69,   81, -128,
         572, -349,   66,  340,  108, -229,  632,  226,  600,  -20,  431,  461,
         124,   36,  101,   43,  192,  156, -163,   45,  417, -226,   64,  210,
         290,   96,  210,  532,  355,  259,   89,  -82,  526, -163,  -32,  506,
         453, -100,   84,   67,  387, -245,  217,  294,   50,  191,  376,   13,
         335,  -44,  -98,  234,  423,   78,  482,   21,  286, -149,  426,  287,
         229,   37,    4,  -66,  125, -184,   26,  501,  115,   44,  275, -187,
         251,  114,  343,  605, -315,  197,  619, -199,  295,  213,  -26,  481,
         194, -215,  254,  144,  469,  178,  441,  731,  286, -122,  157,    6,
         281,  133, -480,   33,  381, -105,  198,  -90,  130,   71,  246,  109,
          45,  -87,  238,  129,  618,   99,  161,  265,  657,  126,  173, -245,
         433,  160,   25,  160,  197, -162,  277, -159,  502,   92,  283,  158,
         496,  305,  210,  191,  141,  419,  411,  487,  245, -113,   70, -265,
         646,  466,  187,  444,  157,  -77,  118,  -94,  121, -135,  343,  142,
         -52,  -92,  349,   94,  413, -179,  163,  357, -136, -195,  574,  458,
         443,  -82, -160,  221,  -56, -130,  567,  348,  490,  -75,  216,  348,
          74, -264,  109,  596,  255, -269,  158,   48,  301,   77,  300, -115,
         318, -129,  279,  198,  287,  292,  328,  550,  437,   54,  255,  114,
         121,   75,  366,  228,  335,  -21,  -50,  401,   -5, -320,  -85,  184,
         440, -319,   60,  115,  555,  -53,  485,  154,  302,  241,  -15,  -60,
         245, -328,  247,   59,  224,  123,  433,  315,  382,  225,  176,  315,
         227,  146,   71,  178,  -40,  -78, -218,   37,  -32,  -16,  335,  280,
         463, -148,  162, -148,  322,   35,  251,  103,  201,  241,  497, -156,
         430, -232,  129,  232,  226,  601,   81,  -79,  376,  132,  341,  161,
         229,   63,  328,  -53,  249,  -13,  471,  371,   23,   71,  442,  -63,
         773,   -8, -152,  492,  270,   96,  -79,  177,  519,  -63,  243,   36,
         112, -317,   94,  281,  146,   22,  389,  260,  309, -563,  328,  269,
         366,  -93,  513,  -30,  245,   76,  292, -225,  524,  259,  196,  171,
         150,  133,  287,   21,  197,   62,  -94,  177,  351,  256,  571,  142,
         360,  258, -197,  486,  414,   92,  481,  126,  458,  -73,  438,  360,
         522,  266,  530,  -74,  242,   93,  157,  464,  312, -226,  244, -208,
         225,  -43,  315,  428,  131,    1,  464,   64,  107,  439,  -69,  369,
         335, -346,    2,  -26,   75,   -5,  111,  158,  346, -304,  135, -336,
         148, -180, -415,  424,  -45,    1,  505,  396,  431,  -97,  119,  708,
        -136, -373,  404,  100,  459, -150,   37,  369,   80,  103,  -30,  219,
         314, -367,  154,  625, -142,  -97,  -59, -320,  412,  102,  -90,   43,
         387, -131,  384,  -49,  197, -111,  248,  314,  644,  -19,  149,   11,
         813,  258,   50,  -19,  468,  265,  315,  -32,  158,  152, -159,  374,
         167, -229,  189,  -86,  320,  -97,   22,  303,  322, -138,  705,  267,
         503,  -27,   81,  381,  186,  242,  333,  117,  367,   10,  -98,  313,
         383,   40,  379,  355,  -72, -291, -160,  326,   47,  -10,   22,   44,
         437,  469,   97,  114,  234,  177,  290,   85,  190,  137,  449,  451,
         263, -142,  284,  141,  393,  286,  316,  500,  340,  -72,  210, -355,
         -36,  119,   65,  629,
    ];

    #[test]
    fn sampler2() {
        if fn_dsa_comm::has_avx2() {
            unsafe {
                let rndb = hex::decode(KAT512_RND).unwrap();
                let mut samp = Sampler::<NotARealRNG>::new(9, &rndb);
                for i in 0..1024 {
                    let mu = KAT512_MU_INVSIGMA[2 * i + 0];
                    let isigma = KAT512_MU_INVSIGMA[2 * i + 1];
                    assert!(KAT512_OUT[i] == samp.next(mu, isigma));
                }
                assert!(samp.rng.ptr == samp.rng.len);
            }
        }
    }
}
