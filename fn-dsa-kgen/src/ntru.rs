#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use super::fxp::*;
use super::mp31::*;
use super::poly::*;
use super::vect::*;
use super::zint31::*;

// ======================================================================== 
// Solving the NTRU equation
// ======================================================================== 

// Check that (f,g) has an acceptable orthogonalized norm.
// If this function returns false, then the (f,g) pair should be
// rejected.
// tmp min size: 2.5*n
pub(crate) fn check_ortho_norm(
    logn: u32, f: &[i8], g: &[i8], tmp: &mut [FXR]) -> bool
{
    let n = 1usize << logn;
    let (fx, tmp) = tmp.split_at_mut(n);
    let (gx, rt3) = tmp.split_at_mut(n);
    vect_to_fxr(logn, fx, f);
    vect_to_fxr(logn, gx, g);
    vect_FFT(logn, fx);
    vect_FFT(logn, gx);
    vect_invnorm_fft(logn, rt3, fx, gx, 0);
    vect_adj_fft(logn, fx);
    vect_adj_fft(logn, gx);
    vect_mul_realconst(logn, fx, FXR::from_i32(Q as i32));
    vect_mul_realconst(logn, gx, FXR::from_i32(Q as i32));
    vect_mul_selfadj_fft(logn, fx, rt3);
    vect_mul_selfadj_fft(logn, gx, rt3);
    vect_iFFT(logn, fx);
    vect_iFFT(logn, gx);
    let mut sn = FXR::ZERO;
    for i in 0..n {
        sn += fx[i].sqr() + gx[i].sqr();
    }
    // Constant is (0.999*1.17*sqrt(q))^2, scaled up by 2^32 for the
    // fixed-point representation.
    sn < FXR::from_u64_scaled32(72107278641426)
}

const Q: u32 = 12289;

// At recursion depth d, with:
//   slen = MOD_SMALL_BL[d]
//   llen = MOD_LARGE_BL[d]
//   tlen = MOD_SMALL_BL[d + 1]
// then:
//   (f, g) at this level use slen words for each coefficient
//   (F', G') from deeper level use tlen words for each coefficient
//   unreduced (F, G) at this level use llen words for each coefficient
//   output (F, G) use slen words for each coefficient
const MOD_SMALL_BL: [usize; 11] = [ 1, 1, 2, 3,  4,  8, 14, 27,  53, 104, 207 ];
const MOD_LARGE_BL: [usize; 10] = [ 1, 2, 3, 6, 11, 21, 40, 78, 155, 308 ];

// Minimum depth for which intermediate (f,g) values are saved.
const MIN_SAVE_FG: [u32; 11] = [ 0, 0, 1, 2, 2, 2, 2, 2, 3, 3, 4 ];

// When log(n) >= MIN_LOGN_FGNTT, we use the NTT to subtract (k*f,k*g)
// from (F,G) during the reduction.
const MIN_LOGN_FGNTT: u32 = 4;

// Number of top words to consider during reduction.
const WORD_WIN: [usize; 10] = [ 1, 1, 2, 2, 2, 3, 3, 4, 5, 7 ];

// Number of bits gained per each round of reduction.
const REDUCE_BITS: [u32; 11] = [ 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 8 ];

// Given polynomials f and g (modulo X^n+1 with n = 2^logn), find
// polynomials F and G such that:
//    -127 <= F[i], G[i] <= +127   for all i in [0, n-1]
//    f*G - g*F = q  mod X^n+1     (with q = 12289)
// Returned value is true on success, false on error. If the function does
// not succeed, then the contents of F and G are not modified.
// All four slices f, g, F and G must have length exactly 2^logn.
// tmp_u32 min size: 5*n
// tmp_fxr min size: 2*n
pub(crate) fn solve_NTRU(logn: u32,
    f: &[i8], g: &[i8], F: &mut [i8], G: &mut [i8],
    tmp_u32: &mut [u32], tmp_fxr: &mut [FXR]) -> bool
{
    assert!(1 <= logn && logn <= 10);
    let n = 1usize << logn;
    assert!(f.len() == n && g.len() == n);
    assert!(F.len() == n && G.len() == n);

    if !solve_NTRU_deepest(logn, f, g, tmp_u32) {
        return false;
    }
    for depth in (1..logn).rev() {
        if !solve_NTRU_intermediate(logn, f, g, depth, tmp_u32, tmp_fxr) {
            return false;
        }
    }
    if !solve_NTRU_depth0(logn, f, g, tmp_u32, tmp_fxr) {
        return false;
    }

    // Solution is in the first 2*n slots of tmp_u32.
    // We must check that all coefficients are in [-127,+127].
    for i in 0..(2 * n) {
        let z = tmp_u32[i] as i32;
        if z < -127 || z > 127 {
            return false;
        }
    }

    // Success! Return the result.
    for i in 0..n {
        F[i] = (tmp_u32[i] as i32) as i8;
        G[i] = (tmp_u32[i + n] as i32) as i8;
    }
    return true;
}

// Solving the NTRU equation, deepest level.
// This computes the integers F and G such that:
//   Res(f,X^n+1)*G - Res(g,X^n+1)*F = q
// The two integers are written into tmp[], over MOD_SMALL_BL[logn]
// words each.
fn solve_NTRU_deepest(logn: u32,
    f: &[i8], g: &[i8], tmp: &mut [u32]) -> bool
{
    let slen = MOD_SMALL_BL[logn as usize];

    // Get (f,g) at the deepest level. Obtained (f,g) are in RNS+NTT;
    // since degree is 1 at the deepest level, then NTT is a no-op and
    // we have (f,g) in RNS.
    make_fg_deepest(logn, f, g, tmp);

    // Reorganize work area:
    //   Fp   output F (slen)
    //   Gp   output G (slen)
    //   fp   Res(f, X^n+1) (slen)
    //   gp   Res(g, X^n+1) (slen)
    //   t1   rest of temporary
    tmp.copy_within(0..(2 * slen), 2 * slen);
    let (Fp, tmp) = tmp.split_at_mut(slen);
    let (Gp, tmp) = tmp.split_at_mut(slen);
    let (fgp, t1) = tmp.split_at_mut(2 * slen);

    // Convert the resultants into plain integers. The resultants are always
    // non-negative, hence we do not normalize to signed.
    zint_rebuild_CRT(fgp, slen, 1, 2, false, t1);
    let (fp, gp) = fgp.split_at_mut(slen);

    // Apply the binary GCD to get (F, G).
    if zint_bezout(Gp, Fp, fp, gp, t1) != 0xFFFFFFFF {
        // Resultants are not coprime to each other; we reject that case
        // (note: we also reject the case where the GCD is exactly q = 12289,
        // even though that case could be handled.
        return false;
    }

    // Multiply the obtained (F,G) by q to get a solution f*G - g*F = q.
    // We only multiply F since G is dropped.
    if zint_mul_small(Fp, Q) != 0 {
        // If the multiplication overflows, we reject.
        return false;
    }

    true
}

// Solving the NTRU equation, intermediate level.
fn solve_NTRU_intermediate(logn_top: u32,
    f: &[i8], g: &[i8], depth: u32,
    tmp_u32: &mut [u32], tmp_fxr: &mut [FXR]) -> bool
{
    let logn = logn_top - depth;
    let n = 1usize << logn;
    let hn = n >> 1;

    // slen   size for (f,g) at this level (and also output (F,G))
    // llen   size for unreduced F at this level
    // tlen   size for F from the deeper level
    // Note: we always have llen >= tlen
    let slen = MOD_SMALL_BL[depth as usize];
    let llen = MOD_LARGE_BL[depth as usize];
    let tlen = MOD_SMALL_BL[(depth + 1) as usize];

    // Input layout:
    //   Fd   F from deeper level (tlen * hn)
    // Fd is in plain representation.

    // Get (f,g) for this level.
    let min_sav = MIN_SAVE_FG[logn_top as usize];
    if depth < min_sav {
        // (f,g) were not saved previously, recompute them.
        make_fg_intermediate(logn_top, f, g, depth,
            &mut tmp_u32[(tlen * hn)..]);
    } else {
        // (f,g) were saved previously, get them.
        let mut sav_off = tmp_u32.len();
        for d in min_sav..(depth + 1) {
            sav_off -= MOD_SMALL_BL[d as usize] << (logn_top + 1 - d);
        }
        tmp_u32.copy_within(sav_off..(sav_off + 2 * slen * n), tlen * hn);
    }

    // Current layout:
    //   Fd   F from deeper level (tlen * hn)
    //   ft   f from this level (slen * n)
    //   gt   g from this level (slen * n)
    // We now move things to this layout:
    //   Ft   F from this level (unreduced) (llen * n)
    //   ft   f from this level (slen * n) (RNS+NTT)
    //   gt   g from this level (slen * n) (RNS+NTT)
    //   Fd   F from deeper level (tlen * hn) (plain)
    tmp_u32.copy_within(0..(tlen * hn), (llen + 2 * slen) * n);
    tmp_u32.copy_within(
        (tlen * hn)..(tlen * hn + 2 * slen * n), llen * n);

    // Convert Fd to RNS, with output temporarily stored in Ft.
    // Fd has degree hn only; we store the values for each modulus p
    // in the _last_ hn slots of the n-word line for that modulus.
    {
        let (Ft, work) = tmp_u32[..].split_at_mut(llen * n);
        let (_, work) = work.split_at_mut(2 * slen * n);  // ft and gt
        let (Fd, _) = work.split_at_mut(tlen * hn);
        for i in 0..llen {
            let p = PRIMES[i].p;
            let p0i = PRIMES[i].p0i;
            let R2 = PRIMES[i].R2;
            let Rx = mp_Rx31(tlen as u32, p, p0i, R2);
            let kt = i * n + hn;
            for j in 0..hn {
                Ft[kt + j] = zint_mod_small_signed(
                    &Fd[j..], tlen, hn, p, p0i, R2, Rx);
            }
        }
    }

    // Fd is no longer needed.

    // Compute F (unreduced) modulo sufficiently many small primes.
    // We also un-NTT (f,g) as we go; when slen primes have been processed,
    // we have (f,g) in RNS, and we apply the CRT to get (f,g) in plain
    // representation.
    {
        let (Ft, work) = tmp_u32[..].split_at_mut(llen * n);
        let (fgt, work) = work.split_at_mut(2 * slen * n);  // ft and gt
        for i in 0..llen {
            let p = PRIMES[i].p;
            let p0i = PRIMES[i].p0i;
            let R2 = PRIMES[i].R2;

            // Memory layout:
            //   Ft    (n * llen)
            //   ft    (n * slen)
            //   gt    (n * slen)
            //   gm    NTT support (n)
            //   igm   iNTT support (n)
            //   gx    temporary g mod p (NTT) (n)
            {
                let (ft, gt) = fgt.split_at_mut(slen * n);
                let (gm, work) = work.split_at_mut(n);
                let (igm, work) = work.split_at_mut(n);
                let (gx, _) = work.split_at_mut(n);

                mp_mkgmigm(logn, PRIMES[i].g, PRIMES[i].ig, p, p0i, gm, igm);
                if i < slen {
                    gx.copy_from_slice(&gt[(i * n)..((i + 1) * n)]);
                    mp_iNTT(logn, &mut ft[(i * n)..((i + 1) * n)], igm, p, p0i);
                    mp_iNTT(logn, &mut gt[(i * n)..((i + 1) * n)], igm, p, p0i);
                } else {
                    let Rx = mp_Rx31(slen as u32, p, p0i, R2);
                    for j in 0..n {
                        gx[j] = zint_mod_small_signed(
                            &gt[j..], slen, n, p, p0i, R2, Rx);
                    }
                    mp_NTT(logn, gx, gm, p, p0i);
                }

                // We have F in RNS in Ft; we apply the NTT modulo p. Note
                // that we can use gm (generated for degree n) for an NTT
                // with degree hn = n/2.
                let kt = i * n + hn;
                mp_NTT(logn - 1, &mut Ft[kt..(kt + hn)], gm, p, p0i);

                // Compute F (unreduced) modulo p.
                let kt = i * n;
                for j in 0..hn {
                    let ga = gx[2 * j + 0];
                    let gb = gx[2 * j + 1];
                    let mFp = mp_mmul(Ft[kt + hn + j], R2, p, p0i);
                    Ft[kt + 2 * j + 0] = mp_mmul(gb, mFp, p, p0i);
                    Ft[kt + 2 * j + 1] = mp_mmul(ga, mFp, p, p0i);
                }
                mp_iNTT(logn, &mut Ft[kt..(kt + n)], igm, p, p0i);
            }

            if (i + 1) == slen {
                // (f,g) are now in RNS, convert them to plain.
                zint_rebuild_CRT(fgt, slen, n, 2, true, work);
            }
        }

        // Edge case: if slen == llen, then we have not rebuilt f
        // into plain representation yet, so we do it now.
        if slen == llen {
            let (ft, _) = fgt.split_at_mut(slen * n);
            zint_rebuild_CRT(ft, slen, n, 1, true, work);
        }

        // Ft is in RNS, we want it in plain representation.
        zint_rebuild_CRT(Ft, llen, n, 1, true, work);
    }

    // Current memory layout:
    //   Ft   F from this level (unreduced) (llen * n) (plain)
    //   ft   f from this level (slen * n) (plain)

    // We now reduce these F with Babai's nearest plane algorithm.
    // algorithm. The reduction conceptually goes as follows:
    //   k <- round((F*adj(f) + G*adj(g))/(f*adj(f) + g*adj(g)))
    //   (F, G) <- (F - k*f, G - k*g)
    // We only have F; however, G is such that:
    //   f*G - g*F = q
    // hence:
    //   G = (q + g*F)/f
    // which we can move into the expression of k, which simplifies into:
    //   k = round(F/f + q*adj(g)/(f*(f*adj(f) + g*adj(g))))
    // The second part only depends on f and g; moreover, it is
    // heuristically negligible, i.e. we can compute an approximate
    // value of k as:
    //   k = round(F/f)
    // In practice, this approximation is good enough for our purposes,
    // which is to let the algorithm keep going (at the end, a less
    // approximate k is used to finish up the values).
    //
    // We use fixed-point approximations of f and F to get a value k
    // as a small polynomial with scaling; we then apply k on the
    // full-width polynomial. Each iteration "shaves" a few bits off F.
    //
    // We apply the process sufficiently many times to reduce F
    // to the size of f with a reasonable probability of success.
    // Since we want full constant-time processing, the number of
    // iterations and the accessed slots work on some assumptions on
    // the sizes of values (sizes have been measured over many samples,
    // and a margin of 5 times the standard deviation).

    // If depth is at least 2, and we will use the NTT to subtract
    // k*f from F, then we will need to convert f to NTT over slen+1
    // words, which requires an extra word to ft.
    let use_sub_ntt = depth > 1 && logn >= MIN_LOGN_FGNTT;
    let slen_adj = if use_sub_ntt { slen + 1 } else { slen };

    // Current memory layout:
    //   Ft    F from this level (unreduced) (llen * n) (plain)
    //   ft    f from this level (slen_adj * n) (plain)

    // For the reduction, we will consider only the top rlen words
    // of f.
    let rlen = WORD_WIN[depth as usize];
    let blen = slen - rlen;

    // We are going to convert f into fixed-point approximations (into
    // rt3). The values will be scaled down by 2^(scale_fg + scale_x).
    // scale_fg is a public value, but scale_x is set according to the
    // current values of f, and therefore it is secret. scale_x is set
    // such that the largest coefficient is close to, but lower than,
    // some limit t (in absolute value). The limit t is chosen so that
    // f*adj(f) does not overflow, i.e. all coefficients must remain
    // below 2^31.
    //
    // Let n be the degree (n <= 2^10). The squared norm of a polynomial
    // is the sum of the squared norms of the coefficients, with the
    // squared norm of a complex number being the product of that number
    // with its complex conjugate. If all coefficients of f are less
    // than t (in absolute value), then the squared norm of f is less
    // than n*t^2. The squared norm of FFT(f) (f in FFT representation)
    // is exactly n times the squared norm of f, so this leads to
    // n^2*t^2 as a maximum bound. adj(f) has the same norm as f. This
    // implies that each complex coefficient of FFT(f) has a maximum
    // squared norm of n^2*t^2 (with a maximally imbalanced polynomial
    // with all coefficient but one being zero). The computation of
    // f*adj(f) exactly is, in FFT representation, the product of each
    // coefficient with its conjugate; thus, the coefficients of
    // f*adj(f), in FFT representation, are at most n^2*t^2.
    //
    // Since we want the coefficients of f*adj(f) not to exceed 2^31, we
    // need n^2*t^2 <= 2^30, i.e. n*t <= 2^15.5. We can adjust t
    // accordingly (called scale_t in the code below). We also need to
    // take care that t must not exceed scale_x. Approximation of f is
    // extracted with scale scale_fg + scale_x - scale_t, and later
    // fixed by dividing them by 2^scale_t.
    let scale_fg = 31 * (blen as u32);
    let mut scale_FG = 31 * (llen as u32);
    let scale_x;

    {
        let (_, work) = tmp_u32.split_at_mut(n * llen);
        let (ft, _) = work.split_at_mut(n * slen_adj);

        // FXR values:
        //   rt3   n
        //   rt1   n/2
        // TODO: share (rt3,rt1) with space just after ft
        let (rt3, _) = tmp_fxr.split_at_mut(n);

        // scale_x is the maximum bit length of f and g (beyond scale_fg)
        scale_x = poly_max_bitlength(logn, &ft[(n * blen)..], rlen);

        // scale_t is from logn, but not greater than scale_x
        let scale_t = 15 - logn;
        let scale_t = scale_t
            ^ ((scale_t ^ scale_x) & tbmask(scale_x.wrapping_sub(scale_t)));
        let scdiff = scale_x - scale_t;

        // Extract the approximation of f (scaled).
        poly_big_to_fixed(logn, &ft[(n * blen)..], rlen, scdiff, rt3);

        // Compute adj(f)/(f*adj(f)) into rt3 (FFT).
        vect_FFT(logn, rt3);
        vect_inv_mul2e_fft(logn, rt3, scale_t);
    }

    // New layout:
    //   Ft    F from this level (unreduced) (llen * n)
    //   ft    f from this level (slen_adj * n)
    //   k     n
    //   t2    3*n
    //
    //   rt3   n (FXR)
    //   rt1   n (FXR)
    //
    // TODO: merge the FXR space with the u32 space:
    //   rt3 starts right after ft
    //   k,t2 can share the same space as rt1
    {
        let (Ft, work) = tmp_u32.split_at_mut(llen * n);
        let (ft, work) = work.split_at_mut(slen_adj * n);
        let (k, t2) = work.split_at_mut(n);

        let (rt3, work) = tmp_fxr.split_at_mut(n);
        let (rt1, _) = work.split_at_mut(n);

        // Ft, ft and rt3 are already set.
        // If we use poly_sub_scaled_ntt(), then we convert f to NTT.
        if use_sub_ntt {
            let (gm, tn) = t2.split_at_mut(n);
            for i in 0..slen_adj {
                let p = PRIMES[i].p;
                let p0i = PRIMES[i].p0i;
                let R2 = PRIMES[i].R2;
                let Rx = mp_Rx31(slen as u32, p, p0i, R2);
                mp_mkgm(logn, PRIMES[i].g, p, p0i, gm);
                for j in 0..n {
                    tn[(i << logn) + j] = zint_mod_small_signed(
                        &ft[j..], slen, n, p, p0i, R2, Rx);
                }
                mp_NTT(logn, &mut tn[(i << logn)..], gm, p, p0i);
            }
            ft.copy_from_slice(&tn[..(slen_adj * n)]);
        }

        // Reduce F repeatedly.
        // Each iteration is expected to reduce the size of the coefficients
        // by reduce_bits.
        let mut FGlen = llen;
        let reduce_bits = REDUCE_BITS[logn_top as usize];
        loop {
            // Convert F into fixed-point. We want to apply scaling
            // scale_FG + scale_x.
            let (sch, coff) = divrem31(scale_FG);
            let clen = sch as usize;
            poly_big_to_fixed(logn,
                &Ft[(clen * n)..], FGlen - clen, scale_x + coff, rt1);

            // rt1 <- (F*adj(f)) / (f*adj(f))
            vect_FFT(logn, rt1);
            vect_mul_fft(logn, rt1, rt3);
            vect_iFFT(logn, rt1);

            // k <- round(rt1)  (i32 elements, stored in u32 slice)
            for i in 0..n {
                k[i] = rt1[i].round() as u32;
            }

            // f is scaled by scale_fg + scale_x
            // F is scaled by scale_FG + scale_x
            // Thus, k is scaled by scale_FG - scale_fg, which is public.
            let scale_k = scale_FG - scale_fg;

            if depth == 1 {
                poly_sub_kf_scaled_depth1(logn_top,
                    Ft, FGlen, k, scale_k, f, t2);
            } else if use_sub_ntt {
                poly_sub_scaled_ntt(logn, Ft, FGlen, ft, slen, k, scale_k, t2);
            } else {
                poly_sub_scaled(logn, Ft, FGlen, ft, slen, k, scale_k);
            }

            // We now assume that F and G have shrunk by at least
            // reduce_bits.
            if scale_FG <= scale_fg {
                break;
            }
            if scale_FG <= (scale_fg + reduce_bits) {
                scale_FG = scale_fg;
            } else {
                scale_FG -= reduce_bits;
            }
            while FGlen > slen
                && 31 * ((FGlen - slen) as u32) > scale_FG - scale_fg + 30
            {
                // We decrement FGlen; when we do so, we check that it
                // does not damage any of the values, i.e. that the removed
                // words are redundant with the remaining words. In practice,
                // this test reliably catches reduction failures early enough.
                FGlen -= 1;
                let off = (FGlen - 1) << logn;
                for i in 0..n {
                    let sw = (Ft[off + i] >> 30).wrapping_neg() >> 1;
                    if Ft[off + i + n] != sw {
                        return false;
                    }
                }
            }
        }
    }

    // Output F is already in the right place.
    true
}

// Solving the NTRU equation, top-level.
fn solve_NTRU_depth0(logn: u32,
    f: &[i8], g: &[i8], tmp_u32: &mut [u32], tmp_fxr: &mut [FXR]) -> bool
{
    let n = 1usize << logn;
    let hn = n >> 1;

    // Normally, F from depth 1 should use one word per coefficient.
    // The code in this function assumes it.
    assert!(MOD_SMALL_BL[1] == 1);

    // At depth 0, all values fit on 30 bits, so we work with a single
    // modulus p.
    let p = P0.p;
    let p0i = P0.p0i;
    let R2 = P0.R2;

    // Split work area into five n-slot buffers.
    // Fd (from depth 1) is in the first hn slots of t1.
    let (t1, work) = tmp_u32.split_at_mut(n);
    let (t2, work) = work.split_at_mut(n);
    let (t3, work) = work.split_at_mut(n);
    let (t4, work) = work.split_at_mut(n);
    let (t5, _) = work.split_at_mut(n);

    // Convert Fd to RNS+NTT, into t3.
    mp_mkgm(logn, P0.g, p, p0i, t4);
    poly_mp_set(logn - 1, t1, p);
    mp_NTT(logn - 1, t1, t4, p, p0i);
    t3[..hn].copy_from_slice(&t1[..hn]);

    // Compute F (unreduced, RNS+NTT) into t1.
    poly_mp_set_small(logn, g, p, t2);
    mp_NTT(logn, t2, t4, p, p0i);
    for i in 0..hn {
        let ga = t2[(i << 1) + 0];
        let gb = t2[(i << 1) + 1];
        let mF = mp_mmul(t3[i], R2, p, p0i);
        t1[(i << 1) + 0] = mp_mmul(gb, mF, p, p0i);
        t1[(i << 1) + 1] = mp_mmul(ga, mF, p, p0i);
    }

    // Layout:
    //   t1   F (unreduced, RNS+NTT)
    //   t2   g (RNS+NTT)
    //   t3   free
    //   t4   gm (NTT support)
    //   t5   free

    // Load f and convert to RNS+NTT (into t3). Since we are about to
    // divide by f modulo p, we also need to check that f is invertible
    // modulo p (which should almost always be the case in practice).
    poly_mp_set_small(logn, f, p, t3);
    mp_NTT(logn, t3, t4, p, p0i);
    for i in 0..n {
        if t3[i] == 0 {
            return false;
        }
    }

    // Layout:
    //   t1   F (unreduced, RNS+NTT)
    //   t2   g (RNS+NTT)
    //   t3   f (RNS+NTT)
    //   t4   free
    //   t5   free

    // We want to perform the reduction. Since this is the last one,
    // we want to be precise, i.e. to use the full expression for k:
    //
    //   k = round((F*adj(f) + G*adj(g))/(f*adj(f) + g*adj(g)))
    //
    // We do not have G but we know that G = (q + g*F)/f, which we
    // can compute modulo p (the division by f is exact over the
    // integers, hence computing it modulo p yields the correct result,
    // as long as the coefficients of G are in [-p/2,+p/2], which is
    // heuristically the case). We accumulate the numerator and
    // denominator into t2 and t3, respectively.
    for i in 0..hn {
        let tf0 = t3[i];
        let tf1 = t3[n - 1 - i];
        let tg0 = t2[i];
        let tg1 = t2[n - 1 - i];
        let tF0 = t1[i];
        let tF1 = t1[n - 1 - i];
        let mf0 = mp_mmul(tf0, R2, p, p0i);
        let mf1 = mp_mmul(tf1, R2, p, p0i);
        let mg0 = mp_mmul(tg0, R2, p, p0i);
        let mg1 = mp_mmul(tg1, R2, p, p0i);
        let tG0 = mp_div(mp_add(Q, mp_mmul(mg0, tF0, p, p0i), p), tf0, p);
        let tG1 = mp_div(mp_add(Q, mp_mmul(mg1, tF1, p, p0i), p), tf1, p);
        let kn0 = mp_add(
            mp_mmul(mf1, tF0, p, p0i),
            mp_mmul(mg1, tG0, p, p0i), p);
        let kn1 = mp_add(
            mp_mmul(mf0, tF1, p, p0i),
            mp_mmul(mg0, tG1, p, p0i), p);
        let kd = mp_add(
            mp_mmul(mf0, tf1, p, p0i),
            mp_mmul(mg0, tg1, p, p0i), p);
        t2[i] = kn0;
        t2[n - 1 - i] = kn1;
        t3[i] = kd;
        t3[n - 1 - i] = kd;
    }

    // Layout:
    //   t1   F (unreduced, RNS+NTT)
    //   t2   F*adj(f) + G*adj(g) (RNS+NTT)
    //   t3   f*adj(f) + g*adj(g) (RNS+NTT)
    //   t4   free
    //   t5   free

    // Convert back numerator and denominator to plain integers.
    mp_mkigm(logn, PRIMES[0].ig, p, p0i, t4);
    mp_iNTT(logn, t2, t4, p, p0i);
    mp_iNTT(logn, t3, t4, p, p0i);
    for i in 0..n {
        // NOTE: no truncature to 31 bits.
        t2[i] = mp_norm(t2[i], p) as u32;
        t3[i] = mp_norm(t3[i], p) as u32;
    }

    let SCALE = 32 - 10;
    // We need to divide t2 by t3, and round the result. We convert
    // them to FFT representation, downscaled by 2^10 (to avoid overflows).
    // We first convert f*adj(f) + g*adj(g), which is self-adjoint;
    // thus, its FFT representation only has half-size. */
    for i in 0..n {
        let x = ((t3[i] as i32) as i64) << SCALE;
        tmp_fxr[i] = FXR::from_u64_scaled32(x as u64);
    }
    vect_FFT(logn, tmp_fxr);
    let (rt5, rt3) = tmp_fxr.split_at_mut(hn);
    for i in 0..n {
        let x = ((t2[i] as i32) as i64) << SCALE;
        rt3[i] = FXR::from_u64_scaled32(x as u64);
    }
    vect_FFT(logn, rt3);
    // rt5   f*adj(f) + g*adj(g)   (FFT, half-size)
    // rt3   F*adj(f) + G*adj(g)   (FFT, half-size)
    vect_div_selfadj_fft(logn, rt3, rt5);
    vect_iFFT(logn, rt3);
    for i in 0..n {
        t2[i] = mp_set(rt3[i].round(), p);
    }

    // Layout:
    //   t1   F (unreduced, RNS+NTT)
    //   t2   k (RNS)
    //   t3   free
    //   t4   free
    //   t5   free

    // Get back f and g, convert all polynomials to RNS+NTT.
    mp_mkgm(logn, PRIMES[0].g, p, p0i, t5);
    poly_mp_set_small(logn, f, p, t3);
    poly_mp_set_small(logn, g, p, t4);
    mp_NTT(logn, t2, t5, p, p0i);
    mp_NTT(logn, t3, t5, p, p0i);
    mp_NTT(logn, t4, t5, p, p0i);

    // Layout:
    //   t1   F (unreduced, RNS+NTT)
    //   t2   k (RNS+NTT)
    //   t3   f (RNS+NTT)
    //   t4   g (RNS+NTT)
    //   t5   free

    // Reduce F by subtracting k*F, and recompute the corresponding G
    // with:
    //   G = (q + g*F)/f
    // (We did not keep the unreduced G, in order to save RAM.) */
    for i in 0..n {
        let tF = t1[i];
        let tk = t2[i];
        let tf = t3[i];
        let tg = t4[i];
        let mf = mp_mmul(tf, R2, p, p0i);
        let mg = mp_mmul(tg, R2, p, p0i);
        let tF = mp_sub(tF, mp_mmul(mf, tk, p, p0i), p);
        let tG = mp_div(mp_add(Q, mp_mmul(mg, tF, p, p0i), p), tf, p);
        t1[i] = tF;
        t2[i] = tG;
    }

    // Convert back F and G into normal representation.
    mp_mkigm(logn, PRIMES[0].ig, p, p0i, t3);
    mp_iNTT(logn, t1, t3, p, p0i);
    mp_iNTT(logn, t2, t3, p, p0i);
    poly_mp_norm(logn, t1, p);
    poly_mp_norm(logn, t2, p);

    // By construction, f*G - g*F = q modulo p; if both F and G are in
    // the correct range ([-127,+127]), then this equation will also
    // hold over plain integers:
    //   N_inf(f*G - g*F) <= (127^2)*n*2 < 2^25 < p/2
    // Verifying that F and G are in range is done by the caller.
    true
}

// Inject (f,g) at the top-level: f and g are converted to NTT and
// written into the first 2*n words of tmp[].
fn make_fg_depth0(logn: u32, f: &[i8], g: &[i8], tmp: &mut [u32]) {
    let n = 1usize << logn;
    let p = P0.p;
    let p0i = P0.p0i;
    let (ft, tmp) = tmp.split_at_mut(n);
    let (gt, tmp) = tmp.split_at_mut(n);
    let (gm, _)   = tmp.split_at_mut(n);
    poly_mp_set_small(logn, f, p, ft);
    poly_mp_set_small(logn, g, p, gt);
    mp_mkgm(logn, P0.g, p, p0i, gm);
    mp_NTT(logn, ft, gm, p, p0i);
    mp_NTT(logn, gt, gm, p, p0i);
}

// One step of computing (f,g) at a given depth.
// Input: (f,g) of degree 2^(logn_top - depth)
// Output: (f',g') of degree 2^(logn_top - (depth+1))
fn make_fg_step(logn_top: u32, depth: u32, work: &mut [u32]) {
    let logn = logn_top - depth;
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MOD_SMALL_BL[depth as usize];
    let tlen = MOD_SMALL_BL[(depth + 1) as usize];

    // Prepare buffers:
    //   fd, gd: output polynomials
    //   fs, gs: source polynomials
    //   gm, igm: buffers for NTT support arrays
    //   data: remaining slots (used for CRT)
    let data = work;
    data.copy_within(0..(2 * n * slen), 2 * hn * tlen);
    let (fd, data) = data.split_at_mut(hn * tlen);
    let (gd, data) = data.split_at_mut(hn * tlen);
    let (fgs, data) = data.split_at_mut(2 * n * slen);

    // First slen words: we use the input values directly, and apply
    // inverse NTT as we go, so that we get the sources in RNS (non-NTT).
    {
        let (fs, gs) = fgs.split_at_mut(n * slen);
        let (igm, _) = data.split_at_mut(n);
        for i in 0..slen {
            let p = PRIMES[i].p;
            let p0i = PRIMES[i].p0i;
            let R2 = PRIMES[i].R2;
            let ks = i * n;
            let kd = i * hn;
            for j in 0..hn {
                fd[kd + j] = mp_mmul(
                    mp_mmul(fs[ks + 2 * j], fs[ks + 2 * j + 1], p, p0i),
                    R2, p, p0i);
                gd[kd + j] = mp_mmul(
                    mp_mmul(gs[ks + 2 * j], gs[ks + 2 * j + 1], p, p0i),
                    R2, p, p0i);
            }
            mp_mkigm(logn, PRIMES[i].ig, p, p0i, igm);
            mp_iNTT(logn, &mut fs[ks..], igm, p, p0i);
            mp_iNTT(logn, &mut gs[ks..], igm, p, p0i);
        }
    }

    // Remaining output words.
    if tlen > slen {
        // fs and gs are in RNS, rebuild them into plain integer coefficients.
        zint_rebuild_CRT(fgs, slen, n, 2, true, data);

        let (fs, gs) = fgs.split_at_mut(n * slen);
        let (gm, data) = data.split_at_mut(n);
        let (t2, _) = data.split_at_mut(n);
        for i in slen..tlen {
            let p = PRIMES[i].p;
            let p0i = PRIMES[i].p0i;
            let R2 = PRIMES[i].R2;
            let Rx = mp_Rx31(slen as u32, p, p0i, R2);
            mp_mkgm(logn, PRIMES[i].g, p, p0i, gm);
            let kd = i * hn;

            for j in 0..n {
                t2[j] = zint_mod_small_signed(
                    &fs[j..], slen, n, p, p0i, R2, Rx);
            }
            mp_NTT(logn, t2, gm, p, p0i);
            for j in 0..hn {
                fd[kd + j] = mp_mmul(
                    mp_mmul(t2[2 * j], t2[2 * j + 1], p, p0i),
                    R2, p, p0i);
            }

            for j in 0..n {
                t2[j] = zint_mod_small_signed(
                    &gs[j..], slen, n, p, p0i, R2, Rx);
            }
            mp_NTT(logn, t2, gm, p, p0i);
            for j in 0..hn {
                gd[kd + j] = mp_mmul(
                    mp_mmul(t2[2 * j], t2[2 * j + 1], p, p0i),
                    R2, p, p0i);
            }
        }
    }
}

// Recompute (f,g) at a given depth.
fn make_fg_intermediate(logn_top: u32,
    f: &[i8], g: &[i8], depth: u32, work: &mut [u32])
{
    make_fg_depth0(logn_top, f, g, work);
    for d in 0..depth {
        make_fg_step(logn_top, d, work);
    }
}

// Recompute (f, g) at the deepest level. Intermediate (f,g) values
// (below the save threshold) are copied at the end of the work area.
//
// If f is not invertible modulo X^n+1 and modulo p = 2147473409,
// then this function returns false (but everything else is still
// computed); otherwise, this function returns true. There is no such
// test on g.
fn make_fg_deepest(logn: u32, f: &[i8], g: &[i8], mut work: &mut [u32]) {
    make_fg_depth0(logn, f, g, work);

    // Compute all the reduced (f,g) values, saving the intermediate
    // values (except that the highest levels).
    for d in 0..logn {
        make_fg_step(logn, d, work);
        let d2 = d + 1;
        if d2 < logn && d2 >= MIN_SAVE_FG[logn as usize] {
            let slen = MOD_SMALL_BL[d2 as usize];
            let fglen = slen << (logn + 1 - d2);
            let sav_off = work.len() - fglen;
            work.copy_within(0..fglen, sav_off);
            work = &mut work[..sav_off];
        }
    }
}
