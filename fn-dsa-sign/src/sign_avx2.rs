#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use super::*;
use fn_dsa_comm::mq_avx2;

#[path = "poly_avx2.rs"]
mod poly_avx2;

#[path = "sampler_avx2.rs"]
mod sampler_avx2;

// This is a specialized version of decode_inner() (defined in the
// parent module); it leverages AVX2 intrinsics to speed up operations.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn decode_avx2_inner(logn_min: u32, logn_max: u32,
    f: &mut [i8], g: &mut [i8], F: &mut [i8], G: &mut [i8],
    vrfy_key: &mut [u8], hashed_vrfy_key: &mut [u8],
    tmp_u16: &mut [u16], src: &[u8]) -> Option<u32>
{
    if src.len() < 1 {
        return None;
    }
    let head = src[0];
    if (head & 0xF0) != 0x50 {
        return None;
    }
    let logn = (head & 0x0F) as u32;
    if logn < logn_min || logn > logn_max {
        return None;
    }
    if src.len() != sign_key_size(logn) {
        return None;
    }
    let n = 1usize << logn;
    assert!(f.len() >= n);
    assert!(g.len() >= n);
    assert!(F.len() >= n);
    assert!(G.len() >= n);
    assert!(vrfy_key.len() >= vrfy_key_size(logn));
    assert!(hashed_vrfy_key.len() == 64);
    let f = &mut f[..n];
    let g = &mut g[..n];
    let F = &mut F[..n];
    let G = &mut G[..n];
    let vk = &mut vrfy_key[..vrfy_key_size(logn)];

    // Coefficients of (f,g) use a number of bits that depends on logn.
    let nbits_fg = match logn {
        2..=5 => 8,
        6..=7 => 7,
        8..=9 => 6,
        _ => 5,
    };
    let j = 1 + codec::trim_i8_decode(&src[1..], f, nbits_fg)?;
    let j = j + codec::trim_i8_decode(&src[j..], g, nbits_fg)?;
    let j = j + codec::trim_i8_decode(&src[j..], F, 8)?;
    // We already checked the length of src; any mismatch at this point
    // is an implementation bug.
    assert!(j == src.len());

    // Compute G from f, g and F. This might fail if the decoded f turns
    // out to be non-invertible modulo X^n+1 and q, or if the recomputed G
    // is out of the allowed range (its coefficients should all be in
    // the [-127,+127] range).
    // Method:
    //   f*G - g*F = q = 0 mod q
    // thus:
    //   G = g*F/f mod q
    // We also compute the public key h = g/f mod q.
    let (w0, w1) = tmp_u16.split_at_mut(n);

    // w0 <- g/f  (NTT)
    mq_avx2::mqpoly_small_to_int(logn, &*g, w0);
    mq_avx2::mqpoly_small_to_int(logn, &*f, w1);
    mq_avx2::mqpoly_int_to_NTT(logn, w0);
    mq_avx2::mqpoly_int_to_NTT(logn, w1);
    if !mq_avx2::mqpoly_div_ntt(logn, w0, w1) {
        // f is not invertible
        return None;
    }

    // w1 <- h*F = g*F/f = G  (NTT)
    mq_avx2::mqpoly_small_to_int(logn, &*F, w1);
    mq_avx2::mqpoly_int_to_NTT(logn, w1);
    mq_avx2::mqpoly_mul_ntt(logn, w1, w0);

    // Convert back h to external representation and encode it.
    mq_avx2::mqpoly_NTT_to_int(logn, w0);
    mq_avx2::mqpoly_int_to_ext(logn, w0);
    vk[0] = 0x00 + (logn as u8);
    let j = 1 + codec::modq_encode(&w0[..n], &mut vk[1..]);
    assert!(j == vk.len());
    let mut sh = shake::SHAKE256::new();
    sh.inject(vk);
    sh.flip();
    sh.extract(hashed_vrfy_key);

    // Convert back G to external representation and check that all
    // elements are small.
    mq_avx2::mqpoly_NTT_to_int(logn, w1);
    if !mq_avx2::mqpoly_int_to_small(logn, w1, G) {
        return None;
    }

    // Decoding succeeded.
    Some(logn)
}

// This is a specialized version of compute_basis_inner() (defined in the
// parent module); it leverages AVX2 intrinsics to speed up operations.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn compute_basis_avx2_inner(logn: u32,
    f: &[i8], g: &[i8], F: &[i8], G: &[i8], basis: &mut [flr::FLR])
{
    let n = 1usize << logn;

    // Lattice basis is B = [[g, -f], [G, -F]].
    let (b00, work) = basis.split_at_mut(n);
    let (b01, work) = work.split_at_mut(n);
    let (b10, work) = work.split_at_mut(n);
    let (b11, _) = work.split_at_mut(n);

    poly_avx2::poly_set_small(logn, b01, f);
    poly_avx2::poly_set_small(logn, b00, g);
    poly_avx2::poly_set_small(logn, b11, F);
    poly_avx2::poly_set_small(logn, b10, G);
    poly_avx2::FFT(logn, b01);
    poly_avx2::FFT(logn, b00);
    poly_avx2::FFT(logn, b11);
    poly_avx2::FFT(logn, b10);
    poly_avx2::poly_neg(logn, b01);
    poly_avx2::poly_neg(logn, b11);
}

// This is a specialized version of sign_inner() (defined in the parent
// module); it leverages AVX2 intrinsics to speed up operations.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn sign_avx2_inner<T: CryptoRng + RngCore, P: PRNG>(
    logn: u32, rng: &mut T,
    f: &[i8], g: &[i8], F: &[i8], G: &[i8], hashed_vrfy_key: &[u8],
    ctx: &DomainContext, id: &HashIdentifier, hv: &[u8], sig: &mut [u8],
    #[cfg(not(feature = "small_context"))]
    basis: &[flr::FLR],
    tmp_i16: &mut [i16], tmp_u16: &mut [u16], tmp_flr: &mut [flr::FLR])
{
    let n = 1usize << logn;
    assert!(f.len() == n);
    assert!(g.len() == n);
    assert!(F.len() == n);
    assert!(G.len() == n);
    assert!(sig.len() == signature_size(logn));

    // Special behaviour for the original Falcon algorithm (for test
    // reproducibility). TODO: remove when switching to final test vectors.
    let orig_falcon = id.0.len() == 1 && id.0[0] == 0xFF;

    // Hash the message with a 40-byte random nonce, to produce the
    // hashed message.
    let mut nonce = [0u8; 40];
    let mut first = true;

    // Usually the signature generation works at the first attempt, but
    // occasionally we need to try again because the obtained signature
    // is not a short enough vector, or cannot be encoded in the target
    // signature size.
    loop {
        let hm = &mut tmp_u16[0..n];
        // We must generate a random 40-byte nonce, and hash the
        // message to a polynomial hm[].
        // In the original Falcon, this was done once; in FN-DSA, this
        // is done at each loop restart.
        // (TODO: align with final spec)
        if first || !orig_falcon {
            rng.fill_bytes(&mut nonce);
            hash_to_point(&nonce, hashed_vrfy_key, ctx, id, hv, hm);
            first = false;
        }

        // We initialize the PRNG with a 56-byte seed, to match the
        // practice from the C code (it makes it simpler to reproduce
        // test vectors). Any seed of at least 32 bytes would be fine.
        let mut seed = [0u8; 56];
        rng.fill_bytes(&mut seed);
        let mut samp = sampler_avx2::Sampler::<P>::new(logn, &seed);

        // Lattice basis is B = [[g, -f], [G, -F]]. We need it in FFT
        // format, then we compute the Gram matrix G = B*adj(B).
        // Formulas are:
        //   g00 = b00*adj(b00) + b01*adj(b01)
        //   g01 = b00*adj(b10) + b01*adj(b11)
        //   g10 = b10*adj(b00) + b11*adj(b01)
        //   g11 = b10*adj(b10) + b11*adj(b11)
        //
        // For historical reasons, this implementation uses g00,
        // g01 and g11 (upper triangle), and omits g10, which is
        // equal to adj(g01).
        //
        // We need the following in tmp_flr:
        //   g00 g01 g11 b11 b01

        #[cfg(feature = "small_context")]
        {
            // We do not have a precomputed basis, we recompute it.
            compute_basis_inner(logn, f, g, F, G, tmp_flr);

            let (b00, work) = tmp_flr.split_at_mut(n);
            let (b01, work) = work.split_at_mut(n);
            let (b10, work) = work.split_at_mut(n);
            let (b11, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, _) = work.split_at_mut(n);

            // t0 <- b01*adj(b01)
            t0.copy_from_slice(&*b01);
            poly_avx2::poly_mulownadj_fft(logn, t0);

            // t1 <- b00*adj(b10)
            t1.copy_from_slice(&*b00);
            poly_avx2::poly_muladj_fft(logn, t1, b10);

            // b00 <- b00*adj(b00)
            poly_avx2::poly_mulownadj_fft(logn, b00);

            // b00 <- g00
            poly_avx2::poly_add(logn, b00, t0);

            // Save b01 into t0.
            t0.copy_from_slice(b01);

            // b01 <- g01
            poly_avx2::poly_muladj_fft(logn, b01, b11);
            poly_avx2::poly_add(logn, b01, t1);

            // b10 <- b10*adj(b10)
            poly_avx2::poly_mulownadj_fft(logn, b10);

            // b10 <- g11
            t1.copy_from_slice(b11);
            poly_avx2::poly_mulownadj_fft(logn, t1);
            poly_avx2::poly_add(logn, b10, t1);
        }

        #[cfg(not(feature = "small_context"))]
        {
            // We have the precomputed basis B in FFT format.
            let (b00, work) = basis.split_at(n);
            let (b01, work) = work.split_at(n);
            let (b10, work) = work.split_at(n);
            let (b11, _) = work.split_at(n);

            let (g00, work) = tmp_flr.split_at_mut(n);
            let (g01, work) = work.split_at_mut(n);
            let (g11, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, _) = work.split_at_mut(n);

            g00.copy_from_slice(b00);
            poly_avx2::poly_mulownadj_fft(logn, g00);
            t0.copy_from_slice(b01);
            poly_avx2::poly_mulownadj_fft(logn, t0);
            poly_avx2::poly_add(logn, g00, t0);

            g01.copy_from_slice(b00);
            poly_avx2::poly_muladj_fft(logn, g01, b10);
            t0.copy_from_slice(b01);
            poly_avx2::poly_muladj_fft(logn, t0, b11);
            poly_avx2::poly_add(logn, g01, t0);

            g11.copy_from_slice(b10);
            poly_avx2::poly_mulownadj_fft(logn, g11);
            t0.copy_from_slice(b11);
            poly_avx2::poly_mulownadj_fft(logn, t0);
            poly_avx2::poly_add(logn, g11, t0);

            t0.copy_from_slice(b11);
            t1.copy_from_slice(b01);
        }

        // Memory layout at this point:
        //   g00 g01 g11 b11 b01

        {
            let (_, work) = tmp_flr.split_at_mut(3 * n);
            let (b11, work) = work.split_at_mut(n);
            let (b01, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, _) = work.split_at_mut(n);

            // Set the target (t0,t1) to [hm, 0].
            // (t1 is not actually set; subsequent computations take into
            // account that it is conceptually zero)
            for i in 0..n {
                t0[i] = flr::FLR::from_i32(hm[i] as i32);
            }

            // Apply the lattice basis to obtain the real target vector
            // (after normalization with regard to the modulus).
            poly_avx2::FFT(logn, t0);
            t1.copy_from_slice(t0);
            poly_avx2::poly_mul_fft(logn, t1, b01);
            poly_avx2::poly_mulconst(logn, t1, -INV_Q);
            poly_avx2::poly_mul_fft(logn, t0, b11);
            poly_avx2::poly_mulconst(logn, t0, INV_Q);
        }

        // b01 and b11 can now be discarded; we move back (t0, t1).
        tmp_flr.copy_within((5 * n)..(7 * n), 3 * n);

        // Memory layout at this point:
        //   g00 g01 g11 t0 t1

        {
            // Apply sampling.
            let (g00, work) = tmp_flr.split_at_mut(n);
            let (g01, work) = work.split_at_mut(n);
            let (g11, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, work) = work.split_at_mut(n);
            samp.ffsamp_fft(t0, t1, g00, g01, g11, work);
        }

        // Rearrange layout back to:
        //   b00 b01 b10 b11 t0 t1
        tmp_flr.copy_within((3 * n)..(5 * n), 4 * n);

        #[cfg(feature = "small_context")]
        compute_basis_avx2_inner(logn, f, g, F, G, tmp_flr);

        #[cfg(not(feature = "small_context"))]
        tmp_flr[..(4 * n)].copy_from_slice(&basis[..(4 * n)]);

        let (b00, work) = tmp_flr.split_at_mut(n);
        let (b01, work) = work.split_at_mut(n);
        let (b10, work) = work.split_at_mut(n);
        let (b11, work) = work.split_at_mut(n);
        let (t0, work) = work.split_at_mut(n);
        let (t1, work) = work.split_at_mut(n);
        let (tx, work) = work.split_at_mut(n);
        let (ty, _) = work.split_at_mut(n);

        // Get the lattice point corresponding to the sampled vector.
        tx.copy_from_slice(t0);
        ty.copy_from_slice(t1);
        poly_avx2::poly_mul_fft(logn, tx, b00);
        poly_avx2::poly_mul_fft(logn, ty, b10);
        poly_avx2::poly_add(logn, tx, ty);
        ty.copy_from_slice(t0);
        poly_avx2::poly_mul_fft(logn, ty, b01);
        t0.copy_from_slice(tx);
        poly_avx2::poly_mul_fft(logn, t1, b11);
        poly_avx2::poly_add(logn, t1, ty);
        poly_avx2::iFFT(logn, t0);
        poly_avx2::iFFT(logn, t1);

        // We compute s1, then s2 into buffer s2 (s1 is not retained).
        // We accumulate their squared norm in sqn, with an "overflow"
        // flag in ng. Since every value is coerced to the i16 type,
        // a squared norm going over 2^31-1 necessarily implies at some
        // point that the high bit of sqn is set, which will show up
        // as the high bit of ng being set.
        let mut sqn = 0u32;
        let mut ng = 0;
        for i in 0..n {
            let z = (hm[i] as i32) - (t0[i].rint() as i32);
            let z = (z as i16) as i32;
            sqn = sqn.wrapping_add((z * z) as u32);
            ng |= sqn;
        }

        // With standard degrees (512 and 1024), it is very improbable that
        // the computed vector is not short enough; however, it may happen
        // for smaller degrees in test/toy versions (e.g. degree 16). We
        // need to loop in these cases.
        let s2 = &mut tmp_i16[..n];
        for i in 0..n {
            let sz = (-t1[i].rint()) as i16;
            let z = sz as i32;
            sqn = sqn.wrapping_add((z * z) as u32);
            ng |= sqn;
            s2[i] = sz;
        }

        // If the squared norm exceeded 2^31-1 at some point, then the
        // high bit of ng is set. We saturate sqn to 2^32-1 in that case
        // (which will be enough to make the value too large, and force
        // a new loop iteration).
        sqn |= ((ng as i32) >> 31) as u32;
        if sqn > mq_avx2::SQBETA[logn as usize] {
            continue;
        }

        // We have a candidate signature; we must encode it. This may
        // fail, since encoding is variable-size and might not fit in the
        // target size.
        if codec::comp_encode(s2, &mut sig[41..]) {
            sig[0] = 0x30 + (logn as u8);
            sig[1..41].copy_from_slice(&nonce);
            return;
        }
    }
}
