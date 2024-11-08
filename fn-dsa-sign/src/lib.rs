#![no_std]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//! # FN-DSA signature generation
//!
//! This crate implements signature generation for FN-DSA. A `SigningKey`
//! instance is created by decoding a signing key (from its encoded
//! format). Signatures can be generated with the `sign()` method on the
//! `SigningKey` instance. `sign()` uses the instance mutably because the
//! process uses relatively large RAM buffers which are part of the
//! instance (to avoid oversized stack allocation on embedded systems).
//! The same `SigningKey` can be used for generating several signatures;
//! this even allows CPU savings since some computations depend only on
//! the key and can be reused for several signatures.
//!
//! The signature process uses a domain-separation context, which is an
//! arbitrary binary strings (up to 255 bytes in length). If no such
//! context is required in an application, use `DOMAIN_NONE` (the empty
//! context).
//!
//! The message is supposed to be pre-hashed by the caller: the caller
//! provides the hashed value, along with an identifier of the used hash
//! function. The `HASH_ID_RAW` identifier can be used if the message is
//! not actually pre-hashed, but is provided directly instead of a hash
//! value.
//!
//! FN-DSA is parameterized by a degree, which is a power of two.
//! Standard versions use degree 512 ("level I security") or 1024 ("level
//! V security"); smaller degrees are deemed too weak for production use
//! and meant only for research and testing. The degree is represented
//! logarithmically as the `logn` value, such that the degree is `n =
//! 2^logn` (thus, degrees 512 and 1024 correspond to `logn` values 9 and
//! 10, respectively). The signature size is fixed for a given degree
//! (see `signature_size()`).
//!
//! ## WARNING
//!
//! **The FN-DSA standard is currently being drafted, but no version has
//! been published yet. When published, it may differ from the exact
//! scheme implemented in this crate, in particular with regard to key
//! encodings, message pre-hashing, and domain separation. Key pairs
//! generated with this crate MAY fail to be interoperable with the final
//! FN-DSA standard. This implementation is expected to be adjusted to
//! the FN-DSA standard when published (before the 1.0 version release).**
//!
//! ## Example usage
//!
//! ```ignore
//! use rand_core::OsRng;
//! use fn_dsa_sign::{
//!     sign_key_size, signature_size, FN_DSA_LOGN_512,
//!     SigningKey, SigningKeyStandard,
//!     DOMAIN_NONE, HASH_ID_RAW,
//! };
//! 
//! let mut sk = SigningKeyStandard::decode(encoded_signing_key)?;
//! let mut sig = vec![0u8; signature_size(sk.get_logn())];
//! sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, b"message", &mut sig);
//! ```

mod flr;
mod poly;
mod sampler;

use fn_dsa_comm::{codec, hash_to_point, mq, shake, PRNG};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Re-export useful types, constants and functions.
pub use fn_dsa_comm::{
    sign_key_size, vrfy_key_size, signature_size,
    FN_DSA_LOGN_512, FN_DSA_LOGN_1024,
    HashIdentifier,
    HASH_ID_RAW,
    HASH_ID_ORIGINAL_FALCON,
    HASH_ID_SHA256,
    HASH_ID_SHA384,
    HASH_ID_SHA512,
    HASH_ID_SHA512_256,
    HASH_ID_SHA3_256,
    HASH_ID_SHA3_384,
    HASH_ID_SHA3_512,
    HASH_ID_SHAKE128,
    HASH_ID_SHAKE256,
    DomainContext,
    DOMAIN_NONE,
    CryptoRng, RngCore, RngError,
};

/// Signing key handler and temporary buffers.
///
/// Signature generation uses relatively large temporary buffers (about
/// 42 or 84 kB, for the two standard degrees), which is why they are
/// part of the `SigningKey` instance instead of being allocated on the
/// stack. An instance can be used for several successive signature
/// generations. Implementations of this trait are expected to handle
/// automatic zeroization (overwrite of all contained secret values when
/// the object is released).
pub trait SigningKey: Sized {

    /// Create the instance by decoding the signing key from its storage
    /// format.
    ///
    /// If the source uses a degree not supported by this `SigningKey`
    /// type, or does not have the exact length expected for the degree
    /// it uses, or is otherwise invalidly encoded, then this function
    /// returns `None`; otherwise, it returns the new instance.
    fn decode(sec: &[u8]) -> Option<Self>;

    /// Get the degree associated with this key.
    ///
    /// The degree is returned in a logarithmic scale (`logn`, value ranges
    /// from 2 to 10).
    fn get_logn(&self) -> u32;

    /// Encode the public (verifying) key into the provided buffer.
    ///
    /// The output buffer must have the exact size of the verifying key.
    fn to_verifying_key(&self, vrfy_key: &mut [u8]);

    /// Generate a signature.
    ///
    /// Parameters:
    ///
    ///  - `rng`: a cryptographically secure random source
    ///  - `ctx`: the domain separation context
    ///  - `id`: the identifier for the pre-hash function
    ///  - `hv`: the pre-hashed message (or the message itself, if `id`
    ///    is `HASH_ID_RAW`)
    ///  - `sig`: the output slice for the generated signature; its size
    ///    MUST be exactly that expected for the key degree (see
    ///    `signature_size()`).
    fn sign<T: CryptoRng + RngCore>(&mut self, rng: &mut T,
        ctx: &DomainContext, id: &HashIdentifier, hv: &[u8], sig: &mut [u8]);
}

macro_rules! sign_key_impl {
    ($typename:ident, $logn_min:expr, $logn_max:expr) =>
{
    #[doc = concat!("Signature generator for degrees (`logn`) ",
        stringify!($logn_min), " to ", stringify!($logn_max), " only.")]
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct $typename {
        f: [i8; 1 << ($logn_max)],
        g: [i8; 1 << ($logn_max)],
        F: [i8; 1 << ($logn_max)],
        G: [i8; 1 << ($logn_max)],
        vrfy_key: [u8; vrfy_key_size($logn_max)],
        hashed_vrfy_key: [u8; 64],
        tmp_i16: [i16; 1 << ($logn_max)],
        tmp_u16: [u16; 2 << ($logn_max)],
        tmp_flr: [flr::FLR; 9 << ($logn_max)],

        // Basis B = [[g, -f], [G, -F]], in FFT format.
        #[cfg(not(feature = "small_context"))]
        basis: [flr::FLR; 4 << ($logn_max)],

        logn: u32,

        // On x86_64, we use AVX2 if available, which is dynamically
        // tested. We do not do that on plain x86, because plain x86 uses
        // the emulated floating-point, not the native types (on 32-bit
        // x86, native floating-point is x87, not SSE2).
        #[cfg(target_arch = "x86_64")]
        use_avx2: bool,
    }

    impl $typename {

        fn decode_key(&mut self, src: &[u8]) -> Option<u32> {
            #[cfg(target_arch = "x86_64")]
            if self.use_avx2 {
                unsafe {
                    return sign_avx2::decode_avx2_inner($logn_min, $logn_max,
                        &mut self.f[..], &mut self.g[..],
                        &mut self.F[..], &mut self.G[..],
                        &mut self.vrfy_key[..], &mut self.hashed_vrfy_key[..],
                        &mut self.tmp_u16[..], src);
                }
            }

            decode_inner($logn_min, $logn_max,
                &mut self.f[..], &mut self.g[..],
                &mut self.F[..], &mut self.G[..],
                &mut self.vrfy_key[..], &mut self.hashed_vrfy_key[..],
                &mut self.tmp_u16[..], src)
        }

        #[cfg(not(feature = "small_context"))]
        fn compute_basis(&mut self) {
            let n = 1usize << self.logn;

            #[cfg(target_arch = "x86_64")]
            if self.use_avx2 {
                unsafe {
                    sign_avx2::compute_basis_avx2_inner(self.logn,
                        &self.f[..n], &self.g[..n], &self.F[..n], &self.G[..n],
                        &mut self.basis[..(4 * n)]);
                }
                return;
            }

            compute_basis_inner(self.logn,
                &self.f[..n], &self.g[..n], &self.F[..n], &self.G[..n],
                &mut self.basis[..(4 * n)]);
        }
    }

    impl SigningKey for $typename {

        fn decode(src: &[u8]) -> Option<Self> {
            let f = [0i8; 1 << ($logn_max)];
            let g = [0i8; 1 << ($logn_max)];
            let F = [0i8; 1 << ($logn_max)];
            let G = [0i8; 1 << ($logn_max)];
            let vrfy_key = [0u8; vrfy_key_size($logn_max)];
            let hashed_vrfy_key = [0u8; 64];
            let tmp_i16 = [0i16; 1 << ($logn_max)];
            let tmp_u16 = [0u16; 2 << ($logn_max)];
            let tmp_flr = [flr::FLR::ZERO; 9 << ($logn_max)];

            #[cfg(not(feature = "small_context"))]
            let basis = [flr::FLR::ZERO; 4 << ($logn_max)];

            let mut sk = Self {
                f, g, F, G, vrfy_key, hashed_vrfy_key,
                tmp_i16, tmp_u16, tmp_flr,
                #[cfg(not(feature = "small_context"))]
                basis,
                logn: 0,
                #[cfg(target_arch = "x86_64")]
                use_avx2: fn_dsa_comm::has_avx2(),
            };
            sk.logn = sk.decode_key(src)?;

            #[cfg(not(feature = "small_context"))]
            sk.compute_basis();

            Some(sk)
        }

        fn get_logn(&self) -> u32 {
            self.logn
        }

        fn to_verifying_key(&self, vrfy_key: &mut [u8]) {
            let len = vrfy_key_size(self.logn);
            assert!(vrfy_key.len() == len);
            vrfy_key.copy_from_slice(&self.vrfy_key[..len]);
        }

        fn sign<T: CryptoRng + RngCore>(&mut self, rng: &mut T,
            ctx: &DomainContext, id: &HashIdentifier, hv: &[u8], sig: &mut [u8])
        {
            let n = 1usize << self.logn;

            #[cfg(target_arch = "x86_64")]
            if self.use_avx2 {
                unsafe {
                    sign_avx2::sign_avx2_inner::<T, shake::SHAKE256x4>(
                        self.logn, rng,
                        &self.f[..n], &self.g[..n], &self.F[..n], &self.G[..n],
                        &self.hashed_vrfy_key, ctx, id, hv, sig,
                        #[cfg(not(feature = "small_context"))]
                        &self.basis[..(4 * n)],
                        &mut self.tmp_i16, &mut self.tmp_u16,
                        &mut self.tmp_flr);
                }
                return;
            }

            sign_inner::<T, shake::SHAKE256x4>(self.logn, rng,
                &self.f[..n], &self.g[..n], &self.F[..n], &self.G[..n],
                &self.hashed_vrfy_key, ctx, id, hv, sig,
                #[cfg(not(feature = "small_context"))]
                &self.basis[..(4 * n)],
                &mut self.tmp_i16, &mut self.tmp_u16, &mut self.tmp_flr);
        }
    }
} }

// A SigningKey type that supports the standard degrees (512 and 1024).
sign_key_impl!(SigningKeyStandard, 9, 10);

// A SigningKey type that supports only degree 512. It uses less RAM than
// SigningKeyStandard.
sign_key_impl!(SigningKey512, 9, 9);

// A SigningKey type that supports only degree 1024. It uses as much RAM as
// SigningKeyStandard but enforces the level V security variant.
sign_key_impl!(SigningKey1024, 10, 10);

// A SigningKey type that supports only weak/toy degrees (4 to 256). It is
// meant only for research and testing purposes.
sign_key_impl!(SigningKeyWeak, 2, 8);

#[cfg(target_arch = "x86_64")]
mod sign_avx2;

// Decode a private key.
fn decode_inner(logn_min: u32, logn_max: u32,
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
    mq::mqpoly_small_to_int(logn, &*g, w0);
    mq::mqpoly_small_to_int(logn, &*f, w1);
    mq::mqpoly_int_to_NTT(logn, w0);
    mq::mqpoly_int_to_NTT(logn, w1);
    if !mq::mqpoly_div_ntt(logn, w0, w1) {
        // f is not invertible
        return None;
    }

    // w1 <- h*F = g*F/f = G  (NTT)
    mq::mqpoly_small_to_int(logn, &*F, w1);
    mq::mqpoly_int_to_NTT(logn, w1);
    mq::mqpoly_mul_ntt(logn, w1, w0);

    // Convert back h to external representation and encode it.
    mq::mqpoly_NTT_to_int(logn, w0);
    mq::mqpoly_int_to_ext(logn, w0);
    vk[0] = 0x00 + (logn as u8);
    let j = 1 + codec::modq_encode(&w0[..n], &mut vk[1..]);
    assert!(j == vk.len());
    let mut sh = shake::SHAKE256::new();
    sh.inject(vk);
    sh.flip();
    sh.extract(hashed_vrfy_key);

    // Convert back G to external representation and check that all
    // elements are small.
    mq::mqpoly_NTT_to_int(logn, w1);
    if !mq::mqpoly_int_to_small(logn, w1, G) {
        return None;
    }

    // Decoding succeeded.
    Some(logn)
}

fn compute_basis_inner(logn: u32,
    f: &[i8], g: &[i8], F: &[i8], G: &[i8], basis: &mut [flr::FLR])
{
    let n = 1usize << logn;

    // Lattice basis is B = [[g, -f], [G, -F]].
    let (b00, work) = basis.split_at_mut(n);
    let (b01, work) = work.split_at_mut(n);
    let (b10, work) = work.split_at_mut(n);
    let (b11, _) = work.split_at_mut(n);

    poly::poly_set_small(logn, b01, f);
    poly::poly_set_small(logn, b00, g);
    poly::poly_set_small(logn, b11, F);
    poly::poly_set_small(logn, b10, G);
    poly::FFT(logn, b01);
    poly::FFT(logn, b00);
    poly::FFT(logn, b11);
    poly::FFT(logn, b10);
    poly::poly_neg(logn, b01);
    poly::poly_neg(logn, b11);
}

// 1/12289
const INV_Q: flr::FLR = flr::FLR::scaled(6004310871091074, -66);

fn sign_inner<T: CryptoRng + RngCore, P: PRNG>(logn: u32, rng: &mut T,
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
        let mut samp = sampler::Sampler::<P>::new(logn, &seed);

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
            poly::poly_mulownadj_fft(logn, t0);

            // t1 <- b00*adj(b10)
            t1.copy_from_slice(&*b00);
            poly::poly_muladj_fft(logn, t1, b10);

            // b00 <- b00*adj(b00)
            poly::poly_mulownadj_fft(logn, b00);

            // b00 <- g00
            poly::poly_add(logn, b00, t0);

            // Save b01 into t0.
            t0.copy_from_slice(b01);

            // b01 <- g01
            poly::poly_muladj_fft(logn, b01, b11);
            poly::poly_add(logn, b01, t1);

            // b10 <- b10*adj(b10)
            poly::poly_mulownadj_fft(logn, b10);

            // b10 <- g11
            t1.copy_from_slice(b11);
            poly::poly_mulownadj_fft(logn, t1);
            poly::poly_add(logn, b10, t1);
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
            poly::poly_mulownadj_fft(logn, g00);
            t0.copy_from_slice(b01);
            poly::poly_mulownadj_fft(logn, t0);
            poly::poly_add(logn, g00, t0);

            g01.copy_from_slice(b00);
            poly::poly_muladj_fft(logn, g01, b10);
            t0.copy_from_slice(b01);
            poly::poly_muladj_fft(logn, t0, b11);
            poly::poly_add(logn, g01, t0);

            g11.copy_from_slice(b10);
            poly::poly_mulownadj_fft(logn, g11);
            t0.copy_from_slice(b11);
            poly::poly_mulownadj_fft(logn, t0);
            poly::poly_add(logn, g11, t0);

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
            poly::FFT(logn, t0);
            t1.copy_from_slice(t0);
            poly::poly_mul_fft(logn, t1, b01);
            poly::poly_mulconst(logn, t1, -INV_Q);
            poly::poly_mul_fft(logn, t0, b11);
            poly::poly_mulconst(logn, t0, INV_Q);
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
        compute_basis_inner(logn, f, g, F, G, tmp_flr);

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
        poly::poly_mul_fft(logn, tx, b00);
        poly::poly_mul_fft(logn, ty, b10);
        poly::poly_add(logn, tx, ty);
        ty.copy_from_slice(t0);
        poly::poly_mul_fft(logn, ty, b01);
        t0.copy_from_slice(tx);
        poly::poly_mul_fft(logn, t1, b11);
        poly::poly_add(logn, t1, ty);
        poly::iFFT(logn, t0);
        poly::iFFT(logn, t1);

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
        if sqn > mq::SQBETA[logn as usize] {
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

#[cfg(test)]
mod tests {

    use super::*;
    use fn_dsa_comm::shake::SHAKE256;

    // PRNG implementation based on ChaCha20, used to mimic the reference
    // C code to get reproducible behaviour. The seed MUST have length
    // 56 bytes exactly (this is how it is used in sign_inner()).
    #[derive(Clone, Copy, Debug)]
    struct ChaCha20PRNG {
        buf: [u8; 512],
        state: [u8; 256],
        ptr: usize,
    }

    const CW: [u32; 4] = [
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
    ];

    impl ChaCha20PRNG {

        fn refill(&mut self) {
            let mut cc = u64::from_le_bytes(
                *<&[u8; 8]>::try_from(&self.state[48..56]).unwrap());
            for i in 0..8 {
                let mut state = [0u32; 16];
                state[0..4].copy_from_slice(&CW);
                for j in 0..12 {
                    state[4 + j] = u32::from_le_bytes(
                        *<&[u8; 4]>::try_from(
                            &self.state[(4 * j)..(4 * j + 4)]).unwrap());
                }
                state[14] ^= cc as u32;
                state[15] ^= (cc >> 32) as u32;
                for _ in 0..10 {
                    fn qround(st: &mut [u32; 16],
                        a: usize, b: usize, c: usize, d: usize)
                    {
                        st[a] = st[a].wrapping_add(st[b]);
                        st[d] ^= st[a];
                        st[d] = st[d].rotate_left(16);
                        st[c] = st[c].wrapping_add(st[d]);
                        st[b] ^= st[c];
                        st[b] = st[b].rotate_left(12);
                        st[a] = st[a].wrapping_add(st[b]);
                        st[d] ^= st[a];
                        st[d] = st[d].rotate_left(8);
                        st[c] = st[c].wrapping_add(st[d]);
                        st[b] ^= st[c];
                        st[b] = st[b].rotate_left(7);
                    }
                    qround(&mut state, 0,  4,  8, 12);
                    qround(&mut state, 1,  5,  9, 13);
                    qround(&mut state, 2,  6, 10, 14);
                    qround(&mut state, 3,  7, 11, 15);
                    qround(&mut state, 0,  5, 10, 15);
                    qround(&mut state, 1,  6, 11, 12);
                    qround(&mut state, 2,  7,  8, 13);
                    qround(&mut state, 3,  4,  9, 14);
                }

                for j in 0..4 {
                    state[j] = state[j].wrapping_add(CW[j]);
                }
                for j in 0..10 {
                    state[4 + j] = state[4 + j].wrapping_add(
                        u32::from_le_bytes(*<&[u8; 4]>::try_from(
                            &self.state[(4 * j)..(4 * j + 4)]).unwrap()));
                }
                state[14] = state[14].wrapping_add(
                    u32::from_le_bytes(*<&[u8; 4]>::try_from(
                        &self.state[40..44]).unwrap()) ^ (cc as u32));
                state[15] = state[15].wrapping_add(
                    u32::from_le_bytes(*<&[u8; 4]>::try_from(
                        &self.state[44..48]).unwrap()) ^ ((cc >> 32) as u32));
                cc += 1;

                for j in 0..16 {
                    let k = (i << 2) + (j << 5);
                    self.buf[k..(k + 4)].copy_from_slice(
                        &state[j].to_le_bytes());
                }
            }
            self.state[48..56].copy_from_slice(&cc.to_le_bytes());
            self.ptr = 0;
        }
    }

    impl PRNG for ChaCha20PRNG {

        fn new(seed: &[u8]) -> Self {
            let mut p = Self {
                buf: [0u8; 512],
                state: [0u8; 256],
                ptr: 0,
            };
            p.state[..56].copy_from_slice(seed);
            p.refill();
            p
        }

        fn next_u8(&mut self) -> u8 {
            if self.ptr == self.buf.len() {
                self.refill();
            }
            let x = self.buf[self.ptr];
            self.ptr += 1;
            x
        }

        fn next_u16(&mut self) -> u16 {
            let x0 = self.next_u8();
            let x1 = self.next_u8();
            (x0 as u16) | ((x1 as u16) << 1)
        }

        fn next_u64(&mut self) -> u64 {
            let mut i = self.ptr;
            if i >= (self.buf.len() - 9) {
                self.refill();
                i = 0;
            }
            self.ptr = i + 8;
            u64::from_le_bytes(
                *<&[u8; 8]>::try_from(&self.buf[i..(i + 8)]).unwrap())
        }
    }

    const KAT_RNG_1: [u64; 128] = [
        0xDB1F30843AAD694C, 0xFAD9C14E86D5B53C, 0x7F84F914F46C439F,
        0xC46A6E399A376C6D, 0x47A5CD6F8C6B1789, 0x1E85D879707DA987,
        0xC7B0CE6C2C1DB3E7, 0xA65795537B3D977C, 0x748457A98AC7F19C,
        0xD8C8F161EEB7231F, 0xE81CAE53A7E8967F, 0x27EAD55A75ED57F8,
        0x9680953F3A192413, 0x784145D6687EA318, 0x9B454489BE56BAEB,
        0xF546834B0F799C67, 0xAC8E4F657C93FB88, 0xD0E6C7610CC4028B,
        0x417296FB7E1124BD, 0xE7968F18E3221DDC, 0x1DDEC33FC7F2D5FB,
        0x76556A8C07FB48EE, 0x7910EAA4C163BC2F, 0xAAC5C6291F779D17,
        0x575B2692885C4CFA, 0x0664AA8C3E99DA19, 0xFA55C1AE9A615133,
        0x7F1DB1A620F63220, 0xE740AE9AF9CC9755, 0x8393056E1D0D81E1,
        0x556EEF4483B434AA, 0xC6D17BEF7C2FB0C3, 0x27D142BD5BBF6014,
        0x6FD90B14DB4AA0BB, 0x7ACDD6F240530D0D, 0xE980F9F9DBE6109A,
        0xA30C677211C7BF37, 0x1E41FD290B90CE8B, 0x478FCD48D5E4A9ED,
        0x10586F987EA5FA7A, 0x691891C568F5DAC7, 0x3277735ED18D9107,
        0x78FCC576E47E8D71, 0x940A2C6777E3BEBB, 0x814612E210DD9715,
        0xABBCAFCC6B54279B, 0x2550E2538A063BFC, 0x7965EFC9D3F8A5BE,
        0xAE35E74B5A0B8717, 0xD855D6ABB96EA3AF, 0xAB4689B903C01C4E,
        0x8D8018988CA554AC, 0x0BB6689524F3A2B1, 0xAC0676FCBB193A87,
        0xD0A83D30F34F65EC, 0x26D3A8C167CA09F4, 0x7D17403D2B1DD9A0,
        0x47B1C836A0224550, 0xF6ABECF6422C5A56, 0x6FB1B2FF5CDDEC25,
        0x118276B244B55F88, 0x1FB953EF9E6C2C41, 0xF351C2717ACE9BF3,
        0xDF787B64D51A5440, 0xE4B8B81149B8A70B, 0x337E5363F506228B,
        0x48948ADE314B5980, 0x7FBF7A7139004610, 0xA6CB33F6802C96C7,
        0x745888A51A99BBED, 0x49D411403BA9CFDA, 0xA547A6EA4BDD5538,
        0x2D65DCF44F045E9F, 0x734FBE9360EFCC44, 0x1131E0AD573D37A0,
        0xADF3E9199FD90113, 0x8EDF3EAF50E6E00B, 0xFE0240D04C171901,
        0x45A97204596F7C46, 0x54D1D1F962484BC5, 0xEBAC109CDB975ED4,
        0x51182BF46BD2D61C, 0xF12D0EC8A80092D3, 0x69CA22BA55B34270,
        0x5FF97BBE7A525BF7, 0xF4E19780A4149ACA, 0x2CD5AE45826309FC,
        0xF0EF1F0A309C1BCF, 0xC16AF49962FE8A87, 0x2CD2575C27761E54,
        0xD9199411E9CC816D, 0xA0C397A63D036B05, 0xF439D283DFE4C172,
        0x5DAAD309E61F2A60, 0x2E7DDC8F9CD47E91, 0x2E1BFCDDC439FD58,
        0x8E62B7C84C3C27F8, 0xECD06ED0C1938A5E, 0x0335351E644A9155,
        0x71A735982C6DBBF7, 0xD8FE9FAF2DDF9AFF, 0x06BC9F654B9814E7,
        0x2DF46A488EC46052, 0x80CB8E04CDEF7F98, 0x9B65042EE20B4DAF,
        0x203BF49ACB5B34D2, 0x54E8F69957D8903B, 0x84D63D4BA389AF36,
        0x7A2D4A2230D0DC82, 0x3052659534D82FB8, 0xC5058A8EC3716238,
        0xB8063774064F4A27, 0x2F0BE0CE382BFD5B, 0xEE4CEAD41973DA0F,
        0xFB56581EB2424A5A, 0x09F21B654D835F66, 0x1968C7264664F9CC,
        0x2CBD6BB3DD21732C, 0xA9FB1E69F446231C, 0xDBEAD8399CB25257,
        0x28FF84E3ECC86113, 0x19A3B2D11BA6E80F, 0xC3ADAE73363651E7,
        0xF33FFB4923D82396, 0x36FE16582AD8C34C, 0x728910D4AA3BB137,
        0x2F351F2EF8B05525, 0x8727C7A39A617AE4
    ];

    const KAT_RNG_2: [u8; 1024] = [
        0xC9, 0x45, 0xBC, 0xC4, 0x5B, 0x67, 0xA3, 0x25, 0x97, 0x19,
        0x64, 0x67, 0x4A, 0x98, 0xD4, 0xB7, 0xA7, 0x83, 0x18, 0xC8,
        0x40, 0xE2, 0x7F, 0xB8, 0x25, 0x8B, 0x7E, 0x92, 0x4A, 0x8C,
        0x68, 0x1B, 0x77, 0x61, 0x1E, 0x70, 0xED, 0xC2, 0xC4, 0xA5,
        0xDF, 0x9E, 0x76, 0xED, 0x49, 0x84, 0x3D, 0x08, 0xFE, 0xFE,
        0x99, 0xE2, 0xC6, 0xEF, 0xFE, 0x2C, 0xD4, 0xC0, 0x04, 0xD8,
        0x9A, 0x51, 0x21, 0xCD, 0x5B, 0xDB, 0x9F, 0x0B, 0x9C, 0x47,
        0xCF, 0xE8, 0x38, 0x6B, 0xB4, 0x94, 0xDC, 0xCD, 0x9A, 0x9B,
        0xB7, 0xED, 0xEE, 0x82, 0x64, 0x53, 0x20, 0xA0, 0x8F, 0x59,
        0xB2, 0x4F, 0xE2, 0x5A, 0x35, 0x88, 0x39, 0x5B, 0x6C, 0x59,
        0x59, 0x8C, 0x10, 0xC5, 0x2B, 0xF3, 0x7C, 0x49, 0xFD, 0x99,
        0x0C, 0x86, 0x07, 0x9E, 0x35, 0x71, 0x8E, 0x23, 0x7B, 0x9D,
        0x23, 0x34, 0x7A, 0xC8, 0x8A, 0x17, 0xDA, 0x7B, 0xA2, 0x97,
        0x0A, 0x78, 0x2B, 0x19, 0xAD, 0xB1, 0x35, 0xBD, 0xB1, 0xE7,
        0x74, 0x4B, 0x82, 0xFB, 0x72, 0x9C, 0x8C, 0x51, 0x3B, 0xE3,
        0xF0, 0x31, 0x11, 0xAA, 0x59, 0xA4, 0x66, 0xAC, 0xAA, 0x9E,
        0x85, 0xD9, 0x2D, 0xAD, 0xCA, 0x2B, 0x69, 0x5E, 0x19, 0x9F,
        0x77, 0x15, 0x43, 0xF0, 0xC9, 0x9F, 0xBC, 0x5B, 0x66, 0x26,
        0x7F, 0x7D, 0x7C, 0x95, 0x5D, 0x60, 0xE0, 0x49, 0x15, 0xC4,
        0x56, 0x47, 0x7E, 0x8D, 0x68, 0x3C, 0x54, 0x6F, 0x20, 0xF9,
        0x00, 0x43, 0xB4, 0x52, 0xD8, 0x46, 0x51, 0xFC, 0x0B, 0x92,
        0x15, 0xEF, 0x56, 0x45, 0x49, 0x94, 0xC2, 0xD0, 0x5E, 0x95,
        0xC4, 0x6D, 0x00, 0xDD, 0x13, 0x93, 0x78, 0xC2, 0x85, 0x21,
        0x5D, 0x18, 0x92, 0xB9, 0x48, 0xD2, 0x96, 0x45, 0x89, 0x0D,
        0x69, 0x2B, 0x85, 0x5D, 0x23, 0x5D, 0x10, 0x92, 0xD7, 0xDC,
        0xDC, 0xF8, 0x60, 0x5E, 0xED, 0x1F, 0x21, 0xB2, 0x19, 0x27,
        0xB7, 0xB7, 0xCD, 0x49, 0x98, 0x29, 0x90, 0xC9, 0x81, 0xCD,
        0x4E, 0x44, 0xB5, 0x39, 0x56, 0xED, 0x2B, 0xAA, 0x53, 0x34,
        0x3B, 0xB0, 0xBA, 0x1F, 0xBC, 0xF8, 0x58, 0x5F, 0x3E, 0xD0,
        0x4D, 0xB3, 0xA8, 0x5E, 0xC9, 0xB8, 0xD2, 0x70, 0xD3, 0x30,
        0xC0, 0x3C, 0x45, 0x89, 0x9B, 0x4C, 0x5F, 0xE8, 0x05, 0x7F,
        0x78, 0x99, 0x48, 0x3A, 0xD7, 0xCB, 0x96, 0x9A, 0x33, 0x97,
        0x62, 0xE9, 0xBD, 0xCE, 0x04, 0x72, 0x4D, 0x85, 0x67, 0x51,
        0x69, 0xFB, 0xD3, 0x12, 0xBC, 0xFC, 0xB5, 0x77, 0x56, 0x3B,
        0xB9, 0xB5, 0x3D, 0x5D, 0x7D, 0x2B, 0x34, 0xB0, 0x36, 0x2D,
        0x56, 0xE9, 0x24, 0xC2, 0x5A, 0xE9, 0x2A, 0xF8, 0xEE, 0x83,
        0x74, 0xC1, 0x0C, 0x80, 0xAD, 0x43, 0x5C, 0x04, 0x49, 0xB0,
        0x41, 0xD2, 0x29, 0x32, 0x9C, 0x7D, 0x70, 0xD5, 0x3D, 0xFE,
        0x82, 0x27, 0x8A, 0x38, 0x19, 0x12, 0x14, 0x78, 0xAA, 0x2A,
        0x29, 0xE2, 0x2B, 0xBB, 0x87, 0x4F, 0x7A, 0xDC, 0xC0, 0x72,
        0x30, 0xB6, 0xDE, 0x73, 0x7C, 0x04, 0x2D, 0xB6, 0xDF, 0x5E,
        0x4C, 0x3B, 0x82, 0xF6, 0x10, 0xE4, 0x94, 0xCE, 0x90, 0xD4,
        0x23, 0x0C, 0xBD, 0xCA, 0x56, 0xB7, 0x09, 0x6C, 0xAC, 0x35,
        0xA8, 0x47, 0xF0, 0x94, 0x21, 0xBD, 0xD5, 0x09, 0x18, 0x78,
        0x7C, 0x8D, 0x1E, 0x03, 0x15, 0xB1, 0x1A, 0xE8, 0x72, 0xB7,
        0x98, 0x5F, 0x23, 0x3A, 0x91, 0xB2, 0xDF, 0xFD, 0x70, 0x69,
        0xC4, 0x3B, 0xFA, 0x73, 0x17, 0xCC, 0xFB, 0xCF, 0xA6, 0xCF,
        0xC1, 0x32, 0x3E, 0x74, 0x0C, 0xCC, 0x73, 0xB2, 0xBE, 0x73,
        0xAC, 0x8E, 0x44, 0x51, 0x45, 0xED, 0xF6, 0x60, 0x21, 0x3D,
        0x0C, 0xE3, 0x3E, 0x1B, 0x11, 0x55, 0x68, 0x1A, 0x15, 0x97,
        0x80, 0x67, 0x23, 0x4F, 0x37, 0xF5, 0x30, 0x3D, 0x05, 0x4E,
        0xCF, 0x0E, 0x03, 0xB9, 0x2F, 0xD1, 0xD5, 0xD6, 0x5F, 0x79,
        0xF6, 0x61, 0x15, 0xBC, 0x79, 0x80, 0xA4, 0xD7, 0x98, 0x5B,
        0x38, 0x7A, 0x07, 0x9B, 0x02, 0xB2, 0x47, 0x89, 0xB2, 0x25,
        0xEF, 0x7B, 0xB1, 0xB0, 0xA5, 0x35, 0x39, 0xEB, 0xA0, 0x1C,
        0x24, 0xF4, 0xDB, 0x0C, 0x6C, 0x2B, 0xA3, 0x75, 0x47, 0x00,
        0xA3, 0xC8, 0xBC, 0x1E, 0x15, 0x3A, 0xC6, 0x1D, 0x91, 0x19,
        0xBA, 0xB4, 0xCA, 0x28, 0xD2, 0x57, 0x7C, 0x0D, 0x71, 0x4A,
        0x03, 0xD5, 0xAE, 0x96, 0x6D, 0x92, 0x70, 0x27, 0x82, 0x88,
        0xB6, 0x12, 0x1A, 0x84, 0x38, 0x1B, 0x74, 0x2F, 0x74, 0x33,
        0xE0, 0xA1, 0x82, 0x93, 0x62, 0xB6, 0x5B, 0x9E, 0x4E, 0xC2,
        0xE6, 0x5B, 0x49, 0x7E, 0x4A, 0x68, 0x8D, 0x08, 0xA9, 0xD8,
        0xEA, 0x47, 0xFC, 0xD2, 0x31, 0x21, 0x38, 0xEE, 0xE4, 0xE4,
        0x97, 0xFA, 0x91, 0x90, 0xC4, 0x26, 0x4B, 0xA5, 0xB3, 0x7D,
        0x33, 0x7F, 0x5A, 0x2D, 0x54, 0xB3, 0x01, 0xCF, 0x9C, 0x0D,
        0x9E, 0x97, 0x01, 0xE8, 0x54, 0x3C, 0xC2, 0x13, 0x69, 0x0C,
        0x35, 0xCD, 0x63, 0x02, 0x70, 0xC8, 0xA1, 0x1F, 0xC2, 0xBE,
        0x8F, 0xFC, 0xCE, 0x05, 0xA7, 0x3F, 0xCC, 0x04, 0x3D, 0x18,
        0xC4, 0x13, 0x38, 0x0D, 0x4C, 0xEE, 0x81, 0xFA, 0x02, 0xF8,
        0xFC, 0x4F, 0x21, 0xD0, 0xE6, 0xF2, 0x7B, 0x92, 0x76, 0xC5,
        0x8E, 0x96, 0x6C, 0x53, 0x84, 0x3E, 0x74, 0x1D, 0xD5, 0x0F,
        0x98, 0x03, 0x0E, 0x6A, 0x9D, 0x49, 0x03, 0xAE, 0xBE, 0x70,
        0x61, 0x5B, 0x45, 0xC0, 0x1E, 0x2F, 0x94, 0x42, 0xFA, 0x16,
        0x9F, 0xFA, 0xD5, 0x9B, 0x60, 0x88, 0x92, 0x19, 0x08, 0x02,
        0x31, 0x99, 0x6D, 0xA1, 0x72, 0xCB, 0x45, 0xC6, 0x93, 0xBA,
        0xA8, 0x71, 0x42, 0xC6, 0x85, 0x28, 0x6C, 0x1B, 0x60, 0x7C,
        0x14, 0x2F, 0x9A, 0x17, 0x10, 0x34, 0x27, 0x48, 0x36, 0xB2,
        0xE8, 0xD3, 0xEA, 0xE4, 0x9D, 0x67, 0xE4, 0x46, 0x2E, 0xC6,
        0x41, 0xE1, 0x83, 0x42, 0xB8, 0x82, 0x5F, 0x79, 0x61, 0xA3,
        0x0C, 0x63, 0x00, 0xCB, 0x7C, 0xB9, 0x30, 0x53, 0xF4, 0xFC,
        0xAF, 0xAC, 0x22, 0x71, 0x87, 0x4D, 0x4B, 0x4B, 0x9E, 0xAE,
        0x69, 0xB5, 0x58, 0x04, 0x9C, 0x03, 0x57, 0x58, 0x8D, 0x2F,
        0x82, 0x95, 0x57, 0x2F, 0xC3, 0xA1, 0xC5, 0xB1, 0xF1, 0xF1,
        0x98, 0x9A, 0xF8, 0x99, 0x74, 0x5C, 0xC5, 0xAC, 0x4A, 0x32,
        0xE9, 0x24, 0xCF, 0x1D, 0x1E, 0x29, 0x18, 0x7C, 0xBF, 0x43,
        0x74, 0x23, 0x28, 0xB0, 0x3D, 0xD1, 0xB3, 0x8C, 0xE1, 0x28,
        0x02, 0x3E, 0x8F, 0x7F, 0xDD, 0xF0, 0x5B, 0x4D, 0x37, 0x96,
        0xF7, 0x73, 0x73, 0x7F, 0xBC, 0xAD, 0x6C, 0x84, 0xFC, 0x47,
        0xD2, 0x1E, 0xAB, 0xEB, 0xB6, 0xCA, 0x4E, 0x3A, 0x2C, 0x47,
        0x59, 0x61, 0x0D, 0xA0, 0x17, 0xCF, 0xDD, 0x62, 0x6F, 0xA3,
        0xF4, 0x72, 0x2D, 0xB0, 0xB2, 0x34, 0x2A, 0xE1, 0x63, 0xC3,
        0x5B, 0xAC, 0xE8, 0x6F, 0x92, 0x77, 0x78, 0xE2, 0x34, 0xAD,
        0x4F, 0x6C, 0xFF, 0x71, 0xE1, 0x92, 0xFD, 0xED, 0xA1, 0x20,
        0xCA, 0xCB, 0x80, 0x32, 0xD1, 0x78, 0x72, 0x68, 0xFE, 0xAE,
        0x73, 0x22, 0xD7, 0x60, 0x23, 0x1D, 0x3D, 0x06, 0xD6, 0x2A,
        0x81, 0xC4, 0x43, 0x98, 0xFD, 0x4E, 0xBD, 0x85, 0x09, 0x29,
        0x11, 0xE8, 0x36, 0xE1, 0xCE, 0xCF, 0x07, 0xA7, 0x45, 0x8C,
        0xCB, 0xB2, 0xDC, 0xD0, 0x98, 0xB9, 0x93, 0x33, 0x8A, 0x2A,
        0x13, 0x82, 0x36, 0x3D, 0x22, 0xB0, 0x9C, 0x74, 0x3F, 0xCE,
        0x6F, 0xCC, 0x69, 0xFF, 0x81, 0xE8, 0xAE, 0xC8, 0x57, 0x0D,
        0x98, 0xEB, 0xC5, 0x2A, 0x45, 0x55, 0xDC, 0xBB, 0x0A, 0x5B,
        0x3D, 0xB4, 0x61, 0xC4, 0xAE, 0x11, 0x68, 0x7D, 0xD4, 0x45,
        0x83, 0xAE, 0x66, 0xC8
    ];

    #[test]
    fn chacha20_prng() {
        let mut sh = SHAKE256::new();
        sh.inject(&b"rng"[..]);
        sh.flip();
        let mut seed = [0u8; 56];
        sh.extract(&mut seed);
        let mut p = ChaCha20PRNG::new(&seed);

        for i in 0..KAT_RNG_1.len() {
            assert!(p.next_u64() == KAT_RNG_1[i]);
        }
        for i in 0..KAT_RNG_2.len() {
            assert!(p.next_u8() == KAT_RNG_2[i]);
        }
    }

    // Fake CryptoRng that returns only predefined data, for test purposes.
    struct FakeCryptoRng(usize);
    impl CryptoRng for FakeCryptoRng {}
    impl RngCore for FakeCryptoRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!();
        }
        fn next_u64(&mut self) -> u64 {
            unimplemented!();
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.copy_from_slice(&KAT_512_RND[self.0..(self.0 + dest.len())]);
            self.0 += dest.len();
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test]
    fn sign_512() {
        // We use a fake random source that returns some predefined bytes.
        let mut rng = FakeCryptoRng(0);

        // Sign a specific message with the private key.
        let mut tmp_i16 = [0i16; 2 << 9];
        let mut tmp_u16 = [0u16; 2 << 9];
        let mut tmp_flr = [flr::FLR::ZERO; 9 << 9];
        let mut sig = [0u8; signature_size(9)];

        // We are using the original Falcon rules; public key does not
        // actually matter.
        let mut hvk = [0u8; 64];
        let mut sh = shake::SHAKE256::new();
        sh.inject(&KAT_512_VK);
        sh.flip();
        sh.extract(&mut hvk);

        #[cfg(not(feature = "small_context"))]
        let basis = {
            let mut basis = [flr::FLR::ZERO; 4 << 9];
            compute_basis_inner(9,
                &KAT_512_f, &KAT_512_g, &KAT_512_F, &KAT_512_G, &mut basis);
            basis
        };

        sign_inner::<FakeCryptoRng, ChaCha20PRNG>(9, &mut rng,
            &KAT_512_f, &KAT_512_g, &KAT_512_F, &KAT_512_G,
            &hvk, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &b"data1"[..],
            &mut sig,
            #[cfg(not(feature = "small_context"))]
            &basis,
            &mut tmp_i16, &mut tmp_u16, &mut tmp_flr);

        // Check that the signature value (s2) is exactly the one which
        // was expected.
        assert!(sig[0] == 0x39);
        assert!(sig[1..41] == KAT_512_RND[0..40]);
        let mut sig_raw = [0i16; 512];
        assert!(codec::comp_decode(&sig[41..], &mut sig_raw[..]));
        assert!(sig_raw == KAT_512_sig_raw);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn sign_avx2_512() {
        if !fn_dsa_comm::has_avx2() {
            return;
        }
        // We use a fake random source that returns some predefined bytes.
        let mut rng = FakeCryptoRng(0);

        // Sign a specific message with the private key.
        let mut tmp_i16 = [0i16; 2 << 9];
        let mut tmp_u16 = [0u16; 2 << 9];
        let mut tmp_flr = [flr::FLR::ZERO; 9 << 9];
        let mut sig = [0u8; signature_size(9)];

        // We are using the original Falcon rules; public key does not
        // actually matter.
        let mut hvk = [0u8; 64];
        let mut sh = shake::SHAKE256::new();
        sh.inject(&KAT_512_VK);
        sh.flip();
        sh.extract(&mut hvk);

        #[cfg(not(feature = "small_context"))]
        let basis = {
            let mut basis = [flr::FLR::ZERO; 4 << 9];
            unsafe {
                sign_avx2::compute_basis_avx2_inner(9,
                    &KAT_512_f, &KAT_512_g, &KAT_512_F, &KAT_512_G, &mut basis);
            }
            basis
        };

        unsafe {
            sign_avx2::sign_avx2_inner::<FakeCryptoRng, ChaCha20PRNG>(
                9, &mut rng,
                &KAT_512_f, &KAT_512_g, &KAT_512_F, &KAT_512_G,
                &hvk, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &b"data1"[..],
                &mut sig,
                #[cfg(not(feature = "small_context"))]
                &basis,
                &mut tmp_i16, &mut tmp_u16, &mut tmp_flr);
        }

        // Check that the signature value (s2) is exactly the one which
        // was expected.
        assert!(sig[0] == 0x39);
        assert!(sig[1..41] == KAT_512_RND[0..40]);
        let mut sig_raw = [0i16; 512];
        assert!(codec::comp_decode(&sig[41..], &mut sig_raw[..]));
        assert!(sig_raw == KAT_512_sig_raw);
    }

    const KAT_512_f: [i8; 512] = [
        -4, -2, -5, -1, 4, -2, 0, -3, -1, 1, -2, -2, -6, -3, 3, -5, -1,
        4, -3, -8, 4, -1, 2, -1, -8, 5, -6, -3, 6, 0, -2, 4, 5, -6, 2,
        3, 6, 4, 2, 3, 3, 7, 0, 1, 5, -3, -1, -9, -1, 6, -2, -5, 4, 0,
        4, -2, 10, -4, -3, 4, -7, -1, -7, -2, -1, -6, 5, -1, -9, 3, 2,
        -5, 4, -2, 2, -4, 4, -3, -1, 0, 5, 2, 2, -1, -9, -7, -2, -1, 0,
        3, 1, 0, -1, -2, -5, 4, -1, -1, 3, -1, 1, 4, -3, 2, -5, -2, 2,
        -4, 3, 6, 3, 9, 1, -2, 4, -1, -1, -6, -2, -2, 4, 5, -1, 0, 10,
        -2, 1, -2, -3, 0, -4, -4, -1, 0, 1, -5, -3, -7, -2, -1, 2, -6,
        3, 0, 0, 4, -4, 0, 0, -5, -2, 5, -8, 8, 5, 4, 10, -4, 3, 8, 5,
        1, -7, 0, -5, 0, -4, 3, -4, -2, 2, -2, 6, 8, 2, -1, 4, -4, -2,
        1, 0, 3, 7, 0, 9, -3, 1, 4, -3, 2, -1, 5, -8, 4, -1, 1, -8, 2,
        4, -9, -3, 1, 3, -1, -7, 5, 5, 4, -3, 0, -7, -3, -1, -6, -7, 0,
        -3, 0, 3, -3, 0, -3, 1, 3, 4, -6, -6, -3, 6, 0, 2, -5, 1, -3,
        -6, -6, -1, -7, -2, -4, 3, 0, -4, -1, 2, 7, -7, -2, 4, 2, 0, 1,
        -1, -3, 2, 1, 8, -1, 1, -2, 1, -1, 1, 4, 0, -4, 4, 3, -2, 6, -3,
        -2, 1, 2, 3, 6, 5, -4, -7, -6, 4, 3, -4, 3, -3, 3, -3, 2, -1, 1,
        5, -2, 2, 1, 0, -7, 0, 0, -1, 4, -3, 2, 1, -3, 5, 4, -6, -1, -3,
        2, -1, -8, 4, 2, 4, 0, 1, -5, 8, 5, 4, -3, -1, -2, 4, 0, 2, -2,
        0, -2, -1, -7, 5, 0, 1, 2, 1, -2, 2, -1, 1, -4, 1, 0, 4, -4, 0,
        5, 1, 4, -5, -2, -3, -2, 1, 3, 1, 2, 5, 12, 0, -1, 4, -6, 1, -4,
        3, -5, -4, 4, 2, -2, -6, 1, 1, 3, -1, 0, -4, -4, -4, 6, -2, 4,
        -3, 0, -2, -1, 0, -6, -3, -2, 0, 6, 5, -5, -5, 3, 0, 3, -3, -2,
        5, 7, -3, 1, -1, 0, 3, 0, 3, -7, 2, -4, -4, 1, 1, 1, 0, -3, -8,
        3, 6, 1, -2, -7, 3, 3, 4, -1, -2, -5, 9, 7, 1, 2, -4, 4, 0, -11,
        3, 0, -3, -5, 5, -1, -1, 7, 6, -1, 6, 3, 9, 5, -2, -3, -3, 1,
        -2, 0, -1, 1, -2, 2, 0, -5, -1, -4, -2, 2, -1, -3, 0, -3, 0, 1,
        3, -3, 2, 5, 8, -2, 3, -4, -7, 0, 4, -8, 1, 8, -2, 1, -1, 2, 0,
        -2, 1, 3, 3, 4, -2, -4, 3, -4, 2, 3, -2, -4, 1, -4, 10, 2
    ];
    const KAT_512_g: [i8; 512] = [
        -1, 5, -7, -1, -4, 6, 4, -1, -4, -13, -1, -5, -2, -8, 2, 1, 4,
        2, 0, 0, 2, 0, -1, 2, 5, -5, -8, 8, 1, 11, 0, -8, -4, 1, 1, -6,
        -4, 1, -3, 0, -10, -4, -6, -3, -2, 1, 6, 2, 8, -2, 2, -2, 1, 3,
        -4, 2, -1, -1, -2, -2, -3, 0, -3, 2, -3, 2, -3, -4, 2, 3, 4, -5,
        6, -3, -2, -1, -1, -6, -2, 1, -4, -7, 8, 0, 2, -2, 2, 0, 1, 0,
        4, 9, 7, 0, -1, -1, 4, -3, -2, 6, 6, 0, 1, 7, -6, -5, 5, 1, 4,
        -1, 0, -2, 3, -4, 1, -1, -3, -2, 0, -1, -7, -8, -1, 2, 0, -5, 0,
        1, -4, 6, -5, 6, 4, 1, -4, -5, 8, -1, 1, -2, 1, 1, 1, 3, 0, -1,
        1, 1, -4, -5, -4, 2, -3, 2, -2, 3, 7, -4, 4, -1, -2, 4, -4, -5,
        2, 6, -7, 5, -1, 1, 3, 0, -5, -5, 3, -2, -3, -1, -6, 0, 2, 3, 2,
        7, -3, -2, -2, 1, -5, 3, 3, -7, 0, 4, 4, -1, 2, -3, 1, 3, -1,
        -1, 0, -7, -6, -3, 7, -3, 5, -5, 1, -2, 0, 9, -2, 3, -1, -5, -3,
        -5, 3, 1, -4, -3, 2, -2, 2, 8, -1, 0, 5, -3, -2, -6, 4, 0, 3,
        -3, -3, 4, -1, 0, 0, -2, -1, 3, 7, 4, 5, -1, 8, 0, -1, -6, -3,
        4, 3, -3, 5, 2, -1, -2, 1, -1, 3, -2, -6, 4, 0, 0, -4, 1, 6, 2,
        0, 10, 9, 2, -2, 0, 2, 1, -3, -1, -1, 3, 2, 1, 1, -3, -2, 7, 2,
        -1, 5, -3, -2, 1, -2, 2, -2, -4, 3, 2, 1, -4, 1, 4, 3, -7, -4,
        2, -5, -2, 5, -3, 1, -4, -5, 1, 0, 0, 0, 7, -5, -1, 2, 2, -3, 6,
        -6, 4, -3, -5, -6, -7, -4, 3, -2, -2, -10, -3, 2, -1, -6, -4, 1,
        2, 2, 1, 4, 1, -5, -10, -2, 2, -4, 4, 4, -2, 1, 4, -3, 0, -6,
        -3, 1, 5, -7, -6, -4, 8, -1, 0, -1, 6, -3, -2, -2, 6, 2, 3, -3,
        -3, 5, -2, 1, 1, -4, -4, 8, 0, 3, 2, 3, 7, 4, 3, 2, -6, -9, 0,
        -8, 11, -2, 2, -2, -2, 3, 0, -6, 2, -1, 4, 2, -2, 0, -3, -7, -1,
        -1, 0, -1, -4, -2, -5, 3, -4, 2, 2, -1, -1, 7, -1, 3, 6, -7, 1,
        -5, 0, -7, 4, 3, -5, -1, 0, 3, -4, 1, 2, -7, 1, -2, -8, -2, -5,
        -5, 1, -4, -4, 4, -3, -2, 2, -4, -8, -1, 0, -9, 5, -1, -2, 3, 2,
        6, -1, 1, -1, -5, 5, 9, 3, -6, -5, 1, -6, 0, 2, -4, 6, 2, 7, 2,
        15, 0, -2, 9, 0, 1, 6, 4, -1, -1, -6, -3, 3, 1, -6, -3, 2, 2, -2
    ];
    const KAT_512_F: [i8; 512] = [
        0, -25, -39, 21, 7, -5, -10, 4, -1, -38, -9, -1, 4, -23, 15, -1,
        8, 1, -38, 41, 29, 22, 9, 12, -46, 0, 9, -17, -19, 32, 38, -3,
        14, 6, 2, -6, -18, -1, 23, 80, -12, -20, 24, 22, -31, -38, -11,
        8, 17, 18, 19, -10, 0, -1, 28, -5, -28, -33, 4, -31, -33, -8,
        -9, -44, 46, -11, -5, -21, -22, -7, 1, -11, 33, -8, 12, -7, -6,
        63, 17, 12, -49, -11, -31, -8, 7, -28, 33, -28, -19, 8, 46, -73,
        9, 32, 18, 7, -43, 0, -6, -4, 8, -39, -17, 11, 15, -25, -9, -28,
        -2, 24, -23, 10, -15, 4, 41, 46, 18, 2, -3, -29, 11, -3, 20, 35,
        21, 23, 5, -8, -3, -27, -69, 0, 26, -29, -24, 8, 19, 6, -14,
        -18, 47, 5, 21, -50, 17, -44, -36, 24, 9, 16, -38, -5, -54, 34,
        13, 31, -2, 9, 8, -12, -14, -17, 28, -59, -20, 19, 31, 14, 14,
        7, -32, 37, 5, -3, -7, -6, 21, -29, -33, 23, -25, -23, 14, 38,
        -29, -33, -9, 23, -43, 18, -12, 2, 30, 32, -28, -21, 42, 1, 6,
        -6, 58, 34, -22, 1, 5, -2, -8, 14, -19, -4, -6, 10, -3, -3, 32,
        18, -19, -12, 49, 13, 4, -18, 57, 37, -19, 25, 14, 18, -51, 13,
        4, 4, 17, -37, -2, 1, 41, -36, -8, -13, 49, -6, 9, 46, -36, -6,
        -20, -18, -6, -29, -42, -21, -25, -29, 5, -41, 51, 49, -20, -22,
        -9, 3, -6, -52, 10, 41, 12, -27, -20, 31, -17, -23, -16, 3, 44,
        -3, -5, -2, 0, -22, 14, -30, -41, 3, -27, 3, 18, 38, 10, 49, 45,
        -13, -27, -4, -10, -67, -1, -17, -2, 72, 46, 20, 24, 22, 16, 25,
        6, -6, -31, 2, 0, -13, -14, 9, 4, 31, 18, 22, 12, 59, -1, -3,
        -24, -47, -10, 48, 37, -34, -32, -4, 18, -2, 52, -8, -7, 34,
        -44, -14, -21, -49, -35, 41, -4, 31, 3, 23, 9, 8, 0, -24, 38,
        -9, -9, 4, -10, -55, -19, 21, 27, 22, 41, 6, -23, 41, -2, 28,
        -46, 20, 52, 16, 20, 32, 18, 2, -3, 9, 16, 33, -18, 12, 6, -9,
        -19, 1, -5, -15, -17, 6, -3, 4, -22, 30, -34, 43, -4, 9, -3,
        -33, -43, -5, -13, -56, 38, 16, 11, -36, 11, -4, -56, 2, 0, -19,
        -45, -8, -34, 16, 31, -3, 16, 27, -16, -9, 8, 45, -51, -20, 62,
        -17, -4, 4, 17, -45, 4, -15, -19, 39, 39, 15, 17, -19, 2, 45,
        36, -22, 16, -23, 28, 34, 12, 5, 10, -7, 28, -35, 17, -37, -50,
        -28, 19, -25, 9, 45, -6, -7, -16, 57, 27, 50, -30, 2, -10, -1,
        -57, -49, -23, 0, -9, -36, -4, -3, 32, -6, -25, 67, -27, -19,
        25, -6, 1, -17, -14, 0, 29, 26, -12, -20, 44, 14, 10, 8, -11,
        -18, -53, 22, 25, 27, 35, 6, -16, 12, 71, -8
    ];
    const KAT_512_G: [i8; 512] = [
        27, 6, 12, -3, -31, -42, 27, 17, 11, 8, 34, 6, -3, 2, 11, -11,
        18, 48, 1, 21, -7, -6, 9, 33, -18, -40, -55, -9, -71, -50, 32,
        -36, 11, 4, 29, 33, 10, -19, -43, -10, 22, -36, -23, -21, -14,
        -47, 25, -4, -14, 30, 16, -18, -11, 6, -37, -27, -12, 6, 7, 33,
        -36, 33, -2, 12, -21, 1, 16, 49, -11, -16, -41, 15, 11, 8, 20,
        -15, 26, -8, 11, -43, -36, 28, 2, -47, -30, -47, -1, 1, 48, -6,
        -22, 24, -20, -3, -1, -15, -12, 62, 12, 7, -9, 15, -71, 49, 22,
        27, 20, -8, -28, -13, -31, 18, 28, 54, 29, 5, 0, 33, -5, -22,
        -21, -12, -14, -2, 11, -24, 32, -26, -71, 21, -15, -20, -12, 36,
        -5, 35, 46, 13, -34, -8, 10, -10, 10, 40, -52, 8, 0, 18, -33,
        -10, 8, 43, -8, -6, -31, -17, 19, 30, 12, -9, 8, -19, -32, -18,
        -1, -37, 4, 43, 27, 14, -6, -14, -44, -34, -8, 16, -39, 13, 6,
        -32, 8, 17, -12, 23, -44, -25, -66, -12, -31, 30, 14, -9, -5,
        -10, 44, -12, -2, -43, -22, -18, -7, -9, -15, -7, -21, -27, -5,
        1, -13, -10, 8, -8, 29, 21, 64, 47, -28, -9, -28, 25, -47, -34,
        -3, -14, -26, -12, -5, -10, -27, -9, -14, -23, -2, -31, 28, 17,
        -4, -30, 31, 3, -15, 25, 9, -32, 0, -6, -22, 20, -37, 3, 12,
        -19, -17, 13, 30, 11, -15, 15, 50, 66, -31, -31, 16, 2, 3, -8,
        40, -21, -31, -2, 41, -29, -12, 9, 14, -4, 9, 8, -20, 28, 12,
        20, -10, 5, -6, -33, 6, 21, 51, 30, 9, 3, 8, 7, 19, -53, 19, 15,
        4, -38, 19, 29, 18, 6, 19, 3, -17, -32, 16, 3, 46, -6, -3, 47,
        3, -66, 3, 25, -6, -6, 21, -24, -9, 28, -39, -42, 42, -6, -19,
        -14, 6, -8, 9, 28, -4, 23, 12, -17, -13, 3, 3, 6, 44, 6, -5, 38,
        -4, -16, 12, -15, 8, -11, 45, 1, -16, 37, -35, 20, 26, 9, 13,
        34, 25, -3, -10, -2, -42, -23, -22, -56, -56, 6, 17, -9, 0, 36,
        20, 6, -58, 12, 0, -3, -29, -49, -24, -12, -13, 5, -39, -8, 36,
        -9, 44, 35, -64, -22, -12, 26, -15, 41, 36, -19, -37, -20, 46,
        35, 9, 32, -5, 27, 21, -36, -51, 19, 10, -23, 28, 46, 28, 8, 22,
        -31, 18, 2, -16, -9, 1, -22, -22, 31, 14, 5, 44, -3, 38, 0, -12,
        50, -23, -19, 1, 42, 15, 1, 13, 32, 45, 37, 15, 11, -9, -23, -6,
        -23, 36, 4, -34, -14, -14, -37, -28, 19, 20, 14, 24, -48, -34,
        -27, -34, -12, 9, -20, -30, 25, 28, -51, -13, 11, -20, -1, -3,
        6, -38, -46, -15, 28, 10, -4, 3, -1, 4, -40, 16, 61, 31, 28, 8,
        -2, 21, -3, -25, -12, -32, -15, -38, 20, -7, -35, 28, 29, 9, -27
    ];
    const KAT_512_VK: [u8; 897] = [
        0x09, 0x02, 0xCE, 0x21, 0x6B, 0xE4, 0x2C, 0xD0, 0x4F, 0xC8,
        0x4C, 0x24, 0xC7, 0x1D, 0x13, 0x07, 0x8E, 0xCA, 0x07, 0x97,
        0x6E, 0xE4, 0xAD, 0xBA, 0x2C, 0x98, 0x23, 0x46, 0xD8, 0x78,
        0xC0, 0x94, 0x76, 0x7F, 0xE2, 0x9C, 0x34, 0x5C, 0xE2, 0xFA,
        0x87, 0x4B, 0xEE, 0x23, 0x9E, 0xA6, 0x0B, 0xDF, 0xA7, 0x27,
        0xA5, 0x16, 0x82, 0xC3, 0xDF, 0x06, 0xA2, 0x68, 0x49, 0xC3,
        0xF7, 0x26, 0x46, 0x2A, 0x59, 0xE9, 0xC4, 0x16, 0x63, 0x87,
        0xBA, 0x89, 0x56, 0xDF, 0xC9, 0xFA, 0x62, 0x20, 0x95, 0x20,
        0xED, 0x65, 0x39, 0xCA, 0xDD, 0xA8, 0xF9, 0xE8, 0x11, 0xA6,
        0x8E, 0xD8, 0x69, 0x70, 0x13, 0x5A, 0xD5, 0x02, 0x6D, 0xBD,
        0x16, 0xF1, 0x59, 0x97, 0xA4, 0xBB, 0xBE, 0x35, 0x68, 0x38,
        0xD7, 0x5C, 0x7A, 0x91, 0x34, 0xED, 0xB8, 0xBF, 0x25, 0xBC,
        0xBA, 0x0A, 0x03, 0x13, 0x77, 0xEB, 0xF0, 0x11, 0x0D, 0x54,
        0x73, 0xC8, 0x46, 0x82, 0x7B, 0x25, 0x6B, 0x9A, 0xB4, 0xD0,
        0x26, 0x1E, 0x41, 0xC8, 0xDB, 0xF1, 0xA4, 0x24, 0xB6, 0xDA,
        0x1F, 0x21, 0xD0, 0xE2, 0x1A, 0x89, 0xBD, 0x29, 0x94, 0x07,
        0x4F, 0xA5, 0x36, 0x5E, 0xA7, 0x70, 0x0E, 0xEB, 0xD2, 0x26,
        0x94, 0x7C, 0xFA, 0x7B, 0xE1, 0xA7, 0x65, 0xF4, 0xD7, 0xF9,
        0x27, 0x50, 0x02, 0x3D, 0xF2, 0x68, 0x94, 0x51, 0x2E, 0x79,
        0x48, 0xC5, 0x64, 0x69, 0xE8, 0x81, 0xD1, 0x99, 0xDA, 0x81,
        0x35, 0xAF, 0xC1, 0x6E, 0x52, 0x3A, 0xF8, 0xA2, 0x3F, 0xD5,
        0x80, 0x22, 0xAE, 0x22, 0x9A, 0xC9, 0x5C, 0xFF, 0x09, 0x5D,
        0x6F, 0xF3, 0x2C, 0x89, 0x0D, 0xB2, 0x29, 0x41, 0x19, 0x21,
        0x90, 0x5B, 0x3B, 0xA5, 0x2D, 0x54, 0xB5, 0x0D, 0xEC, 0xB4,
        0x4D, 0xC3, 0xD7, 0xC8, 0x99, 0x66, 0x79, 0xE8, 0x28, 0xA4,
        0x3B, 0x8D, 0x06, 0x87, 0xE8, 0xBD, 0xE0, 0x60, 0xC5, 0x10,
        0x15, 0xAA, 0x9E, 0x00, 0x0C, 0x92, 0x59, 0x8F, 0x05, 0xB8,
        0x70, 0xA9, 0x4B, 0x29, 0x01, 0xA9, 0xE1, 0x2A, 0xE9, 0xAB,
        0xF2, 0x0A, 0x51, 0x71, 0x4A, 0x03, 0x6A, 0x85, 0x1C, 0xCE,
        0x89, 0x15, 0x42, 0xD1, 0xEB, 0x52, 0x7E, 0x73, 0x10, 0x76,
        0xD4, 0xFF, 0x2F, 0x09, 0xBA, 0x68, 0x94, 0xA2, 0x09, 0x03,
        0xCA, 0x6F, 0xA7, 0x6E, 0x13, 0xD1, 0x2D, 0xC0, 0xAB, 0xA6,
        0xB9, 0x26, 0xED, 0x6E, 0x89, 0x54, 0x84, 0x1D, 0xC0, 0x52,
        0x4A, 0x55, 0xE3, 0x65, 0x6C, 0x9C, 0x19, 0x88, 0x5E, 0xAB,
        0x65, 0x4D, 0x86, 0x94, 0x93, 0x51, 0xFB, 0x8B, 0x02, 0xEA,
        0x32, 0xAE, 0x71, 0x5F, 0x09, 0x8B, 0xE2, 0x4E, 0x83, 0xD2,
        0xE2, 0x71, 0xCC, 0x8C, 0x24, 0x14, 0x8E, 0x7B, 0xD5, 0x92,
        0x59, 0x28, 0x38, 0xFA, 0x55, 0xB8, 0x8A, 0xDB, 0x89, 0x7B,
        0xE5, 0xD9, 0x96, 0x97, 0xE3, 0xFC, 0xAC, 0xFA, 0xC0, 0x25,
        0xB4, 0x51, 0xF6, 0x2B, 0x6C, 0x35, 0x62, 0xC9, 0xEF, 0x90,
        0x71, 0x44, 0x57, 0xA2, 0xF6, 0x49, 0x22, 0x5F, 0x70, 0x20,
        0xE9, 0xAF, 0xDB, 0xB9, 0x2A, 0xE2, 0xBE, 0xDB, 0xA6, 0x19,
        0x33, 0xB9, 0x05, 0xCF, 0xD4, 0x1A, 0x03, 0x08, 0x2B, 0xD6,
        0xDF, 0x8B, 0x24, 0x27, 0xEC, 0x7B, 0xFC, 0xAB, 0x2A, 0xDE,
        0x16, 0x78, 0x9C, 0x09, 0x67, 0x45, 0x67, 0xDE, 0x11, 0x29,
        0xC1, 0xB2, 0xF6, 0x9E, 0x9C, 0x0F, 0x8F, 0xB2, 0x37, 0xC5,
        0x5D, 0x05, 0xCF, 0x8F, 0x69, 0xAD, 0x8B, 0xB7, 0x27, 0xA2,
        0x08, 0x9A, 0x43, 0x71, 0x1E, 0xC6, 0xCA, 0x54, 0xB6, 0x12,
        0xC1, 0xD7, 0x2F, 0xA0, 0x2B, 0x66, 0x40, 0x98, 0x78, 0x6D,
        0x08, 0x53, 0xD1, 0xBC, 0x98, 0xE1, 0x4A, 0x57, 0x90, 0xB2,
        0xCA, 0xC6, 0xC7, 0xD2, 0x48, 0x57, 0xD0, 0xFB, 0x44, 0xF5,
        0xD9, 0x5F, 0x34, 0x21, 0x33, 0x96, 0x86, 0xE8, 0xAF, 0xA5,
        0xBA, 0x92, 0x4B, 0xBA, 0x94, 0xF0, 0x73, 0xC9, 0x09, 0xE9,
        0xFB, 0x8A, 0xD0, 0xA4, 0x62, 0x24, 0xD6, 0xF8, 0x1B, 0x22,
        0xA2, 0x01, 0xAE, 0xDB, 0xA8, 0x94, 0xC2, 0xAA, 0x44, 0xBA,
        0xD6, 0x87, 0x4D, 0x6E, 0x24, 0xCE, 0x1B, 0xB8, 0x3F, 0x51,
        0xE6, 0x9F, 0x34, 0xA1, 0x40, 0xAD, 0x88, 0x55, 0x4F, 0x6C,
        0x47, 0x48, 0xFF, 0x9F, 0x64, 0x6F, 0x0D, 0xDB, 0xD3, 0xA4,
        0x85, 0xD0, 0xBA, 0xD8, 0x05, 0xFA, 0x29, 0xEB, 0x99, 0x68,
        0x18, 0x51, 0x71, 0x45, 0x05, 0xE3, 0x71, 0xA6, 0x4A, 0x7B,
        0xCF, 0x68, 0x97, 0x95, 0x81, 0x44, 0x91, 0xDC, 0x9D, 0xC5,
        0x27, 0x52, 0xE9, 0xA2, 0x7F, 0x96, 0xF4, 0x6C, 0xE8, 0xF8,
        0xA4, 0x27, 0x95, 0xC7, 0x10, 0x7E, 0xC1, 0x86, 0x78, 0x92,
        0x49, 0x6C, 0x91, 0xA1, 0x77, 0xFB, 0x80, 0x95, 0x0D, 0x69,
        0x3B, 0xD4, 0xAD, 0xDE, 0x30, 0x2E, 0x90, 0x3C, 0x41, 0x32,
        0xEC, 0x95, 0x38, 0x86, 0x8D, 0xE8, 0xCF, 0x80, 0x5F, 0x5A,
        0x21, 0x92, 0x96, 0x7F, 0xA6, 0xC3, 0x50, 0x6A, 0x1A, 0xAB,
        0x3C, 0x11, 0xA1, 0x5F, 0x1E, 0x47, 0xB3, 0xB4, 0x6E, 0x64,
        0x97, 0xB1, 0x5A, 0x88, 0x2E, 0x2C, 0xC8, 0x49, 0xA1, 0xB4,
        0x42, 0x49, 0xE9, 0x7F, 0x61, 0xF1, 0x6B, 0xD0, 0xEC, 0xEA,
        0xD5, 0x47, 0xDD, 0x71, 0xC5, 0xDD, 0xA5, 0xAA, 0x8A, 0x56,
        0xFE, 0x36, 0x31, 0x22, 0x15, 0x85, 0x2E, 0x78, 0xDA, 0x98,
        0x5D, 0x55, 0xA4, 0xA4, 0xD8, 0xF7, 0x14, 0x8E, 0x45, 0x67,
        0xD1, 0xE4, 0x67, 0x87, 0xC2, 0x23, 0x87, 0xCA, 0x4A, 0x85,
        0xF0, 0x11, 0xE3, 0x75, 0xC4, 0x5C, 0xCA, 0x0C, 0xE0, 0xA1,
        0x5B, 0xCD, 0x13, 0x37, 0xBD, 0xC9, 0x27, 0x1B, 0xFA, 0x84,
        0x73, 0xE1, 0x88, 0x2F, 0x33, 0x85, 0x58, 0x69, 0x7D, 0x9A,
        0xAF, 0x07, 0x5A, 0x90, 0x78, 0x33, 0x5A, 0x1F, 0xB8, 0xA1,
        0xB3, 0xB6, 0xE9, 0xD9, 0xCF, 0x43, 0x62, 0x84, 0x06, 0x7C,
        0x58, 0xC5, 0xA4, 0x8E, 0x04, 0x7A, 0x40, 0x08, 0xD0, 0x2B,
        0x7C, 0x85, 0x07, 0xC2, 0xEE, 0x6F, 0x88, 0xDA, 0x4C, 0x97,
        0xF6, 0x0F, 0x75, 0x44, 0x4C, 0x78, 0x84, 0x96, 0x67, 0x84,
        0x32, 0xC9, 0x5F, 0x3A, 0x92, 0x08, 0xB4, 0xA8, 0xC1, 0xCB,
        0xC6, 0xE2, 0xD4, 0xDA, 0x61, 0x25, 0x3D, 0xA0, 0x81, 0x27,
        0x5E, 0x8F, 0x34, 0xDB, 0xE4, 0xA1, 0xEC, 0xC2, 0x22, 0x24,
        0xC3, 0x08, 0x00, 0xA7, 0x75, 0x35, 0x74, 0xC8, 0x95, 0x86,
        0x95, 0x66, 0x6C, 0x28, 0x95, 0xB3, 0x5C, 0xCE, 0x07, 0x89,
        0x44, 0xA3, 0x10, 0x41, 0xA5, 0x23, 0x83, 0x7C, 0xED, 0x72,
        0x17, 0x69, 0x0F, 0xA1, 0x7C, 0x36, 0xCB, 0x45, 0x92, 0x63,
        0x35, 0xE6, 0x7B, 0x18, 0x04, 0x95, 0x9D,
    ];

    const KAT_512_RND: [u8; 40 + 56] = [
        // nonce: 40 bytes
        0x16, 0xC1, 0x25, 0x15, 0x25, 0x80, 0x93, 0x79, 0x99, 0x56,
        0x36, 0x8C, 0xDF, 0xC1, 0x82, 0xC1, 0xCA, 0x4A, 0x34, 0xF0,
        0x77, 0xE9, 0x24, 0x44, 0x16, 0xA8, 0xC4, 0xC1, 0x3F, 0xB0,
        0xCA, 0x24, 0x1E, 0x8B, 0x7A, 0xC1, 0x71, 0x2D, 0x28, 0xEB,

        // seed for the ChaCha20 PRNG: 56 bytes
        0xFF, 0xD8, 0x57, 0xF1, 0x49, 0x5C, 0xA5, 0x98, 0xDB, 0x2C,
        0x88, 0x64, 0xAF, 0x31, 0xFA, 0x8F, 0x37, 0xBC, 0x73, 0x8D,
        0xCD, 0xB6, 0xDD, 0xAA, 0xFD, 0x25, 0x4A, 0xBF, 0xE3, 0x01,
        0xB7, 0x91, 0x9B, 0x7E, 0x9B, 0x9F, 0xEC, 0xEA, 0x4E, 0xF0,
        0x01, 0xC9, 0x62, 0x9B, 0x96, 0x6B, 0x58, 0xD6, 0x81, 0x25,
        0x2F, 0xF3, 0x38, 0x9E, 0x81, 0x6B,
    ];
    const KAT_512_sig_raw: [i16; 512] = [
        11, 201, 176, -24, -141, -151, -63, -323, 154, -363, 168, -173,
        -29, -184, -142, 419, -48, 104, 103, -245, -374, 252, -59, 32,
        77, -237, 182, -9, 181, -54, -47, 52, -6, 81, 147, 113, -36, 28,
        -156, -261, -277, -431, 175, -182, 115, -273, 33, -76, -270,
        -124, -25, -61, -166, 65, -9, 34, 52, -104, 240, -81, 120, 55,
        9, 273, -13, -1, -193, 442, -43, -58, -86, -100, -14, -96, 245,
        -120, 10, 2, -40, 341, 8, 112, -260, 100, -24, -22, -181, -207,
        -123, -6, 108, -271, 194, 131, -60, 87, -66, 173, 44, 133, -270,
        -182, 176, 59, 289, 25, 98, -47, 153, -257, 160, -21, 73, 58,
        -4, -39, 79, -124, 31, 119, -175, -125, -222, -36, 71, 3, -153,
        -101, 20, 234, 235, 162, -147, -18, 155, -11, -90, -157, -18,
        -408, -18, -53, -16, 169, 104, -135, 303, -219, 572, 109, -235,
        -478, 114, 66, -17, 186, -13, -57, 31, -132, 73, 134, 35, -165,
        -279, 27, -360, -3, 44, -40, -262, 60, 100, 35, 78, -102, -281,
        -189, -66, 122, -65, -73, -287, -236, -131, -121, -24, 72, 68,
        -156, -69, 54, -127, -185, 154, 60, 144, -99, -81, 139, 80, 98,
        -93, 227, 170, -338, -15, 162, 149, -247, -89, 290, 36, -231,
        -77, 121, 205, -45, 140, 6, 45, -134, 248, -252, 58, 210, 204,
        272, 205, 282, 19, -15, 327, 70, 102, -36, 93, 67, -42, -243,
        106, 104, 47, -333, -139, 195, 49, -22, -138, 166, 308, 143, 57,
        -305, -26, -176, -46, -243, -130, 134, -176, -131, -277, 240,
        -228, -177, 142, -51, 84, 44, 187, 213, 24, 83, -134, -202, 286,
        48, 58, -199, 7, -18, 173, 113, 52, -190, 1, -117, -177, 122,
        -229, 83, -90, 46, 115, 63, -33, -4, 23, -51, 148, 97, 169,
        -183, -128, 37, 80, 61, 102, -28, 75, 142, 292, -89, -260, -47,
        62, 86, 184, 15, -258, -48, -47, -29, 211, -357, 228, -133,
        -144, 275, -110, -127, -83, -74, -89, 149, 9, -44, -208, -46,
        121, -157, 147, 216, 133, -96, 12, 247, 189, 100, -93, 135, -14,
        105, 175, -202, 37, 178, 141, 142, -140, -174, -60, -13, 95,
        -208, -84, -52, -144, -125, -2, 63, -436, -273, 47, 106, 122,
        -221, -180, 104, -4, -163, -121, 87, 405, 107, -229, 259, 118,
        -136, -313, -35, -84, 208, 128, -4, 13, 304, -40, 75, 165, 183,
        -196, 7, -48, -21, -250, 160, -280, 370, 91, 198, -228, -70, 30,
        -54, -263, -10, -125, -18, -231, -3, 287, -388, -10, 208, -358,
        -107, 148, -154, 31, -6, -119, -206, -37, -59, -30, -285, -13,
        69, -57, 153, -113, -108, 100, 58, -91, -239, -68, -181, 81, 43,
        18, -110, -59, -18, 97, -96, 27, 181, -62, -156, -19, -204, 343,
        66, -110, -52, 28, -188, -35, 49, -59, 38, -43, 64, -177, 171,
        132, -38, -120, 214, -42, 110, -324, -34, 158, -102, -4, -61,
        -117, -134, -310, -99, 79, -308, -306, -199, -126, -190, 27,
        -43, 120, 94, 340, -435, -99, 167, 210, -70, -84, 199
    ];
}
