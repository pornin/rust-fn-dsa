#![no_std]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//! # FN-DSA key pair generation
//!
//! This crate implements key pair generation for FN-DSA. The process
//! uses some temporary buffers which are held in an instance that
//! follows the trait `KeyPairGenerator`, on which the `keygen()` method
//! can be called. A cryptographically secure random source (e.g.
//! [`OsRng`]) must be provided as parameter; the generator will extract
//! an initial seed from it, then work deterministically from that seed.
//! The output is a signing (private) key and a verifying (public) key,
//! both encoded as a sequence of bytes with a given fixed length.
//!
//! FN-DSA is parameterized by a degree, which is a power of two.
//! Standard versions use degree 512 ("level I security") or 1024 ("level
//! V security"); smaller degrees are deemed too weak for production use
//! and meant only for research and testing. The degree is provided
//! logarithmically as the `logn` parameter, such that the degree is `n =
//! 2^logn` (thus, degrees 512 and 1024 correspond to `logn` values 9 and
//! 10, respectively).
//!
//! Each `KeyPairGenerator` instance supports only a specific range of
//! degrees:
//!
//!  - `KeyPairGeneratorStandard`: degrees 512 and 1024 only
//!  - `KeyPairGenerator512`: degree 512 only
//!  - `KeyPairGenerator1024`: degree 1024 only
//!  - `KeyPairGeneratorWeak`: degrees 4 to 256 only
//!
//! Given `logn`, the `sign_key_size()` and `vrfy_key_size()` constant
//! functions yield the sizes of the signing and verifying keys (in
//! bytes).
//!
//! ## WARNING
//!
//! **The FN-DSA standard is currently being drafted, but no version has
//! been published yet. When published, it may differ from the exact
//! scheme implemented in this crate, in particular with regard to key
//! encodings, message pre-hashing, and domain separation. Key pairs
//! generated with this crate MAY fail to be interoperable with the final
//! FN-DSA standard. This implementation is expected to be adjusted to
//! the FN-DSA standard when published (before the 1.0 version
//! release).**
//!
//! ## Example usage
//!
//! ```ignore
//! use rand_core::OsRng;
//! use fn_dsa_kgen::{
//!     sign_key_size, vrfy_key_size, FN_DSA_LOGN_512,
//!     KeyPairGenerator, KeyPairGeneratorStandard,
//! };
//! 
//! let mut kg = KeyPairGeneratorStandard::default();
//! let mut sign_key = [0u8; sign_key_size(FN_DSA_LOGN_512)];
//! let mut vrfy_key = [0u8; vrfy_key_size(FN_DSA_LOGN_512)];
//! kg.keygen(FN_DSA_LOGN_512, &mut OsRng, &mut sign_key, &mut vrfy_key);
//! ```
//!
//! [`OsRng`]: https://docs.rs/rand_core/0.6.4/rand_core/struct.OsRng.html
//! 
//! Modified by The Resonance Network developers 2025
//! 
mod fxp;
mod gauss;
mod mp31;
mod ntru;
mod poly;
mod vect;
mod zint31;

#[cfg(all(not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")))]
mod ntru_avx2;

#[cfg(all(not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")))]
mod poly_avx2;

#[cfg(all(not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")))]
mod vect_avx2;

#[cfg(all(not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")))]
mod zint31_avx2;

use fn_dsa_comm::{codec, mq, shake};
use fn_dsa_comm::PRNG;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Re-export useful types, constants and functions.
pub use fn_dsa_comm::{
    sign_key_size, vrfy_key_size, hashed_vrfykey_from_vrfykey,
    FN_DSA_LOGN_512, FN_DSA_LOGN_1024,
    CryptoRng, RngCore, RngError,
};

/// Key pair generator and temporary buffers.
///
/// Key pair generation uses relatively large temporary buffers (about 26
/// or 52 kB, for the two standard degrees), which is why they are part
/// of the `KeyPairGenerator` instance instead of being allocated on the
/// stack. An instance can be used for several successive key pair
/// generations. Implementations of this trait are expected to handle
/// automatic zeroization (overwrite of all contained secret values when
/// the object is released).
pub trait KeyPairGenerator: Default {

    /// Generate a new key pair.
    ///
    /// The random source `rng` MUST be cryptographically secure. The
    /// degree (`logn`) must be supported by the instance; a panic is
    /// triggered otherwise. The new signing and verifying keys are
    /// written into `sign_key` and `vrfy_key`, respectively; these
    /// destination slices MUST have the exact size for their respective
    /// contents (see the `sign_key_size()` and `vrfy_key_size()`
    /// functions).
    fn keygen<T: CryptoRng + RngCore>(&mut self,
        logn: u32, rng: &mut T, sign_key: &mut [u8], vrfy_key: &mut [u8]);
    
    /// Generate a new key pair using a provided seed.
    fn keygen_with_seed(&mut self,
        logn: u32, seed: &[u8], sign_key: &mut [u8], vrfy_key: &mut [u8]);

}

macro_rules! kgen_impl {
    ($typename:ident, $logn_min:expr, $logn_max:expr) =>
{
    #[doc = concat!("Key pair generator for degrees (`logn`) ",
        stringify!($logn_min), " to ", stringify!($logn_max), " only.")]
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct $typename {
        tmp_i8: [i8; 4 * (1 << ($logn_max))],
        tmp_u16: [u16; 2 * (1 << ($logn_max))],
        tmp_u32: [u32; 5 * (1 << ($logn_max))],
        tmp_fxr: [fxp::FXR; 5 * (1 << (($logn_max) - 1))],
    }

    impl KeyPairGenerator for $typename {

        fn keygen<T: CryptoRng + RngCore>(&mut self,
            logn: u32, rng: &mut T, sign_key: &mut [u8], vrfy_key: &mut [u8])
        {
            // Enforce minimum and maximum degree.
            assert!(logn >= ($logn_min) && logn <= ($logn_max));
            
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            
            self.keygen_with_seed(logn, &seed, sign_key, vrfy_key);
        }

        fn keygen_with_seed(&mut self,
            logn: u32, seed: &[u8], sign_key: &mut [u8], vrfy_key: &mut [u8])
        {
            // Enforce minimum and maximum degree.
            assert!(logn >= ($logn_min) && logn <= ($logn_max));
            keygen_inner_with_seed(logn, seed, sign_key, vrfy_key,
                &mut self.tmp_i8, &mut self.tmp_u16,
                &mut self.tmp_u32, &mut self.tmp_fxr);
        }
    }

    impl Default for $typename {
        fn default() -> Self {
            Self {
                tmp_i8:  [0i8; 4 * (1 << ($logn_max))],
                tmp_u16: [0u16; 2 * (1 << ($logn_max))],
                tmp_u32: [0u32; 5 * (1 << ($logn_max))],
                tmp_fxr: [fxp::FXR::ZERO; 5 * (1 << (($logn_max) - 1))],
            }
        }
    }
} }

// An FN-DSA key pair generator for the standard degrees (512 and 1024,
// for logn = 9 or 10, respectively). Attempts at creating a lower degree
// key pair trigger a panic.
kgen_impl!(KeyPairGeneratorStandard, 9, 10);

// An FN-DSA key pair generator specialized for degree 512 (logn = 9).
// It differs from KeyPairGeneratorStandard in that it does not support
// degree 1024, but it also uses only half as much RAM. It is intended
// to be used embedded systems with severe RAM constraints.
kgen_impl!(KeyPairGenerator512, 9, 9);

// An FN-DSA key pair generator specialized for degree 1024 (logn = 10).
// It differs from KeyPairGeneratorStandard in that it does not support
// degree 512. It is intended for applications that want to enforce use
// of the level V security variant.
kgen_impl!(KeyPairGenerator1024, 10, 10);

// An FN-DSA key pair generator for the weak/toy degrees (4 to 256,
// for logn = 2 to 8). Such smaller degrees are intended only for testing
// and research purposes; they are not standardized.
kgen_impl!(KeyPairGeneratorWeak, 2, 8);

// Generate a new key pair, using the provided random generator as
// source for the initial entropy. The degree is n = 2^logn, with
// 2 <= logn <= 10 (normal keys use logn = 9 or 10, for degrees 512
// and 1024, respectively; smaller degrees are toy versions for tests).
// The provided output slices must have the correct lengths for
// the requested degrees.
// Minimum sizes for temporaries (in number of elements):
//   tmp_i8:  4*n
//   tmp_u16: 2*n
//   tmp_u32: 5*n
//   tmp_fxr: 2.5*n

fn keygen_inner_with_seed(logn: u32, seed: &[u8],
    sign_key: &mut [u8], vrfy_key: &mut [u8],
    tmp_i8: &mut [i8], tmp_u16: &mut [u16],
    tmp_u32: &mut [u32], tmp_fxr: &mut [fxp::FXR])
{
    assert!(2 <= logn && logn <= 10);
    assert!(sign_key.len() == sign_key_size(logn));
    assert!(vrfy_key.len() == vrfy_key_size(logn));

    let n = 1usize << logn;

    // Make f, g, F and G.
    // Keygen is slow enough that the runtime cost for AVX2 detection
    // is negligible. If we are on x86 and AVX2 is available then we
    // can use the specialized implementation.
    let (f, tmp_i8) = tmp_i8.split_at_mut(n);
    let (g, tmp_i8) = tmp_i8.split_at_mut(n);
    let (F, tmp_i8) = tmp_i8.split_at_mut(n);
    let (G, _) = tmp_i8.split_at_mut(n);
    let (h, t16) = tmp_u16.split_at_mut(n);

    loop {
        #[cfg(all(not(feature = "no_avx2"),
            any(target_arch = "x86_64", target_arch = "x86")))]
        if fn_dsa_comm::has_avx2() {
            unsafe {
                keygen_from_seed_avx2(
                    logn, &seed, f, g, F, G, t16, tmp_u32, tmp_fxr);
                fn_dsa_comm::mq_avx2::mqpoly_div_small_nttx(logn, f, g, h, t16);
            }
            break;
        }

        keygen_from_seed(logn, &seed, f, g, F, G, t16, tmp_u32, tmp_fxr);
        mq::mqpoly_div_small_nttx(logn, f, g, h, t16);
        break;
    }

    // Encode the verifying key.
    vrfy_key[0] = 0x00 + (logn as u8);
    let j = 1 + codec::modq_encode(h, &mut vrfy_key[1..]);
    assert!(j == vrfy_key.len());

    // Encode the signing key (f, g, F and H(vkey), in that order).
    sign_key[0] = 0x50 + (logn as u8);
    let nbits_fg = match logn {
        2..=5 => 8,
        6..=7 => 7,
        8..=9 => 6,
        _ => 5,
    };
    let j = 1 + codec::trim_i8_encode(f, nbits_fg, &mut sign_key[1..]);
    let j = j + codec::trim_i8_encode(g, nbits_fg, &mut sign_key[j..]);
    let j = j + codec::trim_i8_encode(F, 8, &mut sign_key[j..]);
    sign_key[j..].copy_from_slice(&hashed_vrfykey_from_vrfykey(vrfy_key));
}

// Internal keygen function:
//  - processing is deterministic from the provided seed;
//  - the f, g, F and G polynomials are not encoded, but provided in
//    raw format (arrays of signed integers);
//  - the public key h = g/f is not computed (but the function checks
//    that it is computable, i.e. that f is invertible mod X^n+1 mod q).
// Minimum sizes for temporaries (in number of elements):
//   tmp_u16: n
//   tmp_u32: 5*n
//   tmp_fxr: 2.5*n
fn keygen_from_seed(logn: u32, seed: &[u8],
    f: &mut [i8], g: &mut [i8], F: &mut [i8], G: &mut [i8],
    tmp_u16: &mut [u16], tmp_u32: &mut [u32], tmp_fxr: &mut [fxp::FXR])
{
    // Check the parameters.
    assert!(2 <= logn && logn <= 10);
    let n = 1usize << logn;
    assert!(f.len() == n);
    assert!(g.len() == n);
    assert!(F.len() == n);
    assert!(G.len() == n);

    let mut rng = <shake::SHAKE256_PRNG as PRNG>::new(seed);

    loop {
        // Generate f with odd parity.
        gauss::sample_f(logn, &mut rng, f);

        // f must be invertible modulo X^n+1 modulo q.
        if !mq::mqpoly_small_is_invertible(logn, &*f, tmp_u16) {
            continue;
        }

        // Generate g with odd parity.
        gauss::sample_f(logn, &mut rng, g);

        // Ensure that ||(g, -f)|| < 1.17*sqrt(q). We compute the
        // squared norm; (1.17*sqrt(q))^2 = 16822.4121
        let mut sn = 0;
        for i in 0..n {
            let xf = f[i] as i32;
            let xg = g[i] as i32;
            sn += xf * xf + xg * xg;
        }
        if sn >= 16823 {
            continue;
        }

        // (f,g) must have an acceptable orthogonalized norm.
        if !ntru::check_ortho_norm(logn, &*f, &*g, tmp_fxr) {
            continue;
        }

        // Solve the NTRU equation.
        if ntru::solve_NTRU(logn, &*f, &*g, F, G, tmp_u32, tmp_fxr) {
            // We found a solution.
            break;
        }
    }
}

// keygen_from_seed() variant, with AVX2 optimizations.
#[cfg(all(not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")))]
#[target_feature(enable = "avx2")]
unsafe fn keygen_from_seed_avx2(logn: u32, seed: &[u8],
    f: &mut [i8], g: &mut [i8], F: &mut [i8], G: &mut [i8],
    tmp_u16: &mut [u16], tmp_u32: &mut [u32], tmp_fxr: &mut [fxp::FXR])
{
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;

    use core::mem::transmute;
    use fn_dsa_comm::mq_avx2;

    // Check the parameters.
    assert!(2 <= logn && logn <= 10);
    let n = 1usize << logn;
    assert!(f.len() == n);
    assert!(g.len() == n);
    assert!(F.len() == n);
    assert!(G.len() == n);

    let mut rng = <shake::SHAKE256_PRNG as PRNG>::new(seed);

    loop {
        // Generate f with odd parity.
        gauss::sample_f(logn, &mut rng, f);

        // f must be invertible modulo X^n+1 modulo q.
        if !mq_avx2::mqpoly_small_is_invertible(logn, &*f, tmp_u16) {
            continue;
        }

        // Generate g with odd parity.
        gauss::sample_f(logn, &mut rng, g);

        // Ensure that ||(g, -f)|| < 1.17*sqrt(q). We compute the
        // squared norm; (1.17*sqrt(q))^2 = 16822.4121
        if logn >= 4 {
            let fp: *const __m128i = transmute(f.as_ptr());
            let gp: *const __m128i = transmute(g.as_ptr());
            let mut ys = _mm256_setzero_si256();
            let mut ov = _mm256_setzero_si256();
            for i in 0..(1usize << (logn - 4)) {
                let xf = _mm_loadu_si128(fp.wrapping_add(i));
                let xg = _mm_loadu_si128(gp.wrapping_add(i));
                let yf = _mm256_cvtepi8_epi16(xf);
                let yg = _mm256_cvtepi8_epi16(xg);
                let yf = _mm256_mullo_epi16(yf, yf);
                let yg = _mm256_mullo_epi16(yg, yg);
                let yt = _mm256_add_epi16(yf, yg);

                // Since source values are in [-127,+127], any individual
                // 16-bit product in yt is at most 2*127^2 = 32258, which
                // is less than 2^15; thus, any overflow in the addition
                // necessarily implies that the corresponding high bit will
                // be set at some point in the loop.
                ys = _mm256_add_epi16(ys, yt);
                ov = _mm256_or_si256(ov, ys);
            }
            ys = _mm256_add_epi16(ys, _mm256_srli_epi32(ys, 16));
            ov = _mm256_or_si256(ov, ys);
            ys = _mm256_and_si256(ys, _mm256_setr_epi16(
                -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0));
            ys = _mm256_add_epi32(ys, _mm256_srli_epi64(ys, 32));
            ys = _mm256_add_epi32(ys, _mm256_bsrli_epi128(ys, 8));
            let xs = _mm_add_epi32(
                _mm256_castsi256_si128(ys),
                _mm256_extracti128_si256(ys, 1));
            let r = _mm256_movemask_epi8(ov) as u32;
            if (r & 0xAAAAAAAA) != 0 {
                continue;
            }
            let sn = _mm_cvtsi128_si32(xs) as u32;
            if sn >= 16823 {
                continue;
            }
        } else {
            let mut sn = 0;
            for i in 0..n {
                let xf = f[i] as i32;
                let xg = g[i] as i32;
                sn += xf * xf + xg * xg;
            }
            if sn >= 16823 {
                continue;
            }
        }

        // (f,g) must have an acceptable orthogonalized norm.
        if !ntru_avx2::check_ortho_norm(logn, &*f, &*g, tmp_fxr) {
            continue;
        }

        // Solve the NTRU equation.
        if ntru_avx2::solve_NTRU(logn, &*f, &*g, F, G, tmp_u32, tmp_fxr) {
            // We found a solution.
            break;
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use sha2::{Sha256, Digest};

    // For degrees 256, 512, and 1024, 100 key pairs have been generated
    // with falcon.py from ntrugen; this implementation is supposed to be
    // able to reproduce them exactly, from the same seeds. Since testing
    // all the keys in debug mode is slow, only a few keys for each
    // degree are actually retested in the tests, and the other key pairs
    // are commented out.

    static KAT_KG256: [&str; 10] = [
        "35439d2efbd2ac0715c3aa998e96afb3c4759bd5fec237fd173efda4fdc7c0e1",
        "ea672aee22de008fbf5b437321fc5ce43ea5068045a2e1909d6fac5f3942e096",
        "639d51cf297c3c457a2d0a34495fc37a66fa8b1cf6e3005e11403e0bcf8c4cd4",
        "177c28d479a02c1aa92ac925a2b5a8294a185b38d2e8962f528f2eb2be2b2764",
        "560e7652990e55d7b2047f1545f40852fd2c7fde0161277a8ad9afe28987c2e3",
        "35a9fb1542e8e2c181e4870eaa973251138eb0838d1df205e260bb1afd8d9932",
        "8881e2902edaa3302a0f7830b7112dc666ba61fc4b901387f9f13446641c5a89",
        "e681c5f2a2ace27f8a0f06dcd121af473277f35f750f41e5ef7244661eba47b1",
        "43da3f36445871fc253a6a5ace1ffb0446e2a7a9de692d132e5e7ad250e1a5f0",
        "6da68c0a531da643e33b22a7861898511a6fa55af47e3d7acf21a8bb4e1f3d33",
        /*
        "23b5271b75ab7b03b8a32239d0bcd67221bd7aab8411783f6212cc6f930a317e",
        "29b9be875ab140d024e655d1a5f9ba280acc2ee14eb6e3dbb7c72eba18ad4e38",
        "aeb0b31e8d50abf0900f70a3568a748538d5b1c2c22d51bc0b859766d9826e33",
        "b79477a661c03775b431f0bcacd90018ec26eb895a7beb140874a26aa78be468",
        "80d253caff529d0ff597c1d9cc62c92573198d0f9b6c6305b42a55347e7fa806",
        "1299715bd0a312e63e08fa07c5c05063ea11462bc84ee2651ec240c154a14fa0",
        "4b3dedaec9ae124f7d680109b5d5d2735581e43c60e5fac7eb2e5579a343a678",
        "5f2efe225f06e33caccc8f0cae3ede092a0a00f01c586eebd578e2525d672685",
        "f411034a4de8912a317d343ab4e31c43b3f3a0bd0ef33108448726bd6486e65d",
        "0b4d565e33a0dd74d92002b98b2be1b53434ccf97ebbcdf9a9193ad1b555aa61",
        "f165f14533f13e63c71549a99f643f304779adc2017b2d849aa264a1b490f465",
        "8ca7bd14f28840de9fe9ac497945606a1be010e596c0e7034b4060b23abbf469",
        "b0084a498798d335b62f7ecd71da075d4c9fa5c3c196c5db52f8b2796255b63c",
        "0ebf31bdb6e28ca2d4ff6719a40dddc301c63f6ad13c58d9a6112b333e95c80d",
        "5976617f5774aa2fd041853a6a3d614c6100d533f5649708f25a15115a0b087d",
        "d61e11e438483d6c98fa45033e940cd4395bd3c0ddd8034e96a957853c25f3af",
        "010bddeb3047e1ce7d698047aba8c173f3afec91d447b3ddb5241f3d0f5f7ec2",
        "b9a59392431d4383103f6fdd83045c3d1641675e54746a7680534713ecd90cd2",
        "8393c15cd4066ea723dc2aa899571ca51d9518c87f00239bca52c3e459c504cb",
        "e6bb4890119ec39c05be6618607d02800fa8aa79cecab8ca9a85781944327b4e",
        "ebdabb0012db336b234bc6341bef3043858f365eaf2ebb60f0340c2a79047468",
        "0afbffcb816e0a92406bb8e859baa1b3627e37e24c55cd3a3d5ab107c46c91d4",
        "384cf2bdd2cfd88283e7ede1784cf7f2039a3a3cf28b6ec32f1b301679198bf6",
        "2e0333b83c90a15f6a500313ccb63831bb82e9614c8c1bfcf98ff627de30bf22",
        "48223532f9cbf2a3ef7f97ebe8d3847640c278e455e4e3602bd3c4291c2df5dd",
        "c57f63bb9a922f2e71b9bc2b130eff50bce5da815d90485bf58f95fce7abbb83",
        "6f71b3d99dba3c2c81746e30760a3be28de99db9347ae74150b93b750139023a",
        "f5000646fe51fefa36a238dd1eaac7ba12a3be2b51a595f18eec2ca1f197fdac",
        "9ef67e3325f4a12be713a6bf6a7e990244f746da06c812f768ba7049556b9fb3",
        "87edbe27372bd8b93778a145e847e190b79d59e3b2e5a7f4bbd4c9118305a9b6",
        "b00aeeec73ba31d90aa65c0583422387d0b3edf0957f7c4f08d7f6dcbd622b21",
        "e5d7995ac96007d1870ed04e60980b04df5f7be57e6ae64621977526e7e1d506",
        "4791888818190f26546eabb38f0159c41eaec7cecf3b5fb668136104600db065",
        "413e5a0761e73d1a5e3f1feaec2f81e99d8bfb6c4495c16c004a5840b527f994",
        "d964d8e90fe8b5bba46ee41203b264046ca4dd1a0edf330f90dd3df6d888c6be",
        "d1a7558d8904682e152cae7f74a7314456654733fb2c97c510dcea72b61fd79f",
        "4fd9cfef3358fa3fb99be8d6dc6dd0a96b43ac9e0f706710537b63206b05c544",
        "671bfbc3857059b4fff4af9ede1257694eb3113009c0528b19bfbb439b3d0a6b",
        "3c6315aaf8e44b71802e0c18e7a2bcdb4dd4971a67c61f4eb2898bad992fc79e",
        "e9830d2a13386ae1ba9865fb916b11c30ea5e758426ebb0f970e44d950c7d288",
        "4cd2e2b107ecb90de1b2dd21024cdcbfbe7c8386bffb75b08300b58b6a901ad2",
        "6f679b479ab4825384806eb047b777fac9fcbc400612f11095ad9837f399cbcd",
        "de371046ee2559b125c81110c24247770a87d27dcda9dd870435324e045146d0",
        "87bd3422f8781bfae643811a05eddb0d4fe712b1b3287ed7292bfdf9f5ffaf70",
        "fb4fa3f79e0cf4143b278843c9b3b5913fe39a2ba48bdced60fa8116e3708d18",
        "0ca3ce97f870c3d6b40170252561df4a7a6a2a2d6f870a122f442d5e215f1397",
        "30ef03eb2725354e48ad543f0ccbeb78b108283c5649f989d86460ac371e8c25",
        "cb89add58b2665ee58f492fc16cabe976f5d5e6cd297ef133a559e30744c6c73",
        "b07c9c8fb1608e0b00cb925210a394982f29141f113cc7277fff3a1ef1c7f89b",
        "e2fc8804c3c0e3efb0f234f6cbfcc629a9c88e25c22ce6427486e2e2336218ba",
        "e11abcb2793f7f9c9a83ef065fd96a6f19ec537496bc20764661ff3681e2e734",
        "afcab9baf811ab4b87175ea9e54e8a6a005c6e2d28c9dc169f0dab91267a305c",
        "99da29c031a87e82bafcaa7f56b92a3a4a5aa00817be3603bf26fb2c227bab35",
        "c7006d19eb1ab52e8a7287c0ed237c307b57aeb1e4add9e1e79d2ad78fde937f",
        "a1d1fbfb264d64fd41dfcc94d684d178ae89f32015b5479fa378566ffffa835b",
        "ff04372288da155fd8c31028652ed170ae255c1f035b04894bb87cb36b00f6e2",
        "b10a1d3cd077824aa3295ad71e2d173ac3b37bf6c64904f6aa63a428d5eff292",
        "231a04d9440a648553c382d43a0e6e19950b88359171665a076a8c42a3421f77",
        "b421b7736c629479b574d2e7f70757b1d0bf17cd522e3f851c99182e5d080df7",
        "5b4d4ae3062e9837c9e1600d01a4c1ae163b4b568b2e410df7b1c21c97ee95dc",
        "49845eaca210b9b881583e5dcebf024e50e838a30e81e5e8b830008c72cbf2d2",
        "ade875dafb7caea7d1e0d0a1eed062f2dfb89276ff71971381e6683b22ded880",
        "c45e6cbdd688eaf3cf152f5be5c0d26ed41e4f5a665eae57404436a651728767",
        "bc49787b1856c15d9f931eae7a8884a15c1034ec1778ab5d005cfd882721acc7",
        "5fed421b0ad5c0562ca3012f471cb042f5ee08a00a341bda1b81705a3a18b26f",
        "123b5c65b912a5f23f0f081c2dfdd0951f5d7c7e583437702ba9d245af4c326c",
        "c922533a2bc16ae6d0cc0a90ce3514d2ee67b9394f74c8935d32f19325f8a5e8",
        "d3a22a8a1b9860f2e0491e0f329c1b3a717548aef3a8456071eccb788de99461",
        "c96c7466691ce9e83ff2ec3a0cfa20e938126df118dd1e4b94fe16cc7ffbb46b",
        "ff2bfeb083a81c350fee8a59c9d1e70cfef963364aa3b202d3d7865435ba2261",
        "bffa46b837a074f2468591ddee8e87c2a2f2dabc1c32f3a90ee6e362fd1570d3",
        "c396446b2991afc11acc398e735a14074e08045beb5e6d9f897b1297094c3143",
        "836397b79c699269e010e2a56ef4a5a52d3f1441149fc62d47f3a06b6a48036a",
        "bad24ac4693168fa16de54b32a1e3f4afdc8e299ad5fae945025f18777fc8454",
        "e3f3e65147c998c59d2acf261dc32482f4a64022a5457e8b69f6811680d5953c",
        "390e74e50e450c9063e294e09428a4aca7abb594712e18e241b6bc64435a7fd7",
        "927e5252eb5f727345a7240edafb5357928c052ab891746913e012ec83fb9dab",
        "5d44ed16e2fb168e00833e4fdaeb2f9bc78deed13d14662897ea62e7f9274ee8",
        "84a0266cd0325bb91a28a5686ec42adb731c59e336d4f88d9103a32c216ab669",
        "f13c1e758a92e0e73a890dfd136134b6df1bb4d04587c1a4e56104a1ee12d235",
        "abb953e6a9b161e23da3cab848944fd238b6bb95a7d710e0ddcd0dc7c56fa3b1",
        "d12bf8b1ba5f76b19c1b20b44dc9c6b7167771766a998b58955d6b68d014c9d2",
        "e7ba4fd2312a05debd140587c3d2da23a417da355e3e6d0631f989f216bb3bcd",
        "fb7015c4d603ecca688340e15b9626c8094cb035af86a1fb7da66742212eedbd",
        "ada8f670b393f36bcf01923b894ad5417045dc1a816f86e0834dae376951ecb9",
        "c08bc13d2d95dff670ca8f5bd5aa8bec1160a1f77d606ab022e09fb4413a2909",
        "d9196a286c854a4aa677ab7e4b1e830a73f1651e7105f2b3b2b05c6d6409b683",
        "0cd5ff650dfc2257d7b05bc73dbf47815aa8407809de2bbff7377cf70031a221",
        "48341bb275e90ce0cb85df2489dc201d8d5a9f69d20fd1916fb02e2390eaa369",
        "c4b1819b82ba459331681419e24ac72b5b3934abb36d376e78ec4bd3a39dcf4b",
        */
    ];

    static KAT_KG512: [&str; 5] = [
        "986c56eb85223849ec226e7bee9407eba4e0d648c5d1774ea53e22cf9311db5a",
        "03056bc154032e313eec34c6363cdb52856d8a2d0c6043134983f35c53b3e783",
        "8247d57762a812b840ff794f148be537bcb06f738ea6e89f6d7464e0f33569c4",
        "625beff1e2aeb8a3aa17570c760a67704a8dc2caebc1ab8a0a95bd4d759ac77b",
        "3e9fdd4b2f559eff07c478f1bcb7b85449a3454943556a8c25352fec07ee2b24",
        /*
        "4f16c4d73ace4b063fcba4d5ac98d0ab7fe47cfcd55216e54697dc1f2e7eb653",
        "cc9641cd07bd5bca58b92c5078def8e48e63fa9f2abf18ca3fdd5c18a16352a0",
        "9c6b013476fbb0dfdebc88ef8399f1c08efd64f496a3832637b3522d1adbe44e",
        "65c5b37b4ab9000056832532c8ad91c50ab378b3ed392cb1fd769796b8fb92f9",
        "5a3b7b61ea2303d6fd2b86902275f34007615bf558badca041a0e45758239bd9",
        "5ac1d8ae2adafea9b1f9d2ee074bb72dd059441b9fd2bc16898d4ba0dd4fc95c",
        "982c5e9db57b5d2c653dadf42c27db4411c62027ed937f68e0fabede5dfd73b5",
        "50c0b9ae91e5ace82e290983a4db41acc5ee1fda8d0726d5223051370738f045",
        "73214a0c4a95a993ff2bff93b6ac283b40ac2cf3eaeb18a521980061dab2f480",
        "89e86926777aa53d75a689f3d37392c163409fbd2ee9b9215eed68120564b53b",
        "5b5dc23925e4ac9d8198eca97ee69cf7d346f98ebf55fb8c1556fc54b0a11407",
        "9de55bd1a8ff914c71636ff4cc2ddfa2f1a6888b263af753f874f4b62cddb5ce",
        "8a8892712305d1f80f2530ae2699349d5b8617209da235074ccef214aad1ee65",
        "a8e69865511ab630cd18df324b31f662d20e5a533a81a231b7fa8fc59b84b9ff",
        "7e702f7aba71ebc6d38a1ea746759f3fe1973fb0f0ea70f9dac39b86b8e1b5ca",
        "3636273dce58b0cf34397bfba32db220c3918b41b9375d712902c93be91059f1",
        "6f1f3a938f67376e68ac9a578baa9cabe6a31e5f71cc2c5965bbdd466f59158f",
        "ee3ed44b66c8be23fdbb1c8b30cd822b15bf3db9329c70c13027c6302f613b05",
        "2bbd561e678cb02ec585f5879e547f637806925ea8b6248a640dd9ee59e50e4d",
        "edba7af043ca3f30bbdb74c9005e5a934eb1618e8a05f4f1e9b0e9989eeb6d39",
        "af0d1e21a6747f6c1353671792ce4983d867c60b310b45fb2fecb61e579dced4",
        "141473239aef9507afc7615eb1184d3d754fa57a406d9a450e1f2cb0c35972e7",
        "aaa69d4f9e3757f9abfbf0cbada998a4b52f39ab12499ae3ddd1b8f36d761423",
        "21847721e2c518ee800cb878a01d8062d8c23467ed6e44a4ee072d9790ee9c24",
        "6bccfa043117671f22b355e254d2157263ddae7f520670edb1309925464bca29",
        "42a9bd52e0b059e259ed7f2688399b3cbb7f09ea9f487e2d83e63b4b0eb7b7f5",
        "1901d7f37d6413138643521d5fc413718e000ea5ab81e61084da3d59efc95643",
        "20a403cadadeecec49cc926c33e54774df2c947e7512b52ec2001dada085d156",
        "75fb39f553c8405a24362164383835265892d9579a7e5b708388ba0a30371e89",
        "f04fd5d9a13251a630543f5857058262702a1cc5132039ec9e87d1421ddd298c",
        "68de34bb309c1e1406c55f89a3119c58337f2b48fd2d409e44d51fbfdbbdd53c",
        "3d0b42686b139b83e3f0bfb308e18851617bf867cdba7073b828679e52571992",
        "fbf98ba202f9d6cd6bc93bf7dab5bf43b0af6112c11f4eb50361a02aedeb2313",
        "fe0d3112d19a9c9030f977c3ab96a99e3c5227f59de1fa8502f3de72df29b8b0",
        "0310c23c38018ef34d18abf808299da692d0330d9ac61b8a89627657f248b411",
        "fd9c88ffbaa3c4431091490ca215cc29756d9ce8f7b336c8fc035b2037964e77",
        "81cdef53221e7388cb12e644504ed792896706a4e16168e5e510d68fcada1fa4",
        "2655f3777d770fc338826ccbf55257718d84f9fc29fbfad433b59af52302a24f",
        "30d34a00b3468c27fbaa6741eae43a6e45dc5e6b0572c8798ac34fcd7adb08c2",
        "3443de7ebea34f141b7e5b250b7dd6363aaf237f2e0f6d42b267832f71019348",
        "1b50845e760517b99d3f8fca033e51c5ee8092483dd54137ffac654c5f42bfcd",
        "00efaa9d88ab59bb286551aba9a8c10ff131fc16d7f46015b95e3f4b9fbc54bb",
        "67b30f24c36d6446f7a8b29e77f87e7d815bd24e982a2e60e8f688be5603deb6",
        "95892efd0fc3ebb46caf37f59cfbbb0079b5290b0fac78de1a731fa92890a2e4",
        "b2c812e0d4b6d8f3ca31ee9fd01c8af6f43029826229d7ef2150051413507eec",
        "5ee3186b6fedd4230ab4f045164ecd66f050ec33738c8d4db4eb1744d27f55eb",
        "432873e7a6b3ba61c3741ef04040431e7bca77f448d2614e3803d1e9550093af",
        "283df911defce160fcab8cabb994116c2a3c0b66d5197665352fc5924e046a47",
        "cbd3f4d039df2b246b8af17236619e8f6ee523772e58fc8d79d318fc195ad2d8",
        "d3619c49ee7b4ff93c3216fc11cdb025f0fd1fff0aeb984a2d7f815cf40b736e",
        "08b5b5531ba88270c7cac1a6c157ceff181cf8cbf07c01be9c601f4e2d7ac428",
        "b52aee31e4ef9a730350a43961fd99f8f4d3bfc23a4acf0844a4bd876b329fd0",
        "62cf8084b0a2db33735cf6e5662e81c0ea7c7b67f240e8353a4771d829384ad9",
        "91c274289a6de1bd0b1b45ea5e59667db3ed1415509843dd22620b85f1e6d893",
        "72bbea9b8a52d96164eb27c14f7a84a81e103d30cfc1f8386fea556f5ad0771a",
        "9fc478fd5d28824e656bebab3f295d4fe0908b4e5d7819e0ede191d58c84a51d",
        "606f7f9206b7f1842bf4cd9d40a1f533613c6fec9bcaaec90bb6d69c992bb6fe",
        "2c3673167a6af8999bc76e3c142d4ad950ccc5804b72e1ffe8c73cc430635fc1",
        "0a2e5e1128235cab6249a141d46a0e8b2d67ae5ecb731867a2c00e82194ff3ce",
        "729c56fb55543559e36b919e6c96660e75164eb49d85e772321bc12b9cee58e6",
        "47df31f22ef9a6834a1c0de51c072cc252f653ea271b10b18cd1b56fb9f354e6",
        "5bde6592b01fd01db2fff71bc1830025b8218764664f15f442bef978c5fb48df",
        "183c9de2ddd89d729eab841bc16bf5f94eef11bd1837314339379079112590dc",
        "aab1972d80d0457cc00b754ad7edb8385b6750e73ed983718adbf705f49d34cc",
        "6941b75b3f364b8b0afbb62c73fbf8475798960db273ccde8400861ba79b744f",
        "90d540e031070f120f1f50c4e03557010ee92369a46b29c580a499950bf726d4",
        "640a9fce0b6cbdbbd4a0221195b1cc19c03a2dc821c30142fbe5488ba3e9f87b",
        "50bd5667d60574c3219396115eb67a4bf2733e974f2f361f88d1c9cb5bc6e4c3",
        "04807d8704537d01d7c56e629b1cdd1aedfdd2eca92950eb20d0779693bf638f",
        "dcc9fa9b125adb20ff15d7b334bbf6055be535280df24cacb438dac10c58fb73",
        "b3bacf2f33dde7e46210d39cd2770cccc4eea0431145c290fc1a7727aef889e1",
        "f3489720be4deff9497428902e7d946ea507d135a5bff0252dbfa954a4e883c7",
        "c67e9ceb2bfe2f95cb15374161618a39d65530297eb1e77f7c8e32a16a72c022",
        "83de1763431d484519c118d3d9a32290a60cfc292f037b01ff271d67cbf783fb",
        "c781a7b0616a4813759c0f94b71bcebc3be07710179b8196a9f0c80a36a8482e",
        "8b3b302ff8def2bc2f441412ee1a5a8d654f0a936890083df3b237ffde865081",
        "524a1188b0d785cffcf6fca9eb34e4e80ccaa2508de451c600304af14b049b81",
        "06d010ffa87f5ef405d543e347584982a708d634e5de6844bdec525711669b9b",
        "41c357d3ac3cd91c199feb3f8afcaf3104b8bb593ada73ef7d475e734f42c66d",
        "87319c259986cd1da4dcbb0f346a0aa9145bc958470d9cf07b956e4190674e54",
        "5e9c8b92a43e566987a33d85bf687c2be5035bd51033c39c0d3313dccd8ab36b",
        "76f9cc3bfdf92a4b0d6062479cb522092c66447b52b387a74555184d5e19e5bd",
        "2662dfb94b71252a4648a9263cf1d38b27885c8776a6891447bfe25f8b6ba3f4",
        "b008e26801a7db51cb575305cff28bc8b6913f6ab6ac6c4007ac8df8541b909d",
        "6a89e42758bba4c1456d8adf43a93c5e90a074f1c130eee6e0c98c21f9685a05",
        "f33a3f105bda47c4267f3848e384bdaea6de9a3ae03215b9371b51c1242968d1",
        "a42e69c557073f2ff9cb189eec8f2e88f31bf338e4dc604fd951fec7fed0a7f0",
        "a3a598d6bae79ecfdbb1bc30ac21898532104eb2b69d6c6d8db1108032e9b276",
        "19a37f809a696e37958375358a32d2a049bc12b647ff54c9c4c78630656d2806",
        "3db41a3b9972d0c89cd8781df3af1c332636fd42ffcf9d118835e9463a2f1385",
        "8698c906f2b69b3d5faf511abb0d9710b95f6f81aeb4fc3104ec4f56ee56387f",
        "33c6a9c0ee8aef836b107c286159e7e43b9872bc9183b5b98300e946da634638",
        "4d1427e8b1830759e2070d13f27a037ebba0cbde7b66caf141b39b0e7194ddcb",
        "3bc9251d244950f284f40711b5bd4aaadb7ea5a22b8ac0c048735b1630203b21",
        "d99c45b0dc3777638e5257a3b0285216e6c624c80a8ee7c28e4613c4d3b3f8f1",
        */
    ];

    static KAT_KG1024: [&str; 2] = [
        "32b65a96d2111ab4c21fa02335d7290afaee8f1316f8d2a85388b57174a6b71c",
        "d81641446bc52c012aee0f41c77fdb6c8dc7a1a760f802d6989706c52043fadc",
        /*
        "a4df2e5e072ccef2c0e6daf15c73a64d831f9db88c8459c2ee99d0dbf1d489f1",
        "88cd9b69b27a2b6c54fb777e48e73c5b543d5cc17d1f57f547b8cf2a728a58cb",
        "d92f7de90bacd66261612beffabb92eb8c2201ffb946d8ce38a1e2aa06c60c42",
        "c9318099db21719afc98f27f173e87c6f626d71df9b240dff6926375ad148636",
        "bf277ea538678b6460faa4390ccbad6a474b7b1d6b6144117574f6482c304410",
        "59a96489ad34e9aafb9213280ca9850cbac1ddfeae80c2dc776017b059547316",
        "ce072b315dca98a3f8b7e0df0b95098bc9fba0139f9556623690ec05fdbd2b22",
        "8f9338e7705a6d1514676285218051917a2aad83237bd50ae0a82e89fdcc54a3",
        "000b6ec6b58c985afbaf97493cbac3f96b484b7a602817551dd62005954437a3",
        "43b1fdfb68a4b63a551d11a169b836778caade3aef8ed481588e3820e8e726f2",
        "5ff7b32a4122ad24008e5c796000aea7ecf8563b9cb863c1c56a44e663b08e44",
        "6d36b5a131dc453d45360291ff7629949f597709a39f71cc7f4d3702da602f9a",
        "1681e789954c1bb78944a16f14c5c255a5179f9f1be6b06144402656552476b5",
        "e35e058f302c74023bf68fab89ccfd5fd490ef9ddf6725feabc10e69a6183bbf",
        "c6c620bd00199dabb710ae66e712c8f3c78e23eb500964b9affae9f1ecfa09ac",
        "f16bc3c9bf68c773e6be11e1668461b82965b3e5b589ca53a8b5124242128525",
        "f1d2f35588060937a332d8e6c72930768ffac9030379a4b2a8ad69fe41304aff",
        "266842ee142d5e0e73266ef7386f22667667fd0d3db6f34be0ee4c67c257dfb5",
        "55b3fa113bcbe7a7f1078bca7de0ad7b3dc80a32866306b54b26548bb22c4f1b",
        "cced3b57897191af6c151874beb911d59f8a300b1ab0a44932512311e0507edf",
        "0b838ecf2e6b0cd65bce91b0f0ee8aa5ad444f6c9731f178429457962b389ce4",
        "9837dcf1646c3c4f0adf3d899b77473edbfedb6be30ada8dd9eed91c23c1b56a",
        "5d92f67ce6a01f590094de2a6067c064eeaa60a9d3798625a9e59efb0971393c",
        "5a1bc825b27ab3434b0f8a2463f1c718be56f04c28e883c1e07210e45030ab04",
        "3b12507f948411e894978414a592a567f1fb51368ac346ccd8c8e49c858bce28",
        "e1004e341f78050c1ed3f0e0964ac50ba9cc8312c4f59c0981aef48a4330a4fd",
        "eb0042da6c5d10d9118870b6b0d242dd7ba8c334322e1da02cd3de4f8002c082",
        "055ae3cc48e68f50666f937a9f42a518c950a23bcc747c20ded120dce6d6400c",
        "ccc3897ec315db0f3b1c80665e6707c709196d295997c7884fb0eb9a9c7f68a1",
        "c29e826a84812fde6545603fbf20eea3ec716bc292dd98c327cff2f8d9bb5bea",
        "171376f5cc8cd7558a1a481ac59f182260a443fbaa851bc637fa9c4cdf3b21db",
        "03a425e36a0c39a04268ad8b7e7ee9a8df68816127f75fd127afad7e6c974aa4",
        "7738e0a5a4f6730a0291c6242c9c19cf03e75a9200b3a4a23ee3a3c9e4060ec2",
        "3f3185bfce6b7caff409520bc460d5ccd02bc3e8cbb19b5c3d5909645daed046",
        "809f95fbd5296280fadbf5e07c322ba64664717b5ff8ee358d834d0af69008fc",
        "e8890897a52bede78518139ee79c91e031afb3266d12bfcb8e5904232c240ee0",
        "ebd8f50cf4e56bd69f609b7c8c13c5a71626304ecf34f4f652a0193320498d35",
        "8f6af60645af916e5c0e531c34137c2099706e94fae5c3896002d6564b5fed34",
        "e2e1e3addc00ecb5f60e86b8dc17c9a92aa529e170e357e67dc11a0db7ea7ecc",
        "1f439024ade89737d73e8cbc00881a9a1674f8b233a2943007733543ed95a256",
        "431c12fe3626573b860058ea03ccfdca5f86fa4be899d609807555017ce442ef",
        "0420c6ee9c82da34d894e257463bd7d9cb459544fa903ab6e4249b8b192702c8",
        "057227decc5c7ae64ff91bcd7e75a87e80267d2653a606e54372e4d4d56ae533",
        "bc4610e9bd29427359a945d1a31d18e2fb51d60244a4d26678ea434613fda3ed",
        "89e2bc853dd6f242440354d73d4cda92cd0c799371f0a0937105a91e24f084d7",
        "96c6f27edf34cc21396bdf18cbf41fc40c1152a532275a578b3fb37d9caea371",
        "5fff46674a34841098b430fa09dfcfc0b6ca2cd416b7f22e4c7a33ab1abbbe7c",
        "dc5ab2f45e6413f6bae80ac6c3970d24b54176f1303b9f48e4562758fb4e30b6",
        "ffe1ed12dde78ad7919745bc459e99af5191f782d24b2ca9156f7fdb340ebe2f",
        "df4a43128729e699df6f230d4ee85a3a3b6da0ae941c83eb22525884e345b402",
        "f0ad408a735d6f0f90875b63beb0a45afbdb0a0b91a1162955e2f31993112efa",
        "c029ae4fd716790230f271fb07f66e0d9989fe45ca9d9726af74602c4fea015b",
        "6712bb6af1f8a37f39197781531b744a18db05b416370296a8aebd0531b91e0c",
        "123a8bc490a04715dc454c65c192582b740024371b34aa85c1584b3cc9bb6a51",
        "5306e2971bf36393c8b133289524f1b12abc8ca16810be9bde3b4ac013ca3c4c",
        "1e4a29dafeab76894903fa8895ac0c9a4e01ecb5e8951a37dfa5b8d39d12f1e0",
        "0f78b3a57ff7d9cb4a7f7ba4bfa9008cc74d7590226e5df80f6515968d090622",
        "38742af2d065cdc81847c32d93c1bb47898e8531334caa507a3b8796eba2d3b0",
        "afab57656eabbbd263c33a4c9f853b53cc25eff8d31da36123a7c909369e0059",
        "65aec407a07020c217d8a4f4fd31be69e5d3a87d5cd6f6dcd991e01cdd768c27",
        "3d6562dfe697566b116671e15449d5981d9c411b4ad641bbac057da0c512a432",
        "64bba0d69de12a8e5b6be1192324d6884d66d058818f10c2a6eda55348983fd9",
        "63fd6d48c98c053c0862ec0a97c30d095d1538e17471ef98d6e2d4af171661ab",
        "d7e95a43b8b420c36588a1fc7830e92ec4f2129ac5fa6805da289a5eda9ef8e9",
        "762e222f87469d7d4cd460d96d224eed61787b92eab9365b566a2630b82b9b59",
        "96782824abed45c3700b3411cb217bebc718bc1eb07e79124a07c138e08d1e7e",
        "44557cb8f811ff5536d98a809c84de576f2a35f9cb1f987b0eb85b62a7dc7fa6",
        "a359547244ca7141ee4ddc133464dedbb838c06631dfe6ebd0e42b64adf07156",
        "30845f4d855488a36b4b2c4aff43d5d5385d724ad85befd2c15b61d4d0809151",
        "8e461cd1f0328e73ff1c0baf8bee1a288af958d598737c5af15703712b8bb045",
        "4249418a8e55c548e8bd3ecd53e39aae255ab53ba454ac749d5eeaa1efd99065",
        "8e8df7d72280f4d499f273392f787f7a2caa6072a7012b9503a57824e119b67a",
        "c14826db4fa2ec02e610aa85cd291cd58b793f0e25237dfa81bd9c8a80b4af75",
        "4bf57962198b6f3be408c2b0550721f70776143a9f5e7941527aae7b2c276167",
        "7be810fbf1f44ffd4eff9ae63e8bac8f2150f207a461efaad7c3800034ca47f0",
        "e1a29764eb5d7547f58b64b1f02849ed90fe0fd1454f3a1f7b6cf9bb36f71ab7",
        "cd5182e408da17de4d9d31599c534df974f0ff1cf008ed2af61f52aa6d369e29",
        "1492e8dfed9c88b192b929f7b16151977ef22a3ac2cd9cb7bbecb315f893a16b",
        "a07fe86920a91362672a477a5c3ddd36dfaf4fe3009fe79ea4841ffe3ea1d036",
        "6fff26369f91c69dffc8bd9ce4a4e7dbbb92b08a1403130a0d2a4b9c29f2e548",
        "d7f72a85ba1dcf6befcb8131b8df4a58c9a123b6131d9dd0edf3cc51a93bf6b4",
        "c272b7fe2b81a1beb216eeba2a66c72b40848ebf55072d5f5e5f68bec1c95b49",
        "5460fa2573945ecc89dd4c76ae8d8d365f6680544873de3256238efc156b9b0d",
        "ad7acdfc2388da8d72139b5c385d404935d484746939c5d1995b33f0dc30204f",
        "5ec9b4792467f1297588f48aad256c4352ec5de009a9bd05bc0808354d30452a",
        "9bfd3866bef485d5694b027fcc1ba28a66e4f523862f71bb1373e20b058e4860",
        "8dcad4481725d8fe27c7b34f00dd10eaa64f97b502772bd8be672a1e51db0dd2",
        "bc11f4e258a8633275fc4a0beccbb08a96fa2dca9450000a219f4d3769c2be48",
        "2840ca380438c3ebf201a58424929ebfcc76b51ea156cfb42a3e4e5df6aec2bb",
        "2cebdc54e163a838722157dd8756468a2555d8d2e9d99c1ca52566545ba97fc1",
        "33d931e2fc3fa7786e288659b6dc9def00408f981a244ed80a0da6cd0167fb0f",
        "283c6a1a562bd4259ed6d5add4bff439a8cb086b3c6bb8b2d67b030009c18a83",
        "2fef70e002def242d22afb28d1aff870464d69fb8af711aa26a2aaa493613863",
        "78aab28586fc75c9841bb24b9ccc9149dc28b20936274298f9f8bcab1e75fe87",
        "490aff7085fc822e49b765c73672004e7de858f327d2ddca1bec12a5b1d7b7af",
        "2b4e5ebd905c5df7b324edf948bc6ba7d40ba48776ea3f1c9104a8f6680ca77a",
        "21781fc885c903594b994e62063997b6c4022e909786bd978e1c2d909a04d064",
        "d52d6d461b09d910ebad5ae01d0dfd40fbc13dbd5f82286b252c699a72536daa",
        */
    ];

    fn inner_keygen_ref(logn: u32, rh: &[&str]) {
        let n = 1usize << logn;
        let mut f = [0i8; 1024];
        let mut g = [0i8; 1024];
        let mut F = [0i8; 1024];
        let mut G = [0i8; 1024];
        let mut th = [0u8; 4 * 1024];
        let mut t16 = [0u16; 1024];
        let mut t32 = [0u32; 6 * 1024];
        let mut tfx = [fxp::FXR::ZERO; 5 * 512];
        for i in 0..rh.len() {
            let mut seed = [0u8; 10];
            seed[..4].copy_from_slice(&b"test"[..]);
            let seed_len =
                if i < 10 {
                    seed[4] = (0x30 + i) as u8;
                    5
                } else {
                    seed[4] = (0x30 + (i / 10)) as u8;
                    seed[5] = (0x30 + (i % 10)) as u8;
                    6
                };
            let seed = &seed[..seed_len];
            keygen_from_seed(logn, seed,
                &mut f[..n], &mut g[..n], &mut F[..n], &mut G[..n],
                &mut t16, &mut t32, &mut tfx);
            for j in 0..n {
                th[j] = f[j] as u8;
                th[j + n] = g[j] as u8;
                th[j + 2 * n] = F[j] as u8;
                th[j + 3 * n] = G[j] as u8;
            }
            let mut sh = Sha256::new();
            sh.update(&th[..(4 * n)]);
            let hv = sh.finalize();
            assert!(hv[..] == hex::decode(rh[i]).unwrap());

            #[cfg(all(not(feature = "no_avx2"),
                any(target_arch = "x86_64", target_arch = "x86")))]
            if fn_dsa_comm::has_avx2() {
                unsafe {
                    keygen_from_seed_avx2(logn, seed,
                        &mut f[..n], &mut g[..n], &mut F[..n], &mut G[..n],
                        &mut t16, &mut t32, &mut tfx);
                }
                for j in 0..n {
                    assert!(th[j] == (f[j] as u8));
                    assert!(th[j + n] == (g[j] as u8));
                    assert!(th[j + 2 * n] == (F[j] as u8));
                    assert!(th[j + 3 * n] == (G[j] as u8));
                }
            }
        }
    }

    #[test]
    fn test_keygen_ref() {
        inner_keygen_ref(8, &KAT_KG256);
        inner_keygen_ref(9, &KAT_KG512);
        inner_keygen_ref(10, &KAT_KG1024);
    }

    #[test]
    fn test_keygen_self() {
        for logn in 2..11 {
            let n = 1usize << logn;
            let mut f = [0i8; 1024];
            let mut g = [0i8; 1024];
            let mut F = [0i8; 1024];
            let mut G = [0i8; 1024];
            let mut r = [0i32; 2 * 1024];
            let mut t16 = [0u16; 1024];
            let mut t32 = [0u32; 6 * 1024];
            let mut tfx = [fxp::FXR::ZERO; 5 * 512];
            for t in 0..2 {
                let seed = [logn as u8, t];
                keygen_from_seed(logn, &seed,
                    &mut f[..n], &mut g[..n], &mut F[..n], &mut G[..n],
                    &mut t16, &mut t32, &mut tfx);
                for i in 0..(2 * n) {
                    r[i] = 0;
                }
                for i in 0..n {
                    let xf = f[i] as i32;
                    let xg = g[i] as i32;
                    for j in 0..n {
                        let xF = F[j] as i32;
                        let xG = G[j] as i32;
                        r[i + j] += xf * xG - xg * xF;
                    }
                }
                for i in 0..n {
                    r[i] -= r[i + n];
                }
                assert!(r[0] == 12289);
                for i in 1..n {
                    assert!(r[i] == 0);
                }

                #[cfg(all(not(feature = "no_avx2"),
                    any(target_arch = "x86_64", target_arch = "x86")))]
                if fn_dsa_comm::has_avx2() {
                    let mut f2 = [0i8; 1024];
                    let mut g2 = [0i8; 1024];
                    let mut F2 = [0i8; 1024];
                    let mut G2 = [0i8; 1024];
                    unsafe {
                        keygen_from_seed_avx2(logn, &seed,
                            &mut f2[..n], &mut g2[..n],
                            &mut F2[..n], &mut G2[..n],
                            &mut t16, &mut t32, &mut tfx);
                    }
                    assert!(f[..n] == f2[..n]);
                    assert!(g[..n] == g2[..n]);
                    assert!(F[..n] == F2[..n]);
                    assert!(G[..n] == G2[..n]);
                }
            }
        }
    }
}
