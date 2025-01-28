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
#[cfg(not(feature = "shake256x4"))]
use fn_dsa_comm::PRNG;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Re-export useful types, constants and functions.
pub use fn_dsa_comm::{
    sign_key_size, vrfy_key_size,
    FN_DSA_LOGN_512, FN_DSA_LOGN_1024,
    CryptoRng, RngCore, RngError,
};

/// Key pair generator and temporary buffers.
///
/// Key pair generation uses relatively large temporary buffers (about 25
/// or 50 kB, for the two standard degrees), which is why they are part
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
        tmp_u32: [u32; 6 * (1 << ($logn_max))],
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
                tmp_u32: [0u32; 6 * (1 << ($logn_max))],
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
//   tmp_u32: 6*n
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
                fn_dsa_comm::mq_avx2::mqpoly_div_small(logn, f, g, h, t16);
            }
            break;
        }

        keygen_from_seed(logn, &seed, f, g, F, G, t16, tmp_u32, tmp_fxr);
        mq::mqpoly_div_small(logn, f, g, h, t16);
        break;
    }

    // Encode the signing key (f, g and F, in that order).
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
    assert!(j == sign_key.len());

    // Encode the verifying key.
    vrfy_key[0] = 0x00 + (logn as u8);
    let j = 1 + codec::modq_encode(h, &mut vrfy_key[1..]);
    assert!(j == vrfy_key.len());
}

// Internal keygen function:
//  - processing is deterministic from the provided seed;
//  - the f, g, F and G polynomials are not encoded, but provided in
//    raw format (arrays of signed integers);
//  - the public key h = g/f is not computed (but the function checks
//    that it is computable, i.e. that f is invertible mod X^n+1 mod q).
// Minimum sizes for temporaries (in number of elements):
//   tmp_u16: n
//   tmp_u32: 6*n
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

    #[cfg(feature = "shake256x4")]
    let mut rng = shake::SHAKE256x4::new(seed);

    #[cfg(not(feature = "shake256x4"))]
    let mut rng = <shake::SHAKE256_PRNG as PRNG>::new(seed);

    loop {
        // Generate f and g with the right parity.
        gauss::sample_f(logn, &mut rng, f);
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

        // f must be invertible modulo X^n+1 modulo q.
        if !mq::mqpoly_small_is_invertible(logn, &*f, tmp_u16) {
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


    #[cfg(feature = "shake256x4")]
    let mut rng = shake::SHAKE256x4::new(seed);

    #[cfg(not(feature = "shake256x4"))]
    let mut rng = <shake::SHAKE256_PRNG as PRNG>::new(seed);

    loop {
        // Generate f and g with the right parity.
        gauss::sample_f(logn, &mut rng, f);
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

        // f must be invertible modulo X^n+1 modulo q.
        if !mq_avx2::mqpoly_small_is_invertible(logn, &*f, tmp_u16) {
            continue;
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

    #[cfg(feature = "shake256x4")]
    static KAT_KG256: [&str; 10] = [
        "77ebf1d3458617076b4bf2d536f773a35c70ebb698c0dacb1c37e5d3874967b1",
        "c4ca2115a1df738f72384d18cd27fe1e4825aa87214c19d8dc5b5c8396dd6ecb",
        "8ba953ac1f77c37e2def6a29bd7e87d00c374ff10beeb1baa41cdd3675721182",
        "3ec0bb7366b8a3865da582442e167527d745bafda8c26cacd38acef940973db4",
        "e84707ab88abf87b6edbfb28cf0f36f58f91d3216926778ac0ebb08386bfcfaf",
        "d019bc7d96b38e6df6aa42c1d9e7dea0d0c09132b4f4ee4e367cfcd6c1b60853",
        "38d03bb6987b9632d1623f36badf14a91c27b6877671cd9424908100417c6877",
        "91897e49fe47dafcd583599ec5d062032fca069798336d95f60d1ff4c586b2c5",
        "197579636a7d563f123ba248e657da927120979f666006cc0ae78b4e2214e33f",
        "019d20f47e8110afee01924741d671a54b41a0b4ff64f487c30f78644010129f",
        /*
        "9b770f7f7c0c30425c772090c82a1611b9c0a212695b2589b5ac155116ebddd4",
        "dc0a10fb9c7e419cad2e0ab79fd47771157945ae5fd499a298ccb4d0f8acb673",
        "3b9dc90f7bfd48621b280cd7bdc33d759d86be40ac9579f339f62057ec07753a",
        "7c8191757829df839bc1b1f8f6b30fbad5a2192834bce9584403e58d1473392d",
        "37b22ed2dd303830f6d9353fd776ce97e2165bf6367dab760f1875dcd7d6e095",
        "fce8747bb2a6ef156a86f2274db6e1e0f7c33bc6364eb513ceeeec9e380c63c4",
        "f7a906988baf7e70918a96bbe43df17ddc20ee24446c7c95922a6a4243ac1965",
        "9b448a9dd0dad2ee8156ea6d28ebeb42ce09fc368c4a55faccbd3cdc299754ee",
        "71ebda390ac040f9be788db163517606ec31e686388dec9b4300b5153667263c",
        "ada315ac7f973fec8241d4e628ed48556638b8971c7c1ae1f71df4a141ca577d",
        "6539411baf67b348d2eaf433a275d7e4487a544ada795a8a97cb3237a5486af6",
        "8ca9359fc09bd7eb3d633d0486211efb1cd475826ff562b65d6ccd5456448b42",
        "20b26774a9ca8deb50f27bceb8ff466b12bc40ed63e8b23c6cc386c194ff4993",
        "aa25e1b7e512ec1003c449fcd619ae68054d5053854dd089d682837eb4a1c27d",
        "c33fe4643bcc0703b9610dd0671d2ec113f7153d5ed939271ce844003defbbbe",
        "efa4a510340832e3c16c2e07d2ba5d95a1599104bd5dae337fdfc813bfe6a3f2",
        "af000a96021c85837b7034d315a917c531514f7b45711ba5849c00e33204724c",
        "216c4e19bf4b267493d4c869b7792301d7f98fa03065b3ffa13b218c3fa61dc6",
        "c6a959ae113dba3414c4a1aeb9b1a7fd50d527346bea318b35235798f3a61c11",
        "4ad261fbe3ef050ae928db8762558eba4f7a6167997ad075cb524e3bddbf1cce",
        "76f8170697e5c86bb7ee4b30d6a029b50f9e761433d11b5314976a35326887a3",
        "97f6733adafe1bdd1fa111514c979a31130f747384f0cca8955aa79a3f6c90df",
        "894690240a2e3d661564f60232639b7c01ecd757a90f373e6eac30375d227643",
        "ca9c578f051ce47fab6184390f776652c2d20894c70869bfe92c23d220b2ce80",
        "98e6a21d835ebd0fbe77c8eaf54006facf4b5e8d18c14f4765df3b009095dd74",
        "cd693825e01dc4467873839f6e83ed0b235f5f840b6d9f701487c5c78154d3a9",
        "ab2e08894efd64cf97e3031c4ef4279af026497e96c3ca198db623dc03fa11e0",
        "02dc813b66a31b33561879b8fec3499799771c965012f8901afb381dc3671f49",
        "66feddfd5a3b0497e51e397b4d04b0baa4da6ec389aaff8c760f88c853369b35",
        "c0e585dac06f3e959aa5167627f047474f2292acd5b692182509ac4c4d62f6c8",
        "b732b2113abe80fe4f6b5003a1820316924d006bff1096dfcbadecc76438bef8",
        "4c764a8c6e431eded8c42a5dc357ea5d7b2e71695ff1c90ff27c49dfdc10fc2d",
        "c11eaf9f5f39f7b52ca732f305e716131532a814cc4e9fa55f74da5f97828476",
        "7c62e7b928da9a5aadee19b22e72eee64574b1c5b7cd5fdf571eb05c53edb5b9",
        "974d118ce20fda82aec9916075070b264a5732232e001284d5d9a6222a4493d3",
        "2b9d31ea245fda5c0ae2dab4d6931db0f89da89bd9e92a4fb5491904145dba34",
        "226d960ab58b45daf495e65f2b1116226e45c8a5cc87cf1522f0ae2db0b119dc",
        "ba01ce2a885931e61e34baf15d8219dddcd616c7bdf8be873d7fc98a98616bc7",
        "04454564d819310a7cfa71592cdfbebb17897ac80685c9d52742d619c386f02b",
        "af6e8f450742c90f47d805de1a898eb6ff25c298d7316b1390f857e25955b071",
        "873a4e2789eca51659401e593208c0a212d4718486d4d9be866dff7c3a8eba00",
        "b6755e47f292d0f41b46dcb1ab9c3506404ca63b59ae4d043dc48e67ae6c0c00",
        "45794451e11d16089c552998aa0fd57ea0a25cd20ee29bc30aa7d408926c896c",
        "a29ef3541aa98e9cdc7a3e5427e16ae8812ce9d0b18205429a5bd577c50c2dfb",
        "c5671a456fdaae92c02a03eedbc7c4377afb963af2004a4fb2ff727d9a17d0db",
        "4acfc34ca0caf8fe7184fd0f22c1948a650356bbdfd1f31ad6225b2832aec0cc",
        "1bd4a7b83e46bfa49d866dc8ab7251bb32708fb0a729c6ee428f6c7d948ee5ec",
        "c4f38019a3e41200f3615b5f71d8b11207c0e8064fc4ae63c241054662ff94e9",
        "42e30a442e1ea7ceb6b958132184160556c77efe20d03b1c8c63c75df3eb49cc",
        "98bcd8aabd6555e37e2351395d9a11feade1262bc3c9a28a9da504f2a8799320",
        "975f2b0157bd97f51cda0c97522765708c56157efc82096f943ba444dfb917d1",
        "7cad8bda622e9706ffb1586911bde6300897eac9416a61380e69c01f8a87ccd5",
        "993a9e197e4d78ae3e91f674477493e301c86f9292bd15a42cf77b2106e99b2b",
        "0d33410cd0c2aeabed152d2be87206e1d560067368925a4f1f923846e59ec319",
        "461143bf00a33c1eaf6ceaa9d1e26311eee7d1de34ec0e954846eb54575d5b58",
        "2913d9704cedf1006254685805a5555ba0be72da27fcefee3b55f2a25cf3debc",
        "cf5e6082d62f86a42695152a8cc62ee05adaf6b9f91f988b12fa97279596dec7",
        "b252c08049f29e182fd2cbfe6673f4a69bc92b2d4b19261cd3b1dbdfe959e457",
        "3b8ad86196390c160de47211ef9b5fda2e08e1a6bcb6bef73eacd426d2a127e5",
        "24af693c568c0f952a04607bed57fa0d5c50781644016d16c14e3b470cff2b16",
        "4ef75e790c0c17ab8355e4d593a381da525bacb7f90ad7ee6dac93dcd1f5c357",
        "73073279e63e6fe51b219b283facd8b67f61e08fe040ae85f543519909f5e9f9",
        "fe879a263848352876f9cdae95c4d148ec331db5d1804e1a1338e21261ac0fc2",
        "d2846e3bb8ae974604ab6673b449c1196ce2a087f4ad6b7c9ca37b7e7de36177",
        "073ce8a9d0173417a9bb25283e7c4a91fa3ddd5c510690b64b460671663ee6ca",
        "44fcda26c1ec911f4c38e387a230a95c79cd1f0adda238ac9e07e6d640576807",
        "377ac1346ea8fcf4f05aa5c474864e4a18cf18e8755cd871c5c072a1a4daf876",
        "c4a8ce634318284fb48488123b96e1198fc54450b2b708b6d4c6c5ad5a81cfe1",
        "faef9aaf69a1791a3c0ce29aa598c76d0b52bc220b811a5dd8fb6335dfe7c40a",
        "4663f2d43e3a8d45bc7fa9fc71178dc09c6de03d52dd67f414c57602419597dc",
        "b96b4a2d5fbb2d4e169e1b0f894460c2f0d344eb2af4198d9ba900b210ba48d9",
        "0e3a9f096af7489cbeaab60860929a9fb4d119d4c1d821c1f6421f77260ac8a4",
        "957e51872daacb42a0f3b7e40b3c1804b55f5be533415dff75ca8c475be4f446",
        "57eac2c55b74121ddc11d144a24577f02223e9a20f9325495e407f4981ab4da2",
        "e4584e7f32f7a2850764bcad5c180b7aa52260ef6ec5a14d3887c964229d698b",
        "a7d2d1504e0dd9fc1043478f504fa48961681a2b7d45ef4358ff9d41051630f7",
        "708f616b7a75aaa3f577e9aa34fac2b7b767f608155718d54aa1240ab60e602f",
        "4e7f779ac310a8ba7b85392fb4e398ee0baf8c5a27ad89bd99239f589199d24a",
        "51a15f81e1a36126deccf827700bf8505fb6aab24c5829bfdc620f3212e5c683",
        "6b630c05394e195e69216419ac69044df1c7b1a0812dd9038f2edf6e57cd3549",
        "4ad41c79998e81ae486007dd74b59aec44121508ffdb63f26a2d8c0ffd0452fa",
        "f3f4810e7d3ca4d57200cc1688d15e7ab70e915ae81ad0ae2c07e9c0762b4175",
        "be7f17bd2726aa36314707b6b0980672ed8092dc89da21a2247380edd52de0e0",
        "2217fa4bf413c0e1461d49b8dfce33cc8b7c218cae7c5e60c2534cf9825441b6",
        "f1375bef9ad9d62dcd823c558c9b6855c743616586f47716c06fae6ca6032397",
        "5efaae14783b9782072d749822dabbf444076e74c3ecb96c90fce18e97bedcda",
        "d191639a68697bec2060e23c2e03346a5f928735ea61da846d672bca69e051fa",
        "19e7d78d40103de532f9636a4967e7afca79e624458195ef2c4f573741a6da3c",
        "d8e7c3f5e3ab312c5a8400a7b0c00fac8ba1a2da06fba052d2e4a872cb5d90f7",
        "8f563abce76049516e1cabc171e32962a2f4542feed5616bb32dffe5bd5e6b6f",
        */
    ];

    #[cfg(feature = "shake256x4")]
    static KAT_KG512: [&str; 5] = [
        "7b4ecb9d81d2c008f563f1678490defd502ce1d904c76739fcccecb0bcc4e556",
        "53026bbd37da5066a4ff98bd50ca96c99b6c3c78dfed40cf6ed203bdf36922f9",
        "6d741445148bcb0f803f2c415566312752a7a73eaf7fe574a98dcf85df9a66e8",
        "17789234f2d8ae5d86f43cbb75c480a940b62affa4c7e1b3dd2e86132f8e8c72",
        "76d9149b9c2ed7d30f3f8b783456589890aedc9dd78ae8e2bb8d275ad2a118d6",
        /*
        "d7dc660fea140852edc4d7c87cac14a9c9f25c6e931a3561a02b2f075787543e",
        "13e150f0747d9a48c8714e89dfb0691383cd0eb68293c89f929eef3fe1048fee",
        "4caffde46f3985473152ca5876a0186fd7765701af0cf298e1389b55d140c0e4",
        "fbc2b8ec1680b16db80c5b834fcaea4274246da55bc09df0d47671f4d7f7a7bc",
        "e79a7ecf9101d303666961aa172b3493f7f5ce9c34391607ecc185d0ba4819b9",
        "9c5419b9247d64010c66cbd11b3f5632fd4037455b119508159e522caf279bfb",
        "5d18dcd74387696e0deec99206572de32a607efe836760746da7b5c147825e0e",
        "d8363a8f51921e0ec9e5bfd1059a164521cd76f589d319a5dfa6a70157910ade",
        "b1da93e7a9740ae7019b18f9d03df5437fbf31fe6d1ba0aef449e417fd3b4a04",
        "e361866fbce09baa85385e9dc7c5e5df2514ab48102477fd8e7678ce28465b82",
        "b93884a1156e5d22345f3e73f1b489881a64e17db660d89deef6b380d972d24a",
        "244f45eb185211c0944d72d7614bffd46256623ec3fb07ba4adaec9bcab948b5",
        "740200bde5d8dec713e2195946783789e497a29083193e44a1366eb72c353074",
        "d3562bb4a685298c76d14b0927e112043f46dfe1c50b730331e34d81ce75b190",
        "520776f6b96dd2fdd24b7ba240ad7d64899fcb11c4a090267a9728fc7063f1db",
        "6ad110f1606df33ad6e5e4dc34ca9230bdfb0c36c48bf253b6c4568ca14ca7a9",
        "8a0175cde34ad66110389e6b32bedb26736f83f5cc2ed7112930d8faf941a963",
        "c19c849fa170df1868483055693ac9b18a01cbe1e946e23bf47aa3d138b7b87a",
        "e8e18a758c443600e3a8d8b5b74968db7e374a4765ddc1594283507856b4944a",
        "df7784fdee661434fd552fb00879e2648a81ab3e608a16c05829a6fb5b8bf7bb",
        "f5ccd91c6dfd0cf3d1d60ea380ccbb1c43e55f7a648020fbc440b56a84a95269",
        "0e8d22df8026479da5e9996095136ebe3892ba8dd13854ac2517abe1206e37a1",
        "160ae481203a9f0942f43062fbafdc02270f65a84bde6b6a8b4aae42426fceb7",
        "73c34a649152ab81aca7d7576bdf5bfa9090ff2b4493ee88a99704d57cdd711d",
        "29596bd8cbc55c2e0fc455cf240ea74b963cc004145c07a4c3314a56f18625e5",
        "0ed6a8f2a11337c19296b5aa5dc95b13048a7f3734a8d5874d9a21cf09bdc448",
        "bebd567b9523de8ea2b6a5e77d1a186a168f4dff28a23b3e352c82bcbf4983d1",
        "3cc321801fafc650f7302ad83ec54902e36a779e09d25fb150853068b0f22a9d",
        "f1347ac8e2654cd1e722e3486607eae79ea552f8acbfe85d0a4a220178df0c37",
        "c76440332b17230031451434b54070033d86f4756fea13bd4eaab65df18f1707",
        "d1af57db3444267d426745ee585c0f43c2d9cd869a7fc681bd26d873d68d03dc",
        "3db2d8b6940da08539929450726a23d40197f2804d21ddbbcd096b9b8812eb94",
        "7f5e6b62a415538a01ea5536408016fa36b3d25d809f3afc9fe31a12083f554a",
        "eb82a5f16655c226bf544b8992c2f4f1fa24f59176449c77e0053ef48771626a",
        "e8cf44da03a16e59a10503775073594d670f22b49b9a3bfcd6391bfb238b9a2a",
        "fe4e7fee91a52e6423bbecda3d678f35a239f255d3e2d9b2822f254d6a2840f2",
        "411dda726af3a0e7b8e9e04390ab088eceefee9514783c1d6a5cafa261dac8ce",
        "ad44d46facd518b1908fa8018d56ada784c5f33896ae09b0a15d7eddf213d4d5",
        "d289600249257eb676d879da979576affcd9cef2547add5c282c8c7d5e149b82",
        "bc043283ec936d8f76a76cbf72217771aa285c87f9c12da56c1784bd935f204d",
        "efcd793f55a6e48d3186fd1ab1f12705afec1b35cccae411e9b87a50580fff17",
        "453fa4f5026ff9a102492fa7e3b1ded08dca271e1a8d6c2ce0ced6e1e802a6b4",
        "b3dd593967e9ae62e27feaafcb4ab5051b178b0fdc6a85f0e8b9dba3f8f2330c",
        "d3af59836079331c657b71e64def43883c8c3c01c989ab972280271cb613e091",
        "b6639d51edef505e45c031d22a9204d53cbcb6fd6a9baf9d7a417d803617f390",
        "f6f588a5620a01383bf7e473f57667182a28ff2733e4da3618fd111696670e8d",
        "dc122cef901f1d2dc9e704ad181787797bd9b021707756ece43dcc2e031d7820",
        "24b80612589453ad25eb22ac740aec240a542038edc1dcbaf10ad8de2e377589",
        "b8c5433929dd7f78be1c725499f61736ca1e788ce31e75583b852a50edbe3bb6",
        "6517f09bf90baef854c67d86a4b7c06f89242e2e570745d07643122cb9e2dc30",
        "72d8307e30073f60da6467b1235a5a0154f8a6690f5c2ba2ae22e8389998127d",
        "86df3d405ee534f3eeb10a18f9f1ddc8a4150b22b0e16f39eb47eac555b63f8c",
        "469e8d803d2dba2441dd530c53f6799d5b942bd0e90a36bb4d7456a5f427ff0a",
        "b1713b260123fcd5be6512ad10ed22493b030fc4368a6b1cb979ba09783f6993",
        "740bba5bda6d72d925caeeb7d568fba8f318aa646597210cae03cf27453e8b4e",
        "f2c901f9e367ea7d0021f000d415c1d42c3f9a178a18e9a761975a5cd8266e31",
        "c07fd9857fcd2fab6eda988a6a67c05fab6034446649503cd256653d9bb84e4c",
        "273d35e6ea6582372725da603fcb16b445f976e524227c13e32a70c5e12e71c4",
        "2427b6f49050d05672bae9c754d530d5365567574966b27b83970ad757d8eaac",
        "0a480f169a7e205473f01a4414884386e578439553af6bdb224c8fcb36004411",
        "c19d6a5b563e3dd77f4b2ae4f93a8b7aef3e0644aa8430b1488deeae50193c73",
        "ed7c7b60ebe016f2a9283e4c662721a0a3f6b2a8db4d755cba35333fac2f9302",
        "49d58b56fcab56b3529aa1244a9405d17998434a82933f60d59ab0b17c2d4024",
        "55bb23ca26a795cd5906dc86626156c2ef9c1036974d22aedad6df4e970c4ab6",
        "16d3062488b55d967dffe0f1f4e0ee54db2b1c375a5682f6255e4467e8870480",
        "efa7c5d72407b16f8bb21b559fbdb1297d4bec2cd2bb0b94d5f131668e05387c",
        "63c2605e3f7bd0460babec5a459fcdf241c00e165bf296284f1c4099faf0ffd9",
        "4bbc6bbae00b103c69891c47b8982e4ac8e53e0fd338ddf0f39f8f1f89e654e3",
        "c164c98e293d6b956be726974432713ef754b8debd3a9e962c1ea2784b51ade2",
        "f9de1ec4b2d46c60db0bdf628aaf001e49a349f4d53852c075e2b3bf2820624c",
        "625770ff5b4c22caa505cf7491ed673ea759d952930d31b2108af4b0447b117a",
        "b044cf16f7c9db30d371c7e3c6497d33672fa0c84c36d338551c0019b2ccd9a5",
        "4962defc20cc45152fa02d67193bdeeeeb8f5ace7fd9793df92c386716d23760",
        "19acce4e004cfff495c3e3b0f641356807e6483f4ca689b662b6d56262b8f4e1",
        "4e397dae8289e2a2f31424228b2bb97062da9f71ce3ba84ead0349ac603066e9",
        "939de78419bb72b79ea8db45bbbbde2821d13af777355c80914e013d2a509e20",
        "85d3d0f71bd02000a3267f220c157175752f22e5c41c24ac1f3d116f71fc11a9",
        "95835eac4496ffbcb83047da046e64364032c817e12f3c86d5b245a80c5ef4e5",
        "6cfa8f7d9082775746701a093afc4fa2b7736ea93f3ea54d33127f1872e412a5",
        "158718c2bb0ab26d8591897a4011a3baff53451470eb36c7a4588291d111f747",
        "d176b72c085fb2e06ca7faa14b89b7b22a1065eb3a8676cdfe628018063709ac",
        "39ee43a6d609459050b4ed361e60fce3653cc4fe682d2f2e7ee04bd4bfc720d5",
        "fdc36f3a65a9e9fae587efd0a20e9a20a9f940f3655d96b5e3cf7b9e16fc0e79",
        "b29db3e9dabe32c3e36753633ff308e780b309d2ed5757e932a4970dffa8e691",
        "039337243b1e4acc1b5826829ef7db04f56e84cc26c6e7fd56d59b3e26baca6b",
        "e91c0820114cb968f6e848531e2f339cf04b488697146a5bebc58de884cf5ca2",
        "60f7132b689737db411c18039ac2f1c9de4aff7849b0f1df8c7eca98e5d34ff6",
        "4d5bda22a831b920705cc28834ab7f1d35cdac5a6ec6408b11469356422b04cf",
        "0c15ea9b6c2f9ebd3e8f43ea2fd2f4350fb1d8e9995929b5ee32cac665285556",
        "4afcad3af1db16ca1bb794c46fc9589a3053aec9104dc9d50d6d2f6375fff2c5",
        "0e6e344131044600262d1cc18baa6cf2bc8a140d2e4d281c63c5a7d0306be4a4",
        "a5e5d4bae74d6958ab11a275b0032f305be61ec23f0d69c84b1b8f6b1d753de4",
        "c4ae0d7cf63eb3ec2608d84c30967e18df76cfbacb6223a89a045b4269e2bddc",
        "35a1e0571d0227d7aae90417a764df2a3f82b029d7defd83f015b53083c55b6c",
        "c9a64d8900cc341225762a0e25f5fb44298251e7ed6c8256e88f7f10e5f2b30a",
        */
    ];

    #[cfg(feature = "shake256x4")]
    static KAT_KG1024: [&str; 2] = [
        "d4da28c3159d76f13bc93d41f2dc7f087285ae1fa70e6e64421e388ace5aa49c",
        "cb3afab7b9b49f20ca20744996322ffe78b906401ecbba6ee92badceff1cb1d8",
        /*
        "17141697d4c2f71d07ab0939eac0d940163838f00188d3de28272c28e7339444",
        "ba4045926a4dc3b2862d50ddf9dc960cd15d239c02f9c81af4e59c0014f3bf12",
        "a3eca1406ab70ca45e94c230ea1342f9ae1a4411bdf9418e38a27c82073c271f",
        "cd93e7300a9f4bd9cacfd69411448cfc739ee8c725d6ab0e86275fa821f35490",
        "e1fa2e5a73a3613ae0e4f55df72191cbc2538b7c417a7cae108264faf282df21",
        "c408e54b32275e770dc9daf0ec0e55cae94f65d2e15f6327ce7942274d169323",
        "ed3ee095b9ea00893909170e78e7c4bdf673f5fba7e080af6d08f9f978be3025",
        "9980e6b56fc7d30c2dc56eedf56ae98b7c4366a6f7b348b12fac9e27796a1c49",
        "f772f43a39fe76dd100d1231edaf21cd044030ce2193b3707baefa171b624ada",
        "957af3131de376e6359cbce3b414c08be4da0929f0c8b512ae0d46c4c786a0cb",
        "27c92dcd5c0104a7a91a219e1df1fd093ef81e695ce3aadb08c19f2763e0d2c4",
        "abfabb7b3654020d7dff0a71224b8f8149fdd57910206df0ce6f08ccdbfbe4d5",
        "3feb6afd15cfd1358b215bc065073e3d1b2c31facf7c5252b644fb7ee47f5dbc",
        "fb01cc640cfdc973b76274740b40f4e8dd3c4d5b4f379e9ab93cddd57abf2270",
        "3b8f7172f916f97deb00c5f7a49e8ca63b019e7ec40e68848ba7fadb3b001588",
        "c083e5caa98431891d4dff9f5545cc34d754e5374aceb34a198476e700baf85e",
        "f9b3d38bfe7d967bbd8de6d44467a1c220bdbbbafdd351a13a0d2afba906620c",
        "ccca5805dfbcbe614a485c8fddaf3f56b46f8244a0d34abf9655b3e2d724e09b",
        "42b650574796db8dc8da36b8ccc1b528d6eea2c31c020c6a2081777410a55aaa",
        "9d289a1a0557959a5093c072a5e4c7171aa8ecbebe99af6d66f195aa88b92e6b",
        "5262dfab04cb2114d10a97a8756196c261881e94d55ea71de879e13a3df969d5",
        "ee387ec142f5c4ddec3ef839c7610b2bd35438829a65375303e6a6fd75578ac5",
        "98fe51570cb6d50ccf5260bb19ce2e54f613ecd09126bb6c23a2252b6c97e0aa",
        "88fe32c3ce3eaaf4ab140af8eb0db0ae3413bebb27b6347c22c1214c7ed679a3",
        "4875eecceb45bf12bf7db9ccfe37d3a22ea8d70ba5607a271822f7fe2ba41cc2",
        "fd3ac27607763e00ec47392d0922c219ab0606a4e6c9f9d320161622d57e9566",
        "b7eb2de31418090c12cc32befee5e8475c25e8be1d50afbd1a6fbd0b8d4532ff",
        "88074efcd92a78858983bce53f6ca0425c39e7ec16240f0df9e0bcd7c5cde281",
        "5562f4dabceae14124f49323a0413aa19656b2135fd375cfdfb160cbda619502",
        "71e4ae058d30d03efada109cf55c5e96874dbdf97b395c41f6412c6accc9e6bb",
        "dece96ab75dda3c5fa8e45e8919a812282e8e952bd2ae76fa4588daf19dfb88b",
        "d7a73f978933d8df868f875ad4e959ddf62e729087e7a6c6cc481cb04e2ed257",
        "d3789e5ed6639c97712f3ae4e81d8a0e2ce9d8017cce1c055730aad1107f4166",
        "7867c1090f885bf1b25d85f31273ebe54ddf665ca6c2a5a33d205544a4b6bd5c",
        "1054ebb337d3eac89ed6369143ef9eddfca3fce18e9a96cb9dcd08617332d0e0",
        "ef9e9b2935370991f5cc9e367e7d0af18b5be57bbab02c5909a36e914d5cda99",
        "0394a11c70ad6f4985bdf4c9853d8c48bd1be455d9e8e4218c6fa2c8b49f8d99",
        "d977d60536b6648c98627e2b45e73c11474bc1fc2b98a4c6097c3ffceaa23e26",
        "c2bb7ab682f4622ff8e931009e86ebbcc12dae5a87c52186eea5bd8ee2c1fc8f",
        "f10ef348614dda95ed650e6c3f50cdc4b56000e3f6f23eefcb5b9930f1336232",
        "3a0bc893a13093db54e16fd66ee16ccdd1a77b49014d6b736084be7db978740b",
        "e39fab1235c6c1b07466dc36b541347274dc7f2f262f69da1eb82a627002d6de",
        "a3c461a34d1c1999525490f1ddaa10e913bc31a65cba9b16490d2430d6ea52b4",
        "809788c2427854466e3aeb97f7eee31e933b80990fc93e3df77d0e140966031a",
        "0127dbd3a070f9245cad44c8c7191b3f4fccaf94ad5b527310b8c499cb1beab7",
        "8839593c9e3574ef0b135a03276ec2eb624baf0ea1deed81c6288e1dab57ca92",
        "524e788be804214384e063837e38a4a1408ab4ada5dde4b97413fc7e77ad12c0",
        "7ac0dd1aea4846b83e443aaef13ceb5d5c49f59254b81f5a3a5c8912c7ef0f95",
        "edb396ec43f1da1ac6dc6eea7d1c16bf691d70d1a758b331b632f37966a4273d",
        "c1d9c645ea1c580a96fc9e6ffa1c4b3888bb981e5dfbcad36951c39c763797c3",
        "54a775ab64bc64b96ef0300a01c2401a4f91df7633a00becc4c238e775f0b3d7",
        "33d489bc76614e44664c2faab6f5e3704b1ecabac58366430bfd9377b0704101",
        "633ac75250e1b118c3bff994f1173fb95203ef6d947f08a7023eb3921d2e5541",
        "ab49c66d9a44812ade0bc7bca4242dc5df9eaefb832f926b0b585a7ad6ef5524",
        "3810770474911b56ffad591bdbda8a1a76046475ee1fd2347dd5b2e4dec15a55",
        "7c10380a1ac0d237bf788e4685e7f7cf83125350286f0e008d2aeaff07300550",
        "11ba53614b4598cd531192b19c215af9ae1d476e99f890a92cef32935f2516d3",
        "daf053b86db244b02303ba8f18bf8fa5a2c4d99a0987659c3bf52a9ff285eaa8",
        "9415c2cf3758363a38b0580654a231d720f1f5eb9d02916dd6ed537d36bfe374",
        "3d2c9887c984fb3c005b9a121faa9f4a8ed17805e873cfac3a7e0ce4702ec412",
        "4ec79b2dc8a756bb5046ab602b2b95d67b63ea8c7cea098e9b8d8aad8eb557a5",
        "f8c58fcbfd3f7a1a1d03ebc7ce196d4f9a3ef6817cfa0013cc993de186204836",
        "f9de486a7df617199ce4f6027c83c74d77843b7d8040dc33cd2c82fefc02ea32",
        "b57cab7ac07e321cbd0827d56b30b39aea4e3abcaf37789be3defd966998f5d8",
        "f529d94474cb773d1e542ce8d002bea14767fe732886d1933f9ff7df7324cb5f",
        "56f3e56e2505a075bd843a047f697eeb95f529dda5b3690349ad7f2c80cedb37",
        "b760874362858bc751b34e480b7769c74c50446c177124e13ea339d7fff1f0d8",
        "a2c8a13e333dd6d740985355179c69a78012c7be8071ca1ead73db544f3731df",
        "3bdfe9466153c510c57a739de740d5511f815d41204859b2e931c4ded08edd85",
        "cea5a67792bbd333a2ca47776f58b3fa3d4a30461d68e95f02885c9f05c70103",
        "048aaf45b6eb5283098030d68d55967db74730dca0b4083a5582c40290383cf3",
        "a7cc5325847383fb99df3601a4630e78ec51f4c3f3d28582d51fe9f1e2ae0a62",
        "58923ce8fd1ef669730a65af195f0107a3f7df369f759dfda4fcf611dd761347",
        "f8d87248a80fe7b1c1b7118964505e1bc243b948d45649375eae006999fef3c5",
        "4beec6524e9de731fd10d9cf5cb65dfcc1beb6a0c270da5e57fd8a1113d60353",
        "21fb0a6a1fc7d4f82ddfd018b059c620bc9dacd775596458874980068a967c47",
        "c18fe34be457328de809db9be0fec56ccf9e231bea0ee47f34dd4ef5aeac6dba",
        "7f31b9e1500f83f09098aed8377baee0e1c6c96449a6db267538629179119a50",
        "66d1aae51ca3481448188900e45be6010e5bc7d4f0133ccf849fe5da58ed1c51",
        "439c71914e1e88b6b1ccfd47db0a1842209dd904db17d0b24b9c785c0dbed3d3",
        "1166b24a2f708c9bbab97106551bf589c3b0496664f0a2357961fbaf039d7364",
        "5ad544d7bdb51656739d566d59d475cf612c660fedafaf70084e1d493ee21122",
        "52af757035ef08988bc9c09412b1811869fe95db208a8828bbfd50024366cd36",
        "07f66cf5fec6b82e43668dc0cbb21287b0df1e16ac4e734537712671fad6445a",
        "5c6cad7cc5b94ce26234c834562e0b56af0d05d71c26cd0006faf0828af9059b",
        "f5dd5d3d162c12ee4b3123910ff9ae237ea05621976052f93a04f0089c0379cb",
        "a070d94aa96672d0260d21f082f550f6f8edd4fffabfd739f9d95901741b7da6",
        "fd62f918611e00eaad469487311e1c3873bea697800d2f537df87e2d385d7dca",
        "52fc9c072d65f467ebaeddaeab57398a0d26c8ba5f6b33d2aa76ece681cbcad8",
        "8eab18964daf95155597544d45d1b42ead4f20dc4dc3220d5296c40af13d46af",
        "9931a244439cb78ff79e46e448e849863401507c28c49cb033a46eb87a412c6e",
        "e44c8c2a6fef9d4a4d9d4f8eeaa846dad7dbce6df9be196294e1f98cb98ccfbf",
        "beb34429da8e13b4781b38993842b6aa92822d085ddde4b87d9af2687abb97ae",
        "4ef765ac4a7c8c7767a7fb23d6c40be3e23bf569f08cdb3b784055a6c637bfa9",
        "b0fa8b21fc93ad782ee8d71dc5793f6a87a3ab4dd496c01fe81dcd48232da4a2",
        "f2b3580b720fd5fcb1d25a025a00d6d44a4aef19764505776112047f37c26e0b",
        "eb0af8a0f6827233763a181b6dff4373af7939f7a209946e6851f2cc78cb61ef",
        "e033ca6a7ce0e720e008eb6a5d49e4275278842d612f06ab598082e985c724d5",
        */
    ];

    #[cfg(not(feature = "shake256x4"))]
    static KAT_KG256: [&str; 10] = [
        "de0f424040ee28c49a2b38b7dc10bb6df1938c7d0ce9e20576169c25d55af246",
        "fac8420c17892c791d30fdd35e443f5207b5761c689ecaaafa710218ca65af4f",
        "867e7cf0d7bd5ca21ad32be1834575d270dea4f3921868e47bd67192d1931c52",
        "31876d0dc1f20d5a40fd585f8e538e053ea9228cb767bd3da42760af7538c868",
        "5930662522f0fd92395f7955a113a84f8ce751d7aae4c94069f0467472d3c375",
        "e1c69c99a4717a49c27ad9053eeafb5176af62f96f1d2b83fcf46ee6d8c5a1e9",
        "a30fdc78660d4c6e8f1d8e5086c302971fc009179fdff0aabc2003bef7d280d5",
        "ea114e050d851fbdd97f2d8f6183d1843d96be26b933c6289d6fcc2fafd5fd19",
        "7bdaa49ad967998124ca15e16718f5a44c5b9b56050dd321e5e29abf3161d0df",
        "a9383059ec6377d46957c1433fcf9e180ceeb32425ab1c95bcb56667ceefa865",
        /*
        "61c7cfc27c5c6546e50abd2532d8da31c3cf40133a6e141697bf13fd77f56b3d",
        "47d4ec59f461c19226ee0b95de435437dce5f6ed1c6834e03c9ca021bb0482d2",
        "bb4aa5e18f3e299f2cc3e07c0a0692831b2aecf443a52415d3ffb414b0deff86",
        "9502c004d4750c3873dfce5f432390814b93bbc61631f3ed6fab45bff1abe62c",
        "4e36aa45e86c68a2797e663116c5c9f0c63ef4302ba2159a8ef7b4e3e0449a3a",
        "4623d9464aa40baefb09c156c0c5d8dd033c9ee5c0bf13d613cf9c18231b7758",
        "6881e9c309d81a5b1d0c7c788a0dd91fb66494db4ffbb8772244b9d0074a16ae",
        "58b7d2be995aea1454fd0b6df8b22c17bad6db489b2682a5ef3a95e2bca2738a",
        "dce8a811555042dfde6839ff4582ac2f046c8bdf8e53bdc7a1c385ad1b58a9b5",
        "473aa5c11834aa95a1e05e8992145259db007f85711d0e0331ff20f760e9146d",
        "7d8432d07d0b96de3fd5ee690c622e9e5df05499c209fc6d87927189552db3da",
        "a7bb355c5390f1fdbf9469bc6e25796c03c249e604c766457fe1e51252624724",
        "7feade0619b71b8cfaac4f93a6926eef3d00c21b4fb729f5752f2693e0564242",
        "df9ccf7e0d498314f616db20088aed9c3343f45f4f048a5bfee6835eef7ae6c1",
        "0f6dd111d0e191f55a6ddf80e1417af74c2ebda70c50f1a66f5d3f4f01b4710c",
        "62f33664748a589467c8472a8b172ed0f8d82a009d4a7b75719d64275e257dad",
        "c2410ec6493c351e749bf038a8cb695acb7352ee6528986c0ca6d2e6de382e17",
        "14d311928ba963719359308e9b125f34c148656bcb627f9182abc11b2cd87654",
        "6f7ee2d9573693e44bd5491df213eb64590ebb68fb0522b550d05f1e95733d3f",
        "9ca575eda86858f963fcd20f203edf0985a4d1c5fa6c5adc8ec93fb20f1d6863",
        "fc65ad64920349f12b854a8f16f66dd7cf2fc73deedecfc42f166c9a5f92d53d",
        "d2d971ea9b538e44ea1b7e5ef61e51444e024e95aafd2a6c30424c008fb025f3",
        "3f470af16c83620f18ff13100dba3a1fc87e21f81ebd87dcbff1db91e180ede9",
        "00b3fdd3f4cce7b88843dcb73c5c16e3ed7e4f00541e3ad154f11201b18a3072",
        "7196a27df8f889c2febeff1b0e2beff407bb9bfeea9763a5593bf0b3e681d75f",
        "e6e7021fa593413e00bc9e503f5d9d5f079228eeaee364765b456034e1988a20",
        "39eb941a248678c03e8562dc62f16f71b21cf4744b3a06ba66d45b4e052de1c9",
        "45596b38745a5e61ed5a867829833937e68d99db455cf112c3b45926e8ecfeed",
        "9e90d83470a36e4104c9ea68643184546890673e0604a455e2225e9e23750bd0",
        "ed281ce20d10e997977cf0ea3a332e26377a2f39822acd8250b7b90b292941dc",
        "b871dbe1845264315cce3531e17b99c490e4bbfecb36e9b2e024c4751c2a4856",
        "f3b81ca06c61f4c06bd8db57dee9889eb427f88e0bd1eff54b3a9ad3d90745f7",
        "836054ec1c70a1092b7a1aeb759666f793a90e238d6510c7386445034bfba0ae",
        "cf428e64bc06afbfed81b31ae646ab813089f09f9b2bb40bb76f67557aeff250",
        "900fe91e89bfc41615693a9dd9fa8af82af12d97f514d66ec66f673b0ff78748",
        "b828a18cea68063e1e6e1d13e2c98f41eed631ac77c2426499cfa712dcff83f6",
        "22b9d157c0c6fbd0730c71d70178986caac412ea8c2fe995ca903f8ce70a9bee",
        "d22edc1b66567b7bfb880642a797b513bd56c9d694599249c7ffbebfb3caff7b",
        "7ad08f4add7a43c9066b110d7bb7a3156d614a8074e5dbe9781bfd6ce8091dd0",
        "17870d8156804d215bf6de12a164db4540bb55e8bb8544866c755020b93227a1",
        "ab96f504003f00b26fb0111ec836b996cbdaa12e339e228444ca42fefb72f9d2",
        "c903061575bc7a1f39e200cf470c7989be667a82bcc66f2b9aed95565524159b",
        "e623cb17c4f7429efd03a2b17995b3e1e19d2fc90cf6d86420ddc0c52fc6b229",
        "5a44dec0dc9d47ead05f4d418c70bcc48381de7bcb08649a44acdda0d1051b17",
        "f1120c568eed2bca37f2b11225e0eb1cd91c3c4f2e0722742294432dd137272c",
        "cd93b4d3327de93baf8f51e734f72264377d756185e9f144ccddc527fe7c6d9f",
        "6cfacabce77dff6f74ad6e7eb80b4bf775f12020a7b3b9b332d477a778c0f7c8",
        "3c42971d7bd461b3a022b77723dbd95049213c63f50783c460bbf6ca829447d9",
        "3e6cdcf26a5837999e2e37719665e25ca98a73c24e8a1ffbbf2a27ccccfe9460",
        "aff4a67706cb50c071ce160aecbbb444be71490d73eb26d37a432b64422bf1f0",
        "79498669578948f3169d3e450a60f370b4351403b962f1f48332e7480999a909",
        "a9a62d959c1c864a03a27266cd118d5d955767e45a570865a5e23192a3975de1",
        "71d06b6513e52b955bdd4f8e1042d5547e214c5f87b84178ec5e916437e25e0d",
        "4778e284c61f1f9d88888a05088a7f9ecba3b38f55712c2a1903b99ac0986c88",
        "391e1dcd245f0b0516f3f6d6ddd7614dc35ea15a30365e3ac2eab0e86ec9d26b",
        "a67ddf428b54353fc3c40f1313cfa7f4ef29b0e81dae3b5e00afbb59858df75f",
        "884f9dff40e05c9736791c20c169c5fd2551cf6551ca223ccdeda617401ad89d",
        "daf2a1b0e66b5c521bfcfad45f3d592ce2e4569e955a7592eb5d7256348764a4",
        "9a7af0c18d288eebdca6e6482fd37c6237df0b2ad9d2d15adde2001f17e6c601",
        "6733ee612d725f78f6b643c85ff92668ec9a1ff7bcdf1b2456d4b9c06b311661",
        "bfb63b137797a232d63a7a2acd245c462bbfec031a6320deff86224d50cec455",
        "f3b022f2affb6f1bc7af5bce20aeec76a365640d47bc3aa1840d8498ac7d0f24",
        "64e7204aa595af0c7f96ad391106c918a19b09d12b4b14c80fc3f244af83d9cb",
        "094f813e8e217b8c21955fc1299037cc5d16748577f6f9100111bc3c3b510b8f",
        "5e5a380ef3d80316f0229d4a92dc0d7dcb41ff2848a8f8b5f256b6b0380ac5eb",
        "e430e2b237d206b33ccd5f08f679fb87de49b9c3529ff8bf70d5a8cfb356d941",
        "9001bf423dd1744ff882ca45bc162068b768de0b047eaaede06d8de21365fbf3",
        "5dd43ee58aab35151502110254b8e538b71a6d7870109d55332b888bded8fd1c",
        "49c317bf06abf38bd47d721e5aaf2883c2da46edb400b45963801499891c30dd",
        "b0319e817b7337f741cf447caaa01c0c118faf5612fc86254d2e58eb5f18bee6",
        "1f328cbe271e167e023bfd6a2d09a02589f87c2154b6d3c6bbd93b2926b382c5",
        "049087a36358188b0eea8281b023f122ba864bf59f321ac050ce5b938790dcde",
        "3587480ddc44f57da70f542f9df20c451c3f60b54773f3826e09eae5aeb276d8",
        "c0566507d420665e62937fcad090b33b4ad73f1aa72ed4448f1b66f5d554ec5b",
        "a97588c6f1999fdf93b29739b6bab7197511ad75257dc148778f1350424a8784",
        "a4a87ab3dec08e8e75e7420d6ff52719e8b561316714e8ec2d7b2fb0644df5fe",
        "5e226978ee9527934ce5286a7e564153bbc7e52d2cc221a6ed6406f18329946c",
        "669bcfcdb3da9652dcb89c69b8cdb4d51777faa064847f167f5660f0f8884ced",
        "43e4b3508056fc305e99003b53d7a4f3d841fdbbe8548e1bf52f64cc577bca72",
        "4dc7929b2e12690c66a734d65b5154722914f05e9fd3d6b0fc3d23122b85b6f2",
        "cd7e47bdf7ef41a227245b5b808f0ffd1a3d1f62b14f1ac0affb688b723b3afe",
        "c8cdb7a18ae003712f2716318d066ef7fd4bc17bfbebbad277ce620e16acd0da",
        "a6a431e0c4db7ea1c4cb514937526ca059708ba46feff47679600d35a79dd649",
        "0ad411b9f419ccb45567055290e64f7269404690ea9be34760d50bc0622d29c6",
        "c675121421e1fc4acb68a8965736651165a2dc1a6c1e9add5d05d9e048036ed8",
        "e3dd81086c68f48012765578102381d17c9e7a81c20fd77907f8309072a6f791",
        "80444028e6265c367efa8da85d5ab5953e92860b1d55f7567eaa5c4b0bee493c",
        "9fbeee52962fb0e84d99f438e7f8ade577e9f1817405f3ff92e17d99a220c7e7",
        "368628a09c2ecf92907488a39fdc1ad81ac63fd2ae26679b7ba4a3d37eee0022",
        "d9a4a297b883dc4a069e7e21f97615d4d3ca84f3189e4131063074f4ee64df19",
        */
    ];

    #[cfg(not(feature = "shake256x4"))]
    static KAT_KG512: [&str; 5] = [
        "e5b8d48e5ce74c62e3e0ccd40f7ce5762d3a329d5b85bfbb3af88d31bdceb3e6",
        "2771383de7a38daef285c71494fb0ab438be6a03843b7936901b831d0e846f3a",
        "4850f28b3cc310a01abdd6091ffcb1012102da51146bf47fb4045c9527daf22f",
        "7e2db5bed6b3d656b12bb33b7432fc4929bf56c69cf73db9b5ed56c29472d775",
        "8e4dd3c29b862bf392dfe1a97ef89991faef86987b6d8dca2140af316b47b260",
        /*
        "52911f6a2bfbc5e93e840cd2c65ba8a07ec7e1e0749102358cf919457ca62088",
        "a9232378e028b49eb0c90d3b5c0d4e2b79451c37fd79bb8021d65fd504ba4f5d",
        "1e7c6fa2d47fe16000eeff45cd7bc03e9d43a12662c382635da08e5dfd6c9daa",
        "b58d63fa380c85591db5b76a38d4f91bfd74989b3ad7c63aada94fc564b61506",
        "718f7871cecfa6cb3c19728b25833e59a56703918014ee432bf53474f2742196",
        "02f2e783652fb285b1a00594257b9e3729ada3ad6d9542a3ad2b41d00d1f2fdc",
        "69815bf5d01660ff681798748e3063cf8516e519d52165c901afd25a1fd6447b",
        "4d9937b6280ef1a6f8c41547f491c2fbb03e5e2c047b561e2c51a7eaf0813e97",
        "c32aa164642c092dfb6bafc19eea3bb1eb2bb541666a4147ca2154c091dbc72b",
        "8bedf3d67f2d4503f5aba7339b9a8105942ba8ed5f72183ddeb56371a6706b35",
        "a624ad74e350198c4718dcceb5cc697a596be19ee877d947a337240ca592f3c7",
        "f678a793efa76347fb2c814d840f5f64f12b037347466cbe70904bf2225861eb",
        "3d9b3e7a0a0984ce9cb93e2d20199a62dc253d0545641f0af1b4a1f3f73ebf65",
        "94155c1770c22646a0b006e0c6edb2ed4c07f6f54bfd273036c4a4b31d2749ed",
        "cac64451e4be8048ff322da64ce5ada570171bf01af11b69767b50f8c1c6ddae",
        "06f5b9e9d6d3aa968126e3a64adcf4b8b949b2693b58cba31013216bda23e98b",
        "85c07d19490d9c49da7171d1bb216a756f88abec6095f2b7a0c74a7aa6c4fe6a",
        "3013be1028b3875cdc148560f427b6ef5bd6933175ac6ea5fa305ae96df7d8d8",
        "893d998ec96832c9fb4e3755eba9277594bb509cb2706216dfbe575536971e6a",
        "cf2ae10c584e3be778c2c8dbac2bb6b2a2ade0d4bd5a3c011e24c8929bbfd8aa",
        "b7c442cf6768f33536050be1f8a3298c7ef236a10b3012111c28559c58077ee0",
        "6c8c29d04f6fd919077b67edd8615ea4e1245339e078a08dd449806e5bf9469b",
        "d4b68c992f97324ef3335d8e48897ff60e7f0d4778f66014684bfb9bbd5d82db",
        "f155a4346221c13aa27d5fa65a7580d0575505562f0a430d0f12a3e8041fcd22",
        "2a315d6dcf37670105632d68aad1243abb77e98e24ad50956e45173891da9bff",
        "26488bae650c89f1861fa14f54c1d0dba208c2a578f68e905f2efa5c414cf6fc",
        "20e602b7f1a1d8c1e8ccf760537851abcc416da2e916d7d08271fb5055c46acf",
        "8865bad46aca531d9f1722e645e414e7125d2f6a3688f02d4a51f46b8ec96d9b",
        "7a6693fc69fe6d7aee0628f6dee930219831da40945f56c37872b3ed906e5618",
        "a8059465ec99ec68aec622297551ba433a86be0490d2ba6b2bec1ce4316322b7",
        "25afe6ce47fda502e289fad893af6299e5fad8ef61259b9f74c9ceee813488d4",
        "245a33e75fa32ca39098797de9578692963f8b6bb8f532638299ef6606869c49",
        "24f5d04adfdf18dda3c698199ecd17d7d280704ffa3b6fac2edf8d147e9b3643",
        "933c9bf64743ef60ff4a4cf9125debd1854b30f9c995fcd6f73263e3fb37e070",
        "0fa03f2a17d4f2fc5b6e6740c8d85ea9a959a8443f314d7ad5d8191bfa64a22e",
        "46194c6a2f50fdf45d69ea7676adda7a83a1943b0bafb0249260ae7f843f371f",
        "dd905c352a99230f11ab4eb85622a71042fd81384908a59777051a8214177434",
        "c9592a0e448849f4e2c085aab86d68a64ea9d4eb63c93e71f53e057b9713a939",
        "4a3e568773d76cf7b84783e860100b1ca348e24c4fd76428a1dd718609bf0507",
        "df587e46bc8f90a0a0f874cad1a4a23088b5e642c25f73d2c397c42c87b4575c",
        "d0311f06f23f71e4b09b00c896eee03232495330a61da07ffeac500be59fcdfe",
        "8ae6419940f6e07bbc31e6c5e3911b84fecfb085c2a6ebb1d851d16fa698bba6",
        "25d290201c070412be69db399bf16edf7c0a3564ebd5be3cc88f2b393e9d85cf",
        "63276a87c37fe5dbb2798a53eee77ef5822dbac7c06be2ecd562d6b2cc73fe11",
        "382d816550b5830daf7e1ebdf50c428aa0ed1408e24bc33318c6febb9f6eb609",
        "d0a4f9b5b1e654838a978725b53c4b3deb0bddf6738dd386b45e404123e24a66",
        "40d15b74a917ac03f2a80dcf8d3aa1fc5699055c31e98cf18904cd259bdd8808",
        "d2b3fb62e029b52f0b3dc29222587c0568c1a75dd7d08b940649f2eb73283850",
        "09452a7853737bd1a57a90eef0e4ee317da593bc25101247abc719f357569021",
        "c20075f92eb928ef1afcf4be283015fd5e83f3b1f1e6ddbd4b6ecb73b5a2a41c",
        "f6df4ad1759fb5b4451a4e0e98da02dca858344c3fcc8187aca72d6881183f4d",
        "294d56b9f377857c85bcdcc8bdd873cedeb53dce33e96abfa58a90aeab2a9ff8",
        "2c8fe225eeb537378f6afc2c98c88330d18020adaa7c362b097b5f4f35b7c2d7",
        "d10bf6ccacf2ef3f098ea31812385ed142ace1b819b4b14d1ea7d93eb1a54eab",
        "20ace0f895a65e1ba73d4e8660ae7fb3dc6bf237d4b6b2e6114ee7a06af676fa",
        "9446c41d690a4a7180c4a61534e7490588530768ac028f139e1cc73aa83b13b1",
        "d0fe8fc3dd3dd1636267e8b7a86b7b2c3ecee5ecda567b72e10528fa515bff15",
        "ef1bf62bd1e3ad7f3f2b9f42b229c37835619e3d01e76f1679a1109e8031100f",
        "df24b5aaab521bebd0b56132e4ce0ebe731afc41021130e6d06ecff9af70b383",
        "eca556fc2b8f0287ad23313dc09826bb3a64f3dcdd4daea34642f75f9b42eecd",
        "4cc1cd53e949037daad43cb43116ae18d67402a009559e06fb618c7306e8eb52",
        "bea9a4423b3c5bd882918760d4fff5573b3f362c0b7629a60039cf384adf931d",
        "0bc0728bffe151a8b7024404e104373ae59969b8bdbee58e6c12c31caadfb554",
        "f50ec21fa80f2d3e376c0a1ab4969659ec8f3f8d733a3606d6aa4eff0586f969",
        "da25e5226aa777fc9f1dc9158f56a9c2ce260be2a4bf90f2ccfaa08eaf4a3c5e",
        "ee27a8d5c4a95b500769357d3877c289e0b33f132434b73dd5b86320e75bbb61",
        "8adc16061bf0c6eaccfd2da0cf26954f944d936a401dbf41c653737c1556d5de",
        "e9cd4b9e12cf17b9fbfe15749dad8f59973c9fe34f653a36d4eebf1164bd613b",
        "68ba125832070a8251e57012389cdd5d4790c6489e61d7227783fde8d91bb6a7",
        "274acbfecc48e2ee354ae46a83417101c4445a9c03b8db7ceb590acb9db87dcf",
        "7717450e9ade874c1b673885240d725b727873bf01bcc14017218db4072752dc",
        "c6a602279feadbb3d80e2a8f8d3fa58a1954d114604c2833b5b8304e5a0bd38c",
        "de8b6f3349e4b86103578476fcdc51e2ccdb6a57abe3de34e958c736aaf837d0",
        "fb67cf8869a830ac4f0a6ff4c1dc2761dd9b73edd3430e8a6021ff6ebc89627a",
        "e88815f670b0f06b08c7cef11ba76fb269ae449be8cfacb5caea51e8881595d0",
        "6a16c418e8408e65fa32cb8440c8bc0efc1fd0bc289fbe0a918f687a23ccc5e9",
        "6c07dee34cf816af1f17b0e7a1557bce1a9f7be66d10cc952768f5d0da82ecfa",
        "fe627035fdbeef18d0838fb5572edbe3078a23a3ffd171f41a23bfcd61b3236c",
        "90cb7bac4ca0c3b42ff837481d9c11ae1b58fa6bf189347360ac110d2fc50dbb",
        "dfde441a2d24d50a2a68cc3efff345444e1b59972d20558cf588d117519097c5",
        "ea9428cfaf864aedfb03a23429c3f4029779adc654b9debf4f0892f9108de9a2",
        "59f395d2ac1bab169c9b95ecc9632dd86d600e245d55086dcc13bbb04f4fb927",
        "4660b5044aa11d6025f2745cf2299bdb8bdc46a73e112a55973181799c69a080",
        "a64fc194846beb66c68a0e65c28d97c7902d3670cb5d858a142f5ceff84a4926",
        "d7c5784bebe3c01c862c0f2ba31f016b48809bab381b336d5b3f88c58dc80ddd",
        "57fd2b9849373a138efaaa74940b234c81b200e1c076b5e17af67176af69fcf8",
        "2b720fc113a74cc03b0bd95f731f8e8e4a4fb1978aa99b7888810eec5579a33f",
        "7af8e6432f7ba7c368d5f8197d33fcecbbbce510aa45a0d94bd347e939e858e6",
        "02ab32f4c99b4c8aba0fa6a5821be5bcec857c8b6d3cafa6d57d204a719ee408",
        "87b37a27504408c69303f93261eaf83caa3e534f61d7ac05590ebfe27533fc11",
        "8704603289887afb8f81e0ee85783352d6ffab8380b12e6289986a16105720c9",
        "f01f627e9b4010b426c1aba8ee00fc454f40a672f1e3e1aa3ffe3578c97ff9a6",
        "489f538a5e300d31c7bc045ccd913cc28b000c91ab58cd38d95ffbef6cf9eca5",
        "6659376ad90dc28bc55357e64d77a0f325ec84ee933afa5c8c81443064b27181",
        "cde8b82da056ec5eabd47cb7ac30dc9d142b69e0cacf50c3e8170df70324e9cf",
        */
    ];

    #[cfg(not(feature = "shake256x4"))]
    static KAT_KG1024: [&str; 2] = [
        "3801234739381254947850fa291fcd1fd4795eeb6ba3de540a6ce74043940982",
        "e4addc3cf7f628db91432344270b6877065cfc1e92d9cc06ea23a0299651c229",
        /*
        "6ed3259d0165640c497502bd3f43650d291c4014392c518942bb6bcab1bcf939",
        "759ec21a9aa1927fc4646ac2347633170deb1e307e25530fed7758cda0e94155",
        "7880e31fed1b3f61bc8f7ed721c7fe4948925e7d27e3ce2c409266c8c88deedc",
        "0d2c27a300d047fcd4d97e32e044abcc53f3cc65768484333a57a93ce4c4a32f",
        "b6861bdf32d5779d5fcaa0ec61f84800ba8c6e22f5d496d2ce93a102adcf09cb",
        "25193d2acbb31544586b659be761a1fb3ccd1a9a71d3daeaa5d996eb00aeceb8",
        "6afcf9b7b0b26827c2857700612abd295715e34d93adc92bdbdd5da4be51e24b",
        "59eb4c2695cfa35c32af7af322ad20c425b18bf4c1be7ddb7aa62e3a92256d4e",
        "d7d20c80d7fe63b9dd4a7eeb002faebd2fb91630d90ec3eebe71c4cc06a3694a",
        "c083573f375f8c8d7abb844ce0b6254b28bcbf275e3f6c463ec329992a0ef79a",
        "86b330917714d4e23f633bcf065263f3b08b2a89f930ecb64c441e81153d6a9a",
        "5df2572f8b03060bec2d6da78fbcaebbc81738c4ba42eff89d2506dec490a458",
        "1d1a42c974fd8aeb8c8bde063aadfacb0e10631c111ba724f9a21b153682aed4",
        "dd625bd0a84f8030fcb560c26256e5465089c452ef1b927e39785a10a3f0a94b",
        "399bf0cc2d7f886cfdf7345e1fb3e36d85828021e19e3fcadb2668119fad880e",
        "08e0fc2ce6de3a3ff16dedf1a4c5ba1727a9bb0d859b074f085c222ef90347d6",
        "f96eb3c453b357c8b0fd6c31bf70abe8d730301388ab9bb6d482070cb9ef1038",
        "2fd500c9b6f1830186efa359577f698290b97c1e3fba7f58efa17fd992394339",
        "c25ad284240f5fc95a2b4b2d856126550102fe257f19d97f2add911247d14f4e",
        "f3696b95a501e57115ad16bbf381e2ccccb4738bc71ac54e8448ec84b34ec377",
        "b8dc31663a3300279d73a9d1b784ab54e08fe77cb4493963782693ec89045a08",
        "ceb9873e17b350afcef175b592b28b76e98fb5118b6677368ae9e95b32e893c4",
        "1462b5b53799aca25cbc3096db2be61c3fa4195e348a9ac1b19a9302667a5a93",
        "4138f34c2e6c833a2dc5ff173101604cdb0804436a406244d804ed04fb2b9955",
        "588497e62515341b0a5317fd7a3e8bf6165a239e2eaa095173af18f275352b3e",
        "95c0a1795beec635e5c3e382168058e02d2f99099e19fe286e661dfbe94c117b",
        "6aafd3195e0fb48b218ebf9f39c8ef90cb7312e36f160665ff55dbe4d0a30cad",
        "641d09de11ff8ba3a3b5829702ae2983aa89cfd1cca1db6272720aa7343484d9",
        "3605d28075509d4bb83129e33436d5995a5cdae33b9cb4f293fc2a93dff45e13",
        "947d3b06c610c09041fa9f9adcb60355c6cf27ad2904c15ebef34185261e838d",
        "80b3c33c1609d01e7b9df83da23c2d5831ade5df9f8983be0ef022f90346da6d",
        "492cffcc88c1541f66ba627bd36369a351ddd77b8dd844409e316a33f0e4977d",
        "b2fc13363e488e32193628fc41eebfa6ad842d110d912dcfb7bd2e7c2db945e7",
        "4712d9e9a3909d6e14d11296f9147c138d6f5e4dd1fa01a051357f251b098a65",
        "ba9065dc68758bb0473c3bbbee19c1fd40908555cae72fe12528b1b17cabce53",
        "d7075a675ccb05eaa222cad6977c969873561a91a5955e10af708f1c17350a83",
        "67b3604d5a33bd13ce0d965b725bd81ef8a26950d2a03f0aa3efa251f3a0dd7e",
        "17563f95094fddb18bcb042cbb7023f84d1e6e66f0dd621e07958855e89dacee",
        "c0ce47bdf41df4ca9752a83a23c6ef81146b33a3ff13fd52ce6557282a31a7ee",
        "0a2af1d5e307ef913b6b13ce9ea4e0a9a9bc1cf24dab86caea13148eb1076ce7",
        "ef313153d3c3b67aad0b7b465aa86f58f7fc166e59efd681bcc14f077048c573",
        "dbd8eb3db762b31c7d21be6f18ee109201816d415d3bafa06e32f4a0a09f91a7",
        "f951ca0be57c40753809f28b9ea0c660a205b3555629093d851740bdef836c80",
        "fcc5ccda31a41f49ca14eaa3c6c458e416f00b51ddef350402fc86c4e3c18eea",
        "b5ef6760ab4ce155931ec9a4c35842fe2e30e39b7479e9b3ffcc9eb06ecb468f",
        "3b114f9befd523fe460e04c1416cf2d6946431598349e69d89ef5d8d6b1f43ac",
        "40b9e3709a3156148d5bc7e3b59d50aa99366362f9e6c0eab293d3bf6e1fdefb",
        "b5f250fa5b82861d853f0b7a676ce9bf9375d6f474826ec1422a158bcb273a5d",
        "cf0fa4013d527cfc36a5026a8c615ca715ba71fff0c97e5b0c3dbfa024991f83",
        "75b6a2fa54de1e01a5e27085cb0a702908bb6791795b3bf261945a476be0ccec",
        "6aeb05de03474fa04a515c4de59fe01663a6e62ce7cb57867463d24adfb03378",
        "fb152483fb7a3ff2cf8ae2e2eef23dbe73273841f5f306b21a618f8df6a73199",
        "851adce107f2e107562f6ecc1fc16b541eff171049cdf71478771891f040e1b2",
        "a1ac345568314b150449623e4793eca6f6fbc1cf5d2f886a6ac93fac85d30f9d",
        "549db752e4f758665a568f30bece0d82de9cb2ebdf2a399b1ddcd7d38156fbf7",
        "f70189348a1cde00a5df2f31edd447bd0ccbf878523058547dbb2bdc42cee8d7",
        "ee784b34bcee97c1d99c81eadf55c079e9a62af5b00ce67f0e2dea8daf2af681",
        "56bf7af11b728dadfd00acaa2c24a5c535da9d20e5f51c1b363818c7100e60af",
        "d3e4e9f231a0a4f4051be44528dcbde02bab5805cd2fa8d7b5d3884c4356cdc4",
        "9e3f99858a24daa0f2b6536078f3b55b76f390874b60a75da90798e2e583252c",
        "2ca5768fefb5e2a9551f2c54f6a640188d6ad2a671e7a2cd3270b13e23d871eb",
        "cbd1443382a5a3cb0b1d29f8198fe405cbf07d93cfab4cef1f21bcd96e77d78e",
        "fb8319950e8800e788d5d354c1aba5adb530f9da8d0d773557db9a78c6ea1a0a",
        "e2c52f874a6c8fad29ef1be12876644b01632e10d0abfd1f5d6345b1e312efa8",
        "8b4cfe3da1cce28517c3fa3c32afca289032f0824478e4613bf1bb3c8c60af95",
        "40981afc6ddcaf3db43230851663d2b88e78856b7e2c7cc2c6f8adb21cefc2f6",
        "39675db2cd864270a4fe0a6cb995eea620a9d0dac5a13baaceb87992040c07a7",
        "60ec56da832cbf9a7746cdf718a279e00d18b12953bab31275d458f43ff96288",
        "219e45c3f1419697ee93d9b262f071e8a3b5d7b379531daf1d505e07804340b1",
        "b1d5215f2d68ffb35df1275db37ac3886ccf42087222e76891b02e705b9628cf",
        "1f029d9a71da3a08fdf7f661bbc818b12865b4985c715887c5d4f6c8bd28059e",
        "b467b887a54ba723f9b42080ac145f791064b7f39554811e7ec96c202830e00f",
        "e73704c879d75362899a57356f33d9800300654adc6dc52c3ceeaf478161d764",
        "855b46d3255b8cc9ffb5fcd4a970f1a0d07fa862f578338d5421d1a4ee42f4ce",
        "b8932703953a6debc47845f624066eabb9d9855e024faa530bbc047ea760a36a",
        "bc0b8aa042d10e198ce6770272055063705ec1f4308f6a964647c83fc7865f3d",
        "c235f39adcd3937683ce7f1d43e1686bbf49b189973e9ff3990dbabea0079949",
        "8c4922630cee73a7eb4f8893f081e0e12f6b39a1fba724b3f596bcbff47e969b",
        "794ef19762e6e528dab9fa5e59844e49cfbdfd6b658d76edd7f5a1ddaf6415c2",
        "f5aebf2c86a7b3511263ffe96ac2ca8a28ab3e561ec25473c9106951f776084c",
        "8fe94edc1e9f1349c701308475d604f50962948b54ec9b8158d1f4759511ef01",
        "7b08a65b5f39b9fcf4f92dc7e6b9ae9b354b18e075f6502b0f291e14e04bf6ec",
        "d0589b3a0cb45ea6ea4eadb24c491a12b9e1813643933c3d5f8ea5b23e3e0863",
        "d02917cb25109108451d68b47d7d59cc19c6b1986c6a7ad6e7a53381947db768",
        "1b7cc814be3c8ddcee40d7a21c36b136564c66bfbb9338e2320f524d9f46fce8",
        "476a1e220d8933a32700048d7ba1b29a739552b999337d50320220ba045589a5",
        "21d675a0e911f3257190408b577d539c143184cc08dc2f955abae7ae5646c337",
        "81400e00c60aecc62fe3aa00b1775aa526df4f68beb16eea302aea7c683e0b1c",
        "11c459c1fb6299c96d85e6465c17ae4a075ab78c94c1558c077af4c1c80e2c16",
        "5d943fb5326f59d846b6f7b118f3707c2d06d932408afc3ea8b4487466a357c1",
        "d30c09010d6b4de9d8f8e9ea1b947acb605179be897e71bd42e01398ee3e0186",
        "ab27990ad18a2f9cc0b8b71dac762b9c1cdf2f33669be50509a54eedaaa07d70",
        "477918b96d17399efe53503cf685e2e950cca279df55a8ae3adf2b42c7197f89",
        "b1ae653f0f153499b8681da0d422e4b2fc23dd97baa1943d76da4e3b0d118b78",
        "fa4686c039e88b56ea80d980164047889fc882641a0a219ff08a842b1711296d",
        "faff6c3cba96a08af55657529db58f40f8e313c8deea3a03f86330970d58f44f",
        "af24c9e3fe67eec6e5d3114ab44f8e1a20e374b3b93ba3766a0bf813bbe8ecaf",
        "7bb90c1c00604b72df4ae6929aa15beca7f82a2c91334c7644225e84dae1ba6d",
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
