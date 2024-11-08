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

mod fxp;
mod gauss;
mod mp31;
mod ntru;
mod poly;
mod vect;
mod zint31;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod ntru_avx2;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod poly_avx2;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod vect_avx2;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod zint31_avx2;

use fn_dsa_comm::{codec, mq, shake};
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
            keygen_inner(logn, rng, sign_key, vrfy_key,
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
fn keygen_inner<T: CryptoRng + RngCore>(logn: u32, rng: &mut T,
    sign_key: &mut [u8], vrfy_key: &mut [u8],
    tmp_i8: &mut [i8], tmp_u16: &mut [u16],
    tmp_u32: &mut [u32], tmp_fxr: &mut [fxp::FXR])
{
    assert!(2 <= logn && logn <= 10);
    assert!(sign_key.len() == sign_key_size(logn));
    assert!(vrfy_key.len() == vrfy_key_size(logn));

    let n = 1usize << logn;

    // Get a new seed. Everything is generated deterministically from
    // the seed.
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

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
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
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

    let mut rng = shake::SHAKE256x4::new(seed);
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
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
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

    let mut rng = shake::SHAKE256x4::new(seed);
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

            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
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

                #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
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
