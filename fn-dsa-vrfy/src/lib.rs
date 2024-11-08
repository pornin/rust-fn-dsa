#![no_std]

//! # FN-DSA signature verification
//!
//! This crate implements signature verification for FN-DSA. A `VerifyingKey`
//! instance is created by decoding a verifying key (from its encoded
//! format). Signatures can be verified with the `verify()` method on the
//! `VerifyingKey` instance. `verify()` uses stack allocation for its
//! internal buffers (which are not large). The same `VerifyingKey` can be
//! used for verifying several signatures.
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
//! use fn_dsa_vrfy::{
//!     vrfy_key_size, signature_size, FN_DSA_LOGN_512,
//!     VerifyingKey, VerifyingKeyStandard,
//!     DOMAIN_NONE, HASH_ID_RAW
//! };
//! 
//! match VerifyingKeyStandard::decode(encoded_verifying_key) {
//!     Some(vk) => {
//!         if vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, b"message") {
//!             // signature is valid
//!         } else {
//!             // signature is not valid
//!         }
//!     }
//!     _ => {
//!         // could not decode verifying key
//!     }
//! }
//! ```

use fn_dsa_comm::{codec, mq, hash_to_point, shake};

// Re-export useful types, constants and functions.
pub use fn_dsa_comm::{
    vrfy_key_size, signature_size,
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
};

/// Verifying key handler.
pub trait VerifyingKey: Sized {

    /// Create the instance by decoding the verifying key from its storage
    /// format.
    ///
    /// If the source uses a degree not supported by this `VerifyingKey`
    /// type, or does not have the exact length expected for the degree
    /// it uses, or is otherwise invalidly encoded, then this function
    /// returns `None`; otherwise, it returns the new instance.
    fn decode(src: &[u8]) -> Option<Self>;

    /// Verify a signature.
    ///
    /// Parameters:
    ///
    ///  - `sig`: the signature value
    ///  - `ctx`: the domain separation context
    ///  - `id`: the identifier for the pre-hash function
    ///  - `hv`: the pre-hashed message (or the message itself, if `id`
    ///    is `HASH_ID_RAW`)
    ///
    /// Return value is `true` if the signature is valid, `false` otherwise.
    /// Signature decoding errors and degree mismatch with the verifying key
    /// also lead to `false` being returned.
    fn verify(&self, sig: &[u8],
        ctx: &DomainContext, id: &HashIdentifier, hv: &[u8]) -> bool;
}

macro_rules! vrfy_key_impl {
    ($typename:ident, $logn_min:expr, $logn_max:expr) =>
{
    #[doc = concat!("Signature verifier for degrees (`logn`) ",
        stringify!($logn_min), " to ", stringify!($logn_max), " only.")]
    #[derive(Copy, Clone, Debug)]
    pub struct $typename {
        logn: u32,
        h: [u16; 1 << ($logn_max)],
        hashed_key: [u8; 64],

        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        use_avx2: bool,
    }

    impl VerifyingKey for $typename {

        fn decode(src: &[u8]) -> Option<Self> {
            let mut h = [0u16; 1 << ($logn_max)];
            let mut hashed_key = [0u8; 64];
            let mut sh = shake::SHAKE256::new();
            sh.inject(src);
            sh.flip();
            sh.extract(&mut hashed_key);

            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            {
                if fn_dsa_comm::has_avx2() {
                    unsafe {
                        let logn = decode_avx2_inner(
                            $logn_min, $logn_max, &mut h[..], src)?;
                        return Some(
                            Self { logn, h, hashed_key, use_avx2: true });
                    }
                }
            }

            let logn = decode_inner($logn_min, $logn_max, &mut h[..], src)?;
            Some(Self {
                logn, h, hashed_key,
                #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                use_avx2: false,
            })
        }

        fn verify(&self, sig: &[u8],
            ctx: &DomainContext, id: &HashIdentifier, hv: &[u8]) -> bool
        {
            let logn = self.logn;
            let n = 1usize << logn;
            let mut tmp_i16 = [0i16; 1 << ($logn_max)];
            let mut tmp_u16 = [0u16; 2 << ($logn_max)];

            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            if self.use_avx2 {
                unsafe {
                    return verify_avx2_inner(logn,
                        &self.h[..n], &self.hashed_key, sig, ctx, id, hv,
                        &mut tmp_i16[..n], &mut tmp_u16[..(2 * n)]);
                }
            }

            verify_inner(logn,
                &self.h[..n], &self.hashed_key, sig, ctx, id, hv,
                &mut tmp_i16[..n], &mut tmp_u16[..(2 * n)])
        }
    }

} }

// A VerifyingKey type that supports the standard degrees (512 and 1024).
vrfy_key_impl!(VerifyingKeyStandard, 9, 10);

// A VerifyingKey type that supports only degree 512 (NIST level I security).
vrfy_key_impl!(VerifyingKey512, 9, 9);

// A VerifyingKey type that supports only degree 1024 (NIST level V security).
vrfy_key_impl!(VerifyingKey1024, 10, 10);

// A VerifyingKey type that supports the weak/toy degrees (4 to 256, for
// tests and research only).
vrfy_key_impl!(VerifyingKeyWeak, 2, 8);

// Inner verifying key decoding function. The decoded h[] is
// automatically converted to NTT format.
//   logn_min   minimum supported degree (logarithmic) (inclusive)
//   logn_max   maximum supported degree (logarithmic) (inclusive)
//   h          destination buffer for key coefficients
//   src        encoded key
// Returns None on error, or Some(logn) on success.
fn decode_inner(logn_min: u32, logn_max: u32, h: &mut [u16], src: &[u8])
    -> Option<u32>
{
    if src.len() == 0 {
        return None;
    }
    let head = src[0];
    if (head & 0xF0) != 0x00 {
        return None;
    }
    let logn = (head & 0x0F) as u32;
    if logn < logn_min || logn > logn_max {
        return None;
    }
    if src.len() != vrfy_key_size(logn) {
        return None;
    }
    let n = 1usize << logn;
    let _ = codec::modq_decode(&src[1..], &mut h[..n])?;
    mq::mqpoly_ext_to_int(logn, h);
    mq::mqpoly_int_to_NTT(logn, h);
    Some(logn)
}

fn verify_inner(logn: u32, h: &[u16], hashed_key: &[u8],
    sig: &[u8], ctx: &DomainContext, id: &HashIdentifier, hv: &[u8],
    tmp_i16: &mut [i16], tmp_u16: &mut [u16]) -> bool
{
    // Get some temporary buffers of length n elements.
    // s2i is signed, t1 and t2 are unsigned.
    let n = 1usize << logn;
    let s2i = &mut tmp_i16[..n];
    let (t1, tmp_u16) = tmp_u16.split_at_mut(n);
    let (t2, _) = tmp_u16.split_at_mut(n);

    // Decode signature.
    if sig.len() != signature_size(logn) {
        return false;
    }
    let head = sig[0];
    if head != (0x30 + logn) as u8 {
        return false;
    }
    if !codec::comp_decode(&sig[41..], s2i) {
        return false;
    }

    // norm2 <- squared norm of s2. Note that successful decoding implies
    // that every coefficient is at most 2047 (in absolute value); hence,
    // the maximum squared norm is at most 1024*(2047^2) < 2^32.
    let norm2 = mq::signed_poly_sqnorm(logn, &*s2i);

    // t1 <- c = hashed message (internal format)
    hash_to_point(&sig[1..41], hashed_key, ctx, id, hv, t1);
    mq::mqpoly_ext_to_int(logn, t1);

    // t2 <- s2 (NTT format)
    mq::mqpoly_signed_to_ext(logn, &*s2i, t2);
    mq::mqpoly_ext_to_int(logn, t2);
    mq::mqpoly_int_to_NTT(logn, t2);

    // t1 <- s1 = c - s2*h (external format)
    mq::mqpoly_mul_ntt(logn, t2, h);
    mq::mqpoly_NTT_to_int(logn, t2);
    mq::mqpoly_sub_int(logn, t1, t2);
    mq::mqpoly_int_to_ext(logn, t1);

    // norm1 <- squared norm of s1
    let norm1 = mq::mqpoly_sqnorm(logn, &*t1);

    // Signature is valid if the total squared norm of (s1,s2) is small
    // enough. We must take care of not overflowing.
    norm1 < norm2.wrapping_neg() && (norm1 + norm2) <= mq::SQBETA[logn as usize]
}

// AVX2-optimized implementation of key decoding.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[target_feature(enable = "avx2")]
unsafe fn decode_avx2_inner(logn_min: u32, logn_max: u32,
    h: &mut [u16], src: &[u8]) -> Option<u32>
{
    use fn_dsa_comm::mq_avx2;

    if src.len() == 0 {
        return None;
    }
    let head = src[0];
    if (head & 0xF0) != 0x00 {
        return None;
    }
    let logn = (head & 0x0F) as u32;
    if logn < logn_min || logn > logn_max {
        return None;
    }
    if src.len() != vrfy_key_size(logn) {
        return None;
    }
    let n = 1usize << logn;
    let _ = codec::modq_decode(&src[1..], &mut h[..n])?;
    mq_avx2::mqpoly_ext_to_int(logn, h);
    mq_avx2::mqpoly_int_to_NTT(logn, h);
    Some(logn)
}

// AVX2-optimized implementation of verification.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[target_feature(enable = "avx2")]
unsafe fn verify_avx2_inner(logn: u32, h: &[u16], hashed_key: &[u8],
    sig: &[u8], ctx: &DomainContext, id: &HashIdentifier, hv: &[u8],
    tmp_i16: &mut [i16], tmp_u16: &mut [u16]) -> bool
{
    use fn_dsa_comm::mq_avx2;

    // Get some temporary buffers of length n elements.
    // s2i is signed, t1 and t2 are unsigned.
    let n = 1usize << logn;
    let s2i = &mut tmp_i16[..n];
    let (t1, tmp_u16) = tmp_u16.split_at_mut(n);
    let (t2, _) = tmp_u16.split_at_mut(n);

    // Decode signature.
    if sig.len() != signature_size(logn) {
        return false;
    }
    let head = sig[0];
    if head != (0x30 + logn) as u8 {
        return false;
    }
    if !codec::comp_decode(&sig[41..], s2i) {
        return false;
    }

    // norm2 <- squared norm of s2. Note that successful decoding implies
    // that every coefficient is at most 2047 (in absolute value); hence,
    // the maximum squared norm is at most 1024*(2047^2) < 2^32.
    let norm2 = mq_avx2::signed_poly_sqnorm(logn, &*s2i);

    // t1 <- c = hashed message (internal format)
    hash_to_point(&sig[1..41], hashed_key, ctx, id, hv, t1);
    mq_avx2::mqpoly_ext_to_int(logn, t1);

    // t2 <- s2 (NTT format)
    mq_avx2::mqpoly_signed_to_ext(logn, &*s2i, t2);
    mq_avx2::mqpoly_ext_to_int(logn, t2);
    mq_avx2::mqpoly_int_to_NTT(logn, t2);

    // t1 <- s1 = c - s2*h (external format)
    mq_avx2::mqpoly_mul_ntt(logn, t2, h);
    mq_avx2::mqpoly_NTT_to_int(logn, t2);
    mq_avx2::mqpoly_sub_int(logn, t1, t2);
    mq_avx2::mqpoly_int_to_ext(logn, t1);

    // norm1 <- squared norm of s1
    let norm1 = mq_avx2::mqpoly_sqnorm(logn, &*t1);

    // Signature is valid if the total squared norm of (s1,s2) is small
    // enough. We must take care of not overflowing.
    norm1 < norm2.wrapping_neg()
        && (norm1 + norm2) <= mq_avx2::SQBETA[logn as usize]
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn verity_kat_512() {
        verify_kat_inner(&KAT_ORIG_512);
    }

    #[test]
    fn verity_kat_1024() {
        verify_kat_inner(&KAT_ORIG_1024);
    }

    fn verify_kat_inner(kat: &[&str]) {
        for i in 0..(kat.len() / 3) {
            let e_pub = hex::decode(kat[3 * i]).unwrap();
            let mut e_msg = hex::decode(kat[3 * i + 1]).unwrap();
            let mut e_sig = hex::decode(kat[3 * i + 2]).unwrap();

            let vk = VerifyingKeyStandard::decode(&e_pub).unwrap();
            assert!(vk.verify(&e_sig,
                &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &e_msg));
            e_msg[0] ^= 0x01;
            assert!(!vk.verify(&e_sig,
                &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &e_msg));
            e_msg[0] ^= 0x01;
            e_sig[50] ^= 0x01;
            assert!(!vk.verify(&e_sig,
                &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &e_msg));
            e_sig[50] ^= 0x01;

            // Also check the inner function(s).
            let logn = vk.logn;
            let n = 1usize << logn;
            let mut tmp_i16 = [0i16; 1 << 10];
            let mut tmp_u16 = [0u16; 2 << 10];
            assert!(verify_inner(logn, &vk.h[..n], &vk.hashed_key,
                &e_sig, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &e_msg,
                &mut tmp_i16[..n], &mut tmp_u16[..(2 * n)]));
            e_msg[0] ^= 0x01;
            assert!(!verify_inner(logn, &vk.h[..n], &vk.hashed_key,
                &e_sig, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &e_msg,
                &mut tmp_i16[..n], &mut tmp_u16[..(2 * n)]));
            e_msg[0] ^= 0x01;
            e_sig[50] ^= 0x01;
            assert!(!verify_inner(logn, &vk.h[..n], &vk.hashed_key,
                &e_sig, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &e_msg,
                &mut tmp_i16[..n], &mut tmp_u16[..(2 * n)]));
            e_sig[50] ^= 0x01;
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            if fn_dsa_comm::has_avx2() {
                unsafe {
                    assert!(verify_avx2_inner(logn, &vk.h[..n], &vk.hashed_key,
                        &e_sig, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &e_msg,
                        &mut tmp_i16[..n], &mut tmp_u16[..(2 * n)]));
                    e_msg[0] ^= 0x01;
                    assert!(!verify_avx2_inner(logn, &vk.h[..n], &vk.hashed_key,
                        &e_sig, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &e_msg,
                        &mut tmp_i16[..n], &mut tmp_u16[..(2 * n)]));
                    e_msg[0] ^= 0x01;
                    e_sig[50] ^= 0x01;
                    assert!(!verify_avx2_inner(logn, &vk.h[..n], &vk.hashed_key,
                        &e_sig, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON, &e_msg,
                        &mut tmp_i16[..n], &mut tmp_u16[..(2 * n)]));
                    e_sig[50] ^= 0x01;
                }
            }
        }
    }

    const KAT_ORIG_512: [&str; 15] = [
        // Each triplet is: public key, message, signature.

        concat!(
            "091164798255c8c721e8aa5a4ae3ab9ad824d9f98a81724d26517cd6d2354ceb",
            "51b30a006d40ab3bb8a43f4b50b74000d9b098d0a903291c9eb172b994e1e7af",
            "ac4d2c952944715e086a1980047d3822c75187d74fa2184a6a1f9fe30eac998b",
            "00aa8689be52925d69672ddd4b17918f827c156d9458a0b05f1c9ac007e56c86",
            "f5e84ab846df2b8449e8a99154be302474e747dc868052f7e146b03eb00e09f3",
            "9dc28bc4810793245a6ab04dc6974957ace9a0b8ec994a9a19994b3a14bc5c61",
            "2b884fe028069d65f776da0eb6a28504b7836e964600b9c3ef730562ddc87be9",
            "3b9186aadab807f615557ac4911fcb00301612e690845109e456e70a99bfbdf8",
            "da07625f9fea908339d85ca995766835c4d99ffa8708adaa936c319fc7cfc648",
            "2e940f452e2bdf8c8ca147178e587139cde26b562c4e71b425bae6c7abb20f13",
            "4cee7e8cd5019589dddb6caaf025d2a4cf28859b52fb20aa44782b86cf4a2f71",
            "6c1d2963509c29ba3d65a18eaa6b29baa93f2b8f0dd063722f284fa969da0a4c",
            "dfc98c0abfe60c8e938429da80496fb49dc43f6a40646eac71f6b98f5de2960e",
            "4a02bba6d13db9fb445b59ddbef0fbb9e09e08ad3917b4a78f9869a625a705c7",
            "7f1bce6ad973d09e590d42b09503fa9220f17820a0fea7053e798a02d0047ebb",
            "b866cbd65c68c78b1721de87acd566dda80e3c5ed7b108e79e6620afd2f15893",
            "02b63e62aae2c826ac7332f0acfab756c688d8926d58f4242517c98e917d62aa",
            "dd57ae51fa3c70d1d19bbeb03f6857c1bb0aeed7674b5bea84fa67150a1fd214",
            "66cb9a5a13acb1329130d25ff778f6619619eca65e794d8b3518979688c8b219",
            "d4496d867a53fde4659125a3a194c714b5f5b80684cebc95a8a3059e08ab2d04",
            "fc3b10cb938f1e53021ea40d0a1e229bdf08a105b59ea6c32308260644abe756",
            "720a71fee11c280b0ca02a947ca22295dd17e4652dc6587e374bd05b9538f064",
            "33209aa21bca958bcec2fe9f75682190a17660da7207ec2fd42ed8240842dccd",
            "0551c7207d1ce851ac49f07689e2ae7de379b4133497482cf7846df70e586b71",
            "0f44bb7f263c19151af89ad1ad6152d6478c6d3f65fed4d0ad1823b74491e0b5",
            "6a00644ec178363c13a509208f4f8c83e4d5eebf7e3cbb193018b257798c82f8",
            "6dab852e4900aa41091d72f10101cec640281fe3b1618402893d9607aeba2044",
            "ed42a843b88d32e680fc5b849ae193d4a00cc524993d561b8e112441c9332250",
            "05"),
        "dbd71151d7a9b83b0b6e2556ac824225",
        concat!(
            "39d33b744e2ceadc9c9deb583e2d091f65e623e6dfeafbb27b287137d08ace8f",
            "ae59e59b76568913b72f6a8fce049c154bc6a5494ffe4a5b6d8d75fdec7395e4",
            "7bded536b270314dd4073d72a536ed7f9e96fa48f04c427b3ad34396078df9cf",
            "3271fce47194ccefa1071a7ef24098372aad45a6e2929c830f8aa32568691347",
            "78290ac8e5a56583a1348cc5a5997a937583a6d02408ce8ad695bcf6a48cb97b",
            "943c088d10ec1886312a0e39df86883429fbebe62eb49ca2956143ce53063dc4",
            "7129d33c2ab5dbdb5df0f1514606e71beafce39a5b0aaa437e2c2efeac7b71be",
            "4bfafdeedc3752876a6b8eeba5d4c65e24ceeb5b978855d79cd30c61adfe6cf3",
            "1c8bff9b56a631cd635a83af5a8c3a294990b1ef79d4c64f9f004f0c429fb9f3",
            "551b79aef1b4a4d41b54a7c92332ccfac30e894f99ead77a98ce93ae0d2def8c",
            "65508a7c957c6b4dae61a5284b4ce8e2b65b4c7d9e4a5f7aef0492b78ed76a33",
            "d20c32db58902276b51b3cd56bb07534a88d4025515aaad33f45548fecea106b",
            "5bea66b4a0fbb08c13abe08adef96a04d68f729bbd0d3539623829791d47a0b8",
            "73b9bee6dc78475d069cee90e6fd63ee3cecdc473bd1323735fde745ad754171",
            "eb30d614daee543fbfbb59bb89a05908173d0f7a48ab6f8872b30a2f996ba6eb",
            "556f950d749d5269f0b3356ae4b44daf8e3667594e41b794cb481d11cc8be2ca",
            "06b90e9094cb1c03448164ddd71e0b948a6f5015211e46bb12a1216412e33ed8",
            "c690c637bd33581c6a0cd593c12f79c2a320dd71e203c3184ca08fcfcb0d52e9",
            "6b4d9adec31d2f153a1b76d834ce00b9cc9437d91e74382bc7bd0e609aadbd97",
            "75d0eb15af5575c461a55ba52ed12523649f9ff922a37923c99f49cea601c949",
            "6f9c0e7e33e77085a7fcd839f789a00000000000000000000000"),

        concat!(
            "0961988048dfedb9339d9f0675ec3d4a226b5231083949f1cef92f2190bb29d9",
            "5955c8b406859534012fc28cfc7ba3e71b364f9c5774c8256867840036a54491",
            "26b4c4e051a46b102e6300c318e6a849ab977c565d5e8697e081d88e589eb1b5",
            "c50ed861ecfdd00341fbb6a8bcb725e17829e5510a8613195256cb7afb2d6020",
            "8defeaad17490b8a938693e8cc810945789c6c838765a3334808dd8afa7c3b40",
            "c1b1863a437b80e17779295c89c02adb988edc0305ce685ffa1088009cddae24",
            "6c13430f949c9265b8942a862632475308adb924ed0ccafe92294d31065b9e16",
            "241d42ca64660b2676b4c5c418e80086ac9ae077c2bd28ce4805ebaa018fa880",
            "f4d461018fdeda6543cdb941566a5bfa435d3d86dc811fa21cb7651a45709a4e",
            "867e6575be8e080b857419902d63b9d2b27b2787413ee496150258584531c940",
            "c3436e1a1cda15ecc2aabf5c4194f19c83180e14abeb9c1fbaedb354f2ab485a",
            "46e2c4e3562da092e2d382034e12828c93b5531b6421f306fb67651eed7548d9",
            "901a6cec8f959e594200ed2fc9a82876573ebb7012c5bd1c8cd7d3e002cf2ad0",
            "4b4252e0aea4b1cc2505a6f0ad6a0b954ce5f4734ecafbb60fed4b6676c7dbe2",
            "efbd81648b8ad3026a05fce37d25d17445bc6a0ca74b92492f76c9447d914a62",
            "d4c310674ff52bf221d9b37b366ec6044e42a69e63422ed3c8726c4edb40ca2f",
            "8f10bddbd6c4b6ac7650a4555e59607ad0b3a26be3b11290ba4782a13c962683",
            "ac6e3a7829e7ebd9dcbf7c9a01e1c16c6c697983f75054828df9527a3ba447ad",
            "90d0b418e3dfa4e505c03e52e53c7d1060fde158b9cd3290b3c7ba0e4eafe9bf",
            "244b71ec975674ce794c0d922127189186ad692770126d310deb122e655b9d2c",
            "dc929ea7e71f849cea899f4305e136e22b5f051a343f659f54e7182534394a06",
            "603b3a0ecb00617904c580ea4c2116837c31aa9aaadfa4d48364002d3496b9d5",
            "f5cb96c6beb2ed7a8590a22f7ac8416595696abefed3f20003832df551b31d60",
            "bef4091346c6b01a049d4bd6a852a10045e51c4e15523cee559e1e1181a25bb0",
            "3e9740b1b86f9bba281b0aa0da07d9cf941d9c8d7a65cd358c08e4c3b1cca063",
            "5d27dac9219ca855fce1075b530cd2be55fc9f24356ed27682e4f556917230f7",
            "022735183791c0acfe8645fffa64122ca70a9b596341bc8b546ec1ab107e3210",
            "68d370a61c54a57006d3665ab9d48404ba5d44103aff80bad3fb49a2a8833607",
            "34"),
        "739db98759cac439893b6465d6d56186",
        concat!(
            "395d3457743e6a2ef1cb3ded499c2b1b39bf3d21ef3acff157c1f79596f0f917",
            "20d088f3d3e0472f67468735895a6b28dddb37ba233dcad7a7697a68b5cf5dce",
            "5b8973dd204e149619b23098068e41fa675c1619beda6b30b15d0b3c6bf9edee",
            "c29c58a7b534ac86737490d6b6cb484e1af366c8cb6f98ff560088d1db17198e",
            "4d9e5ab52f18bafc2cad7b27af60f6d03a39787d103763f2a213a22d35856291",
            "4ab8a6923a3496fc88a588de095ed2b04d4897f3b54a2ab7a75ad9557a691f43",
            "d4d985173b06360db74570411816c700629e9a216bc83d1bf99c19d757a03502",
            "5b8022531d85609dd362c499af8e2239477ee5aa8d6471a67e585f51f2d1aac1",
            "d920ebf421218a5459ea9afa91a807169ddd31e69b52b72ddd16eb3f0feab48e",
            "47b56543b214be1fe505a0b88d908ac71c45f7a31dd9e2f6995d1af7227a34d0",
            "d49a818d6b8b9c625b861ad8244af71ff656a93c6266364aac49b7f499ad168f",
            "c340345026cc38de65558576357dc676db8a98a43dc557caf49538d28b4320fa",
            "69720083655f9f844ce5cc78b3a6412fa1e3de1cf5f103ebc56679f717812edc",
            "5a271d2c1726f758b7e082fb8a701afced913950b3caea36c3074e3ce87b36a8",
            "5b4cf29aa88494d5b527def8bef65144994dcbe1b5b424ffd68463e3e476e9d7",
            "8e0f04aa5a8ed0d9b2c990aeb24e62ee90b57d4ae6570a44de6ed9a2cbd8e5ad",
            "04aa5dda2432f6d559b6ab1e4ec6b1abb46694b46acb6d7e983d3a4a3ca495c4",
            "bba08b042da7779385034f0867f9ac54888a318f1234c16d5db4b9bf9184c1cd",
            "d74abdd64d82df097528ff0867e78651ad3733968233b94c2acfe2eaf698ca24",
            "b5e34170ec2c6ad5996b5204fab5c1eff5601d867d5984394e0ac504f5a22df3",
            "6d9ba8583f5e47aebf2a665a2bbc1e0000000000000000000000"),

        concat!(
            "093b34bd8284577727e0c59a64e03a3405f7b20ce267b6f8a4258d815c677e14",
            "63da82cfb78c8e23a61b9242157e745b019958e6b2f4d307fc9746be36390e69",
            "108d1f202b2f3b0ed10128f3245a2b3c8d67860e85ad4d0b609bdbad661a98b3",
            "08a3000c9ce592d560d222c994793cab9233520e3274084b107467e7d069b063",
            "601c9856c2207a6900d46349f62c8cf88bf79e1859d845a320dd0eb48abfb851",
            "9cd290a57eb2d04e6962f5a283836badba2461061963b3a4bdcdfaaa683a8080",
            "7b341c24495aba41c1b997942efe9481be682520409609a15e154be8fc22e8c7",
            "e8203e8576f6082b7312c8a5b1e1cfb2d1293977e7226800caf5cacab294588a",
            "460b904c5b8ac457a14c201ac6472771485e199270a660068401507994f1a680",
            "28f85f7b3c0dd9610a500a7b024411b01c602707ad88d6d2014dcb94a9f023c2",
            "ce541f233139d2016dba455a392406a8bd8901e708f2d03846e41c82eedcda54",
            "21bd45b8d7e55de858499d6aff98b203e5265588baac21340d52fc23b1dc0b34",
            "6ea35da9b65757e72669a22d793ec4a6839027e2fedd2267a6ba77576d007fc9",
            "d91501901d9914da57bf9d7fbf4e75c05410cb30e5cc73e1aa3f13452185b956",
            "6f75667b1a862be54450e592c96ea577a02a11b9139857f451bb55414f763880",
            "2802d1fb53942799ca99ae4eb49468524e1e41a11ee547c55181fd52e183ac91",
            "aa3a78e39f51ac878c822262c59a1896e31339ae26a6b86d591fd2680bca1030",
            "7fe7048eea7a6368cdab5f35df26572987bc4ac4f0b1c120a159942430484da7",
            "1ec01a17668d04f14dc854eac09c8d8088e902926baa814ae5d6f93344ff5213",
            "d20b1f901dc5f213c8302dfa32468d77366a2dc5ee0a643cddac6004e422b7de",
            "147432c92db320f5a9ce6d04b9ad91136954a4a71d86948e1b909154c6601986",
            "2623c9f3fbd7437d8b565d22ade7c9928502658f0a64ac76906594563097ad8e",
            "0acf92d87f8d7a43df0d986d812dcb97c8a16f189eb134cf15abf0b1e6c8e221",
            "41562ee4c3a6c2234d3f475e156a1be5db9bc75f3d12816782290e1f14e2a265",
            "d2c415427cecf931addb412e58c5a7addda36885000e5dd5bfaeab6a5ba4d3a3",
            "f11300d960b2b84e8524cb5c7a5a4082e838a24c874509853e998858216093fe",
            "83080fadc3c250deaa308836b4a0df6686758df81388733bc5e5984085204374",
            "e884a58cb787322569f6dc0b7974c8347114b3b87a52351815ff972477f72ee7",
            "dc"),
        "3e1e8bb76a711ebe49620d0b9f5ed233",
        concat!(
            "398f5641ac1f0c367ebf0fde594fd5d99e2abb98e74abd7d9bf7ae50bf8ad9e4",
            "797acab23e9f8b00aeba53977d1272e448ffe87eb110b8e89356b60745fccea3",
            "b57d1471406bf378cc0c967ad75e37461342a3d1a92ff42e8927e9cf59c582e2",
            "aadd66907d1c612f49dd9c363885b00729faf8489d0217b83e9cc4392ba2a5e8",
            "3dd38b6cc6b52974b66abba20c5721584b573b417dbf316861e3b5e692defbd3",
            "2cc597689e459d71b0d14bfe894661d0941f771d2479c97eb18c354f53285153",
            "69578a43ab461154b91f2253fcec3b450c566204672042709286b0c9ec696973",
            "43d5df2958724e6c5d76dc6835fbf8341379c17cf38c13b5cba8f1306e5b0779",
            "91f11374779cbb2a1c4fb620d231a14861522f2a714877dcf9f7718bb1c3ebc8",
            "dea5d1f5b21538fec4ebfb31501a7e173d13b2e552baa52b45acc9097d87a5a6",
            "66bc90bacb351c432519c63527df75790c9aa56f7ea6e804c5849632bafddc8b",
            "7d5cbf7e9a9b3aa0cb9f6c0ae88434838919b33a8e96cd95693f5fb62a311b57",
            "10f47ee38551180127650ebca24988cea88a6726f3009a2dda9173b05bb2f3f4",
            "f250458dc4a12d51b674725ba52030a3024c93c68ac52561c2ed09d742c9d69b",
            "268f2f9a250fab77644b14f1c6f74e99d69b109594b6fb4feb452dcf569ab1b9",
            "fee3e54e3f21e57a302d9c89ffe4bad4bc9c215975a6e979ddeb7754472375b2",
            "6bfa7b2f5e6085ff6dffa7c90775b62d7f826faa4c1245527be46aa9b89e8c85",
            "2b506f520d61cbd9185a45a5e025f8e61bb115321c9554e57e0f55753f867564",
            "683739cd8d362abe546e8faac365bf49d0eb8e750aa62f6dd374c5aafd293a71",
            "52aa90a5bb1a67720d7f17a57eba6ef87c653fcf5352d0881f8a233a4b5a0233",
            "62c7a3abd5a6a938e1452ce78200000000000000000000000000"),

        concat!(
            "09b4f4e8a3b89489be092b1727647151652bc563e95c1d1e60e9d268b1a711a5",
            "a1a74be6349a7599b0c6eb3a5948250c1d2d41e0ef52145ef83e2affaa006a25",
            "80bae1549b20df943520999a2276b9e97747bea32241bc883b0240473904fa91",
            "458b41a126259183d5b2bb92313bc05584059ef174a32256baba7715a7ed9712",
            "fae1a9622851315ef426b7421316ac6536fedeaca9bcb8f4a1a3e471b6d6c3ef",
            "a8dfb688a6301ad51d233069c85220434cec196ac1dcdb72ea71844d5d6619e5",
            "14eb59671b5c1615da9cdf1271d68443c4973f3292f52032a5345bbdccd8fc90",
            "06358998c2249eb8056a92d982438f336d23e0935e3d1944b8d5451dbab05528",
            "982ca78e783567a5418d0868a84f364c82910a6c9da6ef4aca743d660b7b878d",
            "bd8e308976415004fd42d79365a47641c1146d1cc03dd0eee940576a0b7d3417",
            "7320931a9e02a99685adaf168842fa1c9734c422a1ff15004a398956870a393f",
            "bc93948a5d26184648805482b0b348073047cd59b1ec8401a11a8c4afde8639d",
            "838a6f8da19a7b17206582f6f47d1a947ef861d5e687bc3f410e71439aaa0bc1",
            "39720b589137b4cda38615fc546a99409b2c8811a4ef0a6508c6035aae04030b",
            "0824c4a763326c324492b5a7fa9e7f58aaf8180229ac9040db35f262830dfc78",
            "595765c9253c13cb14c3538e58480bceee721a46a654d2c85452e147837f0d57",
            "703931cadf4ed09bfcef9b79469303e1340ba4d7589c85a599d6a80442553608",
            "30c99066f07ef72fdfd3b5beafc7bb6eba493daea14b49cf865aafa44400298f",
            "a6d8e5619fc1b6e67f82d5e88b7411a3872165b28034ecf322c4ab7282baba76",
            "dc837da4e6f13eddf3094a6003e6030f52cad089c1021381d43d054fd5b10b1a",
            "b86aba909598a80f517a58a79b6a1bd72850f061ec72fbbe827e4ec510181cd6",
            "b10b1054003281246a3a4ef4649c1457e238f92f8154179dc2a97461b53bd109",
            "c8f4904c776e128b2180a210e0c993765e31abca48b093ed428ebcc5232ae4c3",
            "9df53e86c62f090acc126a585d9f876984cbc98a74b74c42c6396ba82d903a4a",
            "fda93f3b359eb234d0d76c8a37889f0ec410f9b695e6cb5d194af67b3d5ed07e",
            "e117fab4d084711c525b3b666f6a625fe7796a1a79408622d8df893f70d23696",
            "92861ae17a77968cb19e3d1cf6cfab024ba8bd1b57c3e98f1a2b72bac4e34ab4",
            "7ee3c0d1249a09ee836dd8248ad1d513fc258d0e21dc292f0251ad32cf99ef62",
            "09"),
        "72b73d75c0ccb79130be03e8ec9f602a",
        concat!(
            "397aa5c8ee63cdbd64004f85b317c0d3e472cb55a2ae4f53649815d07b13e9ee",
            "6e207ba7f59d8cc70daab072a00e5b4d256a4c468ebe945f20ca2adb938a5766",
            "b4ca4f3e50c6233d4dcd42fdf6de6fbb6c57ced5b855300db6bb426dd74c739e",
            "222e5d2a2a4f194c9af7b16396552de546ac1d9844e60fd271091c78efc37589",
            "ee575b8dc09914372b815088a41110752c128dbc8fde86c0a617ee5a61cc3d71",
            "832c97529344b5b2c4b7d73f4479adf88f8d48e9fcf86cc98f843e4b9e3af6c7",
            "e7b0e9b4f99fdc4223da47b7e680f95a997ee3e9ba270de45e518e76d2d9de97",
            "9869ec2ce339b7d0bc7d896cfa55fa7b997deb8e8e91b8a118509d017a471f7c",
            "b64e702f75aefa2dc829280082a03021e9dcc05fac0262f49b35995d12f346c5",
            "cf1c3a64dd1e11d801f2e3455dcfcd13476de9edc57217a7fe5777183ffe6b27",
            "539b46248a9ff3308a350cc0c299563dfcbda83336a4c776d4648e442fb1b4ca",
            "bbc1d5382e9be13e728ab61e2f36807158422ae7ed7d8a7a30c9b4cc42b177cc",
            "119abfdad13d9671d0853a4483102d29598c715d029699a008438122e1f52143",
            "2310d4d576acc272e7cb78bcd7a667ead361cc317a72fe9811e634d516cdace8",
            "b728bb6b6adeddf36df7d9bbc21e7429e62af6fb459e1db648692e1e66447bdb",
            "b23c4d49290b216d52a5eb690b75412c7ea5ca76c9dcee249a059dbd57e3cdec",
            "135e813ab3f4d6276b41d304d297f6b3c937c7ac5ac8466b814bfd68cda21d81",
            "67e034fb15bef8e9e69c4c8d02d489e95dada7dda15f16174cd47c6cf8e5b77f",
            "cf98274f4519582a2f0d06f98e7d791a758f1afb53c7010977e7b826db228f45",
            "c84ceb7c927672578a831497a2dbcdaa06a3f4aad386592faeebb7ce996d981d",
            "8de40b05012d09aabbdda9503099beec00000000000000000000"),

        concat!(
            "0994a823d6b7a7881c5091879d43f0396821920e0b4428756caa72d9688070ab",
            "586328e19b00a035189a8d3bc638f50616558c1d6cc7b5001a89dd2041ad1a53",
            "1171efa88de7cd1e283885102e7e1d85b8328453cd85bcd3f09de44172a1f3a3",
            "68118e4ac42be88a5dfd061e68043fc0752eb420e6709d5e2d5dbb131a82cfbc",
            "96bd06c622fd76dd23408598dc6e25fc974c637476213b33c48ad5b81673730b",
            "8e3a974d3b85ff90af30bac3b7df26091db5eec2c952f65d4e91da7c1c0f94ba",
            "7a720329c8336933350fd53dab96a2a00c9aca56b8ea94daeec7bef4cec79042",
            "4235bc63198010bf5012f20058e6f07c3d4d817cd149382124c5c6ebfa1dbc15",
            "327141a1a851230928891507bc151061d2f95d4a7063d9aabb51826d337a12ac",
            "6faa72d932c631a2b22496f707b521fadfcb820e791ded99011debe298b8967b",
            "3eaf85a27e658a5e060b1af65e27a1c42ea75cac62e09d5e95e05a8ba80ed006",
            "d289a7ed9957724a3a18dbc4cf7620c3a8cb1c8f5f7424c76503f5662430b544",
            "420286e809f279ef6b5970eb5013ab84630ccbe9accefb22b8d3e4fbdbfd6b41",
            "65d695db06b2282e0ac8aadbaca0993bb3cea4a106ffe4979a7998f95afac8a9",
            "626d9c59fa46ec0b66099f69278ce65a922cc9fd2d435c9117e51852762e49b2",
            "a74112112378f026788439651271a4576d28a3684910421d4f7d484dd0f2c79b",
            "427431fbc418b776a92ba4da84b75fedf7c7ab070c8b0e37c616694786c28150",
            "47e62604f99c11b0024713416bf4bf213622ca6d86b599c254ec9a1238659195",
            "8e7cd40791f48722cc41add1e0a6de2f04c8c9c310618ed9351f021ac4be0550",
            "5c2b0d224a61a751347a2c7be07ed37102a4cc4924ab16030aa571abc4d19512",
            "f6d1fce98d6ce44f89e4883925122d02841c82be6dd28673ceec36c850076cd5",
            "8e428c9bf79708e393d48eea8b64dc7cfa9ef268005c4f2a5bf7781c5d949268",
            "48e1592423126270361c3d0c9e9d9900923557f451725acb6bb875dcf3dd6d6c",
            "985ecfc4a8a6c0ba9dd327b1da5f7105c9b5f82c7e38ea7f70c9d1415b0820b1",
            "4f8cff12eaecf012488a6389b5ea3e298559a9a1986426de82940f2bd7e5835c",
            "2893214ce18e43e1b758b8590641e926605d19aeba84216a9597b3a358a872f0",
            "aab9848d1d924563427355fe1704db5a3942aad618da50b394dd40dd257c2438",
            "2136c36be55e45ca5abc90045ec519f8aec0276aa4a47b0dc20eacc98b288250",
            "86"),
        "880abe67dfaa4bf4a9cdd51a369a3374",
        concat!(
            "39101627b19c37ac086baa20094e9860e3b23038bf71d819c0d10f9f4fd6d4a1",
            "d76e1fd26abe4c29b89bb1521ce8bf5b66ed6b17dc2c86bfa9566d3be64aba92",
            "e5efbd9d0a28be413129be13ed39866a137c1ee5c9f5ff19f49652edbe9b2bb6",
            "74d2e9bbd6041e289ca3321eef93118fe061b66d4e798cc19ae205d73a3b0fbb",
            "938a295caa998d80de1232c11183dc97b95b9e93105965d73cad259945c9d8a4",
            "d5f3da1e87470062e188b75b04e562e3858e02a3eb708bbd39ba452eab453482",
            "9f99563b410685a4475dc548d398737b2fc999dcd64310d0dbb8e5a6d1bde828",
            "abc431d189c98dbe37f03d59bcc25b119828ba31449398d22cbfc108ac14df40",
            "746e4647ff8d64318c6a21be8ba7c9f23c42ac2e3a2f354878145a5a1833a8a9",
            "576730645562a8f251d2e7555671d3ea50ae6107b50e88674cd4a5b068dad585",
            "e0e18a2278d655214cfad1c0736bd8de9596599bd0102708f11bed76b91e65e3",
            "09ed32d132685986f9c19b25aabf9b471b389f49167d03d7db51860f1a1e072c",
            "a2a1bab63fc7a39056f0b997b66a7a2f0d313269aa277f07026077de76231bb7",
            "e5e294fe1623ab201009c24f835cd854573370f14f1de8cc2580691bcf6b0b80",
            "477fa97abbc09f99dcf30590af7b2f0afa33f0b9fef02469504d10d22590b5f3",
            "10380b63cff4e311099b75ac6c19c49130d3ab3d89ca464a94a211d098d3be08",
            "f6d11c653573947dfe7b65de5ede818679124b4d3d21e6c3d15972267335ea54",
            "3bb8c332d109a1b821d4af953f7994796b5fc439578063497c3a1378f3a3d68e",
            "133bc2c1637e2f3a3100c0c718e635948239344563c5c4700ebe5fc46fc8c901",
            "a6a7bf6d965a010098407debc7e960663af2fc5e94c8bbcac506a0677429077f",
            "3ad3909a7d91cecc2c5014ccc5a0000000000000000000000000"),
    ];

    const KAT_ORIG_1024: [&str; 15] = [
        // Each triplet is: public key, message, signature.

        concat!(
            "0aab5887ca451b1e5cf5464503dca9b5f44c3a7786a9b1648014f224b4a11648",
            "40584034104513f614af92440417c0086b513a5514d01ccfb4b53d7c583dc90c",
            "be16586821652b79d049c56bacb67339e3253f60a2597c4f4920e2c9bfe00924",
            "02517a7e54e6d4bba8d681908ca39cecbc445ab976b4d6c34a76ad68ff086110",
            "497bd72fcede519542b387959955f24e4a75642f0c5617b2b7a9c8bd3e064be5",
            "60120d0d2e376e6b869ac2e8c8925f591718c71b0a1d7a90e61a429a995da258",
            "2cf8470a7e554ef8c7eed71f2a8e8114bc2b755aa67a62560c23712819943b23",
            "01223d3f5b6a056a41a02e24b29dc50d95560601dc1a6bf15184c52fd2ba70e4",
            "31a91a4b9de44c61c6ce0db8a19ad164d5a1b11df302f19fe773bc39565c2f67",
            "362af543b6de0302cab89bd40d271711841ba74b9b96059bd6989e905a309e64",
            "678b8b2cfcf81adf9cfa31e247456301a37145412956c09a40e1dfd8d7cac123",
            "b5bc0791aaa8131126c887c186790923abeac61abd780065158b2eb562ec30a4",
            "9255b7fcfa9a8ca15879f95938354608b8da33686fc7498140743003124183a2",
            "ca55d3dad7b000b4c7cb2f10055a572a92ac9d1cc6eaf721afef1a56859087a4",
            "677dd9b76822624e4e9de4a02780d89a5534c8f1840a482233a95befb5342c55",
            "c0f02c8a3dd6fd370fa17485e65f932fee0f50c8b8e78a525f1ce61f11e7d40a",
            "03fd6eb99f97c8b262a92598c8d497b62ed6e36618033cbb9992ac554834d36b",
            "4a2fda56cc4d2615df402aa2afc3da8a1dad86a9c6e6d99695a6d10167c17500",
            "d8df74a4ca841cc9347a330ffbb0a90bc00dcf9b2310fba40752ea2df4c0b862",
            "a025678ee9296bd8e060ca7a8385907e3a2a4bf2962ee71e7ddcd7d3d0e708b9",
            "4bca1ea0cc6380abd52e8b5c0378b6ea6a55c3646532d5b740740c20a5180180",
            "a156c19aa48715d9214e2129c049489a80dec9e157066a2844227f0de3788e68",
            "c13f19d1042eeba9210fc847c8b5b82329c678963d94e129b14d4a9de9fac722",
            "4552cc66a3dc85bf99cc7389cab90636be851c5bae91acd5a53d118dbee23209",
            "164c1e7daddc282008cc5c021dd8cad2810aa24ee3769d8c070d8f13445ac2bb",
            "0eba1bdd2d5d76ba114666d8a76295d0c1c9d96e98e49679cea5151b9e747278",
            "1d67a9b4b238c1e6ceb7f26a13086a8d66da7daa7bae6c6972b0fb82a5f55919",
            "cebb8a5ce346d9f863e7d49f75d9a7355e29a00de4395a462758ba9207da5f21",
            "430b56fd3121967f67346456f8e098a2bab3872921205406f427c7134243aaab",
            "9847d59eacca83350e20248274b3b69152ac9b9806b60e4b904a64a5609629f0",
            "2d7289973d5790bf4cdae4f599d4bfc25e95f3e93ca70d8952cd6b776de8ee90",
            "e1847562c81eb6dccefb0881678386c07c084cc6daaa88a840ed45daf0a79036",
            "240fd47aaf09bb6849b2011cdb51dc4649f81e2010fe353659d0a58f41bc05a7",
            "a93db7c48851c42caa41356110d4d86c0f10ec135116d125c4e863e2cb8c5be5",
            "ef1a2449d287ae34e693ee1c82ecf4c558252d79fef5548ee09e0d799f2511a8",
            "edbcb699e4bac17238c6173013e3619d35b6eba4654419f92503c7ae8d7fedfb",
            "08bc91a5a3ac2c04da04e89081ffe2cf9aa892bcb05ad3102846f9197b245508",
            "0796ddf23d474213cc05f90a425018a0547749c3697b5905e6b50bb28b7a4fd3",
            "bc57a76f9ef4d71f2b208b507e7a47856b4c08f6c198a26e681aefd3ef2ece42",
            "1275f3652a529cc4df987e54761d1d9352edcd3b1dd11e93dc61b35f999e51e6",
            "8e1c86daf4433d4cb898b41ad595d6902034b2d2bcd7b7a825d0593b8d0c9f8e",
            "ec2901293f67b9f9e8149dd15f550f044f9c52870078640f19218cdacc932d9f",
            "7026b9a0860d0f0e47f69fe4b1dd875f6504907fef746d0d0122c381bd60c14c",
            "50c8e4b72b1de7f6886f358d5c90c4254cb7293e29aabfd22b311648252185b2",
            "16ddfd007eebdfaa35ce0ad619256ba964f18599915fc03d2510631855657210",
            "da5c04138597a290aa1d701ef7a51c67af8ac8f566ded7a04c0eb482ff9ecf4f",
            "3259d5e9ea2154ae437bb52b7f2cea69329b5c4111690c7347d77441f8e6f4f9",
            "de24486ae6d9de9f2b41764fda9c832c8699ddb92d9cfc9365e3b45759889b72",
            "d8026b69df2bd5bf57d2498713f6467bd207616f796004b0a4ada981acc98f44",
            "c9b0bef8474187444ae1fabb920dfea485ba6123199b7162fc64128e8539f263",
            "a1350878bcace361a5d65f61e8ca54f4da1526bd66529f8624065625c70003f0",
            "6b3a0e44801b35b4ca036110a31a868a45980c085c23241750c98f2a20d01a07",
            "e820618689b58615458b5b35c1843c0ab2465d1ab2d446cb981e19593c42c192",
            "3106e1d2037780b6f488cdc322ae4d46d6c44a713bde0927455c5338808458fb",
            "5eda901939086eca0e16ce43354f42e6baa1c1c5afdc7a0a9e42e27e87d7aad6",
            "6013d01767692a90f785190571316000e8501e3d1e364577a7798b31b061b211",
            "66"),
        "b87670516460a6ea2cc450374b6c1cb6",
        concat!(
            "3a12b43c773f49a7d7ac4c1ca469c72aa64c6a0227bba8bb7b86e48cddc9346d",
            "1f7a9cb1a56d6bd45a9d4a60c9ff7e17cea21cf9455e259bcf71ef6722f3b467",
            "ff8ad4aebae3b1daf6b37398ad2e3ef37d218869665da41cdad5080b0d994216",
            "8436b9835cb7b66578da1895fe57f751cc26591572716a55fb7532e276d3d81a",
            "8bf998aa19c636016829ce7f76a07d2064759ba59befdfea72d629356611f275",
            "ccc232cf61e55219f30c89f0326d17b0fb47779b2e4d29b2d7666772c67cc146",
            "e51b7d8dd2194215bf4d15d7a920183624d2e6711b8e9a5f6b5cba91da1e1553",
            "a1c3316501539d4b62a61902de7c15b1184ab6565ca39f69f8e2353f085456f1",
            "61ed7eb0b69ad388495edef9cba76f1414ba5ce3174ad600c37931d5cb23597d",
            "8cb2ff7805511a73afd72ce18c9232e65119c4513397996f99564e18d8e139db",
            "de92186c2671da8a5d90aca1166e7d3da96c38500a65f747b4e7fcfedbbbff9d",
            "2dea542846f3929433126a435d36a19db60062da920723acf1e05ac204b8b984",
            "5600415db11a4a589c0b90a667d4fc2d61e543b22b57061dbd7f1a44cd8fcf31",
            "d4189df1213abd9caf7151ef6388f2e0ddf7f286553c83e51d5681879148195b",
            "f7cdc4c29c8eddf7e77e43f43694313bf99786fe6acb8fa765e3f94d48addb1c",
            "bfef1e195dcb4b91c5535a74187a511aba0ad7351dee172ad04bb07dc8be7df6",
            "1942b6bcba525cc62254c828a80d7f2ee85bacfb96528f62bebad7e84b1b86eb",
            "a3919acfdde8ad34df6717fa314ed75a3de7a350b56652498df96bb36a4c10b0",
            "f08b0a9f242d58d6afae60a42dca99aa2c93384110ad6211eae4f28739ed17f9",
            "0438fb75e638fe4db76794f62f767f96ae508d4d32da092e39063b8475863f11",
            "d3eb6a66b6935396692ed1ecdc857f4c6c7455db83b5675a5abe36dfb231ba46",
            "612f6319b7a91caa2b062a99d2dad7b2296b8ba0508a0eddd24b73e841f1802e",
            "dc2b6b203673bb2b3c65aa66e13875dc4bc7ee7130490efa7989b93df07bfdad",
            "784668907c08c0a32c59df9b4bb8452e7e449ab49262d1266369b6e028a9e22c",
            "69942903d719b5cf9b5c27ff20cfeadd9b2f1b86c7cae2cf36a328505dacd225",
            "00373535f7e8955b53857f93194c8a4c2f0cc2a80f865302c2a829f14785e0f1",
            "51e237c693fcf769c320c0d0ed5dcd61daa32ccc676f28acb56f06214c896693",
            "f32092b56f07c6b35a99a66f3376c9667354c84dad8839d83dc1c28995b7b8f4",
            "3759e595b57469713cc666bd7272ac522a7afdaa7f24261da1e6a799940b6dad",
            "6765f94b65d738d1aa705c62c7c4559db60d15ed25d2e34b17a1767c0f8fbf81",
            "a7af9ff8199c4adff757e690e4f86659d9681c7502d2a191e807d9555f12aa5d",
            "9746c8dfc8ba6c42322fd6f4eb75da0eaa0febbe4749766cffa056552ae6aef1",
            "126bf1617834bc47f1d187ca64b214aa5da1fad1d147c52b851c16a3e6cc4115",
            "d755404cc813fcc795342d60c7f0286fd67b6235edbb8d9c410a9befba8f7a2a",
            "2a6cddf2bd41bdce639884e3ac250172c593d9643139db4f3c3748b78d209bcf",
            "61b39d9bc6d02c176b646f8fb8a6cb0964104218fcba9ff16da9d4549f57a2bb",
            "f2ec383361a3fb501da93451ba446b9c31fb86d7ef4d96af3732bd4f1f747162",
            "4593a49fd08e6d37854bd4d62a9506da63866634a8982ec8811618d2d04f2b50",
            "84aeefd2f9ffefc99265535960f33bfebad326107646c3a3ce14d69e568d6f53",
            "56708a26cdf68ef885278b0ca2f5105fb459d800000000000000000000000000"),

        concat!(
            "0a2f5e87e0e89898aa05b1f3a2175488cc05352f4ba760ad56733c16708499b5",
            "698ecca29d089d858f9abf1398c9347aad0891a500d929c61590469250d1860e",
            "bfe09b581b5c1b9b98be353c92bebc785f6a2b5e0ba1aeb456eb5a7e090d8b34",
            "0b4ba903fd97616b608b06bed8abbcda5ca50db6a57aa41c7c3857e755d440bb",
            "fe6c372f28363776d1d9afccb0b60e880065d3c439851b2b7c25c6b30a78b113",
            "278f2301c514d9ef7789e01cf549153744842f7062d6d46f32f6389e92cb79e6",
            "a09b34cbd96761fd400e4959a4b9ba557b957b709e3df4f4e5214d0cd6b7a309",
            "4f929e52b5129f756ebae5730ca2805a804bf6ca638e3b1e91b4ef8871b34814",
            "d64c550158799be0ab6c5c48b8781744d0b515e6c9d0b6ec411640e3d214d017",
            "8ddcc6671264c9573deaa3aac612b0fe1cbb4bd72c736814900eca2ea4a91d00",
            "172a1b1c4d6e41c2014171c4d3f321073f58c4bd17ccc75f84328c456d8f6f1b",
            "0947749fa73296005c403de4438310d52b0ca9b27d718c9a28810836685f572d",
            "80cc08ee7039f3ab816cf54d4011009f477d8e07f90d863996edc758a46fac09",
            "5e3bd825d28aca1a31d6800b8ed84772c888848aca3244b04c7550c651830ba8",
            "452abdd5b0f75cb472e96190a71d6a37dc3643a4d8de4f18bb658dd631137084",
            "21584b783e39c4572cc9dd40b0145b3aced55fddbca0f59d805a78e559be9b0d",
            "bc2d75376f00976fe443b51a0ec503b45581b45bdc70219b55aa09cd202e2e19",
            "22de923569bf78c1259594f848c93a20317dc69821ba2e68abf41058e3149228",
            "060ff52443eb88be4d00b1ae2d674cd8d67a9c4b9dca39156696196ff44d638a",
            "de4da0a1b04103d3b833956c4179ae4452e2321405c8c57ed22e4b622d7c1a56",
            "84070c295261684cd54d82e62b9693d210c69f7a5d2c8b8e17b3951d3296ebdf",
            "399009e582b04a845708d1381ae8f475424990552fe0b6047c63ba8d0a616601",
            "c4445c6957d129092f874e1ce9deaadd9a2eb826b2a693ae483606529a8bd25f",
            "a836ade4171ac13514c56a82ae5139540753c1a62e5dbc0b1796d4e06091fda3",
            "c7e6ae94296ca1442de40fb4f6d96107931e6ab336fe04123e60469bcecca34f",
            "d154482a150a4d26d9787b2b2981aa3061a01e0f50bafca602aaa636013b7034",
            "ecb33a94be70c4e0378aca2b92b52272a7e98d61e41ed306fa62f7895ff59fbd",
            "63f2c10d0b42c8a83771873596159622b169c447e43b670e6944bec8b9316bc0",
            "955eb86ca148c5308f65f189159e99053ce0506cabdf8b3d0461d36bea0bac68",
            "077dd818aa3c85c2d5654e2675287167a3420894c967be67a1519ed8e717edfa",
            "62f0a9b5d115b57d301a8a4c4f340614aef4e1e8233ae99066a7c411b4fe2219",
            "5c5aa453dd4c273914bd76bce33b9b11bb1406215147d7019748e0a61a11853c",
            "e9178abee8ce92e2f5913306947a9c930ae7675c2ad2a355c91fb938aebfb817",
            "5413369ebb889cc45e0fbd2d13712e8906c2f2e146e662363910b29ee7c0bd69",
            "3a40cf6a046be4579469c9ef99751079e042f15916decb3c44863f490345d8dd",
            "71820cea5635a0ef58c4f381c9dd74025ea192d681cd17a06614f024b504b160",
            "f77f476377c833fbcbdbfa591594d060e37a632a1c7846df1c5bd65560968b96",
            "29b666363e5ae85abc5da0ef6f482eb02cc4e7cf6f37da841bda9f1746add621",
            "d411bb199a23b174929672c9e3e989e869018d2e60130e405541ceeb540d2902",
            "45d861ecc37a00d4f76388455f2822624398af0b88faa20627ad424045c5f7a6",
            "1f2e74b13536de03313959007470eb9b9ad06426a25ce320f5b5f47a4d890c44",
            "3024f0a8d05c28e8bba1543a31ece163b58f160505e06b83c53d34166539942f",
            "c5a13d81a283ca58b9fd7600bdc55c6f58afb09c1d00447976c7378c143dedb4",
            "4843980793d4ba9bbe5a9910c03532700ee30a8655e275cf57b176f9d53e169e",
            "177286187c2be86c689645650f771668006629468e6a86f4075d21a29e0c233a",
            "a6c20b33b93681481bd8843980d86c87a25b76c0682e4bf5815a9064615a2232",
            "e07041e4680c03aa8667111aa21172a2b07805898b8ea8fa9281a3a26a23192e",
            "964141919d97ee64b3223a7be14fa0ad85e2f9a2280d144139cc46e90c8d2a96",
            "374b9565c7237ca4f1b2671663b67d28bc650e2f254a55d4456794ea95a561c5",
            "514cd0772a1adc6c7448c065279aff76e9b52825aaf84708dae68911ac3d96c5",
            "a1195f2772a244a1e5014d3854ddcaf26db279c1afa10bcf6a0dd5e1218b929c",
            "3ca67cb8d294574f30a0047a5855b66dd090e6c8fd2f3e5229534fe7bd810929",
            "71a5b1059454f18142a030ed770bb4107375a18fc67c62b08724fe62f58d7678",
            "896e5bb69ebb05ed9d890748b3aad165e981855635f141196ae2774d569fa647",
            "0a433dd5d16b9dda0432b4f3c4d6a497624908bafcc767bfcabad6d501a4784a",
            "01b96685537b3a6fc0395c0a56e4d6761cdde5acfc6d478f51b392799ef0704e",
            "3f"),
        "b03c5bbb3a51e467c36a19f4cc49313c",
        concat!(
            "3a84511e91366f0adba5aa4c496a27dc9d750cedaf5e27499d10cd8f1285f435",
            "47c2a885eafb4574607f7934dc259d256663db5c6aa4f2ccdc18a91d12167792",
            "b8a55a6cba1ed50c39dc431a74844506ede76d4c52cd10466d64777057264db7",
            "9f23e678d6bb74557e8a3b535c10a2c26cfa77556f591d69aa1edad296461721",
            "b25ac93f245256ea241a4335c5cd2bb4e91107ca30223712d8acb0d5894f2070",
            "b2ce9c1784da3a4f1ddaf1f3cc2e125f8a3684977ae658d9eebffcdc968e4ea7",
            "6304f6318819640f9908b856e6ce792c210a6aa5936c988ec1155891fcce9632",
            "e92d7b3f2e8ba9a314a9d995641eff76890d451984b29af72f3874585e19a2e5",
            "7063d9a21c8b49b8738dc62ec716a56f5caa5649b2245b79bc4ede28df68edb1",
            "0e501198cb9dd7b1c1385284b64b21f1d5ff69866c7ffa5b6c2ca23d91aeff3e",
            "fb4d6907605c2b7ccb7f31bbc48d314bab392ee6368f31a1d27a363fd2db4ca4",
            "312759decff18cac0a3451d14614fcc9665556a2ee4be81ab579f1935735eeab",
            "9596966d297a857aef3e5917bb7db59c289ecacb5f539361bc53ff63798c7e6e",
            "d09d9e7be087dd72508945491333edaa48615b8b6e6e11c469d8e78eb50f8c57",
            "65d04aba8484551c95c92eda8b5dd385c5212380c0b22f5c5dcb79f4bcc3c481",
            "e3565400d3fa3ca9492813d24384e64b598f49205cd827d4d5c67408d608a0e1",
            "df6e126d943eeed4eb1317c4d9700ea1faa455eb69a1ea4ab5a70e588ef9190a",
            "466d8d3d7a525ae43368fd8c785c08f9bb4d1e7d2e0fe359d566f43ddffe5e93",
            "33ee993807e5ddd1d9d9842f62d9ac0f963f2138b625b8231d0d49fa36c8e967",
            "319e6bdd076eb8b8cbdc50902110af1e63806329bc1a3de25b4af1fe3951b279",
            "cf5b77111afcfe8fe5664a8a30c99702cb94249f6cbb325252bcbcb21946f85b",
            "f1ae06aa1664cd2e8483e93b44327c86675dea79a471b9d4187a6eb721842d31",
            "4e06c67d8cb439d12823d51f76193a3454f4b3e74d947253bf5a55d7204cc92f",
            "33eb06ab4752bf248563b594f3a73a854fc1aecf52d3ef0a3923892ad95b22b4",
            "61b345777545751bd39dddd95d936908d9a188439f861eb70a7af9440c0385a4",
            "618a7cde9372450cbb0f1d8e90536180528cbe58dfbe2a3a8b0c8e4ddc26f2db",
            "81bd2573b65f159cd9d72488eabf886ee0198fa62afac0f590f41cfe4ef32991",
            "5c5cf1b8f984658229527731a785b030e7e76915c9eb09a4f779d69875be8402",
            "7aa147d6a555a530f964ad0f953079e743770ec17df4ec4f70e629298253fab2",
            "d127d938fe414d97c89f8936471863e07b37eae8a86144e7538e421e83aeee2a",
            "45a18e5bd0862f784749d631f51f499545a93336c9bef54f87661612c7a9d4a6",
            "4aecceb1d2b04e49d4ff88c033d0de7b1b58747993d9bce25c9c3b14b35accbe",
            "0e7d96432e6b8b0a34c2e4fa822482a04e5093655c47576d19675b463b8f67b3",
            "c9f86896b6b5d6b5b20b9f896fd151c881aecb422c1f8cc628aed1377407ca71",
            "f3a562f2a419fbf749cd21dfc0cd0ac2108aa01b43d6e1b5aca3eca46bb0ebde",
            "9f21f036106d2d7bff15dfbadbb5d2a8635f045245c850762c1237bab37dd11f",
            "8a3887abdaf2058b13ef190553e3e9bd6100850df565e3f6b993f2619ccadc8c",
            "edc591260e04cbd6678e240d2b6a19a47d8adcfe190b4b6772816a679264e105",
            "c1a1ac2c2d2ae823a6c90fd827796232ea59675dd833d2dfc19ec7656008252a",
            "9dad9647f6321fb7230dfbbfe253aa5fe7ff119a69880a3db940000000000000"),

        concat!(
            "0a48ced6450a20ab57dc6041b221a16aba0f1aeec2798011b626774466213578",
            "b670cbfd786aff3afcc90884eed9f43ad6e5529106d568d76d5c1e58e319ada3",
            "2f355b386e4ce08e62d2174c6b0f56b4c1f67e26eb9af16c76091ce3217a9a94",
            "b346a6bd90a0f461060a94e046c16a2d6d58b191eabcd839a0d855da670d9d41",
            "66b7a885dcc8796d4721e44ab0b9a5ac72c706560bdc911a5de81d07d65d555b",
            "029b37b62cb159696eaf018ac7432f3797c2dd63b2087e9015cffb66e58d36a5",
            "eb80c3187a2021b813ef900b3f11f4eb3606379280414770e30f7f5429e1f99f",
            "b75718b4188460cb0aeda9fa8c663f009cc5f82a56f8460048b80f82099d7584",
            "ea6f2154559a780460d7e87d91e48862278e816d881656c65860901da20f0719",
            "4aa55a61bec519799e899a3c69266e11a9581e089a4d0c173509e58606a6f363",
            "3cda2e72f14d2abd54ce792677274655cb4ba92d7628c470025c1da87897ae90",
            "2a36610051c71140dfe4956b213cad8db99c9b3513eed046ee5f039f29923878",
            "6526286ce258459db80ac1ac430587249f3a6ad060d22c7d58c73648df8d6b6e",
            "f281e466600dd6bc0743e3512e969b423b25c445b60842d952c538e9177baf4f",
            "f3505dfc3417aac13efa12c997524b78894408ef5c647a3ef3f304ced56728ab",
            "b6df92041600be7b44c1ad993a60675a6d009742ae2b10876773ba35b0c812ce",
            "2169c720669f1223201e3aa391778a1c482ba5e3b51fdaa3315922653c942de2",
            "9224fd4a1aa5f507d5e2066a82c68b8986733215682127a27acc1f90e16def8f",
            "8939b0dc846527adffa24c54775a4860a3a05ed443bce815bb1e0a7231a9e29a",
            "1264a89a5b891b608934de4bf38e6c53a47464d1e94e29b241e77a6a23589458",
            "c60558ca7a2014e405cbdf4a325dbb070c89573fddbf72f2d22f738110584144",
            "aa6226061ab1a70e266592920bdeff1e785d2a42511e54a2be793d4d0f345ede",
            "a2d4208f920c8ff765c5997f983bc594c964979547d485c55853015648580dc6",
            "796db1a1f5e55272554efb60585b6bd64e42d911ab3bf80e6697e9bd270e6066",
            "0a98360f115567985b2c2a2abfb000940789fcb984830c36bdd4ac1a3444f075",
            "c680aa4327a568e9ddd18085f89931beb90a9da590da9561b70bc46762b1d2d7",
            "9288517214bb465c761328a1048e9a240ab106d8cc057c1fce46b93a5707824c",
            "2c55d9e1aa59610a70e6e05c5a85a4a45a463eabda4548842378b12c14b3049f",
            "6819520c174d1056611068d7fea98cb096fbb4b2e5a0391a640a44455ea774ab",
            "808feaafb632e0789eab001e1e1935868d1440910df6e3dc94832c55296755be",
            "3f126a1a47c82dbaf0d7338a896207c0f9e5d8cefe4c60f75121205eac086926",
            "50423032845eba480ecbbb2258280eeebc242c5da7065b8b58588212f2db3721",
            "24a0d261909c6bfd3f64e4591a17d11a5948ae7a010a8601d84bb81cc40029da",
            "43196cb642059a00a8b6e17e71b9816770a82b9245a0084d5acf6a92aabe1e70",
            "3661f64386ba1d110874987e5c026d33f1a2619884ef9200a7600ee86305424e",
            "eb92593c5328abec0ae61ed32820f518e269e45545dd4b45bb301c4a14631aae",
            "4564af3430b15dc18bc15d44b1b4a26dce448b11ce56a6af4ca624f43896d959",
            "86a87bb6d714a12798f8c708c1d0b02d53a13e414a955de1b019c753088d99e6",
            "fe6a3f9b487cb1ef2773bc66b2a0646f8aa3f00921c0c7133be91504682d640d",
            "74318763d379976cde6a27615460112b31ff5ae19f221ce83c166ea144d39285",
            "cc9f3d99d65763d1d58bfabe8a99ab1785c22e429048c00776111529ab61407d",
            "7df29f98a578d88c23eb27003eb67fe3e75fc5a21c3fd88f95dcbd74aefbd341",
            "5358acb530dd265d6ce99c572f2a9260964a37db6fcc7989f43adcc3d94ed94b",
            "127cc693042a94d9a1a4f050756503725a3f8514e62abd68ab70594448dddc9e",
            "416d07c28daf20464893a05f82616958cd32a019c4251a2a579c62b726a4e2e5",
            "401008bba1c6241a80a03d72f7b17643bf45106fb1e02f779298262652af0b03",
            "9691a54559ab701ea8a123ec849d7d8743af86a23b6a28999dc6038d95b6205e",
            "99a832f9d9a388611c44d4a8c9c995462b3418f0afda4db544a946ac11d1759e",
            "e2743f4ae714ba3ac19b68539708cab3d48a58766ae89a6de5477a7451651784",
            "3d40f6c4d808d268b3912ac34b1b808addd2630588707e05aee5e01e75ab0152",
            "723dcd72659222d8c4d79bba35b175d4d0aa0460c22813a5625c81f217039bb1",
            "211ef1e83a19c2b212a334e205a6a2d954a7812a3e03d13e719b89e94f6a73d7",
            "1b29e01f3a933073006cb1a165b2bd5e8f7586ccf00509599ec19a8b4c834612",
            "8c2bd0740bae12f940050e51d426619220114a1224f80b094f2b3c6711334551",
            "eb42b3d5acc3f61b944c18488a69cddba8c91c52875c0d69e4d9016f6c423891",
            "08b95402049ede34a64d59c88ccd3846d6c93147b633167baea2a4ae8a05ad5b",
            "ce"),
        "cfa02e8b83e98e74ef228bf1750fb359",
        concat!(
            "3a3f39d10d0e17e01ac0c3cf9d12662409f30c601cc4bf1516966f1ed6b7f3c6",
            "9569ac5baaf1af8a674acab1dddd062bca78273b5763dd2eac270d669691509d",
            "f16139f76f13cbb1d153b85abdb354bc3feabc746eb2472c9d28dce91ead04f6",
            "526611d5f3ebf6b4ccfca6c716de6290bd0a16197dfa9144bd38364c99fa59d4",
            "765209494f119957190e425cb5370345608c2b278d449cd8ae8111d251a69306",
            "32014fe0f7d2d954059282779c1b76291930c428c026680330eb5157969ccbbd",
            "8fbcc161f89d2dc4b23d2a8d21eebea2c7a9aec0ffc604dc60d5bc512165b039",
            "15b95dc286c311a7d6c1ba50f10bf4546942b79762bc4b0f01bb9e58373addc2",
            "83cac7491c32b1a2c73cde1e04224d57785a0efed18a2f106ccd5997dfa6c49d",
            "0c954262cce99e47aa352c16209c5d7aeb198be7f1cba4bb873e8fd58c5440fd",
            "23a52f91e12934c2f9b781fc96ac213ed5f73be658a5a72afef5be6765137b66",
            "0525313aa4587e7c872a19f06c56f6a1729f5b20d464aee0ab711518e4e3dad5",
            "4799aa38cc99d4cd2aa18e0cb18b5d1fc6c11dfa302cdd5ebbd080f9b85d94ca",
            "88ff2314c99557eccdebd849f2eac1b17a1621fae1c8f6ff85c263deae3c6f55",
            "bf17dff446259c1dd12c11ce0e6f47d4a852e377742dba4271cdf3fb1e8c23fb",
            "8893c795d262ef9e7f2bddb676e5315fba485df364811dc7e76658da8e05f3eb",
            "4648fa816d912c8544dd8b4785cff97e2f8733697dee4cb0d60c5394c9e0983c",
            "ffb76df6636a711e209ca4b9faa20492fca811d8bb9ca65f188d12d1ae47acb9",
            "e63b7707fd283b043a9ce99832478345a9920cb3109b4f1b6de9f0a5bed5f882",
            "67d8cee9f6fc2713a5a533adc4fb9179ee9e1b3098b733f89757fb109237868d",
            "15b53278f9751e0a3b8d9fc3539c56f1c3e3e640d9c72d5d6126eebfc31b1362",
            "5add3cef1fc137f1de74c6d645c892728fa36ae66d8fad611492fca2b1a7413c",
            "226ed477c965c23c08a25256bccf0e528e4c678dde87c7ad518ce3f14af4a3eb",
            "0751964aa0eac9eedf42d29637d30280beeb3ed244b9d819864e5e62282e6ad8",
            "87902921c14c919d7ccd3b619eeeeb37115d3a6c1a98ccbb497e9b83d2fc52f6",
            "2c6b81aa56a7397d5dc647f6ce57676a27b61091386342e98cba26c51994c9f2",
            "c02d6b76518d47d66fba48c86a787d04053d4b377688c48ad9a28977a74db5e3",
            "88d6b08cfd270fe0589a6c54296b57becb2257171c49710373a50b31ebf4b739",
            "74697092e888e1bb2033c7c8a3e70b61d94d5be130392e74aef32166f90e27b3",
            "33c469b52454824fe179fc999142113c54075e1279c174b03815c308ab630dd2",
            "358140c543d34166734f0b21b16ded530ff380788ab4cf4f599da174b5c2bf9c",
            "6c535bd12b2fd485c6e12524b4072b1bc9565b9b5ca5cbe97a23bb12af73d4e7",
            "183baf6225940c252223b2dbdc51c7fea9a5db07b67dc833d873d3b744685a0f",
            "1f909776a2734210e9eb574f11161e1df49a97519c31164bc4243424b2a1e874",
            "3e953ca5b2a8f7c9acb668299fbbfc0b591688e0d4e96f4509c2b75cd51f41c3",
            "aeb82b12973544506f74248f38f33b13ef224c953400c5a2893337f5365f3476",
            "b0ca2adbd867d70a49b71aeeb31150ddbdfe288c4f7cc3d37faaaeff58a14db7",
            "d05305942b5eca66938e72aa081f0f6d1b83907c7f6b62e5a03152dadf2c51c1",
            "ed66336449271cb6463f357826c61f74a54da4d609774e153c2d52d4656042b1",
            "c42cb64699d935096a390867d7e1319730d9ce7c1e0000000000000000000000"),

        concat!(
            "0a564dc27a0b6cd1265cf75b32d6cfa164ceb183c515315e030acc4c2539a680",
            "f57a856f03f014f2068eb97a4a7751fb92820aecd84188ac1d333a05abda4d48",
            "2329e2ba1710461fa917f8e11f4f07b6e4845ba2f87cdc4149ec6ede2d487ca8",
            "a6d01ea94105b13cca3497026c557aa2a94fedb86a9251548f0de984d2e692b5",
            "7032f5dedc5438e03d5342c6546d5c0fe284c940884d70c06bcfbd30450e349b",
            "1fbc3e0d0cca8000c9b78638925acea95529f8b582661d0ef9fe68ad8f2c28dc",
            "f3554f87fa72fc87327a62c8190d98e9602e552d1a3da5f92effa9aef5f2c011",
            "79a2b12198a3a48fa6e92aa7d304a0176dac3445110f7158e796ad4546b7e188",
            "0883dd5390f4bf4486cd83a7dc654715ce3110b934d2bf86f112bee146fa458c",
            "47b81a3497ae3fb0e401100a4a824344a0e4a29fb0bd71a358d8e807b5fc6f00",
            "960e88898a65904053ae389e90477c85c080bc1087279ecab64cb4018c6d425a",
            "12f8c4fce98833aa58aaa36d978f8054228b4374374a9785aa84ee659ca2a2c8",
            "6e1b83a459267b015a547acd9b7b2a968c38bc31501617720c310be0ce5b1dbc",
            "cd537ad5067b3d9c74870164bf6612a89f2a5082addf11852be23f7a8621d50a",
            "f7a511f065406f174bb0e816bdca3e52d6587afd446a18b19264c64b9c020984",
            "87b41e2b3fd0ba867383fa59e6415bf8d81112165621c308ac2a653ec8f4db33",
            "3f46ef853653294b3ec54789827eb33a03b32b4bae06a88e4be9c699a4fdc2f5",
            "32e6df7e3a9665f0a1b82c92366b9c514db702c52b40598a9d4d16ba0e610f96",
            "ae112a26475e757c8d222044a75cc58d674257286c42f027764ad7191dee1750",
            "9617ab7d7ad6cedb0c4fb8b5e1c98b5e94805750caa6487541a9937290fd25d6",
            "686417d0938d3c085521a43272ac48218da264a00a5bc498efa0151e6b0ba72d",
            "b12866fb27f5cd1cbc71f9d1488ed364342dd032ac4f928ed25962ae75a2f439",
            "801f8a8b3aca079a2142126a8e31b9f787de730d4686d609c674a2918768c5ff",
            "bbc9c463fdec72758874d10a9b2e792e587641e7a39a9c39e4ba67eeb31580b5",
            "56a4d333365c11009d21b305db348f21353bcd70a629e6864ec285402e44c285",
            "55606b671cac5f22ccc335414e53f4a246ed2ab7356a66f9db58c114718027d1",
            "2a7d5ac1c6711fd6dd1658b7bafd4d739b692ea843246e87563c999c68e4a7e8",
            "b7a95e03802bda20088f0c18b8ed89a863adac4ce42475818ee8afc120962904",
            "1f6c59b02376131921c158a7c995b8569579c43e07f0846d13c587e216869c29",
            "0b2aea7d3a1d14468405592b7cdf20c84074938669245460cc6edabc0508934e",
            "597a5c97f4dc643b645b2b6e0953362eef79908aca3d3122e18340ccadc93863",
            "e0d84f15c6b24933e08e00149112a0dda2be24668355997ca086035980a1aabf",
            "5ae808d9ef25025e8068a74fe9353ef585199c728d4aa6bb95e3fa0bfc69f97a",
            "232c0ce9d1a30122f9bcb438248f5d5c446d68b83f438d583c971638ee2d6d4a",
            "cfb1a2422db0893da9b5987f04954bab2c46a05cd4a0919dea170cea9c8af8a0",
            "466ec6822420c7970005a1cb02aec6449120e016e04e709aa9b1f4673128c459",
            "d04b53c6755ecfe08a5151704e65b9f4895a99e929a7fbd2b267116408fd4c17",
            "abdc87db5c03e97e65e77bd6e12c56668522ae036d6d41715bd1855e176d90d3",
            "e1c2e8a07895abe6e729a5cd1aa11e0e49aaf0b830831df10164c47b6006836f",
            "863b2a75967b86048b444354cdb1a25e88c5278db931cca71e2df88ef51d010d",
            "a5682899fcbaaf1d6c2a6a5600a0467c1d4412d3a51c09a71aebb5ef0fd51d72",
            "030152eb0c5aa18b62a7e0439c9985116ba4502f768954831c2b1e04a6661450",
            "70a914e0a9dd0f5d80e532a744114f8c1c81a0cee2160fd1c0d25284eb1926e6",
            "098bc65d87e4beea44455913544c156dcc399aad9b3875163d354210f3472cd7",
            "535980007c0bcb69acacd93b61d98954bbf78520e3979da692abcdd79061a7b4",
            "d5eab995bd84d3cf9db645a83688830cf5aff84772766b0552512fb22f2e8a3e",
            "2d1428c2aab94a65e9637111a5bd70fe1945e8e9a3287405e7836dace8ec994f",
            "1a8872ad82f036217453f91142ea28681caa851a2e62d07e946729c2c0088fd5",
            "9b52d6d43d0395c2f17e558daabd66422c41407d9ecbd5bd41419375e767888e",
            "ad6a04caea16a0b069427b21fbab4cbcd114c897a62f1f0e5201d19d0e28ed51",
            "638fee4b4c0a4d10a292ee615555610fcb9ca554abe6afef5e7716c2bbd35407",
            "6d593260774747034215e35218197b0506261aeab0a19d02b216e81facc62f76",
            "802da0622e68b71664532ac0e124e38e9125307211954eba68084cc5e2a8a168",
            "cc5664631c6e64053b3a2bafdc9cd6227219e1654538eaf27eac2506f5b322bb",
            "26a47692f163abd8c191d999c3af12989dac6d70861f957b8ea8973643db4a80",
            "8f1af6a70e5a76746b09193771513244eaa5174879c8f10e19430028c8363dc9",
            "84"),
        "f8c391dbdf424c65b433d5d57a61d162",
        concat!(
            "3a196b2695aea2d588709f621252cc22531bac24a01ed3ffc4da53d96fc38568",
            "c209d8e12c8131ea7f162006e4c1df757ee571e094e761ba27912a742a0d3647",
            "3ada40ed1dee16aa4124675c3819e5ceb00cbc7908d040dda7fe13e5c10a6384",
            "c24e9634f8ef9c6dd65e06251c64e238affd2ed31ff44bd868e3a9e1f6808c19",
            "cf73a132f95b082089ac918de0afbbeeaf7a7a9f9528ea7d48b46008172b40cd",
            "904c4aadd9bf78b190959b664eb9b1636d0f617a3a74f99c9ba8864a1d99e789",
            "247916cd1a6654c1d43ab308bbea9ccfb170d52666211cd2064863eb77bcc290",
            "ec6c069339c8289b1f491444eebb2c27d1886b3cd75d3c4b025310e500c7a2b5",
            "b89b4ccdcbae1e787e809390421291d760a6d37a671428be50b3fb797bb5db49",
            "9f993737dcf601a85b9f0786c633da2a4a9f5cb0f49820fa715438f37287b66d",
            "8c56b50c2448d93245c8b1646b098b7eda914456144c252e54481a3707e4eb7a",
            "26e953158929149cf12b32262b743659eb09cb9ed755625042499797154ebfdc",
            "6cdae62260a79889961c8431ff584fcbf2a5210cb7863b7827c635c1736e7524",
            "0307aab029b8c8b3c9b42ba90548eebac42e4aace37882e5927fb36cfdb31d71",
            "4684a1d83634a9a9d2d94c313207d7ed765f69f41cd477b784d05a157a7f8b14",
            "5c362d5dc5686c3d2a94a65adde0146d236eb6214c451b3250aa4bec4715e398",
            "2db07713772ad97ff04eee9f47ede0f56c3829aaf92a39f12f274dd5e9a16830",
            "c71204132684b0a76a3f50a2b48f9fc1f38f19bcab27d34c1778148ace27cf1c",
            "7b25a088f3eb7e4c7eee25596c3ebb964d89410cf604ecf4cc9612bb58e350b7",
            "f6bce5e55a1ad62ff9af9c114044d852f9316d31702558e4204959f56695cec3",
            "007dd225875899545fa279de26eeeb3a87d1d77e7b86d846a59cbbef5fbdcc5b",
            "517845d98ddb68f12d7bbd26c57bb89c2d2cd233d8d2aa692996657bc252eac3",
            "634f0393c575d1966496575558cd89ab355e3cd630c366a2791b06fecf3a9fda",
            "ce52f3e687cd1078378755bbba68e9027783b131903d86892ca13366a6b59283",
            "a359e674b6a2e75f106a72186ce75ad5c389ac6ac59f9516cdd69692c17743d4",
            "f7cf639435fca7ef9c97d69c5d1fdd10540a0dd92d75218f1529f9863aa87e75",
            "842acbf5939c8ea66d892f96a0de5dc7bbcbda5c6956fdb46b7cff9eb510b221",
            "b209e91f202e734c5c60e4c2268a21b11668bbe2794edfee7114976d3294087b",
            "108f9feea6176ebf93928d35fd6a31afe8aaccd36f525d536be7bbaaa2707e61",
            "4bf75db993a073229336c5f3b689c6d676b66ad495fd5591302c2466cb46a999",
            "3ae50f056dcbaad8571d1f37b56d42451d54f3964dbde7d9086212e458874d50",
            "851fbf874f17783ec68ed123ca30c96650222a8b0d45230f9394f9201f46c339",
            "07cdd413f95f2121445e6adba1db96d03dafea68f8e438b0cd02ddb39d72d9b8",
            "727b09d7c3f2ccc44f16f978a2778cda46fe72fbf2aaaa43912aac112d859075",
            "64e6bd570ed64c84e6e454a7bec3235cd699d2c375e6eaf9d73dd4306a1bc440",
            "c1a29841263477b31cd967de8c22448835a44a2895d0ea98d46f1ef5fa88d1aa",
            "502c51bceec20336d00d53b1e4da2dd44b9c7a51268bb58aea99a14b60c71371",
            "9b291c7d0d3aa5be337f5e24fa011b65e9a8ff904ad95fbad5a891a06c947dd9",
            "e84e5b984279a76c1ad4866f15e9ec50931ad9b7e56362fff18dd33036b5a743",
            "d289fbd02fa22cfc56d19cf6b260a7ff970f63a9a049f9300000000000000000"),

        concat!(
            "0aa9c546c92890a65819717bff23201b5a9669556ffb40966d10a95fd957e2f1",
            "5796112db45aceca20cb740ecd68b2725b8b48ac84129463ee0f5da5c6415bea",
            "1854d5561b83cb8a72d0e1411a304c30d6b7cc9a5489a26f9a0943f193cee1d1",
            "0cd1949b49d13315049841aadb54f8db74961938c7b257c90c26ebea91062653",
            "567b895660348e950f504a243452580ca8990cdaa0e159a4aa6ea976e8171243",
            "a7d754a994fbd0852d9424b543d80d7ab6654dcb7bcedebd492ee75d2c5c801c",
            "6c1b3a8c7c986e0002b4dd7824a01be351547c8294b4f93e28d60f31b9b7afa3",
            "462b7c6c04b341248b10b62a2160eb464e1bd438108294a99cd94e29411168ad",
            "5ac28b2292d13b39bf0c3ba65dee48d6419e93ac9669ee0c44a11a2df035e68c",
            "2ead75872e02430525a1aa5581ec535a61368bdf6620323361bc2bdfbcf9228b",
            "fae36085954a0aaf605d5775b7c93e4f63b861a03bb294c531b033378a62b898",
            "46c81266d1b06cc9c2c43021abaee81069c454720068505bca9b433e2462c558",
            "db2d20116f9186d584a8e463f02a67184c4d5df3d9573e28226e763f0db39938",
            "ed06f050148d4239538e8b927a19aa42e568305914e9b2f4254d1676af60ba0f",
            "ff51dc37d19cca652214ebdb5fd8d03f611a2942d45973362d058b4d7f0611f6",
            "a7c8267f02048980b083901d70cd30b4dbe291822cc0344e1078410bf5dcdfb5",
            "14944a579f8d5597943df914c7960df0ce642108e7a258bc95159c1b8154a063",
            "04105712713b319e5dba62b1549ae356b3afb1a715c3d9ff305cec6b9bed2963",
            "0c5fab6f9477531806083a5b6e4309fa20d944e9aaa20bb380eab0629629f0a0",
            "a66a85bee28ba66e4a62640498e2d1c22b320a21bd1e6f46ca66090642568ffa",
            "2cc8d15f787f35f2946703b28c3a953a7d08347bfa6d36a3d3c852b148c2d3ae",
            "795d24dd93e20f972e6286290aaacc577937231ddb9f21693c44528fefa332e5",
            "c11b059263ed0e2090e69fb8710906feeda10631b5c9b98d1d37868dd0a7d2e8",
            "357572bbe168642ad21e7122d8f132e5a41b9be625be3d50cbe588c091b21ce3",
            "8adc77bbaa0576e692582b00ed8b36ec31256831b65a1ed44b854a3b4222b82a",
            "747ff9de577b757d72aa786e986c86af7046d45b4e85360a60d7d08c627b7b2f",
            "540c1b468ef3444416527c70787eddb57bf0f6795e9f137d56b5f50de3615e0e",
            "ce38df6e4d77015ff7f32068a662d5903b9e59a0de38502e1b60838c3f352b15",
            "2073963b399be22d65ec8af2386bf36e226898c56be4783cf0e3a6e1aba3ac89",
            "b59c4d321e6cd2f40e14248bdedf0842c55c49b1f39b714b902b54f31a975513",
            "a644875216550e71dd9094e44e813252d770869f34b5d023ca8dafa060511e35",
            "f09e6e0a685fb484e3f591c62f6175cdf5739e79b8911016224174e23d667a95",
            "894eb9c840c30a72c043bc43e12d25baa29edcff7e3062e7cc16610668d92437",
            "c6af74c5bf3728566d38f9fb5aa187e40d7a2fca6c200d3a9c83432c4273a47c",
            "96cb720686a8610ae3c7c6db719ee7205a1b9258f6a24433afed5d9dbb636661",
            "fe07423452a3117a9a5a5e67841d6eb1a03b6aba4aeb67e5c28a79c0937cc061",
            "536152815df031229b1a18470a7906bea317aeed6ea1140ac7660a6b538d6454",
            "4490f674e5129c48fcbc52452b4196316e284da317570c6f41f0628b7ff5c21b",
            "7e1837840810154f44da3925fec1ac1efd5bf92ea79324267b3df1ba2cc55a00",
            "9081979a633d7e1cc6a321a6270178d9c4fbddca861c4d18f0c456a041e982e0",
            "c4aa72282818ada04b35eadcebc11f371d281c598c4d2aa4054687729a5db070",
            "d178dd91d36df88cf80ad677106c8e98ba19d5674624e27f2d88099d19131b5a",
            "aaabf4a96118cfe27ee8c119ff1e5d6228f5033ba6e4a6f6ea22416188bc948a",
            "86a169ed67bc4cf9888bd48628d6b7b692113ec598f9b785260735aff42b4d75",
            "a84ddc974189756bb84ba15a2e0730562ca0e983c84081ee21af4c5684390b64",
            "122e892ba0ec2659ec29259ae70a5c18778549bb62480811bd38f3c5be6f48ab",
            "a11833944914169c8db4e2dfdb818903b5ff9c17293194305b411620f45875c5",
            "2cdc828c63b440019797a1a560f2065ca822a0402e5fd7108cbb6527246b962a",
            "05ea73241960364b9354efe82d39b685bf8cadb3d0c2c343afc303fe09b737cf",
            "28a266638b2a5e918cdd2ac379623a933152d6d52e198a3008fb0d9ea3725c21",
            "6a9a98cd51fa09a1569ad73369972a904d1e1290ee98bb0a236eccd4fbd1691b",
            "84f07cf6cf80ca1b78e2133e079e42012d6ac404ca81b224c70d6c2916600738",
            "3caf027f8a3e9721e64461c5616b6b1a6c14a03a66301a152eedf1b6e5ce0455",
            "849c593d667e480ddf551b08938e5e4be18864604d2673b0ca110b0e4e51f1e2",
            "adb653edd893dd44d96e46bee5519aaeb044e18a409e7f4faefb4af36a923a41",
            "b43b3d20c9868980716b5ec78c1e30b7bb4a7d0f9de7cb1c8ef35d204832a9ca",
            "de"),
        "358512bd1797531ea6c247a31ce8387e",
        concat!(
            "3ae330462a7a92248de80736ff6fc7a0f82e536d1938ea2320e59ee0dba338b4",
            "c0aba3c0b942214014dfd13fd1641206e872d8fbe67fa8d86de77a37aa791e81",
            "55a78d04612ff6d91ff75e8ba7236bc7b1157152083535cf8f18e65966c4b9c5",
            "62012ddb481d94a7611af9441873a152b9bec981ec186793508f4822a4719eb0",
            "66199c2a2db18c72e53c129f64bfdcdb661da08c56954a8eaa2b1b78be6f33f5",
            "1ad661c897d50ed82091e321f2c2e3df78996aee7ef7658f56e6c18f7cd90153",
            "bd4edef2a67bc416c2f911a5c516cf24acfc0cccbaea073dfb94c52bd0d869a4",
            "288f9ea26f0a2e796f21bcd82cea4524fcb90e16ca5ef5ca7264808c64488ce3",
            "889124703745564870c324dd6ad21c01d5703b117f8c239483e7633304265bf2",
            "a5633bb112ec95718d9a22f2c7565a2c504ed94390f6d7d4a621f0aa44d105f8",
            "97a60b2f3afb233a102d9b8865216facc10eb9333bd73147d0416977ad97ae9a",
            "c5f077a601be9cec92ecb1057a1384554d8cfa334471d26e99e94ac11b53b0dc",
            "3f26b5126ff5f7684255aacd64b635fa23d90a450cfb2920eb4ee32a81858b8c",
            "d76fa33563d23652aef1de21bde42b39d58c53fea26703159a14b64e96b114c4",
            "9985af382c896886186093495c3bbef52b8099ffb62468be1ccda1a94badf7dd",
            "3df758833bdc123fafb6b05f9c2929529c4251b8ae9a282468b5a313ae8366af",
            "2ffa675f13cdca965d09c4b359bf39d3946de4d415aaaba92e2643871558b478",
            "d18c9abaa6b795106f929364edd0d15232bc6dbec8ffd33f6cf3d556498380f0",
            "785fb8b9e293a31467f554b255554bdf15f1597e5318af4ca62428e6351cd1eb",
            "1f3a4310ab511c92a1abc365d117a234682eb297e8c93024d9de26ed42e6abde",
            "3396d684954539880ed11d964220c304a864126c72f9eee129dfa3b5ca66b236",
            "6f7f4963797908d385a173d36693eb2230fe53f54cc2ea1eb95fcfe6e194d9f8",
            "927dba13470aa6b8456ef185e8a313a839dc585043f19fd0dad22882b13c28e8",
            "679452886ca23d2056a1a6cf5dc9f97d18b9941b9504ff75be9a57b19ec59091",
            "39dfc15d3d846a0255d27a2d97bae32bbfca43c09663cb5f3f3728a3ac851089",
            "7e883a34610fd55b61e6b6fde1ba6883e30252cff596ff26b1507895eb8ca28d",
            "9f27966d5a3087ecf28aa508c8634bb5f3712b1fce7e43276aeb2c4faaa1e593",
            "12cd514acbf2782a14b510d6c76e3f668959a37572254b162389859e97f8f9cc",
            "344d50f075cec66b15c83cf00a61edd72e73fd6f5d48601001e2dbc2fe9a5d01",
            "9c68d3cede698c88400e9aa7c5719ab54b468cca3c2adb72ead5e28847a35055",
            "f378ed223db9f977b7eb3d0915fb18127ff26958532c93375ac4014072d251bf",
            "44fa79dac29be0ed7f6dec33a09f235dbbc60e2881c3c872759052f7931324a6",
            "4450e64aacf6eb55965e6bffbe46f5ee8ceafce531d4686a0139dbdbf38b7a6b",
            "cba6370bdeef4a84a08a71b15da418fc4e75aefdb5baaa2745c3817479aaf797",
            "1aef657c3b9441d632c9ee6e5b359318b6818dfcdf2d2f06db08525a6276e9ee",
            "52fccf5ef1434bb1fff8676d96d0ea07bda29f27ba1aff33f7dde443e5c6c3b2",
            "99415544f7b7fec7a6b066ea584037533a339960318e5e65cf43596392bc6f22",
            "8c74bb79b3a49628c4f0a2d4f39d1873d695bca24870d2521e8f2564898fe26d",
            "9047232080e0b82bf7d2303dd66c190c532c9bf4bfeb5e9dcab9c7ac8ba52bc1",
            "0219fcec3a844ac88eae83ac80ba90f75e0093204a8b2d000000000000000000"),
    ];
}
