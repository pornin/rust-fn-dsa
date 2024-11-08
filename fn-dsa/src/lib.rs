#![no_std]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//! # FN-DSA implementation
//!
//! This crate is really a wrapper for the [fn-dsa-kgen], [fn-dsa-sign]
//! and [fn-dsa-vrfy] crates that implement the various elements of the
//! FN-DSA signature algorithm. All the relevant types, functions and
//! constants are re-exported here. Users of this implementation only
//! need to import this crate; the division into sub-crates is meant to
//! help with specialized situations where code footprint reduction is
//! important (typically, embedded systems that only need to verify
//! signatures, but not generate keys or signatures).
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
//! ## Implementation notes
//!
//! The whole code is written in pure Rust and is compatible with `no_std`.
//! It has no external dependencies except [rand_core] and [zeroize] (unit
//! tests use a few extra crates).
//!
//! On x86 (both 32-bit and 64-bit), AVX2 opcodes are automatically used
//! for faster operations if their support is detected at runtime. No
//! special compilation flag nor extra runtime check is needed for that;
//! the compiled code remains compatible with plain non-AVX2-aware CPUs.
//!
//! On 64-bit x86 (`x86_64`) and ARMv8 (`aarch64`, `arm64ec`), native
//! (hardware) floating-point support is used, since in both these cases
//! the architecture ABI mandates a strict IEEE-754 unit and can more or
//! less be assumed to operate in constant-time for non-exceptional
//! inputs. This makes signature generation much faster on these
//! platforms (on `x86_64`, this furthermore combines with AVX2
//! optimizations if available in the current CPU). On other platforms, a
//! portable emulation of floating-point operations is used (this
//! emulation makes a best effort at operating in constant-time, though
//! some recent compiler optimizations might introduce variable-time
//! operations). Key pair generation and signature verification do not
//! use floating-point operations at all.
//!
//! The key pair generation implementation is a translation of the
//! [ntrugen] code, which is faster than the originally submitted Falcon
//! code. The signature generation engine follows the steps of the
//! `sign_dyn` operations from the original [falcon] code (indeed, an
//! internal unit tests checks that the sampler returns the same values
//! for the same inputs). Achieved performance on `x86_64` is very close
//! to that offered by the C code (signature verification performance is
//! even better).
//!
//! ## Example usage
//!
//! ```ignore
//! use rand_core::OsRng;
//! use fn_dsa::{
//!     sign_key_size, vrfy_key_size, signature_size, FN_DSA_LOGN_512,
//!     KeyPairGenerator, KeyPairGeneratorStandard,
//!     SigningKey, SigningKeyStandard,
//!     VerifyingKey, VerifyingKeyStandard,
//!     DOMAIN_NONE, HASH_ID_RAW,
//! };
//! 
//! // Generate key pair.
//! let mut kg = KeyPairGeneratorStandard::default();
//! let mut sign_key = [0u8; sign_key_size(FN_DSA_LOGN_512)];
//! let mut vrfy_key = [0u8; vrfy_key_size(FN_DSA_LOGN_512)];
//! kg.keygen(FN_DSA_LOGN_512, &mut OsRng, &mut sign_key, &mut vrfy_key);
//! 
//! // Sign a message with the signing key.
//! let mut sk = SigningKeyStandard::decode(encoded_signing_key)?;
//! let mut sig = vec![0u8; signature_size(sk.get_logn())];
//! sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, b"message", &mut sig);
//! 
//! // Verify a signature with the verifying key.
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
//!
//! [fn-dsa-kgen]: https://crates.io/crates/fn_dsa_kgen
//! [fn-dsa-sign]: https://crates.io/crates/fn_dsa_sign
//! [fn-dsa-vrfy]: https://crates.io/crates/fn_dsa_vrfy
//! [falcon]: https://falcon-sign.info/
//! [ntrugen]: https://eprint.iacr.org/2023/290
//! [rand_core]: https://crates.io/crates/rand_core
//! [zeroize]: https://crates.io/crates/zeroize

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
pub use fn_dsa_comm::shake::{SHAKE, SHAKE128, SHAKE256};
pub use fn_dsa_kgen::{KeyPairGenerator, KeyPairGeneratorStandard, KeyPairGeneratorWeak, KeyPairGenerator512, KeyPairGenerator1024};
pub use fn_dsa_sign::{SigningKey, SigningKeyStandard, SigningKeyWeak, SigningKey512, SigningKey1024};
pub use fn_dsa_vrfy::{VerifyingKey, VerifyingKeyStandard, VerifyingKeyWeak, VerifyingKey512, VerifyingKey1024};

#[cfg(test)]
mod tests {
    use super::*;

    // Fake RNG for tests only; it is actually a wrapper around SHAKE256,
    // initialized with a seed.
    struct FakeRNG(SHAKE256);

    impl FakeRNG {
        fn new(seed: &[u8]) -> Self {
            let mut sh = SHAKE256::new();
            sh.inject(seed);
            sh.flip();
            Self(sh)
        }
    }

    impl CryptoRng for FakeRNG {}
    impl RngCore for FakeRNG {
        fn next_u32(&mut self) -> u32 {
            let mut buf = [0u8; 4];
            self.0.extract(&mut buf);
            u32::from_le_bytes(buf)
        }
        fn next_u64(&mut self) -> u64 {
            let mut buf = [0u8; 8];
            self.0.extract(&mut buf);
            u64::from_le_bytes(buf)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.extract(dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8])
            -> Result<(), RngError>
        {
            self.0.extract(dest);
            Ok(())
        }
    }

    fn self_test_inner<KG: KeyPairGenerator,
        SK: SigningKey, VK: VerifyingKey>(logn: u32)
    {
        let mut kg = KG::default();
        let mut sk_buf = [0u8; sign_key_size(10)];
        let mut vk_buf = [0u8; vrfy_key_size(10)];
        let mut vk2_buf = [0u8; vrfy_key_size(10)];
        let mut sig_buf = [0u8; signature_size(10)];
        let sk_e = &mut sk_buf[..sign_key_size(logn)];
        let vk_e = &mut vk_buf[..vrfy_key_size(logn)];
        let vk2_e = &mut vk2_buf[..vrfy_key_size(logn)];
        let sig = &mut sig_buf[..signature_size(logn)];
        for t in 0..2 {
            // We use a reproducible source of random bytes.
            let mut rng = FakeRNG::new(&[logn as u8, t]);

            // Generate key pair.
            kg.keygen(logn, &mut rng, sk_e, vk_e);

            // Decode private key and check that it matches the public key.
            let mut sk = SK::decode(sk_e).unwrap();
            assert!(sk.get_logn() == logn);
            sk.to_verifying_key(vk2_e);
            assert!(vk_e == vk2_e);

            // Sign a test message.
            sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, &b"test1"[..], sig);

            // Verify the signature. Check that modifying the context,
            // message or signature results in a verification failure.
            let vk = VK::decode(&vk_e).unwrap();
            assert!(vk.verify(sig,
                &DOMAIN_NONE, &HASH_ID_RAW, &b"test1"[..]));
            assert!(!vk.verify(sig,
                &DOMAIN_NONE, &HASH_ID_RAW, &b"test2"[..]));
            assert!(!vk.verify(sig,
                &DomainContext(b"other"), &HASH_ID_RAW, &b"test1"[..]));
            sig[sig.len() >> 1] ^= 0x40;
            assert!(!vk.verify(sig,
                &DOMAIN_NONE, &HASH_ID_RAW, &b"test1"[..]));
        }
    }

    #[test]
    fn self_test() {
        for logn in 9..10 {
            self_test_inner::<KeyPairGeneratorStandard,
                SigningKeyStandard, VerifyingKeyStandard>(logn);
        }
        for logn in 2..8 {
            self_test_inner::<KeyPairGeneratorWeak,
                SigningKeyWeak, VerifyingKeyWeak>(logn);
        }
    }
}
