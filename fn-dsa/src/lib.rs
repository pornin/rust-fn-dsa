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

pub use fn_dsa_comm::shake::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE, SHAKE128, SHAKE256};
pub use fn_dsa_comm::{
    sign_key_size, signature_size, vrfy_key_size, CryptoRng, DomainContext, HashIdentifier,
    RngCore, RngError, DOMAIN_NONE, FN_DSA_LOGN_1024, FN_DSA_LOGN_512, HASH_ID_ORIGINAL_FALCON,
    HASH_ID_RAW, HASH_ID_SHA256, HASH_ID_SHA384, HASH_ID_SHA3_256, HASH_ID_SHA3_384,
    HASH_ID_SHA3_512, HASH_ID_SHA512, HASH_ID_SHA512_256, HASH_ID_SHAKE128, HASH_ID_SHAKE256,
};
pub use fn_dsa_kgen::{
    KeyPairGenerator, KeyPairGenerator1024, KeyPairGenerator512, KeyPairGeneratorStandard,
    KeyPairGeneratorWeak,
};
pub use fn_dsa_sign::{
    SigningKey, SigningKey1024, SigningKey512, SigningKeyStandard, SigningKeyWeak,
};
pub use fn_dsa_vrfy::{
    VerifyingKey, VerifyingKey1024, VerifyingKey512, VerifyingKeyStandard, VerifyingKeyWeak,
};

#[cfg(test)]
mod tests {
    use super::*;

    // We use two fake RNGs for tests; they have been designed to allow
    // reproducing vectors in the C implementation:
    //
    //  - FakeRng1: this is simply SHAKE256 over the provided seed
    //
    //  - FakeRng2: for the given seed, 96-byte blocks are obtained, each
    //    as SHAKE256(seed || ctr), with ctr being a counter that starts at
    //    0, and is encoded over 4 bytes (little-endian). The RNG output
    //    consists of the concatenation of these 96-byte blocks.

    struct FakeRng1(SHAKE256);
    impl FakeRng1 {
        fn new(seed: &[u8]) -> Self {
            let mut sh = SHAKE256::new();
            sh.inject(seed);
            sh.flip();
            Self(sh)
        }
    }
    impl CryptoRng for FakeRng1 {}
    impl RngCore for FakeRng1 {
        fn next_u32(&mut self) -> u32 {
            unimplemented!();
        }
        fn next_u64(&mut self) -> u64 {
            unimplemented!();
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.extract(dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    struct FakeRng2 {
        sh: SHAKE256,
        buf: [u8; 96],
        ptr: usize,
        ctr: u32,
    }
    impl FakeRng2 {
        fn new(seed: &[u8]) -> Self {
            let mut sh = SHAKE256::new();
            sh.inject(seed);
            Self {
                sh,
                buf: [0u8; 96],
                ptr: 96,
                ctr: 0,
            }
        }
    }
    impl CryptoRng for FakeRng2 {}
    impl RngCore for FakeRng2 {
        fn next_u32(&mut self) -> u32 {
            unimplemented!();
        }
        fn next_u64(&mut self) -> u64 {
            unimplemented!();
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut j = 0;
            let mut ptr = self.ptr;
            while j < dest.len() {
                if ptr == self.buf.len() {
                    let mut sh = self.sh.clone();
                    sh.inject(&self.ctr.to_le_bytes());
                    sh.flip();
                    sh.extract(&mut self.buf);
                    self.ctr += 1;
                    ptr = 0;
                }
                let clen = core::cmp::min(dest.len() - j, self.buf.len() - ptr);
                dest[j..j + clen].copy_from_slice(&self.buf[ptr..ptr + clen]);
                ptr += clen;
                j += clen;
            }
            self.ptr = ptr;
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn self_test_inner<KG: KeyPairGenerator, SK: SigningKey, VK: VerifyingKey>(logn: u32) {
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
            let mut rng = FakeRng1::new(&[logn as u8, t]);

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
            assert!(vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, &b"test1"[..]));
            assert!(!vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, &b"test2"[..]));
            assert!(!vk.verify(sig, &DomainContext(b"other"), &HASH_ID_RAW, &b"test1"[..]));
            sig[sig.len() >> 1] ^= 0x40;
            assert!(!vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, &b"test1"[..]));
        }
    }

    #[test]
    fn self_test() {
        for logn in 9..10 {
            self_test_inner::<KeyPairGeneratorStandard, SigningKeyStandard, VerifyingKeyStandard>(
                logn,
            );
        }
        for logn in 2..8 {
            self_test_inner::<KeyPairGeneratorWeak, SigningKeyWeak, VerifyingKeyWeak>(logn);
        }
    }

    // Test vectors:
    // KAT[j] contains 10 vectors for logn = j + 2.
    // For test vector KAT[j][n]:
    //    Let seed1 = 0x00 || logn || n
    //    Let seed2 = 0x01 || logn || n
    //    (logn over one byte, n over 4 bytes, little-endian)
    //    seed1 is used with FakeRng1 in keygen.
    //    seed2 is used with FakeRng2 for signing.
    //    A key pair (sk, vk) is generated. A message is signed:
    //        domain context: "domain" (6 bytes)
    //        message: "message" (7 bytes)
    //        if n is odd, message is pre-hashed with SHA3-256; raw otherwise
    //    KAT[j][n] is SHA3-256(sk || vk || sig)
    const KAT: [[&str; 10]; 9] = [
        [
            "feeb4bde204cb40cbe06c7e5834abdfcec199219197e603883dbe47028bbfbf2",
            "4f7d1867e9e02ee571a45b6d6d24b8f02b68b2e59441d1e341d06bbf36bf668e",
            "8bd38088f833b66d1a5a4319e48c0efd2b1578fd7fc3bb7d20e167f4cd52e8de",
            "24e37763e19942bb1acc6b5e5a4867170d07741fe055e8e3c2411f1b754bbd1b",
            "9679a55739e76b66a475fe94053606bf07b930d47cc05377444f19f2c85ef2e6",
            "3435ac75ffeb8c72df5e5d2c8619ef2a991de0fe9864014306a9af16630b41f3",
            "8913b2791a76a746242160a800737459dc6457d1420317d7b21043ae286c5798",
            "56413a0307b574b7bff2b6f9f9b59e346f6ab16c2c75fe1c64949a025dc40534",
            "570e6fe189c45ab50e039eaa0ac3c5f2f50efbffa08e006368d3364e4d49f7fd",
            "60b307e72b295b3fb13bd7c2f5926b521c34fbbd4d9ee3cdfe89eed9ffb2d2af",
        ],
        [
            "956766887db48fd1f9cac47a93a12c9e55de6e47006457eceee523d3566f3dec",
            "9f41d30fad1bee288928b1f78a376a46dc06a0edc869bdb6cce0acc36583e92f",
            "8389ba7095343bd222c9818da07ac7e66b73dfdeafb6cdc10377242874c27ece",
            "7fd7ba114d952c9afe2c1dd4ee30e644b2e6caed13aed4e7e969260962a25c58",
            "5a65e67783352ade4a5cfc7d0a48849fecbdbefffdcd8d25d425c3f013f9f019",
            "f3044d077d30621ac7735fb3f95c35a58e15a3aa1c391467b6c33e05d8240c28",
            "cf012db9b469ada96be790b8050b68d531fbdd2f4940d0ac07b8ffc02310f8e3",
            "1e1c251797a4b27f4849ab34dfb9b21b3a84a52c4b0c11b93cf07305da26134f",
            "6e051f873582f6d94c93b335f059588acb00722a40e09b310a0c00894fdf05af",
            "d025acba6daf2b1de7d82d423b6eecb946e98cd7f7125f150e302ac8fccc3af2",
        ],
        [
            "7e2561ddd8664383b2e03bcb4da2409d4c43676ed021dee59766e72890a4509b",
            "7f284169006a71440cc27cace9cfeab56440d357ee42b47609e1b76513281b21",
            "46c05f015b609826c310a098a2105a0e94ad271313031b307a5ff6af09b14de2",
            "ed689cbfd26b8d3f4785d2622df343ef6ef11bf7d883d41f570416a632213fe1",
            "3b8c717aa4b2c5ea95b8df2af003e97d982e20230058ccaaa3d465a3239b05ca",
            "71e64b14011712731f7e02dee789d8c76cbc0d5f16c983b044067b30d47971d1",
            "3bc7443e28014cd78cb31eb7e5283aa9e23827d21b1317a8fe4fbb031cedcac5",
            "4ffe1c59cfe27ecbf233710bdc535a4a332c68e741a0a9a1b684d773cfc031f3",
            "49adb0cb6ed7af916adb4f213016d862a88ab284f9a61fc11e12a1828540b1b4",
            "27d2d2558117e4861207851dcc5f51322fb5e21cad7ace06390f5132f4c0ec17",
        ],
        [
            "97517f9cfe9641fbb06b08afa09be14096b13573960f6790ba1119eb01a8f723",
            "66c8669fe31f434582a465705dafea2a09c4acaf5c2c9d5975b4ec72d556c80b",
            "7207b9f036d9b7a40f5d3647f03fb4ebc373719f240791cd65f9f35fc471ef35",
            "bb9f9ebe61c5db1d72ebfaf2d699cc4c70e4c899f896b4f331fae004cd7a9b59",
            "90484e94c5bb5c6c2f5c48bfeec4ce15b4935d09bc55b1fdaa6ad71e3e03e194",
            "ea8822e989b8bf3484eaac010d77275d7d953cd0d16a51dbde9dc43ccf4bed0a",
            "afb52381c81b8b5fa7b48bbd8262e450bc69161e6c31112678a3743b5efbf58b",
            "96be92ccc265fa68564593baa4fe4f3cbac2f4a0c85c81f80ca28b2f3a3c099b",
            "05af0cb90b923f778c7f88b0e6747861da0a0f73481fe2b1587b16417ed7101f",
            "fc3201c8a5763e6b9919c54044aa7c302dc11344ab629917ef14680d3dce82fa",
        ],
        [
            "dc6efcd8382f2ec32a5d0048ccfecd7d0aa2804ed31f9ca7b3b7fe80a1f278d6",
            "8b96fe42791a4ddd3f426ea35d278830d0d688a2259355e568e63a88afe8093a",
            "6fd98e52e33c89a20dda23f4f25744350fd69f3fec640c06590866b004f3799d",
            "b0696877b0de7a9b82b74038b4be03d8a4669de8aa39845c36bc969ec8cdd4a5",
            "e0047e262bfd3df4874587d3966d12191835d27a84935d4f28ee6551c4d56db9",
            "3b61bc4d990adf23afbef5e0366d4d3328f776e74173792de0ebb1ac9d87412b",
            "358eeb3cfa720339970489378e1418cb618f927b47065e580f8c56b74f92f46b",
            "4384664a9f6ef03ddb96b77e09349ce951480ac0e0666e9f4236b213c69cfb2f",
            "8cd018e4d9add2fd5f12dc3015e9ff5ef6195154d4c09f4dfa8436681899db6d",
            "37e523a85668c4ea1ea59eb44e44bb1872d0ce8ec9571e329a1b2a9a60eacd05",
        ],
        [
            "22195e02f65e0906245eaedd12bedd89a89afcb68c62d27ded954a72fdfa1547",
            "dc2051d21719a1276c7a1f860e334c632ea0b1b15ff5203aac6fb93fe11ee123",
            "adc6b4de01547c5d6b382534fbc715fe7c434cd5c213f7bfd2d1d5056e7618a6",
            "191a5490b1a8fb166e3337ffd15b2b9d99dc31ebb07f69c8fa527e5e4878edf6",
            "60592b75cfb9bc459b99ada2e6b357b8b2a0796316a97efdf7d42d49ac8a20ac",
            "ff9660ef3e4f918ed588bc315e5f295421e0e8ff88d3c787d8c587396ab8e881",
            "2dd9b7c1632f64ad88da054db0488324d00f4ef550bddbd5961b963400f824b9",
            "c3d68100de903315d7a7ae47ce3d33ba9da7f9d6a27d563ccce997771a13974f",
            "b793a6fec199c60455ea22cf3b9cf0987a3c1157b4729f522498fdfe1e8f6043",
            "23f66127ac55cfab218a9a4b199fa42bc64056bb040ae653e90e63cc882eff60",
        ],
        [
            "0e19693ced586519efd7ff4cb45b8013d2f300b60eba2d291599d366bb03f1d9",
            "30c926ee6237d407cff189c2baeb3171872aebc461b919484cf30d93250fcde0",
            "3d4268db567841caa0e360e2d6c79c354b659f521509243381b494b4eec2b4af",
            "0c504032ffbdd2f2b26cb8d0c478fbf645e2fe3bdacd1fe25a5d15fd3830edc0",
            "3c9bcb09a3b6b54264068bf1df32051065f1099d4fa0b90ffb14e5391e7af564",
            "2c2efd441d9733dc3c14b1e62444856d9ffe12e4ef5104dd30e891c2c16237f0",
            "5b87a753c041dc60f938b0971e066d6feb6055f1a021db3036ca64741280a116",
            "f38f57b7cda123e36a03ebb7c0bb196a86dda4abd66a038cd054f7a4bd61e50a",
            "755a29fb4dcf7808399f501fde4c0e23d11b9face58c9f6681f1c636b2256989",
            "af091e60104821510b28599068fa84fd814af62d978f6830e7fa2fc51fedcf9b",
        ],
        [
            "a32f07baf6b7ff6bc7c3c4f8c638871ff8c4803b0e54bedb9363f5672011077b",
            "1794cfad199c20879d1ffe10ce263334095e51f0ed191ed74e4cba635e233d80",
            "d16188abb5502eae81e6e03750123e156d8ed7dfa830a0c879560b383a5dc53a",
            "14c03d690bf39bed73ac024a2b94adc1ff276d0c11e35d3455b9ea13c361b96c",
            "c3bdbab8e434c5264c1d6fb523777d5bab1e23a1c292066e3cb731742230b042",
            "d315c931fde38bdaeb83e6378d322f33ec9a36915ea5ed05e84ec3debddafa55",
            "3587e5d75e2f0de5e2116c3a136d1a559e58ffd4a10328060ce9a430e47bd87c",
            "b622711852cdc9893aec144ed635d2ae775778c6f4152e106b7b6b2842c8055d",
            "32b3c2ed31f11795dde312b0574164dc4d00712f4736d1c5142a49cab4261ed4",
            "e2bd2350de9bdab72d3a517251217d8fdbd7ea6e386ad2ff1da19c7c2111bcb2",
        ],
        [
            "16ef63f9dc51b66565bb05ac525f3668fa48186b973a95599e0c963cfd6a4297",
            "f62ac74368b2f8b80b6e12f13e026c9ba493c59b9eb2225a2626dc773e257dba",
            "3f4de163f9a44137c52b0d9d6042a236fb8a05f9bd6617e12fbbd32bb0f2120c",
            "77d567ae787dae191cdcf406f5e6a88e16b6a3729b814ac49f7d182b6cd624d8",
            "d19a28ba50359df8d119fa4557116d45dffec6f422ae9aa563186270a6a36ee0",
            "cbda1bcc23e33ff63864cbb44db9e618c76214a91e8a4f57ea1170b468181728",
            "ebf8388ba558660ffc67ac6d14709b7ffd096603ba23660c761b603767b469d7",
            "233f0de0b9f70c2b7de870fc2f3d0b0d1fa37224a3264525d2d8537862c353d8",
            "9fdf2626bcb2e5a8622dd1fcc78ce78db3a2aceeff030def85574259ae41e555",
            "979346e3d31abf04f815ffd1d7bd44da03c636172b46ab260e365c4a4672445e",
        ],
    ];

    fn inner_kat<KG: KeyPairGenerator, SK: SigningKey, VK: VerifyingKey>(
        logn: u32,
        num: u32,
    ) -> [u8; 32] {
        let seed1 = [
            0x00u8,
            logn as u8,
            num as u8,
            (num >> 8) as u8,
            (num >> 16) as u8,
            (num >> 24) as u8,
        ];
        let mut rng1 = FakeRng1::new(&seed1);
        let seed2 = [
            0x01u8,
            logn as u8,
            num as u8,
            (num >> 8) as u8,
            (num >> 16) as u8,
            (num >> 24) as u8,
        ];
        let mut rng2 = FakeRng2::new(&seed2);

        let mut sk_buf = [0u8; sign_key_size(10)];
        let mut vk_buf = [0u8; vrfy_key_size(10)];
        let mut sig_buf = [0u8; signature_size(10)];
        let sk = &mut sk_buf[..sign_key_size(logn)];
        let vk = &mut vk_buf[..vrfy_key_size(logn)];
        let sig = &mut sig_buf[..signature_size(logn)];

        KG::default().keygen(logn, &mut rng1, sk, vk);
        let mut s = SK::decode(sk).unwrap();
        let v = VK::decode(vk).unwrap();
        let dom = DomainContext(b"domain");
        if (num & 1) == 0 {
            s.sign(&mut rng2, &dom, &HASH_ID_RAW, b"message", sig);
            assert!(v.verify(sig, &dom, &HASH_ID_RAW, b"message"));
        } else {
            let mut sh = SHA3_256::new();
            sh.update(&b"message"[..]);
            let hv = sh.digest();
            s.sign(&mut rng2, &dom, &HASH_ID_SHA3_256, &hv, sig);
            assert!(v.verify(sig, &dom, &HASH_ID_SHA3_256, &hv));
        }
        let mut sh = SHA3_256::new();
        sh.update(sk);
        sh.update(vk);
        sh.update(sig);
        sh.digest()
    }

    #[test]
    fn test_kat() {
        for i in 0..KAT.len() {
            let logn = (i as u32) + 2;
            for j in 0..KAT[i].len() {
                let r = if logn <= 8 {
                    inner_kat::<KeyPairGeneratorWeak, SigningKeyWeak, VerifyingKeyWeak>(
                        logn, j as u32,
                    )
                } else {
                    inner_kat::<KeyPairGeneratorStandard, SigningKeyStandard, VerifyingKeyStandard>(
                        logn, j as u32,
                    )
                };
                assert!(r[..] == hex::decode(KAT[i][j]).unwrap());
            }
        }
    }
}
