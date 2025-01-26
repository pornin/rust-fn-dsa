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
pub use fn_dsa_comm::shake::{SHAKE, SHAKE128, SHAKE256, SHA3_224, SHA3_256, SHA3_384, SHA3_512};
pub use fn_dsa_kgen::{KeyPairGenerator, KeyPairGeneratorStandard, KeyPairGeneratorWeak, KeyPairGenerator512, KeyPairGenerator1024};
pub use fn_dsa_sign::{SigningKey, SigningKeyStandard, SigningKeyWeak, SigningKey512, SigningKey1024};
pub use fn_dsa_vrfy::{VerifyingKey, VerifyingKeyStandard, VerifyingKeyWeak, VerifyingKey512, VerifyingKey1024};

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
        fn next_u32(&mut self) -> u32 { unimplemented!(); }
        fn next_u64(&mut self) -> u64 { unimplemented!(); }
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
            Self { sh, buf: [0u8; 96], ptr: 96, ctr: 0 }
        }
    }
    impl CryptoRng for FakeRng2 {}
    impl RngCore for FakeRng2 {
        fn next_u32(&mut self) -> u32 { unimplemented!(); }
        fn next_u64(&mut self) -> u64 { unimplemented!(); }
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
    #[cfg(feature = "shake256x4")]
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
        ], [
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
        ], [
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
        ], [
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
        ], [
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
        ], [
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
        ], [
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
        ], [
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
        ], [
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
        ]
    ];

    #[cfg(not(feature = "shake256x4"))]
    const KAT: [[&str; 10]; 9] = [
        [
            "517e169d05b8cd4b6afa81847d5f1ed47309650a9ccff39c4445ae57914a2058",
            "ce8f23924e463c769cedbd034eb0f11574c1cb8a453949c6c36b34e09e41d06c",
            "65c2b2a6f2054faf7dbe97454d68b66768ca2ca5f65e7cbea5a91cdc1c6549a4",
            "568e6ad817ba21b555808255db94a710ebbd5005284585365dc5308046e23d66",
            "8ec696eaee01f9ec43bdb04d9dab7ff43d8bd80c7081134b9863f7c6ebbbe284",
            "96e95da3c03426bbb3448084cbb54d83392acae745e3781f890dcddb030572cb",
            "469be4112615d98308ef9df8cb8b0f3da1ca2558d79b7a867530de7d4000fb9b",
            "80d7cc5c779ae2a590249169e10e935a1e8bf481d1c8babf3487acc0838b99d1",
            "faac905c850eeb978e776f1e7fb1bf7ad40dd9618792f25fc3fae9ee47d8ce15",
            "fc484c374ab40a4dbb5ea62b04a10f0c945105cddd48c4a90e729fc07680e88b",
        ], [
            "bef4b8dc62d8e0b5eca9bc09366b1dcf7327dfbac10042406cc2217e9d0791f5",
            "f75a3392c69345b6f5355d104305efae9a9d90fd5dfaa03120a12e02356b34fd",
            "e3c8a660f6ab7102d9a975c94d6c0206e0835cc88ab36dd63556540c15b32ac3",
            "1cd5bcadfc883540211d7803a2d6ff47474e4d5bc8a42b79ff97327f6e75b574",
            "671b901f1535f58e198eab7fb9e84525f4315337abe30f902e6c0305501b0709",
            "680d8b79f8d91ce1ae6a070baebd8f3f99472efe1c14efa35e1a653472ac98c2",
            "3d9c77564d8ac733fd20bbff61d078c0ee094dc50ef2a0d8b53238263bd9f0d9",
            "5b96561ca0cb41b1c09dc569ee48e596067df5a287a838f88b98e2375880d053",
            "b306079cd1f2f4029cee72988ace631572ad7f2620e020cf5ad4b1ae598424e1",
            "9a8cf1dc6b62c9f8b7790943ca9e48beef24aa8326b9002146e1858bc61103d2",
        ], [
            "e3f4742be370ea418feab49c3fee6a98ac52c1f1cb39138a90092449595b3f81",
            "d6659d9895e4b59c1001bf8354319889ef89f9c42570147dc86d615db94ade09",
            "f4b95d6d27a64fbd303a7091625bd8daf61c3301376d512203c2fb53fb726317",
            "8c94c3df7eb93a31ce32b756ed0279c8c36e8cbe9a76901823d61f64244be8a9",
            "c2ff7bff549c1f050c81dc3ca6ccd0537f0345b304f9271457405ac5b0ff1bb6",
            "d03a17462c30a7bd7d594cd0ac209d4f3704a96934e0c12e31010e8bcd58f472",
            "e694f16019b9ed9afa360db94a29bf5036ef88fb4ff5fe8315bcb0cfd9b65bad",
            "89cd099d215ed66c93586484c48994e3d772511768561e0465c74852ff921ac0",
            "366844a98fa179f96019f6f930829c960990ac438da24a945f40791b4ab3771c",
            "736d879d25597e39878548a2efc2b37d7d48744cf621803a97fa84d1337d8478",
        ], [
            "f13154701ddb47458310e09b3bd20350fc8ec13b42dfb2f3414fe49dc21054e5",
            "dccc7800c714f9b1e28f6f414ad0760619bf19d319eee3e7a2f7cbae16ec44f4",
            "0a7c0f023c83e81fce3aa8737aa999131f9b1c78db813c8471af2bf41af34959",
            "65afc54bf77ab9a82c306d15e66a993e4af999a9edb08d822cc70e05d4d73866",
            "b05a93ffe94fb3ea4da3430929ea577310c748744e0b9595bd8c4243ac8ffe7a",
            "7ef713863e94b608f95cf4bb63214fb2fd23812d98d88cd06213e2d9d9dce4c0",
            "39a2b9a5411ae63a80a75725abaab5191d394229d2dd44c2476bc2fee88a29b6",
            "354bd2ccf6b8c814bfa644e4bc9e5610d42d1516e3fe342d9878ba7d03033a5c",
            "9e93e4e05072a624170bccb231caacf69faaaaced8b636eed522ac031eb1e25d",
            "104a62c58b72b70f1fe0eac8ca4b8775ddcbd2ec62f07f91e6b54dd578c1a65c",
        ], [
            "7a65360991f32d38d8267e9b8fa29f21f59923efa27a39214abb3412d316cf13",
            "13c0a7f42988e36cc0440f056341791fab717a0b1f9a62954489388a77c1447f",
            "5aef7941bda5f7ec4b12141eaf09dcafe741e4aac536f232e167b7c154196999",
            "60a910388695d6aa8d1194e70fa7a502e21e98f50017b8282cab0c6c18e82c62",
            "304ffc725fc4b6515f3ca5b45dc7b86155cab3de57657efe9c647643d93e0d69",
            "e2ce9a2d7acdb4d0cf906e1d072d4448537fa42ac2f3e0d0531a6e6336196eee",
            "081848b14fc7dd83df56c2f2379bdb20266241c428ce09cee65c3b4dd1965989",
            "4c9066103f99d6aaac3dbe5be9ef0dd06f090a8479e458aa3e83e6b26c6d19f3",
            "ac6fb3acbae450b3d75927532a462fadd64a1c0f025b1c416f27b2f41f945567",
            "65190b3eb43adbaa09d9bf2ccf971b70fb382c56e8676dc4a579f8d666f953c2",
        ], [
            "4850dc7976386e64a98cdbbb8a886e6d8cdb52c496e9d626f4c8fdd915658494",
            "9d17107e409910f16a43ac73068c2d656db2ca684ba86c0ad7a4cb14ca1bf931",
            "64adc2f8d3594064a32cb1f00ab8ddcfbad33fde6d2398f829c1923cb38d52c5",
            "edad1b81ff0a71bd76ed7984450030ac9cc861e62d432f85ed0ed83b2d463c8a",
            "9d9ae5f83c1a768eb8cd3b3a09aa5d8ba9d659c43fbf00892f0c32b0ead076c2",
            "f27c0674120eace270ae47852a38596ed1867727f6748cd7128682574d4b3a05",
            "d2ee57706149d6838df63dda7b122e32445f0ed2b495fd336c46ce3384a3c0ee",
            "3774f7f8c948792aa4c480d3b9300b5cb91cbb619327a18ee66a89511cad2d92",
            "b915349483e3a85db14fa612327b7eaa1ab201f47d0795a05d06bd5b2d92def2",
            "daed7bab12476abb916a22f092ba52a93da5540506188fb982f538ad98d3db11",
        ], [
            "1c3196947f64e22696a151f75ce97f67626ffc089abc4681adc2caf3c4828b1a",
            "2749938e3936a4ffb83583da86f3506a2a88f73248e80f14c50c8c92cd9d4ede",
            "8884f415f33b2d6a91a12b8d4fa0f9641178b62f2a623ff2f9cdff74cf88cf87",
            "8129eb52137edc7c56accf0b9d273b29085f77548693596075db48106c550c0a",
            "2f1b7292868b1e10cceca079f60a065431f1381ce5046d9f6ae7191822110c40",
            "b040ff3ec202020a879c69fc6f51c350d256fb02691aeaa77b1abfd9df6af42b",
            "0f3c4a77457d920a0c87cf5dbfef8899a67aabda08ed5d8f2c5c5e9eb99fff41",
            "1c51ce7bb6fa8b37a3c5ee99a09138bf9fd8310071d8adb91cd692d34e212daf",
            "c3de8a295ef2ed1dfdc4c6a21f6c989c55435890d40e2706424660cb798befdb",
            "230f62ab8fc0d086140584fc8977597f2c591da1f9627aef502c9e9eee9f4abc",
        ], [
            "53748d0bda7a655b160d1237687f606fc6d85a768af7e52accb320cdc02fea56",
            "566ff306b9e7a8509252fcbd315faa1c7d9a99e90a6e5a1e211dca0492fd2422",
            "3927502da6d66d09c71baad0fb307e767287bca9defd3e5658093758dd6f4eb6",
            "7d00e218c02ca8e2b0b475c67f06b544d74b24a0c79e775066f6d35b85bba168",
            "5c7e80b3b95bbb04272cf6cb5482f98c5f48303119be7c1864fda7d183cf8dd2",
            "8f8238dc09555fb6a06505af7d08ea909829bab3443c651791e91444d4f9ea29",
            "27dc1593aea3529c25112b536ba38bf7ff26796f7199aff8597db61c013316c4",
            "92770a08ede1e89721661b8812879ab2c1cae3ffe66056fa23e2ac4cc984998b",
            "31e9907ba30080033d48535b1ecbc3e25e6b6b450fb1b310935e8b278654700e",
            "779fb106eb89f09e1d09a7c3c3295d8b63fa93ca3e59de9a9adcc1eb3f392c0c",
        ], [
            "c04a645eb9e60d117d29fe4a0d5314bedf1392cbad20bb15f9cc88ac25cd78e2",
            "1f0e8af75f9abfed60ddafda6286c6fb27395188d3191763eedb05c00c908b39",
            "669de6300e9fa19fbb9675769525d1f68d166297f6a67753c4dda74927c83286",
            "d3990a8b5790cf298949bfae84f0fdee9898c95e56d5c54a8a315b81f521ac41",
            "579d09da76792fcd7047cd3a271b3bddca1f8f0e753b1064466af4c297ca82aa",
            "b0154f77732cf43763902e15e6683525841438343e4423f038990d923ee5e9a8",
            "ece2780b43ae0744b5269730688d41871e5280c2ec6ed66535d9b0ece4a3aca5",
            "51ca0dc5ccae2abb38e39eb2fa8bbc1bbfa46e4dca62bf6bd9666fe1eeb22803",
            "8ae1591a9827357670f983a22cca71e754ede9ccae51f9a2f4bff89354903d0f",
            "cde3f08ca0f7dcf93398bcbed80575c114dc1ddc046cb989385149e6a5deba13",
        ]
    ];

    fn inner_kat<KG: KeyPairGenerator, SK: SigningKey, VK: VerifyingKey>(
        logn: u32, num: u32) -> [u8; 32]
    {
        let seed1 = [0x00u8, logn as u8,
            num as u8, (num >> 8) as u8, (num >> 16) as u8, (num >> 24) as u8];
        let mut rng1 = FakeRng1::new(&seed1);
        let seed2 = [0x01u8, logn as u8,
            num as u8, (num >> 8) as u8, (num >> 16) as u8, (num >> 24) as u8];
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
                    inner_kat::<KeyPairGeneratorWeak,
                        SigningKeyWeak,
                        VerifyingKeyWeak>(logn, j as u32)
                } else {
                    inner_kat::<KeyPairGeneratorStandard,
                        SigningKeyStandard,
                        VerifyingKeyStandard>(logn, j as u32)
                };
                assert!(r[..] == hex::decode(KAT[i][j]).unwrap());
            }
        }
    }
}
