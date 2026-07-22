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
//! the FN-DSA standard when published (before the 1.0 version release).**
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
    HASH_ID_EXTMU,
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
    hashed_vrfykey_from_signkey, hashed_vrfykey_from_vrfykey,
    compute_mu, compute_mu_start,
    CryptoRng, RngCore, RngError,
};
pub use fn_dsa_comm::shake::{SHAKE, SHAKE128, SHAKE256, SHA3_224, SHA3_256, SHA3_384, SHA3_512};
pub use fn_dsa_kgen::{KeyPairGenerator, KeyPairGeneratorStandard, KeyPairGeneratorWeak, KeyPairGenerator512, KeyPairGenerator1024};
pub use fn_dsa_sign::{SigningKey, SigningKeyStandard, SigningKeyWeak, SigningKey512, SigningKey1024};
pub use fn_dsa_vrfy::{VerifyingKey, VerifyingKeyStandard, VerifyingKeyWeak, VerifyingKey512, VerifyingKey1024};

#[cfg(test)]
mod tests {
    use super::*;

    // We use fake RNGs for tests.
    // FakeRng1 is just SHAKE256 initialized with an explicit seed.
    // FakeRng2 just responds with hardcoded bytes.
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

    struct FakeRng2<'a> { rnd: &'a [u8], ptr: usize, }
    impl<'a> FakeRng2<'a> {
        fn new(seed: &'a [u8]) -> Self {
            Self { rnd: seed, ptr: 0, }
        }
    }
    impl CryptoRng for FakeRng2<'_> {}
    impl RngCore for FakeRng2<'_> {
        fn next_u32(&mut self) -> u32 { unimplemented!(); }
        fn next_u64(&mut self) -> u64 { unimplemented!(); }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let dlen = dest.len();
            dest.copy_from_slice(&self.rnd[self.ptr..self.ptr + dlen]);
            self.ptr += dlen;
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
        for t in 0..((11 - logn) as u8) {
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
            sk.sign(&mut rng,
                &DOMAIN_NONE, &HASH_ID_RAW, &b"test1"[..], sig).unwrap();

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
    // KAT[logn - 2] contains 10 vectors for n = 2^logn
    // For test vector KAT_n[j]:
    //    Let seed = logn || j
    //    (logn over one byte, j over 4 bytes, little-endian)
    //    SHAKE256(seed) generates seed_kgen (32 bytes) and seed_sign (40 bytes)
    //    A key pair (sk, vk) is generated with seed_kgen.
    //    A message is signed with seed_sign:
    //        domain context: "domain" (6 bytes)
    //        message: "message" (7 bytes)
    //        if j is odd, message is pre-hashed with SHA3-256; raw otherwise
    //    KAT[logn - 2][j] is SHA3-256(sk || vk || sig)

    const KAT: [[&str; 10]; 9] = [
        [
            "d4bb8ac8fa02ca916ace37586269218ded12afcfbacc290a142274661ef9e784",
            "3565c014785b035c2442a93a06c5e9105b895b34ba92d7958a5683d0d9ce29f5",
            "a7a38eaef6b8f43aa39913bac0d8c762c461d61cba2e81f06a1be0f6e2d537e0",
            "53f44db3f24a3ecf59124fbc2bbaf8bc08160e648fb30b0eb8c5f402f8cac536",
            "e63e7f053f6a072f5207b3996e8bdd12def03813d9b217d22a9cd96726f104a0",
            "e53cc18f683951db780d1e68a519d955d9015ff4d94ce42ec8a8d980511aa373",
            "ae6dfaab6db4ad836bc42cfe58344d3e3d0f9d4968f1d243ba38183ca1409730",
            "64a376800ae2bf5090ec1e50b9bc1cb5e2ffdca84a4304d5757794a76324c108",
            "71b39bb48de89f402d5c048cd2f38bdd27bb7720111f6ae88897f6af84f8fdcb",
            "490fb34bfd84adaa504c23dfeb9a621c7b4daab147856c877fae3ad7ba2b3d1f",
        ], [
            "b8ab12d83bd3e559bb1df1c256fa0a77722c3cf7326efbf6dcd0b92ceeed5e16",
            "af5f98191865ddde1bd8f13a065e5b4595bbb721253d10970b240eaa040a0943",
            "a5c08cbd9d776e330e63e91c8e2948b8a411a3f53e86b52a76e67b3ffcf48f55",
            "46d348a1ed975891db62de10ccf48f968f19ff28fb23c4b43a94abec90ca2147",
            "f11171b1598f5c387faba115823b1d78b24147e21d1e7acd0f63d8de784d46e8",
            "e35f94986445b13da057236c2f51d45d76c2477c8957c34b52f7863cbdf2f45a",
            "efebe6c9dc58d702a0a3e9773461ea6f95888fd2e569b1fbf4a6937e99d7e542",
            "5747a79febfdc0402a1f3c4d11f437bcdd284c210d370e55fc5878a65b671189",
            "f4d5a288dc21973dd0929a91cecc392dd385a702acf1e635100a3130cf437997",
            "f93ec3e9e8edc3ad1ced06f2b83741b2afc77248049b617e0e14a5171669dea7",
        ], [
            "137514e7bb1f150426d66f3dd64b26d26272f225d4926e185b7a2dbe9d421460",
            "0dd3bdf334a1379381d9123d9c3c05b5280759c65c99ed81a46df2b0af1320af",
            "c5ffeba6ea3b630701a32a9a6e3e736dcd32ce8394edf855bb81a433daa3f188",
            "3e911daa7655073d9987221f7eeb45c3336bd8aad2909de431c9a5cbd2dc33e6",
            "4fff7e334de3dc4c442aa6953713cbc2a8bd4f1c67eb3ee02a06789a88d2e790",
            "04c12dcd4fcc512097bec078464b1370aba0fa7cd0ab11352ec4e76c64f9cada",
            "b5f62f1d82c76055fc7cd846a54d7f39bb2c0f74ee55e1c2d98b82ee10d076fa",
            "44953161d2d0b6227d3f55730d1034a138c58e8800541fc30346e3c7627eb696",
            "d8d23052ac3f14133b5fa886da8aede2dfe5ce8aca270e65b23688889ea1b821",
            "456772f7f182f3b241a17f4b2482efac038955d76dabceb49562fa6e62ad5d95",
        ], [
            "49151dcac636c59c55930e91a11292426718147fcaf896228bfb690c662d78e2",
            "34dcc0e9699691dff61a72881f04484b333954e3c8de319ce890c47456559f48",
            "73184939665019b4fdfb2de0af502ad3ef4b1f13472d7aa1c739064b074debbf",
            "264f5aa8556e0ae4b11027565e44ac47a52788cd80ed030e1b0e9f758eafd84a",
            "3f5bac7c84a1351c060bb4ee49b957e2a936c9314a75d2f9c06051dea294f407",
            "8b5d3a6f387e1187a500ab55648eb07a7e495a0ae97e7d031a667eca36c11e87",
            "bd6a11ed412ce3c1f7b41763c20cc1f9335b2a5a58be4ea3ecc8943fd698d2a9",
            "3f75f78c35123a4ea85afaa4c4035ee7c56b0ace01cc1c647c84df007dc38aee",
            "8e5e0653c3f087c0c1a608edf03962230efb963d0e00254ce29950905ebb2e50",
            "8938c6f1d88d63f4726363aeb82d91ecaeb058c1c9f8697166d97b2d33fcd78d",
        ], [
            "bbfc086cc6efe456483d80ed130fa3cf468ca927f2f98e0275976fb978034c53",
            "963e9ea43d0733cf4e735d6b85baa32d5a5071442053adf3cf711ee76f8fc0a2",
            "f03c8f8bd2fbbf434c7adb880befdf87aad135bcf933ff3fef1f72ee7518c120",
            "e8d5ccc73b73c2bd78748fcdccdb8bae5fcbd9872b343a41c45b1af04a56487c",
            "674bf0c4e6c0ab53019d0d27564dc25c8c515e1e1306c5512cc4bbf922aa5f6a",
            "22f274014a72d463ed078b729819ac2f4dc5163271731526ea1fca836afb418a",
            "5ae920ac2ca2ced3f0da1292e1a645f5c6a4a78258c207a83b39668ae1556b25",
            "ba169240a38b209cd482137269f0c33cca98e3bd181c576e1523bd5b3306207e",
            "f5ad4fc07a56f20232bd3d51f6c386f93f152fde088e3d545c24da012b893e42",
            "3dcdc145e4c8466e80f19f06bd59ff5d4dc0ad299b6b0d1ee7b78688c41367c7",
        ], [
            "2e590e99833785ee67b7fa004c3b4525f1f77a89d938f9ed38f2b718c331bda8",
            "134537a6a183db2eb232fe2b8f6accf474d34759dfe86bb2ffec669a77dd7a14",
            "471e4f121374d2c25c714865a3960bee910dcb50e3e8645c1f54f4c3e22fb186",
            "48153c04b97c4a3507602db294d8abbebeed34fa87ce7eabcadfc441d69288ad",
            "4f9c6703595b5f77ff6048e270cf4c4ae73a82e65f227edba91f7e84022eb5c0",
            "c8ffe0bce23744ed41933402dc5b9e6416086b129924b171af0d47b2aeb5a5b9",
            "bd7c4187b36bd31ec677e4db4feff6d60511aee7d9716b78e3159aa322168a70",
            "a5b70aa436c3cdff9d1c69a0a9825c505be0775ead0b45608b368df9b4c429af",
            "fc6c1c552ecc836b11f7beb2cb5613254d13de4c0930e234002a3b6418717077",
            "76c61e7f16492c22832057af120a39437deb748c199da5c2404bb4a363c76e1f",
        ], [
            "7c186bbfd1376de1d14e5c9c44fd41183b6cf7d6988e904d14bb977c31519302",
            "5fd57dd9530835813e59a3cce2879554be6df4067717426a4dd7efec4c8c731e",
            "62c592885e4c385766b797e47198a08aa29878d602deeecb143cfb9e3065de8c",
            "2d1a8b654a6100b6e7e238d709f4a95088a2c4b315545ff4ddcb38905f7dbf88",
            "2798f70186b541ea96c3c2adeee96c3266dcc324038bed22c3156931335beca0",
            "06aa91f4ff9a4bd75e7fb87b9a4f766bd3391b34e813ab46bfaa3b108292bdaf",
            "29f0421ae8739fb73c832cb17baef2aea39ac12216028daf9334c08e7f6a23fd",
            "486efe575fc0bafeac5b048da3b12280de402a66d304d2118ee2039fe206519a",
            "954ad7d6cc89cb7066358ea82f14ab944d62212fbb63f53bdc0ac2b8ff57cbc3",
            "c4141cebcb947e3dd702be708ce41eb20d2127719f404d476bc0945a6c5a79dd",
        ], [
            "71009cd3bc68f5061608ab541e9ae27ba0263c42fad97c112825075176d539d0",
            "70d8e2492da097f5407459eb9e3d58697855984e305032973a49709d208ddf1d",
            "91807eec4fc11be204e0bb48d6cc5968dd4dd4e1e886370ddb0c95458d9b68f0",
            "ded7d5c6392f0e16926a8e535b3bdb8b0fb4dc6dfd108ce8229c8ce6a378e965",
            "7c6a265c4b6732dccbb2fcc872be4546709285f8ed13902d7adfef2fb006d513",
            "c4afc6d00b2560fe567a1fab088d8b5e35774d4154a638fc5e4a10cc587aa798",
            "e3a0d6f8aba1c5658e053234fa0526f0d6c05f33fece73965871376a1f9039fc",
            "56d822207747b7c8bd47914482d63609e303bfa380b795b9f0f74cc0728ed040",
            "4021a79b26e2b5ad8603b1ec203a0de7177bbb2c4f7e046be5438842dcef30ad",
            "2ecca13d10dc658e0915bc42a8687d2aa7605c8670a2ca5c67e480487eaa0281",
        ], [
            "51bec3b8ca2565a94b2f1ad7bdc5f3844170495f235b8ea87fdae7e6d3b9dcb6",
            "abed632dec978f230f17e1c9059e36a7f0edfbaac2969ee75100421ea3346446",
            "83868908f2f89ee85a4e869b3d040de1f040e0dfa2e8cdabff00f0a2a2e8c120",
            "66f11c38b7f787bd66cd00ec62f3f2af622b81274a4dbe9462025b8d757710e1",
            "65602b1692abe97e845e41589d21927732f71c36ef1c888d155a15708b7b60e4",
            "95539caec65ac9a9ce23175168af914b905165b8f72c4d700f61b0b746683b11",
            "3a9632ee72a09704519eadea4b3688289c644f17105d29997d3555d21a428c7b",
            "b32a4019b5e5f802d4b61c751b99c58ffdee5adbf8cb97dc59c480756aa0a4f7",
            "439a026581a9472bf11b9f62389a066291b9a4ca789877ee2a44c9c6b5ca9852",
            "37b7f34cd910edc8b53b5302af4e2ff60192a396fe6c44fe8140a0ce0be04888",
        ],
    ];

    fn inner_kat<KG: KeyPairGenerator, SK: SigningKey, VK: VerifyingKey>(
        logn: u32, j: u32) -> [u8; 32]
    {
        let mut seed_kgen = [0u8; 32];
        let mut seed_sign = [0u8; 40];
        let seed = [logn as u8,
            j as u8, (j >> 8) as u8, (j >> 16) as u8, (j >> 24) as u8];
        let mut sh = SHAKE256::new();
        sh.inject(&seed);
        sh.flip();
        sh.extract(&mut seed_kgen);
        sh.extract(&mut seed_sign);
        let mut rng_kgen = FakeRng2::new(&seed_kgen);
        let mut rng_sign = FakeRng2::new(&seed_sign);

        let mut sk_buf = [0u8; sign_key_size(10)];
        let mut vk_buf = [0u8; vrfy_key_size(10)];
        let mut sig_buf = [0u8; signature_size(10)];
        let sk = &mut sk_buf[..sign_key_size(logn)];
        let vk = &mut vk_buf[..vrfy_key_size(logn)];
        let sig = &mut sig_buf[..signature_size(logn)];

        KG::default().keygen(logn, &mut rng_kgen, sk, vk);
        let mut s = SK::decode(sk).unwrap();
        let v = VK::decode(vk).unwrap();
        let dom = DomainContext(b"domain");
        if (j & 1) == 0 {
            s.sign(&mut rng_sign, &dom, &HASH_ID_RAW, b"message", sig);
            assert!(v.verify(sig, &dom, &HASH_ID_RAW, b"message"));
        } else {
            let mut sh = SHA3_256::new();
            sh.update(&b"message"[..]);
            let hv = sh.digest();
            s.sign(&mut rng_sign, &dom, &HASH_ID_SHA3_256, &hv, sig);
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
