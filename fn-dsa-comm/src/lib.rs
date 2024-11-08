#![no_std]

//! This crate contains utility functions which are used by FN-DSA for
//! key pair generation, signing, and verifying. It is not meant to
//! be used directly.

/// Encoding/decoding primitives.
pub mod codec;

/// Computations with polynomials modulo X^n+1 and modulo q = 12289.
pub mod mq;

/// SHAKE implementation.
pub mod shake;

/// Specialized versions of `mq` which use AVX2 opcodes (on x86 CPUs).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod mq_avx2;

// Re-export RNG traits to get a smooth dependency management.
pub use rand_core::{CryptoRng, RngCore, Error as RngError};

/// Symbolic constant for FN-DSA with degree 512 (`logn = 9`).
pub const FN_DSA_LOGN_512: u32 = 9;

/// Symbolic constant for FN-DSA with degree 1024 (`logn = 10`).
pub const FN_DSA_LOGN_1024: u32 = 10;

/// Get the size (in bytes) of a signing key for the provided degree
/// (degree is `n = 2^logn`, with `2 <= logn <= 10`).
pub const fn sign_key_size(logn: u32) -> usize {
    let n = 1usize << logn;
    let nbits_fg = match logn {
        2..=5 => 8,
        6..=7 => 7,
        8..=9 => 6,
        _ => 5,
    };
    1 + (nbits_fg << (logn - 2)) + n
}

/// Get the size (in bytes) of a verifying key for the provided degree
/// (degree is `n = 2^logn`, with `2 <= logn <= 10`).
pub const fn vrfy_key_size(logn: u32) -> usize {
    1 + (7 << (logn - 2))
}

/// Get the size (in bytes) of a signature for the provided degree
/// (degree is `n = 2^logn`, with `2 <= logn <= 10`).
pub const fn signature_size(logn: u32) -> usize {
    // logn   n      size
    //   2      4      47
    //   3      8      52
    //   4     16      63
    //   5     32      82
    //   6     64     122
    //   7    128     200
    //   8    256     356
    //   9    512     666
    //  10   1024    1280
    44 + 3 * (256 >> (10 - logn)) + 2 * (128 >> (10 - logn))
        + 3 * (64 >> (10 - logn)) + 2 * (16 >> (10 - logn))
        - 2 * (2 >> (10 - logn)) - 8 * (1 >> (10 - logn))
}

/// The message for which a signature is to be generated or verified is
/// pre-hashed by the caller and provided as a hash value along with
/// an identifier of the used hash function. The identifier is normally
/// an encoded ASN.1 OID. A special identifier is used for "raw" messages
/// (i.e. not pre-hashed at all); it uses a single byte of value 0x00.
pub struct HashIdentifier<'a>(pub &'a [u8]);

/// Hash function identifier: none.
///
/// This is the identifier used internally to specify that signature
/// generation and verification are performed over a raw message, without
/// pre-hashing.
pub const HASH_ID_RAW: HashIdentifier = HashIdentifier(&[0x00]);

/// Hash function identifier: original Falcon design.
///
/// This identifier modifies processing of the input so that it follows
/// the Falcon scheme as it was submitted for round 3 of the post-quantum
/// cryptography standardization process. When this identifier is used:
///
///  - The message is raw (not pre-hashed).
///  - The domain separation context is not used.
///  - The public key hash is not included in the signed data.
///
/// Supporting the original Falcon design is an obsolescent feature
/// that will be removed at the latest when the final FN-DSA standard
/// is published.
pub const HASH_ID_ORIGINAL_FALCON: HashIdentifier = HashIdentifier(&[0xFF]);

/// Hash function identifier: SHA-256
pub const HASH_ID_SHA256: HashIdentifier = HashIdentifier(
    &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);

/// Hash function identifier: SHA-384
pub const HASH_ID_SHA384: HashIdentifier = HashIdentifier(
    &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);

/// Hash function identifier: SHA-512
pub const HASH_ID_SHA512: HashIdentifier = HashIdentifier(
    &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);

/// Hash function identifier: SHA-512-256
pub const HASH_ID_SHA512_256: HashIdentifier = HashIdentifier(
    &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06]);

/// Hash function identifier: SHA3-256
pub const HASH_ID_SHA3_256: HashIdentifier = HashIdentifier(
    &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08]);

/// Hash function identifier: SHA3-384
pub const HASH_ID_SHA3_384: HashIdentifier = HashIdentifier(
    &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09]);

/// Hash function identifier: SHA3-512
pub const HASH_ID_SHA3_512: HashIdentifier = HashIdentifier(
    &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A]);

/// Hash function identifier: SHAKE128
pub const HASH_ID_SHAKE128: HashIdentifier = HashIdentifier(
    &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B]);

/// Hash function identifier: SHAKE256
pub const HASH_ID_SHAKE256: HashIdentifier = HashIdentifier(
    &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C]);

/// When a message is signed or verified, it is accompanied with a domain
/// separation context, which is an arbitrary sequence of bytes of length
/// at most 255. Such a context is wrapped in a `DomainContext` structure.
pub struct DomainContext<'a>(pub &'a [u8]);

/// Empty domain separation context.
pub const DOMAIN_NONE: DomainContext = DomainContext(b"");

/// Hash a message into a polynomial modulo q = 12289.
///
/// Parameters are:
///
///  - `nonce`:            40-byte random nonce
///  - `hashed_vrfy_key`:  SHAKE256 hash of public (verifying) key (64 bytes)
///  - `ctx`:              domain separation context
///  - `id`:               identifier for pre-hash function
///  - `hv`:               message (pre-hashed)
///  - `c`:                output polynomial
///
/// If `id` is `HASH_ID_RAW`, then no-prehashing is applied and the message
/// itself should be provided as `hv`. Otherwise, the caller is responsible
/// for applying the pre-hashing, and `hv` shall be the hashed message.
pub fn hash_to_point(nonce: &[u8], hashed_vrfy_key: &[u8],
    ctx: &DomainContext, id: &HashIdentifier, hv: &[u8], c: &mut [u16])
{
    // TODO: remove support for original Falcon when the final FN-DSA
    // is defined and has test vectors. Since the message is used "as is",
    // this encoding can mimic all others, and thus bypasses any attempt at
    // domain separation. Moreover, ignoring the domain separation context
    // is a potential source of security issues, since the caller might
    // expect a strong binding to the context value.

    // Input order:
    //   With pre-hashing:
    //     nonce || hashed_vrfy_key || 0x01 || len(ctx) || ctx || id || hv
    //   Without pre-hashing:
    //     nonce || hashed_vrfy_key || 0x00 || len(ctx) || ctx || message
    // 'len(ctx)' is the length of the context over one byte (0 to 255).

    assert!(nonce.len() == 40);
    assert!(hashed_vrfy_key.len() == 64);
    assert!(ctx.0.len() <= 255);
    let orig_falcon = id.0.len() == 1 && id.0[0] == 0xFF;
    let raw_message = id.0.len() == 1 && id.0[0] == 0x00;
    let mut sh = shake::SHAKE256::new();
    sh.inject(nonce);
    if orig_falcon {
        sh.inject(hv);
    } else {
        sh.inject(hashed_vrfy_key);
        sh.inject(&[if raw_message { 0u8 } else { 1u8 }]);
        sh.inject(&[ctx.0.len() as u8]);
        sh.inject(ctx.0);
        if !raw_message {
            sh.inject(id.0);
        }
        sh.inject(hv);
    }
    sh.flip();
    let mut i = 0;
    while i < c.len() {
        let mut v = [0u8; 2];
        sh.extract(&mut v);
        let mut w = ((v[0] as u16) << 8) | (v[1] as u16);
        if w < 61445 {
            while w >= 12289 {
                w -= 12289;
            }
            c[i] = w;
            i += 1;
        }
    }
}

/// Trait for a deterministic pseudorandom generator.
///
/// The trait `PRNG` characterizes a stateful object that produces
/// pseudorandom bytes (and larger values) in a cryptographically secure
/// way; the object is created with a source seed, and the output is
/// indistinguishable from uniform randomness up to exhaustive enumeration
/// of the possible values of the seed.
///
/// `PRNG` instances must also implement `Copy` and `Clone` so that they
/// may be embedded in clonable structures. This implies that copying a
/// `PRNG` instance is supposed to clone its internal state, and the copy
/// will output the same values as the original.
pub trait PRNG: Copy + Clone {
    /// Create a new instance over the provided seed.
    fn new(seed: &[u8]) -> Self;
    /// Get the next byte from the PRNG.
    fn next_u8(&mut self) -> u8;
    /// Get the 16-bit value from the PRNG.
    fn next_u16(&mut self) -> u16;
    /// Get the 64-bit value from the PRNG.
    fn next_u64(&mut self) -> u64;
}

/// Do a rutime check for AVX2 support (x86 and x86_64 only).
///
/// This is a specialized subcase of the is_x86_feature_detected macro,
/// except that this function is compatible with `no_std` builds.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn has_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

    #[cfg(target_arch = "x86")]
    use core::arch::x86::{__cpuid, __cpuid_count, _xgetbv};

    unsafe {
        // Check that we can access function parameter 7 (where the AVX2
        // support bit resides).
        let r = __cpuid(0);
        if r.eax < 7 {
            return false;
        }

        // Check that AVX2 is supported by the CPU.
        let r = __cpuid_count(7, 0);
        if (r.ebx & (1 << 5)) == 0 {
            return false;
        }

        // Check that the full-size (256-bit) ymm registers are enabled.
        let r = _xgetbv(0);
        return (r & 0x06) == 0x06;
    }
}
