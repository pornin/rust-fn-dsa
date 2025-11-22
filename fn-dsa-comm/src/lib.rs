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
#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
pub mod mq_avx2;

// Re-export RNG traits to get a smooth dependency management.
pub use rand_core::{CryptoRng, Error as RngError, RngCore};

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
    44 + 3 * (256 >> (10 - logn))
        + 2 * (128 >> (10 - logn))
        + 3 * (64 >> (10 - logn))
        + 2 * (16 >> (10 - logn))
        - 2 * (2 >> (10 - logn))
        - 8 * (1 >> (10 - logn))
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
pub const HASH_ID_SHA256: HashIdentifier = HashIdentifier(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
]);

/// Hash function identifier: SHA-384
pub const HASH_ID_SHA384: HashIdentifier = HashIdentifier(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
]);

/// Hash function identifier: SHA-512
pub const HASH_ID_SHA512: HashIdentifier = HashIdentifier(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
]);

/// Hash function identifier: SHA-512-256
pub const HASH_ID_SHA512_256: HashIdentifier = HashIdentifier(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
]);

/// Hash function identifier: SHA3-256
pub const HASH_ID_SHA3_256: HashIdentifier = HashIdentifier(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
]);

/// Hash function identifier: SHA3-384
pub const HASH_ID_SHA3_384: HashIdentifier = HashIdentifier(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
]);

/// Hash function identifier: SHA3-512
pub const HASH_ID_SHA3_512: HashIdentifier = HashIdentifier(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A,
]);

/// Hash function identifier: SHAKE128
pub const HASH_ID_SHAKE128: HashIdentifier = HashIdentifier(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
]);

/// Hash function identifier: SHAKE256
pub const HASH_ID_SHAKE256: HashIdentifier = HashIdentifier(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
]);

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
pub fn hash_to_point(
    nonce: &[u8],
    hashed_vrfy_key: &[u8],
    ctx: &DomainContext,
    id: &HashIdentifier,
    hv: &[u8],
    c: &mut [u16],
) {
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

    assert_eq!(nonce.len(), 40);
    assert_eq!(hashed_vrfy_key.len(), 64);
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


#[cfg(feature = "eth_falcon")]
/// Support for ETHFALCON methods
pub mod eth_falcon {
    extern crate alloc;
    use super::{codec, mq, vrfy_key_size};

    use alloc::{vec, vec::Vec};
    use tiny_keccak::{Hasher, Keccak};

    const KECCAK_OUTPUT: usize = 32;

    /// KeccakXOF implements the Keccak PRNG as used in ETHFALCON
    /// This replaces SHAKE256 in standard Falcon
    ///
    /// Keccak-based XOF implementation matching the Python KeccakPRNG
    /// Reference: https://github.com/zknoxhq/ETHFALCON/python-ref/keccak_prng.py
    #[derive(Default)]
    struct KeccakXOF {
        buffer: Vec<u8>,
        state: [u8; KECCAK_OUTPUT],
        counter: u64,
        finalized: bool,

        out_buffer: [u8; KECCAK_OUTPUT],
        out_buffer_pos: usize,
        out_buffer_len: usize,
    }

    impl KeccakXOF {
        /// Inject (absorb) data into XOF state
        /// This is called "update" in the SHAKE256 interface
        pub fn update(&mut self, data: &[u8]) -> Result<(), &'static str> {
            if self.finalized {
                return Err("Cannot update after finalizing");
            }

            // Use dynamic buffer - no size limit
            self.buffer.extend_from_slice(data);

            Ok(())
        }

        /// Finalize the XOF state and prepare for output generation
        /// This is called "flip" in the XOF interface
        pub fn flip(&mut self) -> Result<(), &'static str> {
            if self.finalized {
                return Err("Already finalized");
            }

            // Hash the buffer to create initial state
            let mut keccak = Keccak::v256();
            keccak.update(&self.buffer);
            keccak.finalize(&mut self.state);

            self.finalized = true;

            // Reset output buffer
            self.out_buffer_pos = 0;
            self.out_buffer_len = 0;

            Ok(())
        }

        /// Extract (squeeze) output from the XOF
        /// This is called "read" in the XOF interface
        pub fn read(&mut self, length: usize) -> Result<Vec<u8>, &'static str> {
            if !self.finalized {
                return Err("XOF not finalized");
            }

            let mut output = Vec::with_capacity(length);
            let mut offset = 0;

            // First, use any bytes remaining in the output buffer
            if self.out_buffer_len > self.out_buffer_pos {
                let available = self.out_buffer_len - self.out_buffer_pos;
                let to_copy = core::cmp::min(length, available);

                output.extend_from_slice(
                    &self.out_buffer[self.out_buffer_pos..self.out_buffer_pos + to_copy],
                );
                self.out_buffer_pos += to_copy;
                offset += to_copy;

                // If we've satisfied the request, return early
                if offset == length {
                    return Ok(output);
                }
            }

            // Generate more output blocks as needed
            while offset < length {
                // Prepare input block: state || counter (big-endian)
                let mut block = Vec::with_capacity(KECCAK_OUTPUT + 8);
                block.extend_from_slice(&self.state);
                block.extend_from_slice(&self.counter.to_be_bytes());

                // Generate next block using Keccak-256
                let mut keccak = Keccak::v256();
                keccak.update(&block);
                keccak.finalize(&mut self.out_buffer);

                // Update buffer state
                self.out_buffer_len = KECCAK_OUTPUT;
                self.out_buffer_pos = 0;

                // Copy output
                let remaining = length - offset;
                let to_copy = core::cmp::min(remaining, KECCAK_OUTPUT);

                output.extend_from_slice(&self.out_buffer[..to_copy]);
                self.out_buffer_pos = to_copy;
                offset += to_copy;

                // Increment counter for next block
                self.counter += 1;
            }

            Ok(output)
        }

        /// Reset the XOF to initial state (for future use)
        #[allow(dead_code)]
        pub fn reset(&mut self) {
            self.buffer.clear();
            self.counter = 0;
            self.finalized = false;
            self.out_buffer_pos = 0;
            self.out_buffer_len = 0;
            self.state = [0u8; KECCAK_OUTPUT];
            self.out_buffer = [0u8; KECCAK_OUTPUT];
        }
    }

    /// Hash a message and salt to a point in Z[x] mod(Phi, q)
    /// This follows the same logic as standard Falcon but uses Keccak XOF instead of SHAKE256
    ///
    /// Args:
    ///     n: Degree of the polynomial (512 for Falcon-512)
    ///     message: The message to hash
    ///     salt: The salt value (40 bytes in standard Falcon)
    ///
    /// Returns:
    ///     A vector of n coefficients in [0, q)
    pub fn hash_to_point_keccak(
        n: usize,
        message: &[u8],
        salt: &[u8],
    ) -> Result<Vec<u16>, &'static str> {
        // Q = 12289, which is less than 2^16 = 65536, so this is always true
        // Removed the runtime check to avoid overflow warning
        const Q: usize = 12289;
        const K: u32 = (1u32 << 16) / (Q as u32);

        // Create XOF and hash the inputs
        // Note: In ETHFALCON/KeccakPRNG mode, the order is reversed compared to SHAKE256
        // Python code: if xof != SHAKE: salt, message = message, salt
        let mut xof = KeccakXOF::default();

        // ETHFALCON uses message first, then salt (reversed from SHAKE256)
        xof.update(message)
            .map_err(|_| "Failed to update XOF with message")?;
        xof.update(salt)
            .map_err(|_| "Failed to update XOF with salt")?;

        xof.flip().map_err(|_| "Failed to finalize XOF")?;

        // Output pseudorandom coefficients using rejection sampling
        let mut hashed = Vec::with_capacity(n);
        let mut i = 0;

        while i < n {
            // Read 2 bytes and interpret as a 16-bit integer
            let two_bytes = xof.read(2).map_err(|_| "Failed to read from XOF")?;

            if two_bytes.len() != 2 {
                return Err("Insufficient bytes from XOF");
            }

            // Big-endian: (byte[0] << 8) + byte[1]
            let elt = ((two_bytes[0] as u32) << 8) + (two_bytes[1] as u32);

            // Rejection sampling: accept if elt < k * q
            if elt < K * (Q as u32) {
                hashed.push((elt % (Q as u32)) as u16);
                i += 1;
            }
        }

        Ok(hashed)
    }

    /// Decode a Falcon public key to NTT abi.encodePacked format
    ///
    /// Returns the public key polynomial h in NTT form, abi.encodePacked(uint256[32]) format
    ///
    /// Converts a Falcon public key to ETHFALCOM Solidity format (abi.encodePacked, NTT form)
    ///
    /// NOTE:
    /// Decode Falcon public key to abi.encodePacked NTT format
    ///
    /// Falcon public key format: [header (1 byte)] + [compressed h]
    /// abi.encodePacked format: 1024 bytes (32 uint256 values × 32 bytes each, h in NTT form)
    pub fn decode_pubkey_to_ntt_packed(pubkey: &[u8]) -> Result<Vec<u8>, &'static str> {
        if pubkey.len() < 1 {
            return Err("Public key too short");
        }

        let header = pubkey[0];
        let logn = (header & 0x0F) as u32;

        if logn != 9 {
            return Err("Only Falcon-512 (logn=9) supported");
        }

        if pubkey.len() != vrfy_key_size(logn) {
            return Err("Invalid public key length");
        }

        let n = 1usize << logn; // 512

        // Decode h from compressed format
        let mut h = vec![0u16; n];
        codec::modq_decode(&pubkey[1..], &mut h).ok_or("Failed to decode public key")?;

        // Convert h to NTT form
        mq::mqpoly_ext_to_int(logn, &mut h);
        mq::mqpoly_int_to_NTT(logn, &mut h);

        // Convert h_ntt to abi.encodePacked(uint256[32]) format
        // 512 coefficients → 32 uint256 (16 coefficients per uint256, LSB-first)
        let mut packed = vec![0u8; 1024];

        for chunk_idx in 0..32 {
            let mut value = [0u8; 32]; // Big-endian uint256

            // Pack 16 coefficients into this uint256 (LSB-first)
            for coeff_idx in 0..16 {
                let h_idx = chunk_idx * 16 + coeff_idx;
                let coeff = h[h_idx];

                // Pack into uint256 at correct position (rightmost = coeff 0)
                let byte_offset = 30 - (coeff_idx * 2); // Rightmost bytes first
                value[byte_offset] = (coeff >> 8) as u8;
                value[byte_offset + 1] = coeff as u8;
            }

            // Copy to output
            packed[chunk_idx * 32..(chunk_idx + 1) * 32].copy_from_slice(&value);
        }

        Ok(packed)
    }

    /// Decode a Falcon signature to extract s2 coefficients
    ///
    /// Returns the s2 polynomial in abi.encodePacked(uint256[32]) format
    ///
    /// NOTE:
    /// Decode Falcon compressed signature to abi.encodePacked format
    ///
    /// Falcon signature format: [header (1 byte)] + [salt (40 bytes)] + [compressed s2]
    /// abi.encodePacked format: 1024 bytes (32 uint256 values × 32 bytes each)/
    pub fn decode_signature_to_packed(signature: &[u8]) -> Result<Vec<u8>, &'static str> {
        if signature.len() < 41 {
            return Err("Signature too short");
        }

        let header = signature[0];
        let logn = (header & 0x0F) as u32;

        if logn != 9 {
            return Err("Only Falcon-512 (logn=9) supported");
        }

        let n = 1usize << logn; // 512
        let compressed_s2 = &signature[41..];

        // Decompress s2 using fn-dsa's codec
        let mut s2 = vec![0i16; n];
        if !codec::comp_decode(compressed_s2, &mut s2) {
            return Err("Failed to decompress signature");
        }

        // Convert s2 to abi.encodePacked(uint256[32]) format
        // 512 coefficients → 32 uint256 (16 coefficients per uint256, LSB-first)
        let mut packed = vec![0u8; 1024];

        for chunk_idx in 0..32 {
            let mut value = [0u8; 32]; // Big-endian uint256

            // Pack 16 coefficients into this uint256 (LSB-first)
            for coeff_idx in 0..16 {
                let s2_idx = chunk_idx * 16 + coeff_idx;
                let coeff = s2[s2_idx];

                // Convert signed i16 to unsigned u16 (mod q)
                let coeff_u16 = if coeff < 0 {
                    (12289 + coeff as i32) as u16
                } else {
                    coeff as u16
                };

                // Pack into uint256 at correct position (rightmost = coeff 0)
                let byte_offset = 30 - (coeff_idx * 2); // Rightmost bytes first
                value[byte_offset] = (coeff_u16 >> 8) as u8;
                value[byte_offset + 1] = coeff_u16 as u8;
            }

            // Copy to output
            packed[chunk_idx * 32..(chunk_idx + 1) * 32].copy_from_slice(&value);
        }

        Ok(packed)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_deterministic_32_bytes() {
            let mut xof = KeccakXOF::default();
            xof.update(b"test input").unwrap();
            xof.flip().unwrap();
            let output = xof.read(32).unwrap();

            let expected =
                hex::decode("5b9e99370fa4b753ac6bf0d246b3cec353c84a67839f5632cb2679b4ae565601")
                    .unwrap();
            assert_eq!(
                output, expected,
                "KeccakPRNG output mismatch for 'test input' (32 bytes)"
            );
        }

        #[test]
        fn test_deterministic_64_bytes_second_half() {
            let mut xof = KeccakXOF::default();
            xof.update(b"test input").unwrap();
            xof.flip().unwrap();
            let output = xof.read(64).unwrap();

            // Check the second half (bytes 32-64)
            let expected_second_half =
                hex::decode("569857b781dd8b81dd9cb45d06999916742043ff52f1cf165e161bcc9938b705")
                    .unwrap();
            assert_eq!(
                &output[32..],
                &expected_second_half[..],
                "KeccakPRNG second half mismatch"
            );
        }

        #[test]
        fn test_testinput_no_space() {
            let mut xof = KeccakXOF::default();
            xof.update(b"testinput").unwrap();
            xof.flip().unwrap();
            let output = xof.read(32).unwrap();

            let expected =
                hex::decode("120f76b5b7198706bc294a942f8d17467aadb2bb1fa2cc1fecadbaba93c0dd74")
                    .unwrap();
            assert_eq!(
                output, expected,
                "KeccakPRNG output mismatch for 'testinput'"
            );
        }

        #[test]
        fn test_incremental_inject() {
            // Inject "testinput" as one chunk
            let mut xof1 = KeccakXOF::default();
            xof1.update(b"testinput").unwrap();
            xof1.flip().unwrap();
            let output1 = xof1.read(32).unwrap();

            // Inject "test" then "input" as two chunks
            let mut xof2 = KeccakXOF::default();
            xof2.update(b"test").unwrap();
            xof2.update(b"input").unwrap();
            xof2.flip().unwrap();
            let output2 = xof2.read(32).unwrap();

            assert_eq!(
                output1, output2,
                "Incremental inject should produce same output"
            );
        }

        #[test]
        fn test_multiple_extractions() {
            let mut xof = KeccakXOF::default();
            xof.update(b"test sequence").unwrap();
            xof.flip().unwrap();

            let output1 = xof.read(16).unwrap();
            let output2 = xof.read(16).unwrap();
            let output3 = xof.read(16).unwrap();

            let expected1 = hex::decode("9e96b1e50719da6f0ea5b664ac8bbac5").unwrap();
            let expected2 = hex::decode("eb409b4db770b124363b393a0c96b5d6").unwrap();
            let expected3 = hex::decode("1be071eca45961aca979e88e3784a751").unwrap();

            assert_eq!(output1, expected1, "First extraction mismatch");
            assert_eq!(output2, expected2, "Second extraction mismatch");
            assert_eq!(output3, expected3, "Third extraction mismatch");

            // All three should be different
            assert_ne!(output1, output2);
            assert_ne!(output2, output3);
            assert_ne!(output1, output3);
        }

        #[test]
        fn test_extract_2_2_vs_4() {
            let mut xof1 = KeccakXOF::default();
            xof1.update(b"Danette").unwrap();
            xof1.flip().unwrap();
            let out1a = xof1.read(2).unwrap();
            let out1b = xof1.read(2).unwrap();
            let combined1 = [&out1a[..], &out1b[..]].concat();

            let mut xof2 = KeccakXOF::default();
            xof2.update(b"Danette").unwrap();
            xof2.flip().unwrap();
            let out2 = xof2.read(4).unwrap();

            assert_eq!(combined1, out2, "Reading 2+2 should equal reading 4");
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

#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
cpufeatures::new!(cpuid_avx2, "avx2");

/// Do a rutime check for AVX2 support (x86 and x86_64 only).
///
/// This is a specialized subcase of the is_x86_feature_detected macro,
/// except that this function is compatible with `no_std` builds.
#[cfg(all(
    not(feature = "no_avx2"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
pub fn has_avx2() -> bool {
    cpuid_avx2::get()
}
