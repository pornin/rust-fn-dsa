# FN-DSA

FN-DSA is a new *upcoming* post-quantum signature scheme, currently
being defined by NIST as part of their [Post-Quantum Cryptography
Standardization](https://csrc.nist.gov/pqc-standardization) project.
FN-DSA is based on the [Falcon](https://falcon-sign.info/) scheme.

**WARNING:** As this file is being written, no FN-DSA draft has been
published yet, and therefore what is implemented here is *not* the
"real" FN-DSA; such a thing does not exist yet. When FN-DSA gets
published (presumably as a draft first, but ultimately as a "final"
standard), this implementation will be adjusted accordingly.
Correspondingly, it is expected that **backward compatiblity will NOT be
maintained**, i.e. that keys and signatures obtained with this code may
cease to be accepted by ulterior versions. Only version 1.0 will provide
such stability, and it will be published only after publication of the
final FN-DSA standard.

## Sizes

FN-DSA (Falcon) nominally has two standard "degrees" `n`, equal to 512
and 1024, respectively. The implementation also supports "toy" versions
with lower degrees 4 to 256 (always a power of two); these variants are
meant for research and test purposes only. The API rejects use of such
toy versions unless the caller asks for them explicitly. In the API, the
degree is provided as parameter in a logarithmic scale, under the name
`logn`, with the rule that `n = 2^logn` (hence, `logn` is equal to 9 for
degree 512, 10 for degree 1024). Two relevant constants are defined,
`FN_DSA_LOGN_512` and `FN_DSA_LOGN_1024`, with values 9 and 10,
respectively.

Sizes of signing (private) keys, verifying (public) keys, and signatures
are as follows (depending on degree):

```
    logn    n     sign-key  vrfy-key  signature  security
   ------------------------------------------------------------------
      9    512      1281       897       666     level I (~128 bits)
     10   1024      2305      1793      1280     level V (~256 bits)

      2      4        13         8        47     none
      3      8        25        15        52     none
      4     16        49        29        63     none
      5     32        97        57        82     none
      6     64       177       113       122     none
      7    128       353       225       200     very weak
      8    256       641       449       356     presumed weak
```

Note that the sizes are fixed. Moreover, all keys and signatures use
a canonical encoding which is enforced by the code, i.e. it should not
be feasible to modify the encoding of an existing public key or a
signature without changing its mathematical value.

## Performance

This implementation achieves performance similar to that obtained with C
code. The key pair generation code is a translation of the
[ntrugen](https://github.com/pornin/ntrugen) implementation. On x86
CPUs, AVX2 opcodes are used for better performance if the CPU is
detected to support them (the non-AVX2 code is still included, so that
the compiled binaries can still run correctly on non-AVX2 CPUs). On
64-bit x86 (`x86_64`) and ARMv8 (`aarch64` and `arm64ec`) platforms, the
native floating-point type (`f64`) is used in signature generation,
because on such platforms the type maps to the hardware support which
follows the correct strict IEEE-754 rounding rules; on other platforms
(including 32-bit x86 and 32-bit ARM), an integer-only implementation is
used, which emulates the expected IEEE-754 primitives. Key pair
generation and signature verification use only integer operations.

On an Intel i5-8259U ("Coffee Lake", a Skylake variant), the following
performance is achieved (in clock cycles):

```
    degree    keygen      sign     +sign    verify  +verify
   ---------------------------------------------------------
      512    11800000    840000    645000    75000    52000
     1024    45000000   1560000   1280000   151000   105000
```

`+sign` means generating a new signature on a new message but with the
same signing key; this allows reusing some computations that depend on
the key but not on the message. Similary, `+verify` is for verifying
additional signatures relatively to the same key. We may note that
this is about as fast as RSA-2048 for verification, but about 2.5x
faster for signature generation, and many times faster for key pair
generation.

## Specific Variant

In the original Falcon scheme, the signing process entails generation
of a random 64-byte nonce, and that nonce is hashed together with the
message to sign with SHAKE256; the output is then converted to a
polynomial `hm` with rejection sampling:

```
    hm <- SHAKE256( nonce || message )
```

This mode is supported by the implementation (using the custom
`HASH_ID_ORIGINAL_FALCON` hash identifier); this is an obsolescent
feature and support of the original Falcon design is expected to be
dropped at some point. For enhanced functionality (support of pre-hashed
messages) and better security in edge cases, the implementation
currently implements what is my best guess of how FN-DSA will be
defined, using the existing ML-DSA ([FIPS
204](https://csrc.nist.gov/pubs/fips/204/final)) as a template. The
message is either "raw", or pre-hashed with a collision-resistant
hash function. If the message is "raw" then the `hm` polynomial is
obtained as:

```
    hm <- SHAKE256( nonce || hpk || 0x00 || len(ctx) || ctx || message )
```

where:

  - `hpk` is the SHAKE256 hash (with a 64-byte output) of the encoded
    public key
  - `0x00` is a single byte
  - `ctx` is an arbitrary domain separation context string of up to 255
    bytes in length
  - `len(ctx)` is the length of `ctx`, encoded over a single byte

The message may also be pre-hashed with a hash function such as SHA3-256,
in which case only the hash value is provided to the FN-DSA implementation,
and `hm` is computed as follows:

```
    hm <- SHAKE256( nonce || hpk || 0x01 || len(ctx) || ctx || id || hv )
```

where:

  - `id` is the DER-encoded ASN.1 OID that uniquely identifies the hash
    function used for pre-hashing the message
  - `hv` is the pre-hashed message

Since SHAKE256 is a "good XOF", adding `hpk` and `ctx` to the input,
with an unambiguous encoding scheme, cannot reduce security; therefore,
the "raw message" variant as shown above is necessarily at least as
secure as the original Falcon design. In the case of pre-hashing, this
obviously adds the requirement that the pre-hash function must be
collision resistant, but it is otherwise equally obviously safe. Note
that ASN.1/DER encodings are self-terminated, thus there is no
ambiguousness related to the concatenation of `id` and `hv`.

Adding `hpk` to the input makes FN-DSA achieve [BUFF
security](https://eprint.iacr.org/2024/710), a property which is not
necessarily useful in any given situation, but can be obtained here at
very low cost (no change in size of either public keys or signatures,
and only some moderate extra hashing). The `hpk` value is set to 64
bytes just like in ML-DSA.

As an additional variation: the Falcon signature generation works in a
loop, because it may happen, with low probability, that either the
sampled vector is not short enough, or that the final signature cannot
be encoded within the target signature size (which is fixed). In either
case, with the original Falcon, the process restarts but reuses the same
nonce (hence the same `hm` value). In the variant implemented here
(outside of the "original Falcon" mode), a new nonce is generated when
such a restart happens. Though the original Falcon method is not known
to be unsafe in any way, this nonce regeneration has been [recently
argued](https://eprint.iacr.org/2024/1769) to make it much easier to
prove some security properties of the scheme. Since restarts are rare,
this nonce regeneration does not imply any noticeable performance hit.
In any case, regenerating the nonce cannot harm security.

## Usage

The code is split into five crates:

  - `fn-dsa` is the toplevel crate; it re-exports all relevant types,
    constants and functions, and most applications will only need to
    use that crate. Internally, `fn-dsa` pulls the other four crates
    as dependencies.

  - `fn-dsa-kgen` implements key pair generation.

  - `fn-dsa-sign` implements signature generation.

  - `fn-dsa-vrfy` implements signature verification.

  - `fn-dsa-comm` provides some utility functions which are used by
    all three other crates.

The main point of this separation is that some applications will need
only a subset of the features (typically, only verification) and may
wish to depend only on the relevant crates, to avoid pulling the entire
code as a dependency (especially since some of the unit tests in the key
pair generation and signature generation can be somewhat expensive to
run).

An example usage code looks as follows:

```rust
use rand_core::OsRng;
use fn_dsa::{
    sign_key_size, vrfy_key_size, signature_size, FN_DSA_LOGN_512,
    KeyPairGenerator, KeyPairGeneratorStandard,
    SigningKey, SigningKeyStandard,
    VerifyingKey, VerifyingKeyStandard,
    DOMAIN_NONE, HASH_ID_RAW,
};

// Generate key pair.
let mut kg = KeyPairGeneratorStandard::default();
let mut sign_key = [0u8; sign_key_size(FN_DSA_LOGN_512)];
let mut vrfy_key = [0u8; vrfy_key_size(FN_DSA_LOGN_512)];
kg.keygen(FN_DSA_LOGN_512, &mut OsRng, &mut sign_key, &mut vrfy_key);

// Sign a message with the signing key.
let mut sk = SigningKeyStandard::decode(&sign_key).or_else(...);
let mut sig = vec![0u8; signature_size(sk.get_logn())];
sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, b"message", &mut sig);

// Verify a signature with the verifying key.
match VerifyingKeyStandard::decode(&vrfy_key) {
    Some(vk) => {
        if vk.verify(&sig, &DOMAIN_NONE, &HASH_ID_RAW, b"message") {
            // signature is valid
        } else {
            // signature is not valid
        }
    }
    _ => {
        // could not decode verifying key
    }
}
```
