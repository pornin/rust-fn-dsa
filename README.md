# FN-DSA (in Rust)

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

**2026-07-22:** The implementation has been adjusted to match a "best
guess" at what the FN-DSA draft will be when published. If the guess is
incorrect and the actual FN-DSA draft differs, then this implementation
will be adjusted again, which may further break backward compatibility.
See [the C implementation](https://github.com/pornin/c-fn-dsa) for
details.

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
      9    512      1345       897       666     level I (~128 bits)
     10   1024      2369      1793      1280     level V (~256 bits)

      2      4        77         8        47     none
      3      8        89        15        52     none
      4     16       113        29        63     none
      5     32       161        57        82     none
      6     64       241       113       122     none
      7    128       417       225       200     very weak
      8    256       705       449       356     presumed weak
```

Note that the sizes are fixed. Moreover, all keys and signatures use
a canonical encoding which is enforced by the code, i.e. it should not
be feasible to modify the encoding of an existing public key or a
signature without changing its mathematical value.

## Optimizations, Platforms and Features

The base implementation uses only integer computations, which are
presumed safe, and constant-time to the extent that such things are
possible (this should be considered a "best-effort" implementation,
since recent LLVM versions have become pretty good at inferring that
values are really Booleans in digsuise, and of course the same could
apply to any JIT compilation layer, either hidden in-silicon, or as part
of a virtual machine implementation, e.g. is using WASM). On some
architectures, some optimizations are applied:

  - **x86 and x86_64:** if SSE2 support is detected at compile-time,
    then SSE2 opcodes are used for floating-point computations in
    signature generation. Note that SSE2 is part of the ABI for `x86_64`,
    but is also enabled by default for `x86`.

  - **aarch64:** on ARMv8 (64-bit), if NEON support is detected at
    compile-time, then NEON opcodes are used, for a result similar to
    what is done on `x86` with SSE2. NEON is part of the ABI for
    `aarch64`.

  - **riscv64:** on 64-bit RISC-V systems, we assume that the target
    implements the D extension (double-precision floating-point). Note
    that the compiler, by default, assumes RV64GC, i.e. that I, M, A, F,
    D and C are supported.

On top of that, on `x86` and `x86_64`, a second version of the code is
compiled and automatically used if a _runtime_ test shows that the
current CPU supports AVX2 (and it was not disabled by the operating
system). AVX2 optimizations improve performance of keygen, signing, and
verifying (the performance boost over SSE2 for signing is rather slight,
but for keygen and verifying it almost halves the cost).

The following features, which are not enabled by default, can be used to
modify the code generation:

  - `no_avx2`: do not include the AVX2-optimized code. Using this option
    also removes the runtime test for CPU support of AVX2 opcodes; it
    can be used if compiled code footprint is an issue. SSE2 opcodes will
    still be used.

  - `div_emu`: on `riscv64`, do not use the hardware implementation for
    floating-point divisions. This feature was included because some
    RISC-V cores, in particular the SiFive U74, have constant-time
    additions and multiplications, but division cost varies depending on
    the input operands.

  - `sqrt_emu`: this is similar to `div_emu` but for the square root
    operation. On the SiFive U74, enabling both `div_emu` and `sqrt_emu`
    increases the cost of signature generation by about 25%.

  - `small_context`: reduce the in-memory size of the signature generator
    context (`SigningKey` instance); for the largest degree (n = 1024),
    using `small_context` shrinks the context size from about 114 kB to
    about 82 kB, but it also increases signature cost by about 25%.

Of these options, only `no_avx2` has any impact on keygen or verifying.

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

On an Intel i5-8259U ("Coffee Lake", a Skylake variant), with Rust 1.97.1,
the following performance is achieved (in clock cycles):

```
    degree    keygen      sign     +sign    verify   +verify
   ----------------------------------------------------------
      512     8910000   1130000    933000    63300    46800
     1024    34500000   2140000   1860000   124000    91400
```

`+sign` means generating a new signature on a new message but with the
same signing key; this allows reusing some computations that depend on
the key but not on the message. Similary, `+verify` is for verifying
additional signatures relatively to the same key. We may note that
this is about as fast as RSA-2048 for verification, but about 2.5x
faster for signature generation, and many times faster for key pair
generation.

On an ARM Cortex-A76 CPU (Broadcom BCM2712C1), performance is as
follows:

```
    degree    keygen      sign     +sign    verify  +verify
   ---------------------------------------------------------
      512    16600000   1150000    855000   119000   103000
     1024    62200000   2250000   1710000   237000   206000
```

These figures are very close to what can be achieved on the Intel Coffee
Lake when compiling with `no_avx2`, i.e. the Cortex-A76 with NEON
achieves about cycle-to-cycle parity with the Intel with SSE2, but the
Intel can get an extra edge with AVX2. Some newer/larger ARM CPUs may
implement the SVE or SVE2 opcodes, with extended register size, but they
seem to be a rarity (apparently, even the Apple M1 to M4 CPUs stick to
NEON and do not support SVE).

On a 64-bit RISC-V system (SiFive U74 core), which is much smaller/low-end
than the two previous, the following is achieved:

```
    degree    keygen      sign     +sign    verify  +verify
   ---------------------------------------------------------
      512    39900000   4250000   3290000   296000   252000
     1024   170000000   8510000   6850000   605000   508000
```

To put things into perspective, FN-DSA/512 is substantially faster than
RSA-2048 on all these systems (RSA is especially efficient for signature
verification, and OpenSSL's implementation on x86 has been very
optimized along the years, so that on the `x86_64` RSA-2048 verification
is about as fast as FN-DSA/512; for all other operations, FN-DSA/512 is
faster, sometimes by a large amount, e.g. on the ARM Cortex-A76
signature generation with this code is about 8 times faster than
OpenSSL's RSA-2048).

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
