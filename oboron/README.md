# Oboron

[![Crates.io](https://img.shields.io/crates/v/oboron.svg)](https://crates.io/crates/oboron)
[![Documentation](https://docs.rs/oboron/badge.svg)](https://docs.rs/oboron)
[![License:  MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.77-blue.svg)](https://blog.rust-lang.org/2023/11/16/Rust-1.77.0.html)

Oboron is a general-purpose encryption library focused on developer
ergonomics:
- *String in, string out*: Encryption and encoding are bundled into
  one seamless process
- *Standardized interface*: Multiple encryption algorithms accessible
  through the same API
- *[Unified key management](#key-management)*: A single 512-bit key
  works across all schemes with internal extraction to algorithm-specific
  keys
- *[Prefix-focused entropy](#referenceable-prefixes)*: Maximizes
  entropy in initial characters for referenceable short prefixes (similar
  to Git commit hashes)

In essence, Oboron provides an accessible interface over established
cryptographic primitives—implementing AES-CBC, AES-GCM-SIV, and AES-SIV—
with careful attention to output characteristics.  By reversing
ciphertext in select schemes, entropy is concentrated in the output's
prefix, enabling short, unique references.

Key Advantages:
- *Referenceable prefixes*: High initial entropy enables Git-like short
  IDs
- *Simplified workflow*: No manual encoding/decoding between encryption
  stages
- *Performance optimized* for short-string use cases
- *Compact outputs*

## Contents

- [Quick Start](#quick-start)
- [Formats](#formats)
- [Algorithm](#algorithm)
- [Key Management](#key-management)
- [Properties](#properties)
- [Applications](#applications)
- [Rust API Overview](#rust-api-overview)
- [Compatibility](#compatibility)
- [Getting Help](#getting-help)
- [License](#license)

## Quick Start

Add to your `Cargo.toml`:
```toml
[dependencies]
oboron = "1.0" # default features
# or with minimal features:
# oboron = { version = "1.0", features = ["aasv", "apsv"] }
```

Generate your 512-bit key (86 base64 characters) using the keygen script
(always included with the crate, not feature-gated):
```shell
cargo run --bin keygen
```
or in your code:
```rust
let key = oboron::generate_key();
```
then save the key as an environment variable.

Use AasvC32 (a secure scheme, 256-bit encrypted with AES-SIV, encoded
using Crockford's base32 variant) for enc/dec:
```rust
use oboron::{AasvC32, ObtextCodec};

let key = env::var("OBORON_KEY")?; // get the key

let ob = AasvC32::new(&key)?; // create ObtextCodec instance

let ot = ob.enc("hello, world")?; // encrypt+encode
let pt2 = ob.dec(&ot)?; // decode+decrypt

println!("obtext: {}", ot);
// "obtext: cbv74r1m7a7cf8n6gzdy6tf2vjddkhwdtwa5ssgv78v5c1g"

assert_eq!(pt2, "hello, world");
```

## Formats

Oboron provides various formats for encrypted text (obtext).  Each format
combines a cryptographic scheme with a string encoding.

More specifically, obtext construciton is a multi-stage process:
1. *Encryption*: Plaintext UTF-8 string encrypted to ciphertext bytes
2. *Prefix restructuring* (select schemes only)
3. *Scheme byte*: A byte identifying the encryption scheme is appended
   (enabling scheme auto-detection on decoding)
4. *Encoding*: The binary payload is encoded to a string

*The encryption stage* is implemented using standard cryptographic
algorithms, each variant providing the basis for an Oboron *scheme*.

*Prefix restucturing* is a customization of the standard ciphertext
in order to achieve the prefix refenrenceability property we are used to
from using short Git references.  This stage is only applied to
cryptographic algorithms that do not inherently exhibit the avalanche
property.  Bytes are adjusted to to maximize entropy in output prefixes,
creating a prefix-localized avalanche effect for prefix entropy. This may
be achieved by byte reversal and/or an XOR operation.  Schemes that
customize the cryptographic primitive's ciphertext in this way are
designated with an `x` suffix (e.g., `ob:zrbcx`)

*The encoding stage* offers several supported string encodings: base32
(two variants: standard and Crockford), base64, and hexadecimal.

A combination of a scheme and encoding is referred to as an Oboron
*format*.  Given an encryption key, the format thus uniquely specifies
the complete transformation from a plaintext string to an encoded
"obtext" string.

Formats are represented by compact identifiers, either:
- `ob:{scheme}.{encoding}`, prefixed by the namespace-prefixed identifier
  `ob:` (URI-like syntax), or
- `{scheme}.{encoding}`, when the context is clear and the namespace
  prefix is not necessary.

For example:
- `ob:zrbcx.c32` - `ob:zrbcx` scheme, Crockford base32 encoding
- `ob:upbc.b32` - `ob:upbc` scheme, standard RFC 4648 base32 encoding
- `ob:aags.hex` - `ob:aags` scheme, hexadecimal encoding
- `ob:apsv.b64` - `ob:apsv` scheme (`p`=probabilistic), base64 encoding

A format thus defines the complete transformation, specifying not just
the output encoding but also the encryption algorithm and payload byte
arrangement.

Terminology:
- *Scheme*: Cryptographic algorithm + mode + parameters (e.g., `aasv`)
- *Encoding*: String representation method (e.g., `.b64`)
- *Format*: Scheme + encoding = complete transformation (e.g.,
  `aasv.b64`)

**API Note**: The public interface uses `enc`/`dec` names for methods
and functions. Thus the `enc` operation comprises the full process,
including the encryption and encoding stages.

### Encodings

- `b32` - standard base32: Balanced compactness and readability,
  alphanumeric, uppercase (RFC 4648 Section 6)
- `c32` - Crockford base32: Balanced compactness and readability,
  alphanumeric, lowercase; designed to avoid accidental obscenity
- `b64` - standard URL-safe base64: Most compact, case-sensitive,
  includes `-` and `_` characters (RFC 4648 Section 5)
- `hex` - hexadecimal: Slightly faster performance (~2-3%), longest
  output

> **FAQ:** *Why use Crockford's base32 instead of the RFC standard one?*
>
> Crockford's base32 alphabet minimizes the probability of accidental
> obscenity words.  Whereas accidental obscenity is not an issue when
> working with full encrypted outputs (as any such words would be buried
> as substrings of a 28+ character long obtext), it does become a
> concern when using short prefixes.  While the hexadecimal encoding is
> safe in this regard, the standard base32 is not.

Even though Crockford's base32 encoding is recommended, the standard
base32 encoding (RFC 4648) is also fully supported (`*.b32` formats),
just like base64url (`*.b64`) and hex (`*.hex`).

### Schemes

A scheme defines the encryption algorithm, its mode (deterministic or
probabilistic), and any other parameters for the cryptographic cipher, or
custom post-processing (optional byte reversal for prefix entropy).

#### Scheme Tiers

Schemes are classified into *tiers*, which are encapsulated in the scheme
ID prefix:
- `a` - authenticated (e.g., `ob:aasv`, `ob:apgs`)
- `u` - unauthenticated (e.g., `ob:upbc`)
- `z` - insecure, obfuscation only (e.g., `ob:zrbcx`)

The second letter of the scheme ID further describe the properties of the
scheme:
- `.a..` - avalanche, deterministic (e.g., `ob:aasv`, `ob:aags`)
- `.r..` - referenceable / prefix-restricted avalanche, deterministic
  (e.g., `zrbcx`)
- `.d..` - deterministic without avalanche effect (uniform or localized),
  not suitable for prefix-referencing
- `.p..` - probabilistic: (e.g.,
  `ob:apsv`, `ob:apgs`, `ob:upbc`)

The probabilistic schemes produce a different output in each encryption
pass.  Thus, they are not suitable for referencing unless using lookup
tables.  The referenceability property Oboron is aiming to achieve is a
hash-like inherent property of the plaintext deterministically revealed
by the algorithm.

The remaining two letters in `a`-tier schemes represent the algorithm
used:
- `gs` = GCM-SIV (AES-GCM-SIV)
- `sv` = SIV (AES-SIV)
- `bc` = CBC (AES-CBC)

Summary table:

| Scheme     | Algorithm   | Deterministic? | Authenticated? | Notes |
| :--------- | :---------- | :------------- | :------------- | :---- |
| `ob:aags`  | AES-GCM-SIV | Yes            | Yes            |       |
| `ob:aasv`  | AES-SIV     | Yes            | Yes            |       |
| `ob:apgs`  | AES-GCM-SIV | No             | Yes            |       |
| `ob:apsv`  | AES-SIV     | No             | Yes            |       |
| `ob:upbc`  | AES-CBC     | No             | No             |       |
| `ob:zrbcx` | AES-CBC     | Yes            | No             | INSECURE, uses constant IV. Prioritizes determinism and performance over security. |

Key Concepts:
* *Deterministic:* Same input (key + plaintext) always produces same
  output. Useful for idempotent operations, lookup keys, caching, or
  hash-like references.
* *Probabilistic:* Incorporates a random nonce, producing different
  ciphertexts for identical plaintexts.  Standard for most cryptographic
  use cases (non-cached, not used as hidden references).
* *Authenticated:* Ciphertext is tamper-proof.  Any modification (even
  a single bit flipped) results in decryption failure.

Other than `a`-, `u`-, and `z`-schemes, you may also encounter these
special-purpose schemes:
- `ob:mock1`, `ob:mock2` - testing/identity transforms
  (non-cryptographic)
- `ob:legacy`- legacy scheme for backwards compatibility

#### Important Scheme Security Notes

All schemes use well-regarded cryptographic primitives. However, note
the following:

* `ob:zrbcx` and `ob:upbc` *are not authenticated* and vulnerable to
  tampering.
* **SECURITY WARNING:** **`ob:zrbcx` is cryptographically broken** due to
  its use of a constant IV (by design, in order to achieve deterministic
  output).  This scheme leaks equality and prefix structure and is
  vulnerable to chosen-plaintext attacks.  
  **Do not use `ob:zrbcx` for encrypting sensitive data** or any
  application where confidentiality or integrity matters.
  **Use `zrbcx` only for** maximum compactness and strong prefix entropy
  in non-security-critical contexts (e.g., development or obfuscation).
  For sensitive data, **always use authenticated schemes** (`a`-tier:
  `ob:aags` or `ob:aasv`).

We reiterate that the first letter in the scheme ID is a critically
important one (see [Scheme Tiers](#scheme-tiers) above):
- ***`z`-tier schemes should be viewed as obfuscation, not encryption.***
  (mnemonic: "zero protection")
- ***For encryption applications, always use `a` (authenticated), or
  `u`-tier (unauthenticated) schemes***


> **FAQ:** *Why include an insecure scheme?*
> 
> Oboron is a general purpose library whose utility and application
> domain extend beyond encryption.  For applications such as obfuscation
> or hashing alternative (see Application section below), `z`-schemes
> are sufficient, while outperforming `a`-schemes by 2x to 4x.  In our
> benchmarks, `ob:zrbcx` shows ~40% lower latency than SHA256 for short
> inputs on modern x86 CPUs.

> FAQ: *Why do schemes not include the traditional 128/256/... bit
> encryption designations?*
> Oboron uses the strongest standard encryption with its 512-bit key.
> Both AES-GCM-SIV and AES-SIV use 256-bit encryption (AES-SIV uses a
> 512-bit key for two instance layers, but each is 256-bit encryption.)
> AES-CBC uses 128-bit encryption.


### Secure Defaults

Oboron presets (default features) only include secure schemes.  In order
to use `z`-schemes, you need to enable them explicitly in your
`Cargo.toml`.

The same holds for the `keyless` feature: while it is handy for
development and quick obfuscation (using a hard-coded key), this feature
is not enabled by default, and must be included explicitly in your
`Cargo.toml`.


## Algorithm

Oboron combines encryption and encoding in a single operation, requiring
specific terminology:

- **enc**: Combines encryption and encoding stages
- **dec**: Combines decoding and decryption stages
- **obtext**: The output of the `enc` operation (encryption + encoding),
  distinct from cryptographic ciphertext

The cryptographic ciphertext (bytes, not string) is an internal
implementation detail, not exposed in the public API.

The high-level process flow is:
```
enc operation:
    [plaintext] (string) -> encryption -> [ciphertext] (bytes) -> encoding -> [obtext] (string)

dec operation:
    [obtext] (string) -> decoding -> [ciphertext] (bytes) -> decryption -> [plaintext] (string)
```

The above diagram is conceptual; actual implementation includes
scheme-specific steps like scheme byte appending and optional ciphertext
reversal. With this middle-step included, the diagram becomes:
```
enc operation:
    [plaintext] -> encryption -> [ciphertext] -> oboron pack -> [payload] -> encoding -> [obtext] 

dec operation:
    [obtext] -> decoding -> [payload] -> oboron unpack -> [ciphertext] -> decryption -> [plaintext]
```

### Payload Structure

The payload construction is what gives the obtext its Oboron flavor. The
two goals achieved with the payload structure are:
1. Prefix-restructured ciphertext in schemes in which this improves the
   prefix entropy
2. Including a scheme marker which allows scheme autodetection in
   decoding

The first step gives a transformed ciphertext:
- `[ciphertext'] = [prefix_restr(ciphertext)]` for schemes with `x`
  suffix (`zrbcx`),
- `[ciphertext'] = [ciphertext]` for all other schemes (no change).

The second step is achieved by appending a single byte marker to the
payload prior to encoding.

- `[payload] = [ciphertext'][marker]`

This marker byte is the result of an XOR operation on a constant byte
identifier for the scheme (e.g., `oboron::constants::ZRBCX_BYTE = 0x02`),
and the first byte of the transformed ciphertext (`ciphertext'[0]`).

- `marker = ciphertext'[0] XOR scheme-byte`

The purpose of this XOR is entropy mix-in: by using the constant scheme
byte directly, all `zrbcx` obtexts would have a constant suffix.


> **FAQ:** *Why do some schemes reverse the ciphertext, while others
> don't?*
>
> The prefix restructuring step in `zrbcx` scheme XORs the first AES
> block with the final one, ensuring maximal entropy in the encoded
> prefix.  This scheme use AES-CBC, a block-chaining algorithm: each
> 16-byte block's ciphertext becomes the IV for the next.  Thus, while
> the first ciphertext block contains only the entropy from the first
> plaintext block, the final block accumulates entropy from the entire
> message.  XOR-ing the first plaintext block with the last one brings
> this entropy to the front, creating a prefix-localized avalanche
> effect.

### Padding Design

Oboron's CBC schemes use a custom padding scheme optimized for UTF-8
strings:
- Uses 0x01 byte for padding (Unicode control character, never valid in
  UTF-8)
- No padding needed when plaintext ends at block boundary
- 5% performance improvement over PKCS#7
- Smaller output size compared to PKCS#7

**Rationale:** Oboron exclusively processes UTF-8 strings, not arbitrary
binary data.  The 0x01 padding byte can never appear in valid UTF-8
input, ensuring unambiguous decoding.  Therefore, under the UTF-8 input
constraint, this padding is functionally equivalent to PKCS#7 and does
not weaken security.  The UTF-8 input constraint is guaranteed by the
Rust type system - all `enc` functions and methods accept a `&str`,
therefore passing an input that is not valid UTF-8 would not be allowed
by the Rust compiler.  This UTF-8 guarantee is enforced at compile time,
eliminating padding ambiguity errors at runtime.


## Key Management

### Key Partitioning Model

Oboron uses a single 512-bit master key that is partitioned, not
cryptographically derived, into algorithm-specific subkeys.

This design is intentional and prioritizes low latency for short-string
encryption. No hash-based KDF (e.g., HKDF) is used, as this would
increase per-operation latency by several multiples and dominate runtime
for the intended workloads.

Subkeys are fixed, non-adaptive slices of the master key. With the
exception of `ob:aasv` / `ob:apsv` (AES-SIV schemes), which intentionally
use the full 512-bit key, subkeys do not overlap.

This implies related-key structure by construction. Oboron does not claim
formal related-key security. The design assumes:
- The master key is generated uniformly at random
- Keys are never attacker-controlled
- Ciphertext oracles are not mixed across schemes

Under these assumptions, related-key attacks are not considered practical
for Oboron’s threat model.

The master-key is partitioned into algorithm-specific keys in the
following way:
- `ob:zrbcx`, `ob:upbc`: use the first 16 bytes (128 bits) for AES key
- `ob:zrbcx`: uses the second 16 bytes for IV
- `ob:aags`, `ob:apgs`: use the last 32 bytes (256 bits) for AES-GCM-SIV key
- `ob:aasv`, `ob:apsv`: use the full 64 bytes (512 bits) for AES-SIV key

The master key never leaves your application. Algorithm-specific keys
are extracted on-the-fly and never cached or stored.

> **FAQ:** *Why use a single key across all schemes?*
>
> Oboron uses key extraction to generate algorithm-specific keys from a
> single master key.  This approach:
> - Simplifies deployment: Store one key instead of multiple
> - Reduces errors: No risk of mismatching keys to algorithms

### Key Format

The default key input format is base64. This is consistent with Oboron's
strings-first API design. As any production use will typically read
the key from an environment variable, this allows the string format
to be directly fed into the constructor.

The base64 format was chosen for its compactness, as an 86-character
base64 key is easier to handle manually (in secrets or environment
variables management UI) than a 128-character hex key.

While any 512-bit key is accepted by Oboron, the keys generated with
`oboron::generate_key()` or `cargo run --bin keygen` do not include any
dashes or underscores, in order to ensure the keys are double-click
selectable, and to avoid any human visual parsing due to underscores.

#### Valid Base64 Keys

**Important technical detail:** Not every 86-character base64 string is a
valid 512-bit key.  Since 512 bits requires 85.3 bytes when
base64-encoded, the final character is constrained by padding
requirements. For correct encoding, the last character must be one of
`A`, `Q`, `g`, or `w`.  When generating keys, it is recommended to use
one of the following methods:
1. use Oboron's key generator (`oboron::generate_key()` or
  `cargo run --bin keygen`)
2. generate random 64 bytes, then encode as base64
3. generate random 128 hex characters, then convert hexadecimal to base64

There is also a way avoid the encoding/conversion to base64 in options 2
and 3 above: While base64 keys are used in the primary interface, Oboron
also provides support for working with keys in hexadecimal or raw bytes
formats via `*from_bytes*` and `*from_hex_key*` method and function
variants, but these interfaces are feature-gated:
- to use the hex keys interface, enable the `hex-keys` feature,
- to use the bytes heys interface, enable the `bytes-keys` feature.


## Properties

### Referenceable Prefixes

If you've used Git, you're already familiar with prefix entropy: you can
reference commits with just the first 7 characters of their SHA1 hash
(like `git show a1b2c3d`). This works because cryptographic hashes
distribute entropy evenly across all characters.

Oboron achieves similar prefix quality through careful byte arrangement.
Consider these comparisons:

**Short Reference Strength:**
- Git SHA1 (7 hex chars): 28 bits of entropy
- Oboron (6 base32 chars): 30 bits of entropy
- Oboron (7 base32 chars): 35 bits of entropy

**Collision Resistance:**
For a 1-in-a-million chance of two items sharing the same prefix:
- Git 7-char prefix (28 bits): After ~38 items
- Oboron 6-char prefix (30 bits): After ~52 items
- Oboron 7-char prefix (35 bits): After ~262 items

(These estimates assume uniform ciphertext distribution under a fixed
key.)

**Practical Implications:**
In a system with 1,000 unique items using 7-character Oboron prefixes:
- Collision probability: ~0.007% (1 in 14,000)
- In a system with 10,000 items: ~0.7% (1 in 140)

This enables Git-like workflows for moderate-scale systems: database IDs,
URL slugs, or commit references that are both human-friendly and
cryptographically robust for everyday use cases.

### Deterministic Injectivity

Comparing the prefix collision resistance in the previous section, Oboron
and standard hashing algorithms were compared against each other.  But
when we consider the full output, then they are not on the same plane:
while SHA1 and SHA256 collision probabilities are astronomically small,
they are never zero, and the birthday paradox risk can become a factor
in large systems even with the full hash.  Oboron, on the other hand,
is a symmetric encryption library, and as such it is collision free
(although applying this label to an encryption library is awkward):
for a fixed key and within the block-cipher domain limits, Oboron is
injective (one-to-one), i.e. two different inputs can never result in the
same output.

### Performance Comparison

Oboron is optimized for performance with short strings, often exceeding
both SHA256 and JWT performance while providing reversible encryption.

> **Note:** As a general-purpose encryption library, Oboron is not a
> replacement for either JWT or SHA256.  We use those two for baseline
> comparison, as they are both standard and highly optimized libraries.
> However, as we show in the [Applications](#applications) section below,
> overlaps in applications with JWT and SHA256 are possible.

| Scheme     | 8B Encode | 8B Decode | Security      | Use Case                        |
|------------|----------:|-----------|---------------|---------------------------------|
| `ob:zrbcx` | 132 ns    | 126 ns    | Insecure      | Maximum speed + compactness     |
| `ob:aasv`  | 334 ns    | 364 ns    | Secure + Auth | Balanced performance + security |
| JWT        | 550 ns    | 846 ns    | Auth only`*`  | Signature without encryption    |
| SHA256     | 191 ns    | N/A       | One-way       | Hashing only                    |

`*` **Note**: JWT baseline (HMAC-SHA256) provides authentication without
encryption.  Despite comparing against our stronger **`a`-tier** (secure
+ authenticated), Oboron maintains performance advantages while providing
full confidentiality.

More detailed benchmark results are presented in a separate document:
- [BENCHMARKS.md](BENCHMARKS.md).
Data from JWT and SHA256 benchmarks
performed on the same machine is available here:
- [BASELINE_BENCHMARKS.md](BASELINE_BENCHMARKS.md)

**Performance advantages:**
- `ob:zrbcx` encoding is 4.1x faster than JWT with 4.5x smaller output
- All Oboron schemes outperform JWT for both encoding and decoding
- `ob:zrbcx` shows lower latency than SHA256+hex for short strings while
  providing reversible (cryptographically insecure) encryption

### Output Length Comparison

| Method        | Small string output length |
|---------------|----------------------------|
| `ob:zrbcx`    | 28 characters              |
| `ob:aasv`     | 34-47 characters           |
| `ob:apsv`     | 60-72 characters           |
| SHA256        | 64 characters              |
| JWT           | 150+ characters            |

A more complete output length comparison is given in the
[Appendix](#appendix-obtext-lengths).

### Scheme Selection Guidelines

- `ob:zrbcx`: Non-security-critical applications prioritizing speed and
  compactness
- `ob:aasv`: General-purpose secure encryption with deterministic output
  and compact size
- `ob:apsv`: Maximum privacy protection with probabilistic output
  (larger size due to nonce)

Choose `ob:zrbcx` when:
- Performance and compactness are primary requirements (~28 chars)
- Security requirements are minimal (obfuscation contexts)

Choose `ob:aasv` when:
- Cryptographic security with compact output is needed (~34-47 chars)
- Deterministic behavior is beneficial (lookup keys, caching)

Choose ob:apsv` when:
- Cryptographic security with maximum privacy is required (~60-72 chars)
- Hiding plaintext relationships is critical

### Feature Flags

Oboron supports optional feature flags to reduce binary size by including
only necessary encryption schemes. This is especially useful for
WebAssembly builds where bundle size matters.

**Default:** All secure production-ready schemes are enabled; `ob:zrbcx`
is not-it has to be enabled explicitly in your application.

For details on available features, scheme groups, and optimization
guidance, see [README_FEATURES.md](README_FEATURES.md).

Quick examples:
```toml
# Minimal: only aasv (deterministic AES-SIV)
oboron = { version = "1.0", default-features = false, features = ["aasv"] }

# All authenticated schemes (`a`-tier)
oboron = { version = "1.0", default-features = false, features = ["authenticated-schemes"] }

# All SIV schemes for WebAssembly
oboron = { version = "1.0", default-features = false, features = ["all-siv-schemes"] }
```

### Versioning

This crate follows semantic versioning.  Version 1.0 signifies a stable,
production-ready API with no anticipated breaking changes.  API stability
guarantees do not apply to pre-1.0 versions.


## Applications

While Oboron serves as a general-purpose encryption library with its
"string in, string out" API, its combination of properties—particularly
prefix entropy and compactness—enables specialized applications:

- *Git-like short IDs* - High-entropy prefixes for unique references
- *URL-friendly state tokens* - Encrypt web application state into
  compact URLs
- *No-lookup captcha systems* - Server issues encrypted challenge,
  verifies without database lookup
- *Database ID obfuscation* - Hide sequential IDs while maintaining
  reversibility
- *Compact authentication tokens* - Efficient alternative to JWT for
  simple use cases where JWT may be overkill
- *General-purpose symmetric encryption* - Straightforward string-based
  API

### Comparison with Alternatives

| Use Case            | Traditional Solution | Oboron Approach                         |
|---------------------|----------------------|-----------------------------------------|
| Short unique IDs    | UUIDv4 (36 chars)    | `ob:zrbcx.c32` (28 chars, reversible)   |
| URL parameters      | JWT (150+ chars)     | `ob:aasv.b64` (4.5x smaller, 4x faster) |
| Database ID masking | Hashids (not secure) | Proper encryption                       |
| Simple encryption   | Libsodium (complex)  | String in, string out API               |

### API Simplification

Oboron simplifies symmetric encryption compared to lower-level
cryptographic libraries:

**Before (libsodium/ring - complex, byte-oriented):**
```rust
// Manual key and nonce management
let key = generic_hash::Key::generate();
let nonce = randombytes::randombytes(24);
let ciphertext = secretbox::seal(plaintext, &nonce, &key)?;

// Manual encoding required
let encoded = base64::encode(ciphertext);
```

**After (Oboron - simplified, string-oriented):**
```rust
let ob = AasvC32::new(&env::var("OBORON_KEY")?);
let ot = ob.enc("Hello World")?; // "uf2glao2xd7fnbq5z53cb63ukc"
```

**Benefits:**
- No manual hex/base64 encoding/decoding
- Keys as base64 strings (no byte array management)
- Built-in nonce generation where applicable
- Consistent error handling
- Single dependency vs multiple cryptographic crates

**When Oboron is appropriate:**
- General symmetric encryption requirements
- Need for compact, referenceable outputs
- Simplified key management (single 512-bit key)
- String-to-string interface preferred

**When lower-level libraries may be preferable:**
- Need for specific algorithms (ChaCha20-Poly1305, etc.)
- Streaming encryption of large files
- Asymmetric encryption cryptography requirements
- Specialized protocols (Signal, Noise, etc.)

### Pattern Implementation Examples

#### Database ID Obfuscation

**Before (Hashids - insecure, encoding only):**
```rust
let hashids = Hashids::new("salt", 6);
let obfuscated = hashids.encode(&[123]); // "k2d3e4"
```

**After (Oboron - encrypted, reversible, secure):**
```rust
let ob = AasvC32::new(&env::var("OBORON_KEY")?);
let ot = ob.enc("user:123")?; // "uf2glao2xd7f"
// Can include namespace prefixes to prevent type confusion
```

**Advantages:**
- Encodes arbitrary strings (vs integer-only encoding)
- Actual encryption (not just encoding)
- Can embed metadata (e.g., `"user:"`, `"order:"` prefixes, or JSON)
- Referenceable short prefixes
- Tamper-proof with authenticated schemes

#### State Tokens

**Before (JWT - large, complex):**
```rust
// 150+ characters, requires JWT library
let token = encode(&Header::default(), &claims, &EncodingKey)?;
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**After (Oboron - compact, simple):**
```rust
let ob = AagsC32::new(&env::var("OBORON_KEY")?);
let state = serde_json::to_string(&claims)?;
let token = ob.enc(&state)?; // ~50 characters
// "b4g9lao2xd7fnbq5z53cb63ukc"
```

**When to prefer Oboron over JWT:**
- Simple symmetric encryption requirements
- Compact size important (URL parameters)
- JWT standardization not required
- Performance considerations

**When JWT may be preferable:**
- Industry-standard tokens required
- Public/private key signatures needed
- Complex claims with registered names

#### ID Generation and Hash-like Applications

Oboron provides efficient alternatives to UUIDs and SHA256 for
generating unique, referenceable identifiers.

The examples in this section use `zrbcx` and `keyless` features, which
are not included by default as cryptographically insecure.  Enable the
required features explicitly in your `Cargo.toml`.

##### Approach 1: Full Oboron Output (Reversible)
```rust
let ob = ZrbcxC32::new_keyless(); // Obfuscation context
let full_id = ob.enc("user:alice")?;
// "mdwsx9rdwkntyqcf806r9jhsp6gg" (28 base32 chars, reversible)
```

- Pros:
  - Reversible (decodes to "user:alice"),
  - Opaque structure: When decoded with base32, the obtext produces a
    binary blob, revealing no input patterns.
  - Oboron detects scheme, can decrypt with hardcoded key
- Cons:
  - Using hardcoded key: Given the context (keyless Oboron), anyone can
    decode
- Best for:
  - Internal systems where reversibility is useful
  - Strong obfuscation where attackers have no context of Oboron use

Possible security tightening if reversibility is needed:
- Use `aags` or `aasv` for strong 256-bit tamper-proof encryption.
  (Trade-off: longer output: 44 chars; 2-3x slower than `zrbcx` but still
  comparable performance to SHA256)
- Keep the payload securely encrypted by having a shared secret:
  `env::var("OBORON_KEY")` (Trade-off: shared secret management)


##### Approach 2: Trimmed Prefix (Hash-like, Non-reversible)
```rust
let ob = ZrbcxC32::new_keyless();
let full = ob.enc("user:alice")?;
let short_id = &full[0..20];
```

- Pros:
  - Non-reversible even with hardcoded key
  - No key management
  - Adjustable length
- Cons:
  - Not reversible
- Best for:
  - Public-facing identifiers requiring opacity and referenceable short
    IDs.

#### Oboron for Hash-like Identifier Generation

SHA256 is the ubiquitous go-to solution for hash identifiers. However,
it is not optimized for short strings.  Hashing a 6-digit ID or an
10-character parameter is a very common use-case, however reaching for
SHA256 in this context may have drawbacks:
- the output is much longer than the input (always 64 hex characters)
- cutting the output down to a short prefix requires weighing odds of
  the birthday paradox problem
- performance is not optimal (optimized for large files)

**Performance considerations:**
- SHA256 + hex: ~190 ns, 64 hex characters (128-bit collision resistance)
- Oboron zrbcx (one block): ~130 ns, 28 base32/34 hex chars (37% faster)
- Oboron zrbcx (two blocks): ~147 ns, 53 base32/66 hex chars (27% faster,
  stronger than SHA256)
(Times from benchmarks run on an Intel i5 laptop.)

**Collision resistance comparison:**
- 6 base32 chars (30 bits): Exceeds 7 hex chars (28 bits) for short
  references
- 20 base32 chars (100 bits): Comparable to SHA1 collision resistance
- 28 base32 chars (136 bits): Slightly stronger than SHA256's 128 bits
- 53 base32 chars (264 bits): Substantially stronger than SHA256
Note that the consideration of Oboron's 28- and 53-bit outputs in the
context of collision resistance only makes sense in a global namespace;
when using a fixed key, the collision problem for full Oboron outputs
[disappears altogether](#deterministic-injectivity).

**Oboron advantages:**
1. *Better performance* - 27-37% faster than SHA256 for short strings
2. *More compact encoding* - Base32 provides 5 bits per char vs hex's 4
   bits
3. *Referenceable prefixes* - High entropy from initial characters
4. *Tunable security* - Select prefix length for specific collision
   resistance requirements
5. *Deterministic guarantee* - Different inputs always produce
   different outputs

**When to choose which approach:**
- Oboron (28 chars): General-purpose quasi-hashing with deterministic
  non-collision guarantee, and improved performance over SHA256
- Oboron (53 chars): Stronger-than-SHA256 collision resistance (in a
  scenario without a fixed key)
- Shorter prefixes (6 chars): Git-like short references

**Note:** Oboron provides strong collision resistance for identifier
generation but is not a comprehensive replacement for cryptographic
hashing in all contexts (e.g., password hashing where slow hashes are
desirable).

## Rust API Overview

Oboron provides multiple API styles supporting different use cases. For
most production applications, **compile-time format selection** (option 1
below) offers the best combination of performance, type safety, and
clarity.

### 1. Compile-time Format Selection (Recommended for Production)

Use fixed-format types when formats are known at compile time for optimal
performance and type safety:
```rust
use oboron::{ApgsB64, ObtextCodec};

let key = env::var("OBORON_KEY")?;
let apgs = ApgsB64::new(&key)?;

let ot = apgs.enc("hello")?;
let pt2 = apgs.dec(&ot)?;
assert_eq!(pt2, "hello");
```

Available types include all combinations of scheme variants (e.g.,
`Zrbcx`, `Upbc`, `Aags`, `Apgs`, `Aasv`, `Apsv`) with encoding
specifications (`B64`, `Hex`, `B32`, or `C32`),
and concatenates the two in struct names, for example:
- `ZrbcxB32` - encoder for `ob:zrbcx.b32` format
- `UpbcHex` - encoder for `ob:upbc.hex` format
- `AagsB64` - encoder for `ob:aags.b64` format
- `AasvC32` - encoder for `ob:aasv.c32` format.

Note that the `ob:zrbcx` scheme is not included by default as
cryptographically insecure.  In order to use the associated structs
`ZrbcxC32`, `ZrbcxB32`, `ZrbcxB64`, or `ZrbcxHex`,
you need to enable the `zrbcx` feature in your `Cargo.toml`

### 2. Runtime Format Selection (`Ob`)

When format specification at runtime is required but format changes are
unnecessary, use the immutable `Ob`:
```rust
use oboron::{Ob, ObtextCodec};

let key = env::var("OBORON_KEY")?;
let ob = Ob::new("aasv.b64", &key)?;

let ot = ob.enc("hello")?;
let pt2 = ob.dec(&ot)?;
assert_eq!(pt2, "hello");
```

The type `Ob` supports all formats, but the format is fixed at
construction, providing intermediate flexibility between compile-time
selection and full mutability.

### 3. Mutable Runtime Format (`ObFlex`)

Similar to `Ob` but with mutable format specification:
```rust
use oboron::{ObFlex, ObtextCodec};

let mut ob = ObFlex::new("aags.b64", &key)?;
let ot = ob.enc("hello")?; // aags.b64 obtext

// Format modification
ob.set_format("apsv.hex")?;
let ot_hex = ob.enc("world")?; // apsv.hex obtext
```

### 4. Multiple Format Support (`ObMulti`)

`ObMulti` differs in format management and provides comprehensive
`autodec()` functionality.

**Multi-Format Workflow:** Designed for simultaneous work with different
formats, requiring format specification in each operation:
```rust
use oboron::{ObMulti, ObtextCodec};

let obm = ObMulti::new(&key)?;

// Format specification per operation
let ot = obm.enc("test", "apsv.b64");
let pt2 = obm.dec(&ot, "apsv.b64");
let pt_other = obm.dec(&other, "zrbcx.c32");
```

**Autodecode:** While other interfaces perform *scheme* autodetection in
`dec()` methods, only `ObMulti` provides full format autodetection
including encoding (`b32`, `c32`, `b64`, or `hex`).  Other structs decode
only encodings matching their format.
```rust
// Autodecode when format is unknown
let pt2 = obm.autodec(&ot);
```

Note performance implications: autodetection uses trial-and-error across
encodings, with worst-case performance ~3x slower than known-format
dec operations. Meanwhile, scheme autodetection in other interfaces
(e.g., `Ob.dec()`, `ObFlex.dec()`, `AasvB64.dec()`) has zero overhead, as
the scheme is detected based on the scheme byte in the payload, and the
logic follows a direct path with no retries.

### Using Format Constants

For type safety and discoverability, use the provided format constants
instead of string literals:

```rust
use oboron::{Ob, ObMulti, ObtextCodec, AASV_B64, AASV_HEX};

let key = oboron::generate_key();

// With Ob (runtime format selection)
let ob = Ob::new(AASV_B64, &key)?;

// With ObMulti (multi-format operations)
let obm = ObMulti::new(&key)?;
let ot_b64 = obm.enc("data", AASV_B64)?;
let ot_hex = obm.enc("data", AASV_HEX)?;
```

Available constants:
- `ZRBCX_C32`, `ZRBCX_B32`, `ZRBCX_B64`, `ZRBCX_HEX`
- `UPBC_C32`, `UPBC_B32`, `UPBC_B64`, `UPBC_HEX`
- `AAGS_C32`, `AAGS_B32`, `AAGS_B64`, `AAGS_HEX`
- `APGS_C32`, `APGS_B32`, `APGS_B64`, `APGS_HEX`
- `AASV_C32`, `AASV_B32`, `AASV_B64`, `AASV_HEX`
- `APSV_C32`, `APSV_B32`, `APSV_B64`, `APSV_HEX`
- Testing:  `MOCK1_C32`, `MOCK2_B32`, etc.
- Legacy: `LEGACY_B32`, `LEGACY_C32`, etc.

### Advanced: `Format` Objects

`Format` structs provide a more fine-grained type safety than format
string constants:
```rust
use oboron::{Ob, Format, Scheme, Encoding};

let format = Format::new(Scheme::Aasv, Encoding::B64);
let ob = Ob::new_with_format(format, &key)?;
```

### Typical Production Use

For compile-time known schemes and encodings, however, static types
provide optimal performance, concise syntax, and strongest type
guarantees:
```rust
use oboron::{AasvB64, ObtextCodec};
let ob = AasvB64::new(&key)?;
let ot = ob.enc("secret")?;
```
The format is built into the struct, no format strings, constants, or
Format structs are needed.

### The `ObtextCodec` Trait

All types except `ObMulti` implement the `ObtextCodec` trait, providing a
consistent interface:

- `enc(plaintext: &str) -> Result<String, Error>` - Encode plaintext to
  obtext
- `dec(obtext: &str) -> Result<String, Error>` - Decode with automatic
  scheme detection
- `dec_strict(obtext: &str) -> Result<String, Error>` - Decode only
  matching configured scheme (no autodetection; error if not matching)
- `scheme() -> Scheme` - Current scheme
- `encoding() -> Encoding` - Current encoding
- `key() -> String` - Base64 key access
- `key_hex() -> String` - Hex key access (gated by `hex-keys` feature,
  not enabled by default)
- `key_bytes() -> &[u8; 64]` - Raw key bytes access (gated by
  `bytes-keys` feature, not enabled by default)

### Working with Keys

```rust
// main interface:
let ob = AagsB64::new(&env::var("OBORON_KEY")?);       // base64 key
// with "hex-keys" feature enabled:
let ob = AagsB64::from_hex_key(&env::var("HEX_KEY")?); // hex key
// with "bytes-keys" feature enabled:
let ob = AagsB64::from_bytes(&key_bytes)?;             // raw bytes key
// with "keyless" feature enabled:
let ob = AagsB64::new_keyless()?;              // insecure/testing only
```

**Warning**: `new_keyless()` uses the publicly available hardcoded key
providing no security. Use only for testing or obfuscation contexts where
encryption is not required.  The `keyless` feature must be enabled to use
the hardcoded key.


### Common Issues

- *Key errors*: Ensure keys are exactly 86 base64 characters characters
  properly encoded from 512 bits (see note about
  [valid base64 keys](#valid-base64-keys))
- *Format strings*: Must match exactly, e.g., "aasv.b64" not "aasv-b64".
  Do not use the `ob:` namespace prefix in this context.
- *Decoding errors*: Use `autodec()` when format is unknown

### Minimum Supported Rust Version (MSRV)

This crate requires Rust 1.74.0 or later.

## Compatibility

Oboron implementations maintain full cross-language compatibility:
- Identical encryption algorithms and key management
- Consistent encoding formats and scheme specifications
- Interoperable encoded values across Rust, Python, and Go (latter
  currently under development)

All implementations must pass the common
[test vectors](tests/test-vectors.jsonl)

## Getting Help

- [Documentation](https://docs.rs/oboron)
- [GitHub Issues](https://github.com/ob-enc/oboron-rs/issues)

## License

Licensed under the MIT license ([LICENSE](LICENSE)).

## Appendix: Obtext Lengths

`mock1` is a non-cryptographic scheme used for testing, whose ciphertext
is equal to the plaintext bytes (identity transformation). It is
included in the tables below as baseline.

(Note: the `mock1` scheme is feature gated: use it by enabling the `mock`
feature)

## Base32 encoding (b32/c32)

| Scheme | Encoding | 4B  | 8B  | 12B | 16B | 24B | 32B | 64B  | 128B |
|--------|----------|----:|----:|----:|----:|----:|----:|-----:|-----:|
| mock1  | b32/c32  | 8   | 15  | 21  | 28  | 40  | 53  | 104  | 207  |
| zrbcx  | b32/c32  | 28  | 28  | 28  | 28  | 53  | 53  | 104  | 207  |
| aags   | b32/c32  | 34  | 40  | 47  | 53  | 66  | 79  | 130  | 232  |
| aasv   | b32/c32  | 34  | 40  | 47  | 53  | 66  | 79  | 130  | 232  |
| upbc   | b32/c32  | 53  | 53  | 53  | 53  | 79  | 79  | 130  | 232  |
| apgs   | b32/c32  | 53  | 60  | 66  | 72  | 85  | 98  | 149  | 252  |
| apsv   | b32/c32  | 60  | 66  | 72  | 79  | 92  | 104 | 156  | 258  |

## Base64 Encoding (b64)

| Scheme | Encoding | 4B  | 8B  | 12B | 16B | 24B | 32B | 64B  | 128B |
|--------|----------|----:|----:|----:|----:|----:|----:|-----:|-----:|
| mock1  | b64      | 7   | 12  | 18  | 23  | 34  | 44  | 87   | 172  |
| zrbcx  | b64      | 23  | 23  | 23  | 23  | 44  | 44  | 87   | 172  |
| aags   | b64      | 28  | 34  | 39  | 44  | 55  | 66  | 108  | 194  |
| aasv   | b64      | 28  | 34  | 39  | 44  | 55  | 66  | 108  | 194  |
| upbc   | b64      | 44  | 44  | 44  | 44  | 66  | 66  | 108  | 215  |
| apgs   | b64      | 40  | 50  | 55  | 60  | 71  | 82  | 124  | 210  |
| apsv   | b64      | 46  | 55  | 60  | 66  | 76  | 87  | 130  | 215  |

## Hex Encoding (hex)

| Scheme | Encoding | 4B  | 8B  | 12B | 16B | 24B | 32B | 64B  | 128B |
|--------|---------:|----:|----:|----:|----:|----:|----:|-----:|-----:|
| mock1  | hex      | 10  | 18  | 26  | 34  | 50  | 66  | 130  | 258  |
| zrbcx  | hex      | 34  | 34  | 34  | 34  | 66  | 66  | 130  | 258  |
| aags   | hex      | 42  | 50  | 58  | 66  | 82  | 98  | 162  | 290  |
| aasv   | hex      | 42  | 50  | 58  | 66  | 82  | 98  | 162  | 290  |
| upbc   | hex      | 66  | 66  | 66  | 66  | 98  | 98  | 162  | 290  |
| apgs   | hex      | 66  | 74  | 82  | 90  | 106 | 122 | 186  | 314  |
| apsv   | hex      | 74  | 82  | 90  | 98  | 114 | 130 | 194  | 322  |
