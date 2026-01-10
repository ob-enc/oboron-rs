# Oboron

[![Crates.io](https://img.shields.io/crates/v/oboron-py.svg)](https://crates.io/crates/oboron-py)
[![Documentation](https://docs.rs/oboron-py/badge.svg)](https://docs.rs/oboron-py)
[![License:  MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.77-blue.svg)](https://blog.rust-lang.org/2023/11/16/Rust-1.77.0.html)

Oboron is a general-purpose symmetric encryption library focused on
developer ergonomics:
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
with a focus on developer ergonomics and output characteristics. Each
scheme follows a consistent naming pattern that encodes its security
properties, making it easier to choose the right tool without deep
cryptographic expertise: e.g., `aasv` = Authenticated + Avalanche
property + SiV algorithm (AES-SIV).

Key Advantages:
- *Referenceable prefixes*: High initial entropy enables Git-like short
  IDs
- *Simplified workflow*:
  - No manual encoding/decoding between encryption stages
  - No decoding encryption keys from env vars to bytes
- *Performance optimized*

## Contents

- [Quick Start](#quick-start)
- [Formats](#formats)
- [Algorithm](#algorithm)
- [Key Management](#key-management)
- [Properties](#properties)
- [Python API Overview](#python-api-overview)
- [Applications](#applications)
- [Compatibility](#compatibility)
- [Getting Help](#getting-help)
- [License](#license)
- [Appendix: Obtext Lengths](#appendix-obtext-lengths)

## Quick Start

Installation
```shell
pip install oboron
```

Generate your 512-bit key (86 base64 characters) using the keygen script:
```shell
python -m oboron.keygen
```
or in your code:
```rust
key = oboron.generate_key()
```
then save the key as an environment variable.

Use AasvC32 (a secure scheme, 256-bit encrypted with AES-SIV, encoded
using Crockford's base32 variant) for enc/dec:
```python
import os
from oboron import AasvC32

key = os.getenv("OBORON_KEY")  # get the key
ob = AasvC32(key)              # instantiate codec (cipher+encoder)
ot = ob.enc("hello, world")    # get obtext (encrypted+encoded)
pt2 = ob.dec(ot)               # get plaintext back (decode+decrypt obtext)

print(f"obtext: {ot}")
# "obtext: cbv74r1m7a7cf8n6gzdy6tf2vjddkhwdtwa5ssgv78v5c1g"

assert pt2 == "hello, world"
```

*Version 1.0*: This release marks API stability. Oboron follows semantic
versioning, so 1.x releases will maintain backward compatibility.

## Formats

An Oboron *format* represents the full transformation of the plaintext to
the encrypted text (obtext), including:

1. *Encryption*: Plaintext UTF-8 string encrypted to ciphertext bytes
   using a cryptographic algorithm
2. *Encoding*: The binary payload is encoded to a string representation

### Scheme + Encoding = Format

Formats combine a scheme (cryptographic algorithm) with an encoding
(string representation):
- *Scheme*: Cryptographic algorithm + mode + parameters (e.g., `aasv`)
- *Encoding*: String representation method (e.g., `.b64`)
- *Format*: Scheme + encoding = complete transformation (e.g.,
  `aasv.b64`)


Given an encryption key, the format thus uniquely specifies the complete
transformation from a plaintext string to an encoded *obtext* string.

Formats are represented by identifiers:
- `ob:{scheme}.{encoding}`, (URI-like syntax, e.g., `ob:aasv.c32`),
- `{scheme}.{encoding}`, when the context is clear

**API Notes**:
- The `ob:` namespace prefix is not used in the `oboron` API.
  Formats like `aasv.c32` are used directly.
- The public interface uses `enc`/`dec` names for methods and functions.
  Thus the `enc` operation comprises the full process, including the
  encryption and encoding stages.

### Encodings

- `b32` - standard base32: Balanced compactness and readability,
  uppercase alphanumeric (RFC 4648 Section 6)
- `c32` - Crockford base32: Balanced compactness and readability,
  lowercase alphanumeric; designed to avoid accidental obscenity
- `b64` - standard URL-safe base64: Most compact, case-sensitive,
  includes `-` and `_` characters (RFC 4648 Section 5)
- `hex` - hexadecimal: Slightly faster performance (~2-3%), longest
  output

> **FAQ:** *Why use Crockford's base32 instead of the RFC standard one?*
>
> Crockford's base32 alphabet minimizes the probability of accidental
> obscenity words, which is important when using with short prefixes:
> Whereas accidental obscenity is not an issue when working with full
> encrypted outputs (as any such words would be buried as substrings of a
> 28+ character long obtext), it may become a concern when using short
> prefixes as references or quasi-hash identifiers.

### Schemes

Schemes define the encryption algorithm and its properties, classified
into *tiers*:

#### Scheme Tiers

- **`a` - Authenticated**
  - Provide both confidentiality and integrity protection
  - Examples: `ob:aasv`, `ob:aags`, `ob:apsv`, `ob:apgs`
  - *Always prefer `a`-tier schemes for security-critical applications*

- **`u` - Unauthenticated**
  - Provide confidentiality only (no integrity protection)
  - Example: `ob:upbc`
  - Suitable when integrity is verified externally or not required
  - *Warning*: Vulnerable to ciphertext tampering

- **`z` - Obfuscation tier**
  - *Not cryptographically secure* - for non-security use only
  - Example: `ob:zrbcx` - deterministic obfuscation with constant IV
  - Requires explicit `ztier` feature flag (not enabled by default)
  - See [Z_TIER.md](Z_TIER.md) for details and warnings

#### Scheme Properties

The second letter of the scheme ID further describe the properties of the
scheme:
- **`.a..` - avalanche, deterministic**
  - *deterministic* => same plaintext always produces same obtext
  - *avalanche* => entropy uniformly distributed; change in any byte of
    plaintext completely changes the entire obtext (hash-like property)
  - Examples: `ob:aasv`, `ob:aags`
- **`.p..` - probabilistic**
  - Different output each time
  - Examples: `ob:apsv`, `ob:apgs`, `ob:upbc`

#### Scheme Cryptographic Algorithms

The remaining two letters in scheme IDs indicate the algorithm:
- `gs` = AES-GCM-SIV
- `sv` = AES-SIV
- `bc` = AES-CBC

#### Summary Table

| Scheme     | Algorithm   | Deterministic? | Authenticated? | Notes                              |
| :--------- | :---------- | :------------- | :------------- | :--------------------------------- |
| `ob:aasv`  | AES-SIV     | Yes            | Yes            | General purpose, deterministic |
| `ob:aags`  | AES-GCM-SIV | Yes            | Yes            | Deterministic alternative |
| `ob:apsv`  | AES-SIV     | No             | Yes            | Maximum privacy protection |
| `ob:apgs`  | AES-GCM-SIV | No             | Yes            | Probabilistic alternative |
| `ob:upbc`  | AES-CBC     | No             | No             | Unauthenticated - use with caution |

Key Concepts:
* *Deterministic:* Same input (key + plaintext) always produces same
  output. Useful for idempotent operations, lookup keys, caching, or
  hash-like references.
* *Probabilistic:* Incorporates a random nonce, producing different
  ciphertexts for identical plaintexts.  Standard for most cryptographic
  use cases (non-cached, not used as hidden references).
* *Authenticated:* Ciphertext is tamper-proof.  Any modification (even a
  single bit flipped) results in decryption failure.

#### Choosing a Scheme

- `ob:aasv`: General-purpose secure encryption with deterministic output
  and compact size
- `ob:apsv`: Maximum privacy with probabilistic output (larger size due
  to nonce)
- `ob:upbc`: Only when integrity is handled externally

> *Note on encryption strength*: All `a`-tier and `u`-tier schemes use
  256-bit AES encryption. The `z`-tier uses 128-bit AES for performance
  in non-security contexts.


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
scheme-specific steps like scheme byte appending and (for `z`-tier
schemes only) optional ciphertext prefix restructuring. With this
middle-step included, the diagram becomes:
```
enc operation:
    [plaintext] -> encryption -> [ciphertext] -> oboron pack -> [payload] -> encoding -> [obtext] 

dec operation:
    [obtext] -> decoding -> [payload] -> oboron unpack -> [ciphertext] -> decryption -> [plaintext]
```

In `a`-tier and `u`-tier schemes, the difference between the payload and
the ciphertext is in the 2-byte scheme marker that is appended to the
ciphertext, enabling scheme autodetection in decoding.

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

### Single Master Key Model

Oboron uses a single 512-bit master key partitioned into
algorithm-specific subkeys:

- `ob:aags`, `ob:apgs`: use the first 32 bytes (256 bits) for AES-GCM-SIV
  key
- `ob:aasv`, `ob:apsv`: use the full 64 bytes (512 bits) for AES-SIV key
- `ob:upbc` uses the last 32 bytes (256 bits) for AES-CBC key

**Design Rationale:** This approach prioritizes low latency for
short-string encryption.  No hash-based KDF (e.g., HKDF) is used, as this
would dominate runtime for intended workloads.

The master key never leaves your application. Algorithm-specific keys
are extracted on-the-fly and never cached or stored.

> **FAQ:** *Why use a single key across all schemes?*
>
> - Simplifies deployment: Store one key instead of multiple
> - Reduces errors: No risk of mismatching keys to algorithms

### Key Format

The default key input format is base64. This is consistent with Oboron's
strings-first API design. As any production use will typically read the
key from an environment variable, this allows the string format to be
directly fed into the constructor.

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
requirements. When generating keys, it is recommended to use one of the
following methods:
1. use Oboron's key generator (`oboron::generate_key()` or
  `cargo run --bin keygen`)
2. generate random 64 bytes, then encode as base64
3. generate random 128 hex characters, then convert hexadecimal to base64


## Properties

### Referenceable Prefixes

If you've used Git, you're already familiar with prefix entropy: you can
reference commits with just the first 7 characters of their SHA1 hash
(like `git show a1b2c3d`). This works because cryptographic hashes
distribute entropy evenly across all characters.

Oboron schemes exhibit similar prefix quality.
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
in large systems even with the full hash.  Oboron, on the other hand, is
a symmetric encryption library, and as such it is collision free
(although applying this label to an encryption library is awkward):
for a fixed key and within the block-cipher domain limits, Oboron is
injective (one-to-one), i.e. two different inputs can never result in the
same output.

### Performance Comparison

(All performance benchmarks are from the Rust library benchmarks,
without the Python bindings overhead.)

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
- [BENCHMARKS.md](../oboron/BENCHMARKS.md).
Data from JWT and SHA256 benchmarks
performed on the same machine is available here:
- [BASELINE_BENCHMARKS.md](../oboron/BASELINE_BENCHMARKS.md)

**Performance advantages:**
- `ob:zrbcx` encoding is 4.1x faster than JWT with 4.5x smaller output
- All Oboron schemes outperform JWT for both encoding and decoding
- `ob:zrbcx` shows lower latency than SHA256+hex for short strings while
  providing reversible (cryptographically insecure) encryption

### Output Length Comparison

| Method        | Small string output length |
|---------------|----------------------------|
| `ob:aasv`     | 31-48 characters           |
| `ob:apsv`     | 56-74 characters           |
| `ob:zrbcx`    | 29 characters              |
| SHA256        | 64 characters              |
| JWT           | 150+ characters            |

A more complete output length comparison is given in the
[Appendix](#appendix-obtext-lengths).

### Scheme Selection Guidelines

- `ob:aasv`: General-purpose secure encryption with deterministic output
  and compact size
- `ob:apsv`: Maximum privacy protection with probabilistic output
  (larger size due to nonce)
- `ob:zrbcx`: Non-security-critical applications prioritizing speed and
  compactness

Choose `ob:aasv` when:
- Cryptographic security with compact output is needed (~34-47 chars)
- Deterministic behavior is beneficial (lookup keys, caching)

Choose ob:apsv` when:
- Cryptographic security with maximum privacy is required (~60-72 chars)
- Hiding plaintext relationships is critical

Choose `ob:zrbcx` when:
- Performance and compactness are primary requirements (~28 chars)
- Security requirements are minimal (obfuscation contexts)




## Python API Overview

Oboron provides multiple API styles supporting different use cases. For
most production applications, **compile-time format selection** (option 1
below) offers the best combination of performance, type safety, and
clarity.

### 1. Fixed Format Selection (Recommended for Production)

When your encryption format is fixed, instantiate the specific scheme class
(like `AasvC32`) directly for optimal performance and type safety:

```python
from oboron import ApgsB64
ob = ApgsB64(key)
ot = ob.enc("hello")
pt2 = ob.dec(ot)
assert pt2 == "hello"
```

Available types include all combinations of scheme variants (e.g.,
`Zrbcx`, `Upbc`, `Aags`, `Apgs`, `Aasv`, `Apsv`) with encoding
specifications (`B64`, `Hex`, `B32`, or `C32`),
and concatenates the two in class names, for example:
- `ZrbcxB32` - encoder for `zrbcx.b32` format
- `UpbcHex` - encoder for `upbc.hex` format
- `AagsB64` - encoder for `aags.b64` format
- `AasvC32` - encoder for `aasv.c32` format.

### 2. Runtime Format Selection (`Ob`)

When format specification at runtime is required, use `Ob`:

```python
from oboron import Ob
ob = Ob("aasv.b64", key)
ot = ob.enc("hello")  # aasv.b64 format obtext
pt2 = ob.dec(ot)
assert pt2 == "hello"

ob.set_encoding("c32")  # switch format to aasv.c32
ob.enc("hello")  # now aasv.c32-encoded obtext

ob.set_scheme("aags")  # switch wormat to aags.c32
ob.enc("hello")  # now aags.c32-encoded obtext

ob.set_format("upbc.b64")
ob.enc("hello")  # now upbc.b64-encoded obtext
```

Example use: format provided by environment variable.

### 3. Multiple Format Support (`Omnib`)

`Omnib` differs in format management and provides comprehensive
`autodec()` functionality.

**Multi-Format Workflow:** Designed for simultaneous work with different
formats, requiring format specification in each operation:
```python
from oboron import Omnib

obm = Omnib(key)

# Format specification per operation
ot = obm.enc("test", "apsv.b64")
pt2 = obm.dec(ot, "apsv.b64")
pt_other = obm.dec(other, "zrbcx.c32")
```

**Autodecode:** While other interfaces perform *scheme* autodetection in
`dec()` methods, only `Omnib` provides full format autodetection
including encoding (base32rfc, base32crockford, base64, or hex).  Other
classes decode only encodings matching their format.
```python
# Autodecode when format is unknown
pt2 = obm.autodec(ot)
```

Note performance implications: autodetection uses trial-and-error across
encodings, with worst-case performance ~3x slower than known-format
dec operations. (However, the heuristic encoding detection makes the average
performace much closer to that of normal `dec()` operations than the worst case.)
Meanwhile, scheme autodetection in other interfaces (e.g., `Ob.dec()`,
`AasvB64.dec()`) has zero overhead, as the scheme is detected based
on the scheme byte in the payload, and the logic follows a direct path
with no retries.

### Using Format Constants

For type safety and discoverability, use the provided format constants
instead of string literals:

```python
from oboron import Ob, Omnib, formats

# With Ob (runtime format selection)
ob = Ob(formats.AASV_B64, key)

# With Omnib (multi-format operations)
obm = Omnib(key)
ot_b64 = obm.enc("data", formats.AASV_B64)
ot_hex = obm.enc("data", formats.AASV_HEX)
```

Available constants:
- `ZRBCX_C32`, `ZRBCX_B32`, `ZRBCX_B64`, `ZRBCX_HEX`
- `UPBC_C32`, `UPBC_B32`, `UPBC_B64`, `UPBC_HEX`
- `AAGS_C32`, `AAGS_B32`, `AAGS_B64`, `AAGS_HEX`
- `APGS_C32`, `APGS_B32`, `APGS_B64`, `APGS_HEX`
- `AASV_C32`, `AASV_B32`, `AASV_B64`, `AASV_HEX`
- `APSV_C32`, `APSV_B32`, `APSV_B64`, `APSV_HEX`
- Testing:  `MOCK1_*`, `MOCK2_*`
- Legacy: `LEGACY_*`

### Typical Production Use

For compile-time known schemes and encodings, however, static types
provide optimal performance, concise syntax, and strongest type
guarantees:
```python
from oboron import AasvB64
ob = AasvB64(key)
ot = ob.enc("secret")
```
The format is built into the class, no format strings or constants, are
needed.

### `OboronBase` class

All types except `Omnib` implement the `Oboron` trait, providing a
consistent interface:

Methods:
- `enc(plaintext: str) -> str` - Encrypt plaintext to obtext
- `dec(obtext: str) -> str` - Decrypt obtext to plaintext
Properties:
- `key -> str` - Base64 key access
- `key_bytes -> bytes` - Raw key bytes access
- `format -> str` - Current format (scheme+encoding)
- `scheme -> str` - Current scheme
- `encoding -> str` - Current encoding

### Working with Keys

```python
ob = AagsB64(os.environ.get("OBORON_KEY")) # base64 key
```

**Warning**: `new_keyless()` uses the publicly available hardcoded key
providing no security. Use only for testing or obfuscation contexts where
encryption is not required.

```python
ob = AagsB64(keyless=True)  # hardcoded key
```


### Common Issues

- **Key errors**: Ensure keys are exactly 86 base64 characters characters
  properly encoded from 512 bits (see note about
  [valid base64 keys](#valid-base64-keys))
- **Format strings**: Must match exactly, e.g., "aasv.b64" not "aasv-b64"
- **Decoding errors**: Use `autodec()` when format is unknown


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

### API Simplification

Oboron simplifies symmetric encryption compared to lower-level
cryptographic libraries:

**Before (libsodium/ring - complex, byte-oriented):**
```python
import base64
from nacl import secret, utils, encoding

# --- KEY ---

# Manual key and nonce management
key = utils.random(secret.SecretBox.KEY_SIZE)
nonce = utils.random(secret.SecretBox.NONCE_SIZE)

# --- ENCRYPT+ENCODE ---

# Manual conversion of UTF-8 string to bytes
plaintext_str = "hello, world"
plaintext_bytes = plaintext_str.encode('utf-8')

# Create a box
box = secret.SecretBox(key)

# Encrypt
ciphertext = box.encrypt(plaintext_bytes, nonce)

# Manually encode for print/transport
encoded = base64.urlsafe_b64encode(ciphertext).decode('ascii')
print(f"Encoded ciphertext: {encoded}")

# --- DECODE+DECRYPT ---

# Decode from base64
ciphertext_decoded = base64.urlsafe_b64decode(encoded)

# Decrypt (returns bytes)
decrypted_bytes = box.decrypt(ciphertext_decoded, nonce)

# Manual UTF-8 decoding required
decrypted_str = decrypted_bytes.decode('utf-8')
print(f"Decrypted: {decrypted_str}")

```

**After (Oboron - simplified, string-oriented):**
```python
from oboron import AasvC32, generate_key

# --- KEY ---

# Generate key in base64 (ready for storing as environment variable)
key = generate_key()
ob = AasvC32(key)

# --- ENCRYPT+ENCODE ---
# Direct string in, string out
plaintext = "hello, world"
ot = ob.enc(plaintext)
print(f"obtext: {ot}")

# --- DECODE+DECRYPT ---
pt2 = ob.dec(ot)
print(f"decrypted: {pt2}")
```

**Benefits:**
- No manual hex/base64 encoding/decoding
- Keys as base64 strings (no byte array management)
- Built-in nonce generation where applicable
- Consistent error handling
- Single dependency vs multiple packages

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
```python
import os
from hashids import Hashids

salt = os.environ.get("HASHIDS_SALT")
hashids = Hashids(salt, min_length=6)

obfuscated = hashids.encode(123)  # "k2d3e4"

decoded = hashids.decode(obfuscated)  # 123
```
Problems:
- Only works with integers
- Uses a weak "salt" (not a cryptographic key)
- Output reveals information about input (length, structure)
- Anyone with the salt can decode all IDs

**After (Oboron - encrypted, reversible, secure):**
```python
import os
from oboron import AasvC32

key = os.environ.get("OBORON_KEY")
ob = AasvC32(key)

obtext = ob.enc("123")  # "waz7vh42v1jqwtavafwnxqy2anhn12w6"

plaintext2 = ob.dec(obtext)  # "123"
```
Advantages:
- Encodes arbitrary strings (vs integer-only encoding)
- Actual encryption (not just encoding)
- Can embed metadata (e.g., `"user:"`, `"order:"` prefixes, or JSON)
- Tamper-proof with authenticated schemes

The advantage of Hashids is that they are both short and reversible.
With Oboron, if no reversibility is required, the first 6 characters of
the obtext can be used as a collision-resistant reference (e.g., waz7vh").

#### State Tokens

**Before (JWT - large, complex):**
```python
import jwt
import datetime
import json

secret = os.environ.get("JWT_SECRET")

claims = {
    "user_id": 123,
    "username": "alice",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    "iat": datetime.datetime.utcnow()
}

token = jwt.encode(
    claims, 
    secret, 
    algorithm="HS256"  # Must specify algorithm
)
# 191-character base64 string

restored_claims = jwt.decode(token, secret_key, algorithms=["HS256"])
```
Note the API asymmetry:
- jwt.encode() takes `algorithm="HS256"`
- jwt.decode() takes `algorithms=["HS256"]`
- Security feature needed due to same API supporting both symmetric and
  asymmetric cryptography

Performance (on Intel i5):
- `jwt.encode()`: 20 us
- `jwt.decode()`: 24 us

HS256 accepts any length secret, no warnings for short secrets:
```python
jwt.encode(claims, 'a', algorithm="HS256")  # works fine
```

**After (Oboron - compact, simple):**
```python
import os
import json
import datetime
from oboron import AagsB64  # Deterministic, authenticated scheme

# Same 86 base64 characters format used for all agorithms
# Each algorithm gets proper length cryptographic key
# (e.g. 256-bit key for AES-GCM-SIV)
key = os.environ.get("OBORON_KEY")

ob = AagsB64(key)

claims = {
    "user_id": 123,
    "username": "alice",
    "exp": (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp(),
    "iat": datetime.datetime.utcnow().timestamp()
}

payload = json.dumps(claims)
token = ob.enc(payload)
# 142 characters base64 string

decrypted_payload = ob.dec(token)
restored_claims = json.loads(decrypted_payload)

# Implement your own token validation logic in a few lines of code
if datetime.datetime.utcnow().timestamp() > restored_claims["exp"]:
    print("Token expired")
...
```
Performance comparison (Intel i5 CPU):
| 89B claims (example above) | encode | decode | Note                                                 |
|----------------------------|--------|--------|------------------------------------------------------|
| JWT w/ HS256 auth          | 20 us  | 24 us  |                                                      |
| Oboron w/ string payload   | 1.9 us | 1.9 us | Rust execution dominated by Python bindings overhead |
| Oboron w/ dict to JSON     | 4.7 us | 4.0 us | JSON serialization overhead exceeds encryption call  |

=> encryption + authentication is 5x faster than JWT (HS256 provides auth only)

Token size comparison:
- JWT: 191B
- Oboron: 142B (25% smaller)

**When to prefer Oboron over JWT:**
- Simple symmetric encryption requirements
- Compact size important (URL parameters)
- JWT standardization not required
- Performance considerations

**When JWT may be preferable:**
- Industry-standard token format required
- Public/private key signatures needed
- Complex claims with registered names

#### ID Generation and Hash-like Applications

Oboron provides efficient alternatives to UUIDs and SHA256 for
generating unique, referenceable identifiers.

The examples in this section use `zrbcx` and `keyless` features, which are
not included by default as cryptographically insecure.  Enable
the required features explicitly in your `Cargo.toml`.

##### Approach 1: Full Oboron Output (Reversible)
```python
ob = ZrbcxC32(keyless=True)  # Obfuscaton context
full_id = ob.enc(f"user:alice")
# "mdwsx9rdwkntyqcf806r9jhsp6gg" (28 base32 chars, reversible)
```

- Pros:
  - *Reversible* (decodes to "user:alice"),
  - *Opaque structure:* When decoded with base32, the obtext produces a binary blob, revealing no input patterns.
  - *Automatic handling:* Oboron detects the scheme (`zrbcx`), and can decrypt with its hardcoded key
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
ob = ZrbcxC32(keyless=True)
full = ob.enc("user:alice")
short_id = full[:20]
shorter_id = full[:6]  # "mdwsx9" ~ Git 7 char hex commit reference
```

- Pros:
  - Non-reversible even with hardcoded key
  - No key management
  - Adjustable length
- Cons:
  - Not reversible
- Best for:
  - Public-facing identifiers requiring opacity and referenceable short IDs.

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

## Compatibility

Oboron implementations maintain full cross-language compatibility:
- Identical encryption algorithms and key management
- Consistent encoding formats and scheme specifications
- Interoperable encoded values across Rust, Python, and Go (latter
  currently under development)

All implementations must pass the common
[test vectors](../oboron/tests/test-vectors.jsonl)

## Getting Help

- [Documentation](https://docs.rs/oboron)
- [GitHub Issues](https://github.com/ob-enc/oboron-rs/issues)

## License

Licensed under the MIT license ([LICENSE](LICENSE)).

## Appendix: Obtext Lengths

`mock1` is a non-cryptographic scheme used for testing, whose ciphertext
is equal to the plaintext bytes (identity transformation). It is
included in the tables below as baseline.

(Note: the `mock1` scheme is feature gated: use it by enabling the `mock1`
feature, or the `ob7x` testing feature group, or the `non-crypto` feature
group.)

## Base32 encoding (b32/c32)

| Format    | 4B | 8B | 12B | 16B | 24B | 32B | 64B | 128B |
|-----------|---:|---:|----:|----:|----:|----:|----:|-----:|
| mock1.b32 | 10 | 16 |  23 |  29 |  42 |  55 | 106 |  208 |
|  aags.b32 | 36 | 42 |  48 |  55 |  68 |  80 | 132 |  234 |
|  aasv.b32 | 36 | 42 |  48 |  55 |  68 |  80 | 132 |  234 |
|  apgs.b32 | 55 | 61 |  68 |  74 |  87 | 100 | 151 |  253 |
|  apsv.b32 | 61 | 68 |  74 |  80 |  93 | 106 | 157 |  260 |
|  upbc.b32 | 55 | 55 |  55 |  55 |  80 |  80 | 132 |  234 |
| zrbcx.b32 | 29 | 29 |  29 |  29 |  55 |  55 | 106 |  208 |

## Base64 Encoding (b64)

| Format    | 4B | 8B | 12B | 16B | 24B | 32B | 64B | 128B |
|-----------|---:|---:|----:|----:|----:|----:|----:|-----:|
| mock1.b64 |  8 | 14 |  19 |  24 |  35 |  46 |  88 |  174 |
|  aags.b64 | 30 | 35 |  40 |  46 |  56 |  67 | 110 |  195 |
|  aasv.b64 | 30 | 35 |  40 |  46 |  56 |  67 | 110 |  195 |
|  upbc.b64 | 46 | 46 |  46 |  46 |  67 |  67 | 110 |  195 |
|  apgs.b64 | 46 | 51 |  56 |  62 |  72 |  83 | 126 |  211 |
|  apsv.b64 | 51 | 56 |  62 |  67 |  78 |  88 | 131 |  216 |
| zrbcx.b64 | 24 | 24 |  24 |  24 |  46 |  46 |  88 |  174 |

## Hex Encoding (hex)

| Format    | 4B | 8B | 12B | 16B | 24B | 32B | 64B | 128B |
| ----------|---:|---:|----:|----:|----:|----:|----:|-----:|
| mock1.hex | 12 | 20 |  28 |  36 |  52 |  68 | 132 |  260 |
|  aags.hex | 44 | 52 |  60 |  68 |  84 | 100 | 164 |  292 |
|  aasv.hex | 44 | 52 |  60 |  68 |  84 | 100 | 164 |  292 |
|  upbc.hex | 68 | 68 |  68 |  68 | 100 | 100 | 164 |  292 |
|  apgs.hex | 68 | 76 |  84 |  92 | 108 | 124 | 188 |  316 |
|  apsv.hex | 76 | 84 |  92 | 100 | 116 | 132 | 196 |  324 |
| zrbcx.hex | 36 | 36 |  36 |  36 |  68 |  68 | 132 |  260 |
