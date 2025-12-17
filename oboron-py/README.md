# oboron-py

Python bindings for Oboron - a general-purpose encryption and encoding library designed for developer ergonomics and compact outputs.

## Contents

- [Goals](#goals)
- [Why Oboron?](#why-oboron)
- [Why "ob"?](#why-ob)
- [Versioning](#versioning)
- [Quick Start](#quick-start)
- [Formats](#formats)
- [Encodings](#encodings)
- [Schemes](#schemes)
- [Performance](#performance)
- [Applications](#applications)
- [Python API Overview](#python-api-overview)
- [Compatibility](#compatibility)
- [Getting Help](#getting-help)
- [License](#license)

## Goals

- **Simplicity**: String in, string out.
- **Compactness**: Modern algorithms for short outputs.
- **Referenceable Prefixes**: High entropy in first characters for Git-like references.
- **High Performance**: Comparable to SHA256 for short strings.

## Why Oboron?

| Feature              | Oboron           | SHA256       | JWT        | Notes              |
|----------------------|------------------|--------------|------------|--------------------|
| Output Size          | 26-56 chars      | 64 chars     | 150+ chars | ✅ Most compact    |
| Reversible           | ✅ Yes           | ❌ No        | ✅ Yes     | ✅ Decode original |
| Prefix Referenceable | ✅ Excellent     | ✅ Excellent | ❌ Poor    | ✅ Short human IDs |
| Simple API           | ✅ String in/out | ❌ Bytes     | ❌ Complex | ✅ Easy to use     |

### Referenceable Prefixes

Like Git commit hashes, Oboron outputs are designed so that **short prefixes uniquely identify values**. Instead of memorizing or typing full encrypted strings, you can use just the first 5-7 characters as human-readable identifiers:

```
Full Oboron output:  uf2glao2xd7fnbq5z53cb63ukc
Reference prefix:    uf2gla
```

This works because Oboron ensures **maximal entropy in the first characters** through byte reversal and careful algorithm selection. The probability of two different inputs sharing the same 6-character prefix is astronomically low.

### Shorter References

Base32 encoding provides higher density than hexadecimal:
- **5-6 Oboron characters** = **7 Git hex characters** in entropy
- **Reference prefixes can be shorter** while maintaining the same collision resistance
- **More human-friendly** for IDs, URLs, and visual references

```
Oboron 5-char prefix:    uf2gl
Oboron 6-char prefix:    uf2gla   (more specific than 7-char hex)
SHA256 7-char prefix:    87428fc
```

### A Unique Combination of Properties

While sharing the prefix entropy property of SHA256, Oboron adds:
- **🔄 Reversible** - The original content can be decoded
- **🔒 Encrypted** - Content is cryptographically protected (unlike hash-based solutions)
- **📦 Compact** - 26 chars for typical IDs vs 64 with SHA256

```
Oboron output:  uf2glao2xd7fnbq5z53cb63ukc
SHA256 sum:     87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7
```

### Stronger Than Hashing

While SHA256 is *practically* collision-resistant, Oboron provides **theoretical guarantees**:

- **🎯 Collision-Free**: Unlike cryptographic hashes which are subject to the birthday paradox, deterministic Oboron schemes provide injective encryption - different inputs always produce different outputs.
- **📊 No Birthday Paradox**: Never worry about the √n collision bound that affects all hashing systems

### Faster & More Compact Than Alternatives

- **⚡ 3.5x faster than JWT** with **4.5x smaller output**
- **🚀 Even faster than SHA256+hex** while providing reversible encryption
- **📦 Optimized for short strings** (8-64 bytes) where most crypto libraries underperform

### Simplified Key Management

Oboron uses a standardized 512-bit master key that works across all schemes:

```rust
// One key works for everything
let key = "a1b2c3..."; // 512-bit hex key

// Same key works with any scheme
let ob01 = Ob01::new(key);
let ob32 = Ob32::new(key); 
let ob32p = Ob32p::new(key);
```

No more managing different key lengths for different algorithms - Oboron handles the derivation internally.

Store keys securely using environment variables or secret management services. The 512-bit hex key (128 characters) provides ample security for all schemes.


### String-Based Interface

Oboron works with strings throughout - not just for data, but for keys too:

```rust
// Most crypto libraries: painful byte management
let key_bytes = hex::decode(env::var("SECRET_KEY")?)?;
let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;

// Oboron: just use the hex string directly
let cipher = Ob32::new(env::var("OBORON_KEY")?);

// but you can also use bytes if you prefer:
let cipher = Ob32::from_bytes(&key_bytes)?;
```

No more manual hex decoding - Oboron handles the conversion internally with proper validation.

### Ideal Use Cases

- Git-like short IDs with high-entropy prefixes
- URL-friendly encrypted state tokens
- No-lookup captcha and challenge systems
- Database ID obfuscation with reversibility
- Compact authentication tokens
- General-purpose symmetric encryption

## Why "ob"?

The `ob-` prefix in the project name (Oboron) and scheme names (e.g., ob21p, ob32) stems from a Latin prefix. Here are ob-prefixed Latin verbs describing the library's core functions:

| Feature | Latin verb | Meaning | How Oboron implements it |
|---------|------------|---------|--------------------------|
| **Encryption** | `obstruere` | to block, obstruct | Cryptographically blocks unauthorized access |
| **Referenceable Prefixes** | `obvertere` | to turn toward, focus | Directs entropy to the front for short IDs |
| **Encoding** | `oblinere` | to daub all over, seal up | Transforms data into compact strings |
| **Authentication** | `obsignare` | to affix a seal, stamp, imprint | Authenticates outputs against tampering (ob32/ob31) |
| **Obfuscation** | `obducere` | to protect, to screen | Conceals data in URL-safe representations |
| **Reversibility** | `obambulare` | to traverse, go around | Enables round-trip decoding of original data |
| **Collision-Free** | `obfirmare` | to strengthen, secure | Provides mathematical guarantees vs probabilistic hashing |
| **Standardization** | `obtemperare` | to conform to standard | Standardized interface, 512-bit key works across all schemes |

## Versioning

This crate follows semantic versioning. Version 1.0 signifies a stable, production-ready API with no anticipated breaking changes.

## Quick Start

```bash
pip install oboron
```

```python
from oboron import Ob32

# 1. Set your 512-bit key (128 hex characters)
key = "0123456789abcdef..."  # In practice: os.environ["OBORON_KEY"]

# 2. Create a cipher
cipher = Ob32(key)

# 3. Encrypt and decrypt
encrypted = cipher.encode("Hello World")
decrypted = cipher.decode(encrypted)

print(f"Encrypted: {encrypted}")  # e.g., "uf2glao2xd7fnbq5..."
assert decrypted == "Hello World"
```

## Formats

Oboron encoding is a multi-stage process:
1. Encryption: A cryptographic scheme (e.g., ob31) processes your plaintext.
2. Byte Reversal (select schemes only): The ciphertext bytes are reversed to maximize entropy in the output prefix
3. Scheme byte: A byte identifying the encryption scheme is appended
4. Encoding: The reversed binary encryption output is encoded into a string using a standard format: base32 (default), base64, or hexadecimal

These stages are reflected in the format name: `{scheme}:{encoding}`
- `ob01:b32` - ob01 scheme, base32 encoding
- `ob21:hex` - ob21 scheme, hex encoding
- `ob32p:b64` - ob32p scheme, base64 encoding

**Note**: In probabilistic schemes, the format of the output in stage 1 (Encryption) is `[ciphertext][nonce]`.

**API Note**: While the process involves encryption, the public interface uses `encode`/`decode` terminology to emphasize the string-to-string transformation. Under the hood, this handles both encryption and encoding stages.

## Encodings

- **base32** (default): Balanced compactness and readability, alphanumeric, lowercase.
- **base64**: Most compact, case-sensitive, includes `-` and `_` characters.
- **hexadecimal**: Slightly faster performance than base32 and base64 (~2-3%), longest output.

## Schemes

A scheme defines the encryption algorithm and its properties (deterministic vs. probabilistic, authenticated). Based on their properties, the schemes are divided into *tiers*:
- ob0x - insecure, non-authenticated
- ob1x - insecure, authenticated
- ob2x - secure, non-authenticated
- ob3x - secure, authenticated

**Note:** ob1x tier (insecure, authenticated) currently has no schemes implemented. It is left for possible future additions, and to preserve this symmetry: even scheme tiers = non-authenticated; odd = authenticated

| Scheme | Algorithm | Deterministic? | Authenticated? | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `ob01` | AES-CBC | ✅ Yes | ❌ No | Legacy; uses a constant IV. Prioritizes compactness/entropy over security. |
| `ob21p` | AES-CBC | ❌ No | ❌ No | |
| `ob31` | AES-GCM-SIV | ✅ Yes | ✅ Yes | |
| `ob31p` | AES-GCM-SIV | ❌ No | ✅ Yes | |
| `ob32` | AES-SIV | ✅ Yes | ✅ Yes | |
| `ob32p`| AES-SIV | ❌ No | ✅ Yes | |

**Key Concepts:**
*   **Deterministic:** The same input (key + plaintext) always produces the same output. Useful for idempotent operations, lookup keys, or deterministic testing.
*   **Probabilistic (`p` suffix):** Incorporates a random nonce, so encrypting the same plaintext multiple times yields different, unpredictable ciphertexts. This is the standard for most cryptographic use cases.
*   **Authenticated:** The ciphertext is tamper-proof. Any modification (even flipping one bit) will result in an error during decryption.


### ⚠️ Security Notes

All schemes are implemented using well-regarded cryptographic primitives. However, please note:

*   **`ob01` and `ob21p` are not authenticated.** They are vulnerable to tampering. Furthermore, **`ob01` is cryptographically broken** due to its constant IV.
*   **Use `ob01` only if** you need maximum compactness and strong prefix entropy for *non-security-critical* use cases (e.g., obfuscation, development). For sensitive data, **always use** authenticated schemes (ob3x, such as ob31 or ob32).

## Performance

Oboron is designed for high performance with short strings, often outperforming both SHA256 and JWT while providing reversible encryption.

### Key Performance Insights

| Scheme | 8B Encode | 8B Decode | Security | Use Case |
|--------|-----------|-----------|----------|----------|
| **ob01** | 159 ns | 183 ns | Insecure | Maximum speed + compactness |
| **ob32** | 407 ns | 509 ns | Secure + Auth | Balanced performance + security |
| **JWT** | 550 ns | 846 ns | Auth only`*` | No encryption, signature only |
| **SHA256** | 191 ns | N/A | One-way | Hashing only |

`*` **Note**: The JWT baseline (HMAC-SHA256) provides authentication without encryption, which would correspond to Oboron's **ob1x tier** (insecure but authenticated) - a category we don't yet implement. Despite comparing against our stronger **ob3x tier** (secure + authenticated), Oboron still significantly outperforms JWT while providing full confidentiality.

**Notable advantages:**
- **ob01 is 3.5x faster than JWT** for encoding while producing 4.5x smaller output
- **All Oboron schemes are faster than JWT** for both encoding and decoding
- **ob01 even beats SHA256+hex** while providing reversible encryption

### Output length comparison

|           | Small string output | Visual |
|-----------|--------------------|--------------------|
| Oboron ob01: |  26 characters  | [================] |
| Oboron ob32: |  31 characters  | [===================] |
| Oboron ob32p: | 56 characters  | [===============================] |
| SHA256: |        64 characters | [==================================] |
| JWT:    |      150+ characters | [==================================================...] |

### When to Choose Which Scheme

- **ob01**: Non-security-critical applications needing maximum speed and compactness
- **ob32**: General-purpose secure encryption with deterministic output and compact size
- **ob32p**: Maximum privacy protection with probabilistic output (larger size due to nonce)

**Choose ob01 when:**
- Performance and compactness are paramount (~28 chars)
- Security requirements are minimal (obfuscation only)

**Choose ob32 when:**  
- You need cryptographic security with compact output (~31 chars)
- Deterministic behavior is useful (lookup keys, caching)

**Choose ob32p when:**
- You need cryptographic security with maximum privacy (~56 chars)  
- Hiding plaintext relationships is critical

### Feature Flags

Oboron supports optional feature flags to reduce binary size by including only the encryption schemes you need. This is documented in [README_FEATURES.md].

By default, **all schemes are enabled**.

## Applications

The most straightforward application of Oboron is as an easy-to-use general-purpose encryption library with its simple "string in, string out" API. However, Oboron's unique combination of properties—most notably its prefix entropy and compactness—opens possibilities for various specialized applications:

- **✅ Git-like short IDs** - High-entropy prefixes for unique references
- **✅ URL-friendly state tokens** - Encrypt web app state into compact URLs
- **✅ No-lookup captcha systems** - Server issues encrypted challenge, verifies without DB lookup
- **✅ Database ID obfuscation** - Hide sequential IDs while remaining reversible
- **✅ Compact authentication tokens** - Faster and smaller than JWT for simple use cases
- **✅ General-purpose symmetric encryption** - Simple "string in, string out" API

### Comparison with Alternatives

| Use Case | Traditional Solution | Oboron Advantage |
|----------|----------------------|------------------|
| Short unique IDs | UUIDv4 (36 chars) | **ob01** (26 chars, reversible) |
| URL parameters | JWT (150+ chars) | **4.5x smaller, 3x faster** |
| Database ID masking | Hashids (not secure) | **Proper encryption** |
| Simple encryption | Libsodium (complex) | **String in, string out** |

### Simplifying Crypto Library Usage

Oboron dramatically simplifies symmetric encryption compared to lower-level crypto libraries:

**Before (libsodium/ring - complex, bytes everywhere):**
```rust
// Key management headaches
let key = generic_hash::Key::generate();
let nonce = randombytes::randombytes(24);
let ciphertext = secretbox::seal(plaintext, &nonce, &key)?;

// Manual hex/base64 encoding needed
let encoded = base64::encode(ciphertext);
```

**After (Oboron - simple, strings throughout):**
```rust
let cipher = Ob32::new(env::var("OBORON_KEY")?);
let encrypted = cipher.encode("Hello World")?; // That's it!
// "ob32:uf2glao2xd7fnbq5z53cb63ukc"
```

**Benefits:**
- ✅ No more manual hex/base64 encoding/decoding
- ✅ Keys as simple hex strings (no byte array management)
- ✅ Built-in nonce generation (where applicable)
- ✅ Consistent error handling
- ✅ Single dependency vs multiple crypto crates

**When Oboron fits your crypto needs:**
- General symmetric encryption use cases
- Need for compact, referenceable outputs
- Simple key management (single 512-bit key)
- String-to-string interface (no manual encoding/decoding)

**When to stick with lower-level libraries:**
- Need specific algorithms (ChaCha20-Poly1305, etc.)
- Streaming encryption of large files
- Public-key cryptography
- Specialized protocols (Signal, Noise, etc.)

### Pattern Replacement Examples

#### Database ID Obfuscation (Replacing Hashids)

**Before (Hashids - insecure, not encrypted):**
```rust
let hashids = Hashids::new("salt", 6);
let obfuscated = hashids.encode(&[123]); // "k2d3e4"
```

**After (Oboron - encrypted, reversible, secure):**
```rust
let cipher = Ob32::new(env::var("OBORON_KEY")?);
let encrypted = cipher.encode("user:123")?; // "ob32:uf2glao2xd7f"
// Can include namespace prefix to prevent type confusion
```

**Advantages:**
- ✅ Encodes arbitrary strings (Hashids can only encode integers)
- ✅ Actually encrypted (not just encoded)
- ✅ Can embed metadata (e.g., `"user:"`, `"order:"` prefixes, or JSON format)
- ✅ Referenceable short prefixes
- ✅ Tamper-proof (with authenticated schemes)

#### Simple State Tokens (Replacing JWT)

**Before (JWT - large, complex):**
```rust
// 150+ characters, requires JWT library
let token = encode(&Header::default(), &claims, &EncodingKey)?;
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**After (Oboron - compact, simple):**
```rust
let cipher = Ob31::new(env::var("OBORON_KEY")?);
let state = serde_json::to_string(&claims)?;
let token = cipher.encode(&state)?; // ~31 characters
// "ob31:b4g9lao2xd7fnbq5z53cb63ukc"
```

**When to use Oboron over JWT:**
- ✅ Simple symmetric encryption use cases
- ✅ When compact size matters (URL parameters)
- ✅ When you don't need JWT's standardization
- ✅ When speed is critical

**When to stick with JWT:**
- ❌ Need industry-standard tokens
- ❌ Require public/private key signatures
- ❌ Complex claims with registered names


### UUID-like ID Generation and SHA256 Alternatives

Oboron offers a faster, more compact alternative to both UUIDs and SHA256 for generating unique, referenceable identifiers. The trimmed prefix approach provides hash-like functionality with better performance and superior prefix quality.

#### Two Approaches for Oboron-based IDs

##### Approach 1: Full Oboron Output (Reversible)
```rust
let cipher = Ob01::new_public(); // Obfuscation only
let full_id = cipher.encode(format!("user:{}", user_id))?;
// "ob01:uf2glao2xd7fnbq5z53cb63ukc" (26 base32 chars, reversible)
```

**Pros:** Reversible (can decode back to "user:123"), full Oboron benefits  
**Cons:** With public key: Anyone can decode; reveals structure  
**Best for:** Internal systems where reversibility is useful and structure isn't secret.

##### Approach 2: Trimmed Prefix (Hash-like, Non-reversible)
```rust
let cipher = Ob01::new_public();
// Add constant domain separator for multiple blocks
let full = cipher.encode(format!("myapp:user:{}", user_id))?;
let short_id = &full[0..20]; // "uf2glao2xd7fnbq5z53" (20 base32 chars)
```

**Pros:** Non-reversible even with public key, no key management needed, tunable length  
**Best for:** Public-facing identifiers where you want opacity and referenceable prefixes.

#### Oboron as a SHA256 Alternative

**SHA256 is not optimized for short strings** - it's designed for cryptographic hashing of arbitrary-length data. Oboron outperforms it significantly for short string operations while providing more compact, referenceable outputs.

**Hex Encoding Comparison:**
- **SHA256:** 64 hex characters (256 bits, 128-bit collision resistance)
- **Oboron ob01 (one block):** 34 hex characters for short inputs
- **Oboron ob01 (with padding for two blocks):** 66 hex characters (~330 bits)

**To achieve stronger collision resistance than SHA256,** use a deterministic domain separator to ensure multiple cipher blocks:

```rust
// SHA256 approach (traditional, 64 hex chars)
use sha2::{Sha256, Digest};
let hash = format!("{:x}", Sha256::digest(input)); // ~190 ns
// "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"

// Oboron with hex encoding (34 chars for short inputs)
let cipher = Ob01Hex::new_public();
let hash1 = cipher.encode(input)?; // ~120 ns
// "a1b2c3d4e5f6..." (34 hex chars)

// Oboron with padding for >SHA256 strength (66 hex chars)
let padded = format!("sha256-alternative:{}", input); // Domain separator
let hash2 = cipher.encode(&padded)?; // ~138 ns  
// "a1b2c3d4e5f6..." (66 hex chars, stronger than SHA256)
```

**Base32 Encoding (Default, More Compact):**
- **Oboron ob01 (one block):** 26 base32 characters (same as 34 hex chars)
- **Oboron ob01 (two blocks):** 52 base32 characters (same as 66 hex chars)

**Benchmarks for short strings (8-32 bytes):**
- **SHA256 + hex:** ~190 ns, 64 hex characters (128-bit collision resistance)
- **Oboron ob01 (one block):** ~120 ns, 26 base32/34 hex chars (37% faster)
- **Oboron ob01 (two blocks):** ~138 ns, 52 base32/66 hex chars (27% faster, stronger than SHA256)

#### Collision Resistance Comparison

**Common use cases:**
- **6 base32 chars (30 bits):** Beats 7 hex chars (28 bits) for Git-like short references
- **20 base32 chars (100 bits):** Comparable to SHA1's collision resistance
- **26 base32 chars (130 bits):** Slightly stronger than SHA256's 128 bits  
- **52 base32 chars (260 bits):** Much stronger than SHA256

**Key Advantages of Oboron:**
1. **Better performance** - 27-37% faster than SHA256 for short strings
2. **More compact encoding** - Base32 provides 5 bits per char vs hex's 4 bits
3. **Referenceable prefixes** - High entropy from the first character (matches SHA256 quality)
4. **Tunable security** - Choose exact prefix length for your collision resistance needs
5. **Deterministic guarantee** - No birthday paradox (different inputs always produce different outputs)

#### Performance Comparison:
```
// Generate 1M unique IDs (benchmark for 16-byte inputs):
UUIDv4:                    ~25 ns each = 25 ms total (poor prefixes)
SHA256 (64 hex chars):    ~190 ns each = 190 ms total
Oboron ob01 (26 b32):     ~120 ns each = 120 ms total (37% faster, 59% smaller)
Oboron ob01 (52 b32):     ~138 ns each = 138 ms total (27% faster, stronger)

// Equivalent collision resistance:
SHA256:       190 ns, 64 hex chars, 128-bit collision resistance
Oboron (26):  120 ns, 26 base32 chars, 130-bit collision resistance
Oboron (52):  138 ns, 52 base32 chars, 260-bit collision resistance
```

**When to choose which approach:**
- **Use Oboron (26 chars)** for general-purpose hashing with SHA256-level security and better performance
- **Use Oboron (52 chars)** when you need stronger-than-SHA256 guarantees
- **Use shorter prefixes (6 chars)** for Git-like short references
- **All Oboron variants** beat SHA256 in speed while matching its prefix quality

**Note:** While Oboron provides excellent collision resistance for identifier generation, it's not a drop-in replacement for cryptographic hashing in all contexts (e.g., password hashing, where slow hashes are desired).


## Python API Overview

Oboron-py provides a Pythonic interface to the Oboron library, maintaining consistency with the Rust API while following Python conventions.  The library offers three main API styles:

### 1. **Compile-time Format Selection** (Best Performance)

Use scheme-specific classes when you know the format at import time.  This provides the best performance and clarity:

```python
import oboron

# Get your key (512-bit, 128 hex characters)
key = "0123456789abcdef..."  # In practice: os.environ["OBORON_KEY"]

# Create a cipher with a specific format
cipher = oboron. Ob32_B64(key)

encoded = cipher.encode("hello")
decoded = cipher.decode(encoded)
assert decoded == "hello"
```

Available classes include combinations of schemes (`Ob01`, `Ob21p`, `Ob31`, `Ob31p`, `Ob32`, `Ob32p`) and encodings (`_B64` for Base64, `Hex` for hexadecimal, or default Base32). 

### 2. **Runtime Format Selection** (`Ob`)

When you need to specify the format at runtime, use `Ob`.  In Python, this allows changing the format after creation:

```python
import oboron

key = "0123456789abcdef..."

# Create with initial format
ob = oboron.Ob("ob32:b64", key)

encoded = ob.encode("hello")
decoded = ob.decode(encoded)
assert decoded == "hello"

# Change format on the fly (Python doesn't have immutability)
ob.set_format("ob32p:hex")
encoded2 = ob.encode("world")
```

**Note**: While Rust has both `Ob` (immutable) and `ObFlex` (mutable), Python's `Ob` exposes the mutable `ObFlex` behavior since Python doesn't enforce immutability.

### 3. **Working with Multiple Formats** (`ObMulti`)

`ObMulti` is designed for working with different formats simultaneously.  It doesn't store a format internally - you specify it for each operation:

```python
import oboron

key = "0123456789abcdef..."
multi = oboron.ObMulti(key)

# Encode with different formats
enc_b32 = multi.encode("test", "ob32p:b32")
enc_b64 = multi.encode("test", "ob70:b64")
enc_hex = multi.encode("test", "ob01:hex")

# Decode with explicit format
decoded = multi.decode(enc_b64, "ob70:b64")

# Autodecode - automatically detect both scheme AND encoding
decoded2 = multi. autodecode(enc_b64)  # Detects ob70:b64
```

**Autodecode**: Only `ObMulti` supports full format autodetection (both scheme and encoding).  Other classes only autodetect the scheme, requiring the encoding to match.

### 4. **Convenience Functions** (One-shot Operations)

For simple one-off operations, use the module-level convenience functions:

```python
import oboron

key = oboron.generate_key()

# Basic encode/decode
encoded = oboron.encode("secret", "ob32:b32", key)
decoded = oboron.decode(encoded, "ob32:b32", key)

# Autodecode (detects format automatically)
decoded2 = oboron.autodecode(encoded, key)

# Recommended shortcuts
det = oboron.encode_det("data", key)      # Uses ob32:b32 (deterministic)
prob = oboron.encode_prob("data", key)    # Uses ob32p:b32 (probabilistic)
```

### Available Convenience Functions

```python
# Key generation
oboron.generate_key()           # Returns 128-char hex string
oboron.generate_key_bytes()         # Returns 64 bytes

# Encoding/decoding
oboron.encode(plaintext, format, key)
oboron.decode(obtext, format, key)
oboron.autodecode(obtext, key)

# Recommended defaults
oboron.encode_det(plaintext, key)   # ob32:b32 (deterministic)
oboron.encode_prob(plaintext, key)  # ob32p:b32 (probabilistic)

# Testing only (with public key - NOT SECURE)
oboron.encode_public(plaintext, format)
oboron.decode_public(obtext, format)
oboron.autodecode_public(obtext)
oboron.encode_det_public(plaintext)
oboron.encode_prob_public(plaintext)
```

### The Common Interface

All cipher classes (`Ob32`, `Ob`, `ObMulti`, etc.) share a common interface:

```python
# Encoding/Decoding
encoded = cipher.encode(plaintext)
decoded = cipher.decode(encoded)             # With autodetection
decoded = cipher. decode(encoded, strict=True) # Strict mode (no autodetection)

# Properties
hex_key = cipher.key              # Hex string
raw_bytes = cipher.key_bytes      # bytes object
scheme = cipher.scheme            # e.g., "Ob32"
encoding = cipher. encoding        # e.g., "Base32"

# Only for Ob (mutable format)
ob. set_format("ob31:hex")
ob.set_scheme("Ob32p")
ob.set_encoding("Base64")
current = ob.format()             # Returns "ob32p:b64"
```

### Key Management

Keys can be provided as hex strings (recommended) or for testing, omitted to use the public key:

```python
# From hex string (128 characters = 512 bits)
cipher = oboron.Ob32_B64(hex_key)
# Typically from environment variable
import os
cipher = oboron. Ob32_B64(os.environ["OBORON_KEY"])

# For testing only: use public key (NOT SECURE)
cipher = oboron.Ob32_B64()  # No key = public key
```

**⚠️ Warning**: Omitting the key uses a well-known public key and provides no security. Only use for testing or when obfuscation (not encryption) is the goal. 

### Complete Example

```python
import oboron
import os

# 1. Generate or load key
key = os.getenv("OBORON_KEY")
if not key:
    key = oboron.generate_key()
    print(f"Generated key: {key}")

# 2. Choose your approach based on use case

# Approach A: Fixed format (best performance)
cipher = oboron.Ob32_B64(key)
encrypted = cipher.encode("sensitive data")
decrypted = cipher.decode(encrypted)

# Approach B: Flexible format
ob = oboron.Ob("ob31:b32", key)
encrypted = ob. encode("hello")
ob.set_format("ob32p:hex")
encrypted2 = ob. encode("world")

# Approach C: Multi-format with autodecode
multi = oboron.ObMulti(key)
enc1 = multi.encode("data1", "ob01:b32")
enc2 = multi.encode("data2", "ob32:b64")
dec1 = multi.autodecode(enc1)  # Automatically detects ob01:b32
dec2 = multi.autodecode(enc2)  # Automatically detects ob32:b64

# Approach D: One-shot convenience functions
encrypted = oboron.encode("quick task", "ob70:b64", key)
decrypted = oboron.autodecode(encrypted, key)
```

### Available Schemes

| Scheme | Algorithm | Deterministic?  | Authenticated? | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `Ob00` | AES-CBC | ✅ Yes | ❌ No | **LEGACY** - backward compatibility only |
| `Ob01` | AES-CBC | ✅ Yes | ❌ No | Insecure - constant IV; use for obfuscation only |
| `Ob21p` | AES-CBC | ❌ No | ❌ No | Probabilistic, unauthenticated |
| `Ob31` | AES-GCM-SIV | ✅ Yes | ✅ Yes | Secure, deterministic, authenticated |
| `Ob31p` | AES-GCM-SIV | ❌ No | ✅ Yes | Secure, probabilistic, authenticated |
| `Ob32` | AES-SIV | ✅ Yes | ✅ Yes | **Recommended** - nonce-misuse resistant |
| `Ob32p`| AES-SIV | ❌ No | ✅ Yes | Secure, probabilistic, authenticated |
| `Ob71` | Reverse | ✅ Yes | ❌ No | Testing only - no encryption |
| `Ob70` | Identity | ✅ Yes | ❌ No | Testing only - no encryption |

### Available Encodings

Each scheme supports three encodings:
- **Base32** (default): Balanced, alphanumeric lowercase - e.g., `Ob32`
- **Base64** (`_B64` suffix): Most compact, case-sensitive - e.g., `Ob32_B64`
- **Hexadecimal** (`Hex` suffix): Longer but simple - e.g., `Ob32Hex`

### Common Patterns

#### Database ID Obfuscation

```python
import oboron

cipher = oboron.Ob32(os.environ["OBORON_KEY"])

# Obfuscate sequential IDs
public_id = cipher.encode(f"user:{user_id}")
# "uf2glao2xd7fnbq5z53cb63ukc"

# Reverse when needed
user_str = cipher.decode(public_id)
user_id = int(user_str.split(":")[1])
```

#### Compact State Tokens

```python
import oboron
import json

cipher = oboron.Ob31_B64(os.environ["OBORON_KEY"])

# Encode state as JSON
state = {"user_id": 123, "expires": 1234567890}
token = cipher.encode(json.dumps(state))
# Compact: ~40 characters vs 150+ for JWT

# Decode
state = json.loads(cipher.decode(token))
```

#### Short Unique IDs (Git-like)

```python
import oboron

cipher = oboron.Ob01()  # Public key for obfuscation only

# Generate referenceable IDs
full_id = cipher.encode(f"order:{order_id}")
short_ref = full_id[:7]  # Use first 7 chars as reference
# "uf2glao" - high entropy prefix
```

### Performance Considerations

- **Fixed format classes** (`Ob32_B64`) are fastest - format is compile-time
- **`Ob` class** has minimal overhead for format changes
- **`ObMulti. autodecode()`** has overhead from trying multiple encodings
- **Deterministic schemes** (`Ob32`) are faster than probabilistic (`Ob32p`)

### Error Handling

```python
import oboron

try:
    cipher = oboron.Ob32("invalid_key")
except ValueError as e:
    print(f"Key error: {e}")

try:
    decoded = cipher.decode("corrupted_data", strict=True)
except ValueError as e:
    print(f"Decoding failed: {e}")
```

### Type Hints

The library includes full type hints for better IDE support:

```python
from oboron import Ob32, ObMulti

def encrypt_id(user_id: int, cipher: Ob32) -> str:
    return cipher.encode(f"user:{user_id}")

def flexible_decode(data: str) -> str:
    multi = ObMulti(os.environ["OBORON_KEY"])
    return multi.autodecode(data)
```

## Compatibility

Oboron implementations are fully compatible across languages:
- Same encryption algorithms and key derivation
- Same encoding formats and scheme specifications
- Interoperable encoded values between Rust, Go, Python, Perl, TypeScript

## Getting Help

- [Documentation](https://docs.rs/oboron)
- [GitHub Issues](https://github.com/ob-enc/oboron-rs/issues)

## License

Licensed under the MIT license ([LICENSE](LICENSE)).
