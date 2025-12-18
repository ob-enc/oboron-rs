# Feature Flags

Oboron supports optional feature flags to reduce binary size by including only the encryption schemes you need.

## Default Behavior

By default, **all secure production-ready schemes are enabled**:

```toml
[dependencies]
oboron = "1.0"
```

This includes: `ob21p`, `ob31`, `ob31p`, `ob32`, `ob32p`.

All encodings (`:c32`-Crockford base32, `:b32`-standard base32, `:b64`-URL-safe base64, and `:hex`-hex) are always included.

### NOT INCLUDED BY DEFAULT

- `ob01` scheme (cryptographically broken)
- the `keyless` feature providing Oboron functionality with the hardcoded
  key
- alternative key input formats `hex-keys`, `bytes-keys`
- `unchecked-utf8`

These features must be enabled explicitly in your application.

## Minimal Build

To use only what you need:

```toml
[dependencies]
oboron = { version = "1.0", default-features = false, features = ["ob32"] }
```
This minimal configuration includes only base64 key support and excludes
hex/bytes key interfaces and the keyless testing feature.

## Available Features

### Individual Schemes

- `ob01` - AES-CBC (deterministic)
- `ob21p` - AES-CBC (probabilistic)
- `ob31` - AES-GCM-SIV (deterministic)
- `ob31p` - AES-GCM-SIV (probabilistic)
- `ob32` - AES-SIV (deterministic)
- `ob32p` - AES-SIV (probabilistic)

Testing schemes (non-cryptographic):
- `ob70` - identity transformation (ciphertext = plaintext bytes)
- `ob71` - uses reversed `ob70` ciphertext

### Unsafe Performance Enhancement

- `unchecked-utf8` - Skips UTF-8 validation after decryption.  Use for a
  minor performance improvement in dec operations in trusted source
  scenarios.  Note that using a wrong key may produce garbage out rather
  than an error.

### Experimental and Legacy Schemes

Feature groups:
- `experimental` - Group for experimental schemes
- `legacy` - Includes `ob00` scheme for compatibility with existing
  deployments

**Note:** `ob00` is a legacy scheme used internally by early adopters.
New users should use `ob01` instead, which provides improved prefix
entropy and better padding. This feature is only for maintaining
compatibility with existing encrypted data.

Note: Experimental and legacy features are not covered by semantic
versioning guarantees and may change or be removed in patch releases.

### Scheme Groups

By algorithm
- `all-cbc-schemes` - Includes `ob01`, `ob21p`
- `all-gcm-schemes` - Includes `ob31`, `ob31p`
- `all-siv-schemes` - Includes `ob32`, `ob32p`

By properties:
- `deterministic-schemes` - Includes `ob01`, `ob31`, `ob32`
- `probabilistic-schemes` - Includes `ob21p`, `ob31p`, `ob32p`
- `authenticated-schemes` - Includes `ob31`, `ob31p`, `ob32`, `ob32p`
- `secure-schemes` - Includes all but `ob01`
- `insecure-schemes` - Includes `ob01` only

By tier:
- `ob0x` - Includes `ob01` only
- `ob1x` - No current members
- `ob2x` - Includes `ob21p` only
- `ob3x` - Includes all authenticated schemes (= `authenticated-schemes`)

Testing:
- `non-crypto` - Includes `ob70` and `ob71`

Comprehensive group
- `all-schemes` - Includes all schemes (same as default)

**Applications:**  
- For most cryptographic applications, use authenticated schemes (ob3x
  tier).  
- Choose deterministic schemes when you need the same plaintext to always
  produce the same ciphertext (e.g., for database lookups, caching, or
  hash-like behavior)  
- Choose probabilistic schemes when you need different ciphertexts for
  the same plaintext (e.g., for privacy, hiding relationships)

For detailed guidance on scheme selection, see the [Scheme Selection Guidelines](#scheme-selection-guidelines)
in the main documentation.

### Key Format Support

All disabled by default:
- `hex-keys` - Enables hex string key input
- `bytes-keys` - Enables raw byte array key input
- `keyless` - Enables insecure hardcoded key use for testing and
  obfuscation

### Quick Selection Guide

- **General purpose**: `ob32` (deterministic) or `ob32p` (probabilistic)
- **Maximum speed, most compact output**: `ob01` (insecure, deterministic
  only)
- **Testing/obfuscation**: `ob01` with `keyless` feature

### Binary Size Impact (WASM)

For WebAssembly builds, the biggest size savings come from excluding
entire algorithm families. For example, if you only need AES-SIV, use
features = ["all-siv-schemes"] instead of individual ob32/ob32p features.

## Examples

### Deterministic schemes with keyless feature

```toml
oboron = { version = "1.0", default-features = false, features = ["deterministic-schemes", "keyless"] }
```

### Probabilistic schemes with hex key interface

```toml
oboron = { version = "1.0", default-features = false, features = ["probabilistic-schemes", "hex-keys"] }
```

### SIV schemes (most secure) with bytes key interface

```toml
oboron = { version = "1.0", default-features = false, features = ["all-siv-schemes", "bytes-keys"] }
```

## Note

At least one scheme must be enabled.  Attempting to build with no features will result in a compile error. 
