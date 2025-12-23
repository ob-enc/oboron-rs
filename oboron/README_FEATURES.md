# Feature Flags

Oboron supports optional feature flags to reduce binary size by including only the encryption schemes you need.

## Default Behavior

By default, **all secure production-ready schemes are enabled**:

```toml
[dependencies]
oboron = "1.0"
```

This includes: `upbc`, `aags`, `apgs`, `aasv`, `apsv`.

All encodings (`.c32`-Crockford base32, `.b32`-standard base32, `.b64`-URL-safe base64, and `.hex`-hex) are always included.

### NOT INCLUDED BY DEFAULT

- `zrbcx` scheme (cryptographically broken)
- the `keyless` feature providing Oboron functionality with the hardcoded
  key
- alternative key input formats `hex-keys`, `bytes-keys`
- `unchecked-utf8`

These features must be enabled explicitly in your application.

## Minimal Build

To use only what you need:

```toml
[dependencies]
oboron = { version = "1.0", default-features = false, features = ["aasv"] }
```
This minimal configuration includes only base64 key support and excludes
hex/bytes key interfaces and the keyless testing feature.

## Available Features

### Individual Schemes

- `zrbcx` - AES-CBC (deterministic)
- `upbc` - AES-CBC (probabilistic)
- `aags` - AES-GCM-SIV (deterministic)
- `apgs` - AES-GCM-SIV (probabilistic)
- `aasv` - AES-SIV (deterministic)
- `apsv` - AES-SIV (probabilistic)

Testing schemes (non-cryptographic):
- `mock1` - identity transformation (ciphertext = plaintext bytes)
- `mock2` - reversed plaintext

### Unsafe Performance Enhancement

- `unchecked-utf8` - Skips UTF-8 validation after decryption.  Use for a
  minor performance improvement in dec operations in trusted source
  scenarios.  Note that using a wrong key may produce garbage out rather
  than an error.

### Experimental and Legacy Schemes

Feature groups:
- `experimental` - Group for experimental schemes
- `legacy` - Includes `legacy` scheme for compatibility with existing
  deployments

**Note:** `legacy` is a legacy scheme used internally by early adopters.
New users should use `zrbcx` instead, which provides improved prefix
entropy and better padding. This feature is only for maintaining
compatibility with existing encrypted data.

Note: Experimental and legacy features are not covered by semantic
versioning guarantees and may change or be removed in patch releases.

### Scheme Groups

By algorithm
- `all-cbc-schemes` - Includes `zrbcx`, `upbc`
- `all-gcm-schemes` - Includes `aags`, `apgs`
- `all-siv-schemes` - Includes `aasv`, `apsv`

By properties:
- `deterministic-schemes` - Includes `zrbcx`, `aags`, `aasv`
- `probabilistic-schemes` - Includes `upbc`, `apgs`, `apsv`
- `authenticated-schemes` - Includes `aags`, `apgs`, `aasv`, `apsv`
- `secure-schemes` - Includes all but `zrbcx`
- `insecure-schemes` - Includes `zrbcx` only

By tier:
- `ob0x` - Includes `zrbcx` only
- `ob1x` - No current members
- `ob2x` - Includes `upbc` only
- `ob3x` - Includes all authenticated schemes (= `authenticated-schemes`)

Testing:
- `mock` - Includes `mock1` and `mock2`

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

- **General purpose**: `aasv` (deterministic) or `apsv` (probabilistic)
- **Maximum speed, most compact output**: `zrbcx` (insecure, deterministic
  only)
- **Testing/obfuscation**: `zrbcx` with `keyless` feature

### Binary Size Impact (WASM)

For WebAssembly builds, the biggest size savings come from excluding
entire algorithm families. For example, if you only need AES-SIV, use
features = ["all-siv-schemes"] instead of individual aasv/apsv features.

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
