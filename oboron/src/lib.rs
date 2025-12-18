//! This library provides encryption-based encoding to various text schemes
//! using AES encryption with multiple scheme options.
//!
//! # Quick Start
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "ob32")]
//! # {
//! use oboron::{Ob32, Oboron};
//! let key = oboron::generate_key();   // get key
//! let ob = Ob32::new(&key)?;          // instantiate Oboron (cipher+encoder)
//! let ot = ob.enc("secret data")?;    // get obtext (encoded ciphertext)
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! # Parameter Order Convention
//!
//! All functions in this library follow a consistent parameter ordering convention:
//!
//! **`data` < `format` < `key`**
//!
//! - **Data** (plaintext/obtext) comes first - it's what you're operating on
//! - **Format** comes second (when present) - it's configuration/options
//! - **Key** comes last (when present) - it's the security credential
//!
//! Examples:
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "ob32")]
//! # {
//! # use oboron;
//! # let key = oboron::generate_key();
//! # let obm = oboron::ObMulti::new(&key)?;
//! // Operations: data, format
//! let ot = obm.enc("plaintext", "ob32:b64")?;
//! obm.dec(&ot, "ob32:b64")?;
//!
//! // Constructors: format, key
//! oboron::Ob::new("ob32:b64", &key)?;
//! oboron::ObFlex::new("ob32:b64", &key)?;
//!
//! // Convenience functions: data, format, key
//! let ot = oboron::enc("plaintext", "ob32:b64", &key)?;
//! oboron::dec(&ot, "ob32:b64", &key)?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! # Choosing the Right Type
//!
//! Oboron provides several types optimized for different use cases:
//!
//! ## 1. Static Format Types (Fastest, Compile-Time)
//!
//! Use scheme-specific types when you know the format at compile time:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "ob32")]
//! # {
//! # use oboron::{Ob32, Ob32Base64, Oboron};
//! # let key = oboron::generate_key();
//! let ob32 = Ob32::new(&key)?;            // ob32:c32 format (Base32Crockford)
//! let ob32_b64 = Ob32Base64::new(&key)?;  // ob32:b64 format (Base64)
//!
//! let ot = ob32.enc("hello")?;
//! let pt2 = ob32.dec(&ot)?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! - Use case: Format is known at compile time  
//! - Performance: Fastest (zero overhead)  
//! - Flexibility: Format fixed in type name
//!
//! ## 2. `Ob` - Runtime Format (Immutable)
//!
//! Use `Ob` when you need to choose the format at runtime, but won't change it:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "ob32")]
//! # {
//! # use oboron::{Ob, Oboron};
//! # let key = oboron::generate_key();
//! // Format chosen at runtime, immutable instance
//! let ob = Ob::new("ob32:b64", &key)?;
//!
//! let ot = ob.enc("hello")?;
//! let pt2 = ob.dec(&ot)?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! - Use case: Format determined at runtime (config, user input)
//! - Performance: Near-zero overhead (inlines to static functions)
//! - Flexibility: Runtime format selection, immutable after construction
//!
//! ## 3. `ObFlex` - Mutable Format
//!
//! Use `ObFlex` when you need to change formats during execution:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(all(feature = "ob32", feature = "non-crypto"))]
//! # {
//! # use oboron::{ObFlex, Oboron, Scheme, Encoding};
//! # let key = oboron::generate_key();
//! let mut flex = ObFlex::new("ob32:b64", &key)?;
//! let ot1 = flex.enc("hello")?;    // ob32:b64 format
//!
//! // Change format at runtime
//! flex.set_scheme(Scheme::Ob70)?;  // set_scheme() only with ObFlex
//! let ot2 = flex.enc("hello")? ;   // ob70:b64 format output
//! // Also available:
//! flex.set_encoding(Encoding::Hex)?; // now set as ob70:hex
//! flex.set_format("ob32:b32")?;      // now ob32:b32
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! - Use case: Need to switch between formats dynamically
//! - Performance: Minimal overhead
//! - Flexibility: Fully mutable format
//!
//! ## 4. `ObMulti` - Multi-Format Operations
//!
//! Use `ObMulti` when working with different formats in a single context:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "ob32")]
//! # {
//! # use oboron::ObMulti;
//! # let key = oboron::generate_key();
//! let obm = ObMulti::new(&key)?;
//!
//! // Encode to different formats
//! let ot_b32 = obm.enc("data", "ob32:c32")?;
//! let ot_b64 = obm.enc("data", "ob32:b64")?;
//! let ot_hex = obm.enc("data", "ob32:hex")?;
//!
//! // Decode with automatic format detection
//! let pt2 = obm.autodec(&ot_b64)?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! - Use case: Working with multiple formats or unknown formats
//! - Performance: Small overhead (format parsing per operation)
//! - Flexibility: Maximum - handles any format, autodetects on dec
//!
//! # Typical Production Usage: Fixed Oboron
//!
//! Best performance and type safety for multiple operations with the same format:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(all(feature = "ob32", feature = "non-crypto"))]
//! # {
//! # use oboron::Oboron;
//! # use oboron;
//! # let key = oboron::generate_key();
//! // Fixed format types (best performance for multiple operations with same format)
//! let ob32 = oboron::Ob32::new(&key)?;  // "ob32:c32" format Oboron instance
//! let ob70 = oboron::Ob70::new(&key)?;  // "ob70:c32" format Oboron instance
//!
//! let ot_ob32 = ob32.enc("data1")?;
//! let ot_ob70 = ob70.enc("data2")?;
//!
//! // Decoding uses scheme autodetection by default
//! let pt1 = ob32.dec(&ot_ob32)?;  // Decodes successfully
//! let pt2 = ob32.dec(&ot_ob70)?;  // Also works (autodetects ob70)
//! assert_eq!(pt1, "data1");
//! assert_eq!(pt2, "data2");
//! // Note: The above autodetection works only with shared encodings
//! // ob32:c32 and ob70:c32 are both base32crockford-encoded
//!
//! // Use dec_strict to enforce scheme matching
//! let pt3 = ob32.dec_strict(&ot_ob32)?;         // OK: Matches scheme
//! assert!(ob32.dec_strict(&ot_ob70).is_err());  // Error: Wrong scheme (ob32 != ob70)
//!
//! // Note: For fixed oborons, string encoding (c32/b32/b64/hex) must match the instance encoding
//! let ob32_b64 = oboron::Ob32Base64::new(&key)?;  // "ob32:b64" format Oboron
//! let ot_b64 = ob32_b64.enc("data3")?;
//! assert!(ob32.dec(&ot_b64).is_err());  // Error: Encoding mismatch (c32 != b64)
//! // For mixed encodings, use ObMulti instead (see above)
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! # Encryption Schemes
//!
//! - `Ob01`: AES-CBC (deterministic)
//! - `Ob31`: AES-GCM-SIV (deterministic)
//! - `Ob32`: AES-SIV (deterministic, nonce-misuse resistant)
//! - `Ob21p`, `Ob31p`, `Ob32p`: Probabilistic variants (different output each time)
//!
//! Testing/Demo only schemes using no encryption (`non-crypto` feature group):
//! - `Ob70`: Identity
//! - `Ob71`: Reverse plaintext
//!
//! Each scheme supports four string encodings:
//! - Base32Crockford,
//! - Base32Rfc (RFC 4648 standard),
//! - Base64 (URL-safe RFC 4648 standard),
//! - Hex
//!
//! # The `Oboron` Trait
//!
//! All types (`Ob32`, `Ob`, `ObFlex`, etc.) except `ObMulti` implement the `Oboron` trait,
//! providing a consistent interface:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "ob32")]
//! # {
//! # use oboron::{Oboron, Ob32, Ob};
//! # let key = oboron::generate_key();
//! fn process<O: Oboron>(ob: &O, data: &str) -> Result<String, oboron::Error> {
//!     let ot = ob.enc(data)?;
//!     ob.dec(&ot)
//! }
//!
//! let ob32 = Ob32::new(&key)?;
//! let ob = Ob::new("ob32:c32", &key)?;
//!
//! process(&ob32, "hello")?;
//! process(&ob, "hello")?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! The `Oboron` trait is automatically imported via the prelude.

mod base32;
mod constants;
mod dec;
mod dec_auto;
mod enc;
mod encoding;
mod error;
mod format;
#[cfg(feature = "ob00")]
mod legacy;
mod ob;
mod ob_core;
mod ob_flex;
mod ob_multi;
mod obcrypt;
mod oboron;
mod scheme;

// Re-export public types and constants
pub use constants::{HARDCODED_KEY_BASE64, HARDCODED_KEY_BYTES};
pub use error::Error;

// Re-export from obcrypt
pub(crate) use obcrypt::Keychain;

#[cfg(feature = "ob01")]
pub(crate) use obcrypt::{decrypt_ob01, encrypt_ob01};
#[cfg(feature = "ob21p")]
pub(crate) use obcrypt::{decrypt_ob21p, encrypt_ob21p};
#[cfg(feature = "ob31")]
pub(crate) use obcrypt::{decrypt_ob31, encrypt_ob31};
#[cfg(feature = "ob31p")]
pub(crate) use obcrypt::{decrypt_ob31p, encrypt_ob31p};
#[cfg(feature = "ob32")]
pub(crate) use obcrypt::{decrypt_ob32, encrypt_ob32};
#[cfg(feature = "ob32p")]
pub(crate) use obcrypt::{decrypt_ob32p, encrypt_ob32p};

// Testing
#[cfg(feature = "ob70")]
pub(crate) use obcrypt::{decrypt_ob70, encrypt_ob70};
#[cfg(feature = "ob71")]
pub(crate) use obcrypt::{decrypt_ob71, encrypt_ob71};

pub use obcrypt::{
    generate_key_base64, generate_key_base64 as generate_key, generate_key_bytes, generate_key_hex,
};

// Re-export core types
pub use encoding::Encoding;
pub use format::Format;
pub use scheme::Scheme;

// Re-export trait-based implementations
pub use ob::Ob;
pub use ob_flex::ObFlex;

// Factory functions
#[cfg(feature = "bytes-keys")]
pub use oboron::{from_bytes, from_bytes_with_format};
#[cfg(feature = "hex-keys")]
pub use oboron::{from_hex_key, from_hex_key_with_format};
pub use oboron::{new, new_with_format, ObAny, Oboron};
#[cfg(feature = "keyless")]
pub use oboron::{new_keyless, new_keyless_with_format};

// Conditionally export format string constants (scheme+encoding combinations)
#[cfg(feature = "ob01")]
pub use constants::{OB01_B32, OB01_B64, OB01_C32, OB01_HEX};
#[cfg(feature = "ob21p")]
pub use constants::{OB21P_B32, OB21P_B64, OB21P_C32, OB21P_HEX};
#[cfg(feature = "ob31p")]
pub use constants::{OB31P_B32, OB31P_B64, OB31P_C32, OB31P_HEX};
#[cfg(feature = "ob31")]
pub use constants::{OB31_B32, OB31_B64, OB31_C32, OB31_HEX};
#[cfg(feature = "ob32p")]
pub use constants::{OB32P_B32, OB32P_B64, OB32P_C32, OB32P_HEX};
#[cfg(feature = "ob32")]
pub use constants::{OB32_B32, OB32_B64, OB32_C32, OB32_HEX};
// Testing
#[cfg(feature = "ob70")]
pub use constants::{OB70_B32, OB70_B64, OB70_C32, OB70_HEX};
#[cfg(feature = "ob71")]
pub use constants::{OB71_B32, OB71_B64, OB71_C32, OB71_HEX};
// Legacy
#[cfg(feature = "ob00")]
pub use constants::{OB00_B32, OB00_B64, OB00_C32, OB00_HEX};

// Conditionally export format-specific structs (scheme+encoding combinations)
#[cfg(feature = "ob01")]
pub use oboron::{Ob01Base32Crockford, Ob01Base32Rfc, Ob01Base64, Ob01Hex};
#[cfg(feature = "ob21p")]
pub use oboron::{Ob21pBase32Crockford, Ob21pBase32Rfc, Ob21pBase64, Ob21pHex};
#[cfg(feature = "ob31")]
pub use oboron::{Ob31Base32Crockford, Ob31Base32Rfc, Ob31Base64, Ob31Hex};
#[cfg(feature = "ob31p")]
pub use oboron::{Ob31pBase32Crockford, Ob31pBase32Rfc, Ob31pBase64, Ob31pHex};
#[cfg(feature = "ob32")]
pub use oboron::{Ob32Base32Crockford, Ob32Base32Rfc, Ob32Base64, Ob32Hex};
#[cfg(feature = "ob32p")]
pub use oboron::{Ob32pBase32Crockford, Ob32pBase32Rfc, Ob32pBase64, Ob32pHex};
// Testing
#[cfg(feature = "ob70")]
pub use oboron::{Ob70Base32Crockford, Ob70Base32Rfc, Ob70Base64, Ob70Hex};
#[cfg(feature = "ob71")]
pub use oboron::{Ob71Base32Crockford, Ob71Base32Rfc, Ob71Base64, Ob71Hex};
// Legacy
#[cfg(feature = "ob00")]
pub use legacy::{Ob00Base32Crockford, Ob00Base32Rfc, Ob00Base64, Ob00Hex};

// Aliases for default encoding:
#[cfg(feature = "ob01")]
pub type Ob01 = Ob01Base32Crockford;
#[cfg(feature = "ob21p")]
pub type Ob21p = Ob21pBase32Crockford;
#[cfg(feature = "ob31")]
pub type Ob31 = Ob31Base32Crockford;
#[cfg(feature = "ob31p")]
pub type Ob31p = Ob31pBase32Crockford;
#[cfg(feature = "ob32")]
pub type Ob32 = Ob32Base32Crockford;
#[cfg(feature = "ob32p")]
pub type Ob32p = Ob32pBase32Crockford;
// Testing
#[cfg(feature = "ob70")]
pub type Ob70 = Ob70Base32Crockford;
#[cfg(feature = "ob71")]
pub type Ob71 = Ob71Base32Crockford;
// Legacy
#[cfg(feature = "ob00")]
pub type Ob00 = Ob00Base32Rfc;

// Re-export multi-format Oboron implementation
pub use ob_multi::ObMulti;

/// Convenience prelude for common imports.
///
/// Import everything you need with:
/// ```rust
/// use oboron::prelude::*;
/// ```
pub mod prelude {
    #[cfg(feature = "ob32")]
    pub use crate::Ob32;
    #[cfg(feature = "ob32p")]
    pub use crate::Ob32p;
    pub use crate::{Encoding, Error, Format, Oboron, Scheme};
    pub use crate::{Ob, ObFlex, ObMulti};
}

// ============================================================================
// Convenience Functions
// ============================================================================
//
// All convenience functions follow the parameter order convention:
//   data < format < key
//
// This ensures consistency across the API:
// - Data (plaintext/obtext) always comes first
// - Format specification comes second (when present)
// - Key comes last (when present)
// ============================================================================

/// Encrypt+encode plaintext with a specified format.
///
/// This is a convenience wrapper around [`ObMulti::enc`].
/// For repeated operations, consider creating an [`ObMulti`] instance directly.
///
/// # Parameter Order
/// `(data, format, key)` - follows the convention: data < format < key
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "ob32")]
/// # {
/// # use oboron;
/// # let key = oboron::generate_key();
/// let ot = oboron::enc("secret data", "ob32:b64", &key)?;
/// # }
/// # Ok(())
/// # }
/// ```
pub fn enc(plaintext: &str, format: &str, key: &str) -> Result<String, Error> {
    ObMulti::new(key)?.enc(plaintext, format)
}

/// Encrypt+encode plaintext with a specified format using the hardcoded key (testing only).
///
/// # Parameter Order
/// `(data, format)` - key is implicit (hardcoded key)
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "ob32")]
/// # {
/// # use oboron;
/// let ot = oboron::enc_keyless("test data", "ob32:b64")?;
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "keyless")]
pub fn enc_keyless(plaintext: &str, format: &str) -> Result<String, Error> {
    ObMulti::new_keyless()?.enc(plaintext, format)
}

/// Decode+decrypt obtext with a specified format.
///
/// This is a convenience wrapper around [`ObMulti::dec_with_format`].
/// For repeated operations, consider creating an [`ObMulti`] instance directly.
///
/// # Parameter Order
/// `(data, format, key)` - follows the convention: data < format < key
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "ob32")]
/// # use oboron;
/// # {
/// # let key = oboron::generate_key();
/// # let ot = oboron::enc("test123", "ob32:b64", &key)?;
/// let pt2 = oboron::dec(&ot, "ob32:b64", &key)?;
/// # assert_eq!(pt2, "test123");
/// # }
/// # Ok(())
/// # }
/// ```
pub fn dec(obtext: &str, format: &str, key: &str) -> Result<String, Error> {
    ObMulti::new(key)?.dec(obtext, format)
}

/// Decode+decrypt obtext with a specified format using the hardcoded key (testing only).
///
/// # Parameter Order
/// `(data, format)` - key is implicit (hardcoded key)
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "ob32")]
/// # {
/// # use oboron;
/// # let ot = oboron::enc_keyless("test", "ob32:b64")?;
/// let pt2 = oboron::dec_keyless(&ot, "ob32:b64")?;
/// # assert_eq!(pt2, "test");
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "keyless")]
pub fn dec_keyless(obtext: &str, format: &str) -> Result<String, Error> {
    ObMulti::new_keyless()?.dec(obtext, format)
}

/// Decode+decrypt obtext with automatic format detection.
///
/// Automatically detects both the scheme and encoding used.
/// This is a convenience wrapper around [`ObMulti::dec`].
///
/// # Parameter Order
/// `(data, key)` - format is autodetected
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "ob32")]
/// # {
/// # use oboron;
/// # let key = oboron::generate_key();
/// # let ot = oboron::enc("secret", "ob32:b64", &key)?;
/// let pt2 = oboron::autodec(&ot, &key)?;  // Format autodetected, including encoding
/// # assert_eq!(pt2, "secret");
/// # }
/// # Ok(())
/// # }
/// ```
pub fn autodec(obtext: &str, key: &str) -> Result<String, Error> {
    ObMulti::new(key)?.autodec(obtext)
}

/// Decode+decrypt obtext with automatic format detection using the hardcoded key (testing only).
///
/// # Parameter Order
/// `(data)` - both format and key are implicit
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "ob32")]
/// # {
/// # use oboron;
/// # let ot = oboron::enc_keyless("test", "ob70:b64")?;
/// let pt2 = oboron::autodec_keyless(&ot)?; // Autodetect format; use hardcoded key
/// # assert_eq!(pt2, "test");
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "keyless")]
pub fn autodec_keyless(obtext: &str) -> Result<String, Error> {
    ObMulti::new_keyless()?.autodec(obtext)
}
