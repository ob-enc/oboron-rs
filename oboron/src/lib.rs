//! This library provides encryption-based encoding to various text schemes
//! using AES encryption with multiple scheme options.
//!
//! # Quick Start
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "adsv")]
//! # {
//! use oboron::{AdsvC32, Oboron};
//! let key = oboron::generate_key();   // get key
//! let ob = AdsvC32::new(&key)?;          // instantiate Oboron (cipher+encoder)
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
//! # #[cfg(feature = "adsv")]
//! # {
//! # use oboron;
//! # let key = oboron::generate_key();
//! # let obm = oboron::ObMulti::new(&key)?;
//! // Operations: data, format
//! let ot = obm.enc("plaintext", "adsv:b64")?;
//! obm.dec(&ot, "adsv:b64")?;
//!
//! // Constructors: format, key
//! oboron::Ob::new("adsv:b64", &key)?;
//! oboron::ObFlex::new("adsv:b64", &key)?;
//!
//! // Convenience functions: data, format, key
//! let ot = oboron::enc("plaintext", "adsv:b64", &key)?;
//! oboron::dec(&ot, "adsv:b64", &key)?;
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
//! # #[cfg(feature = "adsv")]
//! # {
//! # use oboron::{AdsvC32, AdsvB64, Oboron};
//! # let key = oboron::generate_key();
//! let adsv = AdsvC32::new(&key)?;      // adsv:c32 format (Crockford base32)
//! let adsv_b64 = AdsvB64::new(&key)?;  // adsv:b64 format (base64url)
//!
//! let ot = adsv.enc("hello")?;
//! let pt2 = adsv.dec(&ot)?;
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
//! # #[cfg(feature = "adsv")]
//! # {
//! # use oboron::{Ob, Oboron};
//! # let key = oboron::generate_key();
//! // Format chosen at runtime, immutable instance
//! let ob = Ob::new("adsv:b64", &key)?;
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
//! # #[cfg(all(feature = "adsv", feature = "mock"))]
//! # {
//! # use oboron::{ObFlex, Oboron, Scheme, Encoding};
//! # let key = oboron::generate_key();
//! let mut flex = ObFlex::new("adsv:b64", &key)?;
//! let ot1 = flex.enc("hello")?;    // adsv:b64 format
//!
//! // Change format at runtime
//! flex.set_scheme(Scheme::Mock1)?;  // set_scheme() only with ObFlex
//! let ot2 = flex.enc("hello")? ;   // mock1:b64 format output
//! // Also available:
//! flex.set_encoding(Encoding::Hex)?; // now set as mock1:hex
//! flex.set_format("adsv:b32")?;      // now adsv:b32
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
//! # #[cfg(feature = "adsv")]
//! # {
//! # use oboron::ObMulti;
//! # let key = oboron::generate_key();
//! let obm = ObMulti::new(&key)?;
//!
//! // Encode to different formats
//! let ot_b32 = obm.enc("data", "adsv:c32")?;
//! let ot_b64 = obm.enc("data", "adsv:b64")?;
//! let ot_hex = obm.enc("data", "adsv:hex")?;
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
//! # #[cfg(all(feature = "adsv", feature = "mock"))]
//! # {
//! # use oboron::Oboron;
//! # use oboron;
//! # let key = oboron::generate_key();
//! // Fixed format types (best performance for multiple operations with same format)
//! let adsv = oboron::AdsvC32::new(&key)?;  // "adsv:c32" format Oboron instance
//! let mock1 = oboron::Mock1C32::new(&key)?;  // "mock1:c32" format Oboron instance
//!
//! let ot_adsv = adsv.enc("data1")?;
//! let ot_mock1 = mock1.enc("data2")?;
//!
//! // Decoding uses scheme autodetection by default
//! let pt1 = adsv.dec(&ot_adsv)?;  // Decodes successfully
//! let pt2 = adsv.dec(&ot_mock1)?;  // Also works (autodetects mock1)
//! assert_eq!(pt1, "data1");
//! assert_eq!(pt2, "data2");
//! // Note: The above autodetection works only with shared encodings
//! // adsv:c32 and mock1:c32 are both base32crockford-encoded
//!
//! // Use dec_strict to enforce scheme matching
//! let pt3 = adsv.dec_strict(&ot_adsv)?;         // OK: Matches scheme
//! assert!(adsv.dec_strict(&ot_mock1).is_err());  // Error: Wrong scheme (adsv != mock1)
//!
//! // Note: For fixed oborons, string encoding (c32/b32/b64/hex) must match the instance encoding
//! let adsv_b64 = oboron::AdsvB64::new(&key)?;  // "adsv:b64" format Oboron
//! let ot_b64 = adsv_b64.enc("data3")?;
//! assert!(adsv.dec(&ot_b64).is_err());  // Error: Encoding mismatch (c32 != b64)
//! // For mixed encodings, use ObMulti instead (see above)
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! # Encryption Schemes
//!
//! - `Zdc`: AES-CBC (deterministic)
//! - `Adgs`: AES-GCM-SIV (deterministic)
//! - `Adsv`: AES-SIV (deterministic, nonce-misuse resistant)
//! - `Upc`, `Apgs`, `Apsv`: Probabilistic variants (different output each time)
//!
//! Testing/Demo only schemes using no encryption (`mock` feature group):
//! - `Mock1`: Identity
//! - `Mock2`: Reverse plaintext
//!
//! Each scheme supports four string encodings:
//! - C32,
//! - B32 (RFC 4648 standard),
//! - B64 (URL-safe RFC 4648 standard),
//! - Hex
//!
//! # The `Oboron` Trait
//!
//! All types (`AdsvC32`, `Ob`, `ObFlex`, etc.) except `ObMulti` implement the `Oboron` trait,
//! providing a consistent interface:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "adsv")]
//! # {
//! # use oboron::{Oboron, AdsvC32, Ob};
//! # let key = oboron::generate_key();
//! fn process<O: Oboron>(ob: &O, data: &str) -> Result<String, oboron::Error> {
//!     let ot = ob.enc(data)?;
//!     ob.dec(&ot)
//! }
//!
//! let adsv = AdsvC32::new(&key)?;
//! let ob = Ob::new("adsv:c32", &key)?;
//!
//! process(&adsv, "hello")?;
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
mod keygen;
#[cfg(feature = "legacy")]
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

#[cfg(feature = "adgs")]
pub(crate) use obcrypt::{decrypt_adgs, encrypt_adgs};
#[cfg(feature = "adsv")]
pub(crate) use obcrypt::{decrypt_adsv, encrypt_adsv};
#[cfg(feature = "apgs")]
pub(crate) use obcrypt::{decrypt_apgs, encrypt_apgs};
#[cfg(feature = "apsv")]
pub(crate) use obcrypt::{decrypt_apsv, encrypt_apsv};
#[cfg(feature = "upc")]
pub(crate) use obcrypt::{decrypt_upc, encrypt_upc};
#[cfg(feature = "zdc")]
pub(crate) use obcrypt::{decrypt_zdc, encrypt_zdc};

// Testing
#[cfg(feature = "mock")]
pub(crate) use obcrypt::{decrypt_mock1, encrypt_mock1};
#[cfg(feature = "mock")]
pub(crate) use obcrypt::{decrypt_mock2, encrypt_mock2};

pub use keygen::generate_key;
#[cfg(feature = "bytes-keys")]
pub use keygen::generate_key_bytes;
#[cfg(feature = "hex-keys")]
pub use keygen::generate_key_hex;

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
#[cfg(feature = "adgs")]
pub use constants::{ADGS_B32, ADGS_B64, ADGS_C32, ADGS_HEX};
#[cfg(feature = "adsv")]
pub use constants::{ADSV_B32, ADSV_B64, ADSV_C32, ADSV_HEX};
#[cfg(feature = "apgs")]
pub use constants::{APGS_B32, APGS_B64, APGS_C32, APGS_HEX};
#[cfg(feature = "apsv")]
pub use constants::{APSV_B32, APSV_B64, APSV_C32, APSV_HEX};
#[cfg(feature = "upc")]
pub use constants::{UPC_B32, UPC_B64, UPC_C32, UPC_HEX};
#[cfg(feature = "zdc")]
pub use constants::{ZDC_B32, ZDC_B64, ZDC_C32, ZDC_HEX};
// Testing
#[cfg(feature = "mock")]
pub use constants::{MOCK1_B32, MOCK1_B64, MOCK1_C32, MOCK1_HEX};
#[cfg(feature = "mock")]
pub use constants::{MOCK2_B32, MOCK2_B64, MOCK2_C32, MOCK2_HEX};
// Legacy
#[cfg(feature = "legacy")]
pub use constants::{LEGACY_B32, LEGACY_B64, LEGACY_C32, LEGACY_HEX};

// Conditionally export format-specific structs (scheme+encoding combinations)
#[cfg(feature = "adgs")]
pub use oboron::{AdgsB32, AdgsB64, AdgsC32, AdgsHex};
#[cfg(feature = "adsv")]
pub use oboron::{AdsvB32, AdsvB64, AdsvC32, AdsvHex};
#[cfg(feature = "apgs")]
pub use oboron::{ApgsB32, ApgsB64, ApgsC32, ApgsHex};
#[cfg(feature = "apsv")]
pub use oboron::{ApsvB32, ApsvB64, ApsvC32, ApsvHex};
#[cfg(feature = "upc")]
pub use oboron::{UpcB32, UpcB64, UpcC32, UpcHex};
#[cfg(feature = "zdc")]
pub use oboron::{ZdcB32, ZdcB64, ZdcC32, ZdcHex};
// Testing
#[cfg(feature = "mock")]
pub use oboron::{Mock1B32, Mock1B64, Mock1C32, Mock1Hex};
#[cfg(feature = "mock")]
pub use oboron::{Mock2B32, Mock2B64, Mock2C32, Mock2Hex};
// Legacy
#[cfg(feature = "legacy")]
pub use legacy::{LegacyB32, LegacyB64, LegacyC32, LegacyHex};

// Aliases for default encoding:
#[cfg(feature = "zdc")]
pub type Zdc = ZdcC32;
#[cfg(feature = "upc")]
pub type Upc = UpcC32;
#[cfg(feature = "adgs")]
pub type Adgs = AdgsC32;
#[cfg(feature = "apgs")]
pub type Apgs = ApgsC32;
#[cfg(feature = "adsv")]
pub type Adsv = AdsvC32;
#[cfg(feature = "apsv")]
pub type Apsv = ApsvC32;
// Testing
#[cfg(feature = "mock")]
pub type Mock1 = Mock1C32;
#[cfg(feature = "mock")]
pub type Mock2 = Mock2C32;
// Legacy
#[cfg(feature = "legacy")]
pub type Legacy = LegacyB32;

// Re-export multi-format Oboron implementation
pub use ob_multi::ObMulti;

/// Convenience prelude for common imports.
///
/// Import everything you need with:
/// ```rust
/// use oboron::prelude::*;
/// ```
pub mod prelude {
    #[cfg(feature = "adsv")]
    pub use crate::AdsvC32;
    #[cfg(feature = "apsv")]
    pub use crate::ApsvC32;
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
/// # #[cfg(feature = "adsv")]
/// # {
/// # use oboron;
/// # let key = oboron::generate_key();
/// let ot = oboron::enc("secret data", "adsv:b64", &key)?;
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "convenience")]
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
/// # #[cfg(feature = "adsv")]
/// # {
/// # use oboron;
/// let ot = oboron::enc_keyless("test data", "adsv:b64")?;
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "convenience")]
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
/// # #[cfg(feature = "adsv")]
/// # use oboron;
/// # {
/// # let key = oboron::generate_key();
/// # let ot = oboron::enc("test123", "adsv:b64", &key)?;
/// let pt2 = oboron::dec(&ot, "adsv:b64", &key)?;
/// # assert_eq!(pt2, "test123");
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "convenience")]
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
/// # #[cfg(feature = "adsv")]
/// # {
/// # use oboron;
/// # let ot = oboron::enc_keyless("test", "adsv:b64")?;
/// let pt2 = oboron::dec_keyless(&ot, "adsv:b64")?;
/// # assert_eq!(pt2, "test");
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "convenience")]
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
/// # #[cfg(feature = "adsv")]
/// # {
/// # use oboron;
/// # let key = oboron::generate_key();
/// # let ot = oboron::enc("secret", "adsv:b64", &key)?;
/// let pt2 = oboron::autodec(&ot, &key)?;  // Format autodetected, including encoding
/// # assert_eq!(pt2, "secret");
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "convenience")]
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
/// # #[cfg(feature = "adsv")]
/// # {
/// # use oboron;
/// # let ot = oboron::enc_keyless("test", "mock1:b64")?;
/// let pt2 = oboron::autodec_keyless(&ot)?; // Autodetect format; use hardcoded key
/// # assert_eq!(pt2, "test");
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "convenience")]
#[cfg(feature = "keyless")]
pub fn autodec_keyless(obtext: &str) -> Result<String, Error> {
    ObMulti::new_keyless()?.autodec(obtext)
}
