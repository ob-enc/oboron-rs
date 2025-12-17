//! Trait-based interface for scheme-specific Oboron implementations.
#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{error::Error, Encoding, Format, Keychain, Scheme};

/// Core trait for Oboron encryption+encoding/decoding+decryption implementations.
///
/// Each scheme+encoding combination (Ob01Base32Crockford, Ob01Base64, etc.) implements this trait
/// to provide a consistent interface for encoding and decoding operations.
///
/// Note: Construction methods (`new`, `from_bytes`, `new_keyless`) are not part of
/// this trait.     Each type provides its own constructor with an appropriate signature.
pub trait Oboron {
    /// Encode a plaintext string.
    fn enc(&self, plaintext: &str) -> Result<String, Error>;

    /// Decode an encoded string back to plaintext with scheme autodetection.
    fn dec(&self, obtext: &str) -> Result<String, Error>;

    /// Decode an encoded string back to plaintext, strictly using the configured scheme.
    fn dec_strict(&self, obtext: &str) -> Result<String, Error>;

    /// Get the full format (encapsulating scheme + encoding) used by this instance
    fn format(&self) -> Format;

    /// Get the scheme identifier.
    fn scheme(&self) -> Scheme;

    /// Get the encoding used by this instance.
    fn encoding(&self) -> Encoding;

    /// Get the base64 key used by this instance.
    fn key(&self) -> String;

    /// Get the hex key used by this instance.
    #[cfg(feature = "hex-keys")]
    fn key_hex(&self) -> String;

    /// Get the key as bytes used by this instance.
    #[cfg(feature = "bytes-keys")]
    fn key_bytes(&self) -> &[u8; 64];
}

#[cfg(feature = "ob00")]
use crate::legacy::{Ob00Base32Crockford, Ob00Base32Rfc, Ob00Base64, Ob00Hex};

/// Macro to implement optimized Oboron types with compile-time specialization.
///
/// This macro generates a complete Oboron implementation with all overhead eliminated:
/// - No runtime scheme matching
/// - No method call overhead for byte()
/// - Direct function calls to encrypt/decrypt
/// - Encoding functions called directly (no dispatch)
/// - All constants baked in at compile time
macro_rules! impl_oboron {
    (
        $name:ident,           // Type name (e.g., Ob01Base32Crockford)
        $scheme:expr,          // Scheme constant (e.g., Scheme::Ob01)
        $encoding:expr,        // Encoding constant (e.g., Encoding::Base32Crockford)
        $format_str:expr       // Format string for docs (e.g., "ob01:c32")
    ) => {
        #[doc = concat!("Oboron implementation for ", $format_str, " format.\n\n")]
        #[doc = concat!("Corresponds to format string: `\"", $format_str, "\"`")]
        #[allow(non_camel_case_types)]
        pub struct $name {
            keychain: Keychain,
        }

        impl $name {
            /// Create a new instance with a 86-character base64 string key.
            #[inline]
            pub fn new(key_b64: &str) -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_base64(key_b64)?,
                })
            }

            /// Create a new instance from a 64-byte key.
            #[inline]
            #[cfg(any(feature = "keyless", feature = "bytes-keys"))]
            fn from_bytes_internal(key: &[u8; 64]) -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_bytes(key)?,
                })
            }

            /// Create a new instance with hardcoded key (testing only).
            #[inline]
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
                })
            }

            /// Create a new instance with a 128-character hex string key.
            #[inline]
            #[cfg(feature = "hex-keys")]
            pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_hex(key_hex)?,
                })
            }

            /// Create a new instance from a 64-byte key.
            #[inline]
            #[cfg(feature = "bytes-keys")]
            pub fn from_bytes(key: &[u8; 64]) -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_bytes(key)?,
                })
            }
        }

        impl Oboron for $name {
            #[inline]
            fn enc(&self, plaintext: &str) -> Result<String, Error> {
                let format = Format::new($scheme, $encoding);
                crate::enc::enc_to_format(plaintext, format, &self.keychain)
            }

            #[inline]
            fn dec(&self, obtext: &str) -> Result<String, Error> {
                // Use autodetection for cross-scheme compatibility
                crate::dec_auto::dec_any_scheme(&self.keychain, $encoding, obtext)
            }

            #[inline]
            fn dec_strict(&self, obtext: &str) -> Result<String, Error> {
                // Decode with known encoding - direct call
                let format = Format::new($scheme, $encoding);
                crate::dec::dec_from_format(obtext, format, &self.keychain)
            }

            #[inline]
            fn format(&self) -> Format {
                Format::new($scheme, $encoding)
            }

            #[inline]
            fn scheme(&self) -> Scheme {
                $scheme
            }

            #[inline]
            fn encoding(&self) -> Encoding {
                $encoding
            }

            #[inline]
            fn key(&self) -> String {
                self.keychain.key_base64()
            }

            #[inline]
            #[cfg(feature = "hex-keys")]
            fn key_hex(&self) -> String {
                self.keychain.key_hex()
            }

            #[inline]
            #[cfg(feature = "bytes-keys")]
            fn key_bytes(&self) -> &[u8; 64] {
                self.keychain.key_bytes()
            }
        }
    };
}

// Generate all scheme+encoding combinations using the optimized macro

// Base32Crockford (default) variants
#[cfg(feature = "ob01")]
impl_oboron!(
    Ob01Base32Crockford,
    Scheme::Ob01,
    Encoding::Base32Crockford,
    "ob01:c32"
);
#[cfg(feature = "ob21p")]
impl_oboron!(
    Ob21pBase32Crockford,
    Scheme::Ob21p,
    Encoding::Base32Crockford,
    "ob21p:c32"
);
#[cfg(feature = "ob31")]
impl_oboron!(
    Ob31Base32Crockford,
    Scheme::Ob31,
    Encoding::Base32Crockford,
    "ob31:c32"
);
#[cfg(feature = "ob31p")]
impl_oboron!(
    Ob31pBase32Crockford,
    Scheme::Ob31p,
    Encoding::Base32Crockford,
    "ob31p:c32"
);
#[cfg(feature = "ob32")]
impl_oboron!(
    Ob32Base32Crockford,
    Scheme::Ob32,
    Encoding::Base32Crockford,
    "ob32:c32"
);
#[cfg(feature = "ob32p")]
impl_oboron!(
    Ob32pBase32Crockford,
    Scheme::Ob32p,
    Encoding::Base32Crockford,
    "ob32p:c32"
);

// Base32Rfc variants
#[cfg(feature = "ob01")]
impl_oboron!(Ob01Base32Rfc, Scheme::Ob01, Encoding::Base32Rfc, "ob01:b32");
#[cfg(feature = "ob21p")]
impl_oboron!(
    Ob21pBase32Rfc,
    Scheme::Ob21p,
    Encoding::Base32Rfc,
    "ob21p:b32"
);
#[cfg(feature = "ob31")]
impl_oboron!(Ob31Base32Rfc, Scheme::Ob31, Encoding::Base32Rfc, "ob31:b32");
#[cfg(feature = "ob31p")]
impl_oboron!(
    Ob31pBase32Rfc,
    Scheme::Ob31p,
    Encoding::Base32Rfc,
    "ob31p:b32"
);
#[cfg(feature = "ob32")]
impl_oboron!(Ob32Base32Rfc, Scheme::Ob32, Encoding::Base32Rfc, "ob32:b32");
#[cfg(feature = "ob32p")]
impl_oboron!(
    Ob32pBase32Rfc,
    Scheme::Ob32p,
    Encoding::Base32Rfc,
    "ob32p:b32"
);

// Base64 variants - with Base64 suffix
#[cfg(feature = "ob01")]
impl_oboron!(Ob01Base64, Scheme::Ob01, Encoding::Base64, "ob01:b64");
#[cfg(feature = "ob21p")]
impl_oboron!(Ob21pBase64, Scheme::Ob21p, Encoding::Base64, "ob21p:b64");
#[cfg(feature = "ob31")]
impl_oboron!(Ob31Base64, Scheme::Ob31, Encoding::Base64, "ob31:b64");
#[cfg(feature = "ob31p")]
impl_oboron!(Ob31pBase64, Scheme::Ob31p, Encoding::Base64, "ob31p:b64");
#[cfg(feature = "ob32")]
impl_oboron!(Ob32Base64, Scheme::Ob32, Encoding::Base64, "ob32:b64");
#[cfg(feature = "ob32p")]
impl_oboron!(Ob32pBase64, Scheme::Ob32p, Encoding::Base64, "ob32p:b64");

// Hex variants - with Hex suffix
#[cfg(feature = "ob01")]
impl_oboron!(Ob01Hex, Scheme::Ob01, Encoding::Hex, "ob01:hex");
#[cfg(feature = "ob21p")]
impl_oboron!(Ob21pHex, Scheme::Ob21p, Encoding::Hex, "ob21p:hex");
#[cfg(feature = "ob31")]
impl_oboron!(Ob31Hex, Scheme::Ob31, Encoding::Hex, "ob31:hex");
#[cfg(feature = "ob31p")]
impl_oboron!(Ob31pHex, Scheme::Ob31p, Encoding::Hex, "ob31p:hex");
#[cfg(feature = "ob32")]
impl_oboron!(Ob32Hex, Scheme::Ob32, Encoding::Hex, "ob32:hex");
#[cfg(feature = "ob32p")]
impl_oboron!(Ob32pHex, Scheme::Ob32p, Encoding::Hex, "ob32p:hex");

// Testing

// ob70 (identity scheme)
#[cfg(feature = "ob70")]
impl_oboron!(
    Ob70Base32Crockford,
    Scheme::Ob70,
    Encoding::Base32Crockford,
    "ob70:c32"
);
#[cfg(feature = "ob70")]
impl_oboron!(Ob70Base32Rfc, Scheme::Ob70, Encoding::Base32Rfc, "ob70:b32");
#[cfg(feature = "ob70")]
impl_oboron!(Ob70Base64, Scheme::Ob70, Encoding::Base64, "ob70:b64");
#[cfg(feature = "ob70")]
impl_oboron!(Ob70Hex, Scheme::Ob70, Encoding::Hex, "ob70:hex");

// ob71 (reverse scheme)
#[cfg(feature = "ob71")]
impl_oboron!(
    Ob71Base32Crockford,
    Scheme::Ob71,
    Encoding::Base32Crockford,
    "ob71:c32"
);
#[cfg(feature = "ob71")]
impl_oboron!(Ob71Base32Rfc, Scheme::Ob71, Encoding::Base32Rfc, "ob71:b32");
#[cfg(feature = "ob71")]
impl_oboron!(Ob71Base64, Scheme::Ob71, Encoding::Base64, "ob71:b64");
#[cfg(feature = "ob71")]
impl_oboron!(Ob71Hex, Scheme::Ob71, Encoding::Hex, "ob71:hex");

/// Type-erased Oboron encoder that can hold any scheme+encoding combination.
///
/// This enum allows for runtime scheme selection without heap allocation.
/// It's returned by the `oboron::new()` factory function.
#[allow(non_camel_case_types)]
pub enum ObAny {
    #[cfg(feature = "ob01")]
    Ob01Base32Crockford(Ob01Base32Crockford),
    #[cfg(feature = "ob01")]
    Ob01Base32Rfc(Ob01Base32Rfc),
    #[cfg(feature = "ob01")]
    Ob01Base64(Ob01Base64),
    #[cfg(feature = "ob01")]
    Ob01Hex(Ob01Hex),
    #[cfg(feature = "ob21p")]
    Ob21pBase32Crockford(Ob21pBase32Crockford),
    #[cfg(feature = "ob21p")]
    Ob21pBase32Rfc(Ob21pBase32Rfc),
    #[cfg(feature = "ob21p")]
    Ob21pBase64(Ob21pBase64),
    #[cfg(feature = "ob21p")]
    Ob21pHex(Ob21pHex),
    #[cfg(feature = "ob31")]
    Ob31Base32Crockford(Ob31Base32Crockford),
    #[cfg(feature = "ob31")]
    Ob31Base32Rfc(Ob31Base32Rfc),
    #[cfg(feature = "ob31")]
    Ob31Base64(Ob31Base64),
    #[cfg(feature = "ob31")]
    Ob31Hex(Ob31Hex),
    #[cfg(feature = "ob31p")]
    Ob31pBase32Crockford(Ob31pBase32Crockford),
    #[cfg(feature = "ob31p")]
    Ob31pBase32Rfc(Ob31pBase32Rfc),
    #[cfg(feature = "ob31p")]
    Ob31pBase64(Ob31pBase64),
    #[cfg(feature = "ob31p")]
    Ob31pHex(Ob31pHex),
    #[cfg(feature = "ob32")]
    Ob32Base32Crockford(Ob32Base32Crockford),
    #[cfg(feature = "ob32")]
    Ob32Base32Rfc(Ob32Base32Rfc),
    #[cfg(feature = "ob32")]
    Ob32Base64(Ob32Base64),
    #[cfg(feature = "ob32")]
    Ob32Hex(Ob32Hex),
    #[cfg(feature = "ob32p")]
    Ob32pBase32Crockford(Ob32pBase32Crockford),
    #[cfg(feature = "ob32p")]
    Ob32pBase32Rfc(Ob32pBase32Rfc),
    #[cfg(feature = "ob32p")]
    Ob32pBase64(Ob32pBase64),
    #[cfg(feature = "ob32p")]
    Ob32pHex(Ob32pHex),
    // Testing
    #[cfg(feature = "ob70")]
    Ob70Base32Crockford(Ob70Base32Crockford),
    #[cfg(feature = "ob70")]
    Ob70Base32Rfc(Ob70Base32Rfc),
    #[cfg(feature = "ob70")]
    Ob70Hex(Ob70Hex),
    #[cfg(feature = "ob70")]
    Ob70Base64(Ob70Base64),
    #[cfg(feature = "ob71")]
    Ob71Base32Crockford(Ob71Base32Crockford),
    #[cfg(feature = "ob71")]
    Ob71Base32Rfc(Ob71Base32Rfc),
    #[cfg(feature = "ob71")]
    Ob71Hex(Ob71Hex),
    #[cfg(feature = "ob71")]
    Ob71Base64(Ob71Base64),
    // Legacy
    #[cfg(feature = "ob00")]
    Ob00Base32Crockford(Ob00Base32Crockford),
    #[cfg(feature = "ob00")]
    Ob00Base32Rfc(Ob00Base32Rfc),
    #[cfg(feature = "ob00")]
    Ob00Base64(Ob00Base64),
    #[cfg(feature = "ob00")]
    Ob00Hex(Ob00Hex),
}

// Macro to delegate Oboron methods to the inner type
macro_rules! delegate_to_inner {
    (fn $method:ident(&self $(, $arg:ident: $argty:ty)*) -> $ret:ty) => {
        fn $method(&self $(, $arg: $argty)*) -> $ret {
            match self {
                #[cfg(feature = "ob01")]
                ObAny::Ob01Base32Crockford(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob01")]
                ObAny::Ob01Base32Rfc(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob01")]
                ObAny::Ob01Base64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob01")]
                ObAny::Ob01Hex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob21p")]
                ObAny::Ob21pBase32Crockford(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob21p")]
                ObAny::Ob21pBase32Rfc(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob21p")]
                ObAny::Ob21pBase64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob21p")]
                ObAny::Ob21pHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob31")]
                ObAny::Ob31Base32Crockford(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob31")]
                ObAny::Ob31Base32Rfc(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob31")]
                ObAny::Ob31Base64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob31")]
                ObAny::Ob31Hex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob31p")]
                ObAny::Ob31pBase32Crockford(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob31p")]
                ObAny::Ob31pBase32Rfc(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob31p")]
                ObAny::Ob31pBase64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob31p")]
                ObAny::Ob31pHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob32")]
                ObAny::Ob32Base32Crockford(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob32")]
                ObAny::Ob32Base32Rfc(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob32")]
                ObAny::Ob32Base64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob32")]
                ObAny::Ob32Hex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob32p")]
                ObAny::Ob32pBase32Crockford(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob32p")]
                ObAny::Ob32pBase32Rfc(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob32p")]
                ObAny::Ob32pBase64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob32p")]
                ObAny::Ob32pHex(ob) => ob.$method($($arg),*),
                // Testing
                #[cfg(feature = "ob70")]
                ObAny::Ob70Base32Crockford(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob70")]
                ObAny::Ob70Base32Rfc(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob70")]
                ObAny::Ob70Base64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob70")]
                ObAny::Ob70Hex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob71")]
                ObAny::Ob71Base32Crockford(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob71")]
                ObAny::Ob71Base32Rfc(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob71")]
                ObAny::Ob71Base64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob71")]
                ObAny::Ob71Hex(ob) => ob.$method($($arg),*),
                // Legacy
                #[cfg(feature = "ob00")]
                ObAny::Ob00Base32Crockford(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob00")]
                ObAny::Ob00Base32Rfc(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob00")]
                ObAny::Ob00Base64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "ob00")]
                ObAny::Ob00Hex(ob) => ob.$method($($arg),*),
            }
        }
    };
}

impl Oboron for ObAny {
    delegate_to_inner!(fn enc(&self, plaintext: &str) -> Result<String, Error>);
    delegate_to_inner!(fn dec(&self, obtext: &str) -> Result<String, Error>);
    delegate_to_inner!(fn dec_strict(&self, obtext: &str) -> Result<String, Error>);
    delegate_to_inner!(fn format(&self) -> Format);
    delegate_to_inner!(fn scheme(&self) -> Scheme);
    delegate_to_inner!(fn encoding(&self) -> Encoding);
    delegate_to_inner!(fn key(&self) -> String);
    #[cfg(feature = "hex-keys")]
    delegate_to_inner!(fn key_hex(&self) -> String);
    #[cfg(feature = "bytes-keys")]
    delegate_to_inner!(fn key_bytes(&self) -> &[u8; 64]);
}

// Inherent constructors for ObAny
impl ObAny {
    /// Create a new instance with a 128-character hex string key.
    ///
    /// Defaults to ob70:c32 format.
    pub fn new(key_b64: &str) -> Result<Self, Error> {
        #[cfg(feature = "ob70")]
        return Ok(ObAny::Ob70Base32Crockford(Ob70Base32Crockford::new(
            key_b64,
        )?));
        #[cfg(feature = "ob71")]
        #[cfg(not(feature = "ob70"))]
        return Ok(ObAny::Ob71Base32Crockford(Ob71Base32Crockford::new(
            key_b64,
        )?));
        #[cfg(feature = "ob01")]
        #[cfg(not(any(feature = "ob70", feature = "ob71")))]
        return Ok(ObAny::Ob01Base32Crockford(Ob01Base32Crockford::new(
            key_b64,
        )?));
        #[cfg(feature = "ob21p")]
        #[cfg(not(any(feature = "ob70", feature = "ob71", feature = "ob01")))]
        return Ok(ObAny::Ob21pBase32Crockford(Ob21pBase32Crockford::new(
            key_b64,
        )?));
        #[cfg(feature = "ob31")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p"
        )))]
        return Ok(ObAny::Ob31Base32Crockford(Ob31Base32Crockford::new(
            key_b64,
        )?));
        #[cfg(feature = "ob31p")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31"
        )))]
        return Ok(ObAny::Ob31pBase32Crockford(Ob31pBase32Crockford::new(
            key_b64,
        )?));
        #[cfg(feature = "ob32")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p"
        )))]
        return Ok(ObAny::Ob32Base32Crockford(Ob32Base32Crockford::new(
            key_b64,
        )?));
        #[cfg(feature = "ob32p")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32"
        )))]
        return Ok(ObAny::Ob32pBase32Crockford(Ob32pBase32Crockford::new(
            key_b64,
        )?));
        #[cfg(feature = "ob00")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p"
        )))]
        return Ok(ObAny::Ob00Base32Crockford(Ob00Base32Crockford::new(
            key_b64,
        )?));
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance from a 64-byte key.
    ///
    /// Defaults to ob70:c32 format.
    #[inline]
    #[cfg(feature = "bytes-keys")]
    pub fn from_bytes(key: &[u8; 64]) -> Result<Self, Error> {
        #[cfg(feature = "ob70")]
        return Ok(ObAny::Ob70Base32Crockford(Ob70Base32Crockford {
            keychain: Keychain::from_bytes(key)?,
        }));
        #[cfg(feature = "ob71")]
        #[cfg(not(feature = "ob70"))]
        return Ok(ObAny::Ob71Base32Crockford(Ob71Base32Crockford {
            keychain: Keychain::from_bytes(key)?,
        }));
        #[cfg(feature = "ob01")]
        #[cfg(not(any(feature = "ob70", feature = "ob71")))]
        return Ok(ObAny::Ob01Base32Crockford(Ob01Base32Crockford {
            keychain: Keychain::from_bytes(key)?,
        }));
        #[cfg(feature = "ob21p")]
        #[cfg(not(any(feature = "ob70", feature = "ob71", feature = "ob01")))]
        return Ok(ObAny::Ob21pBase32Crockford(Ob21pBase32Crockford {
            keychain: Keychain::from_bytes(key)?,
        }));
        #[cfg(feature = "ob31")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p"
        )))]
        return Ok(ObAny::Ob31Base32Crockford(Ob31Base32Crockford {
            keychain: Keychain::from_bytes(key)?,
        }));
        #[cfg(feature = "ob31p")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31"
        )))]
        return Ok(ObAny::Ob31pBase32Crockford(Ob31pBase32Crockford {
            keychain: Keychain::from_bytes(key)?,
        }));
        #[cfg(feature = "ob32")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p"
        )))]
        return Ok(ObAny::Ob32Base32Crockford(Ob32Base32Crockford {
            keychain: Keychain::from_bytes(key)?,
        }));
        #[cfg(feature = "ob32p")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32"
        )))]
        return Ok(ObAny::Ob32pBase32Crockford(Ob32pBase32Crockford {
            keychain: Keychain::from_bytes(key)?,
        }));
        #[cfg(feature = "ob00")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p"
        )))]
        return Ok(ObAny::Ob00Base32Crockford(Ob00Base32Crockford {
            keychain: Keychain::from_bytes(key)?,
        }));
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    #[cfg(feature = "bytes-keys")]
    pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
        #[cfg(feature = "ob70")]
        return Ok(ObAny::Ob70Base32Crockford(Ob70Base32Crockford::new(
            key_hex,
        )?));
        #[cfg(feature = "ob71")]
        #[cfg(not(feature = "ob70"))]
        return Ok(ObAny::Ob71Base32Crockford(Ob71Base32Crockford::new(
            key_hex,
        )?));
        #[cfg(feature = "ob01")]
        #[cfg(not(any(feature = "ob70", feature = "ob71")))]
        return Ok(ObAny::Ob01Base32Crockford(Ob01Base32Crockford::new(
            key_hex,
        )?));
        #[cfg(feature = "ob21p")]
        #[cfg(not(any(feature = "ob70", feature = "ob71", feature = "ob01")))]
        return Ok(ObAny::Ob21pBase32Crockford(Ob21pBase32Crockford::new(
            key_hex,
        )?));
        #[cfg(feature = "ob31")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p"
        )))]
        return Ok(ObAny::Ob31Base32Crockford(Ob31Base32Crockford::new(
            key_hex,
        )?));
        #[cfg(feature = "ob31p")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31"
        )))]
        return Ok(ObAny::Ob31pBase32Crockford(Ob31pBase32Crockford::new(
            key_hex,
        )?));
        #[cfg(feature = "ob32")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p"
        )))]
        return Ok(ObAny::Ob32Base32Crockford(Ob32Base32Crockford::new(
            key_hex,
        )?));
        #[cfg(feature = "ob32p")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32"
        )))]
        return Ok(ObAny::Ob32pBase32Crockford(Ob32pBase32Crockford::new(
            key_hex,
        )?));
        #[cfg(feature = "ob00")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p"
        )))]
        return Ok(ObAny::Ob00Base32Crockford(Ob00Base32Crockford::new(
            key_hex,
        )?));
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance with hardcoded key (testing only).
    ///
    /// Defaults to ob70:c32 format.
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        #[cfg(feature = "ob70")]
        return Ok(ObAny::Ob70Base32Crockford(Ob70Base32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "ob71")]
        #[cfg(not(feature = "ob70"))]
        return Ok(ObAny::Ob71Base32Crockford(Ob71Base32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "ob01")]
        #[cfg(not(any(feature = "ob70", feature = "ob71")))]
        return Ok(ObAny::Ob01Base32Crockford(Ob01Base32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "ob21p")]
        #[cfg(not(any(feature = "ob70", feature = "ob71", feature = "ob01")))]
        return Ok(ObAny::Ob21pBase32Crockford(Ob21pBase32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "ob31")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p"
        )))]
        return Ok(ObAny::Ob31Base32Crockford(Ob31Base32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "ob31p")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31"
        )))]
        return Ok(ObAny::Ob31pBase32Crockford(Ob31pBase32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "ob32")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p"
        )))]
        return Ok(ObAny::Ob32Base32Crockford(Ob32Base32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "ob32p")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32"
        )))]
        return Ok(ObAny::Ob32pBase32Crockford(Ob32pBase32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "ob00")]
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p"
        )))]
        return Ok(ObAny::Ob00Base32Crockford(Ob00Base32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(not(any(
            feature = "ob70",
            feature = "ob71",
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }
}

/// Create an encoder from a format string and base64 key.
pub fn new(fmt: &str, key_b64: &str) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    new_with_format(format, key_b64)
}

/// Create an encoder from a pre-parsed Format and base64 key.
pub fn new_with_format(format: Format, key_b64: &str) -> Result<ObAny, Error> {
    match (format.scheme(), format.encoding()) {
        #[cfg(feature = "ob01")]
        (Scheme::Ob01, Encoding::Base32Crockford) => Ok(ObAny::Ob01Base32Crockford(
            Ob01Base32Crockford::new(key_b64)?,
        )),
        #[cfg(feature = "ob01")]
        (Scheme::Ob01, Encoding::Base32Rfc) => {
            Ok(ObAny::Ob01Base32Rfc(Ob01Base32Rfc::new(key_b64)?))
        }
        #[cfg(feature = "ob01")]
        (Scheme::Ob01, Encoding::Base64) => Ok(ObAny::Ob01Base64(Ob01Base64::new(key_b64)?)),
        #[cfg(feature = "ob01")]
        (Scheme::Ob01, Encoding::Hex) => Ok(ObAny::Ob01Hex(Ob01Hex::new(key_b64)?)),
        #[cfg(feature = "ob21p")]
        (Scheme::Ob21p, Encoding::Base32Crockford) => Ok(ObAny::Ob21pBase32Crockford(
            Ob21pBase32Crockford::new(key_b64)?,
        )),
        #[cfg(feature = "ob21p")]
        (Scheme::Ob21p, Encoding::Base32Rfc) => {
            Ok(ObAny::Ob21pBase32Rfc(Ob21pBase32Rfc::new(key_b64)?))
        }
        #[cfg(feature = "ob21p")]
        (Scheme::Ob21p, Encoding::Base64) => Ok(ObAny::Ob21pBase64(Ob21pBase64::new(key_b64)?)),
        #[cfg(feature = "ob21p")]
        (Scheme::Ob21p, Encoding::Hex) => Ok(ObAny::Ob21pHex(Ob21pHex::new(key_b64)?)),
        #[cfg(feature = "ob31")]
        (Scheme::Ob31, Encoding::Base32Crockford) => Ok(ObAny::Ob31Base32Crockford(
            Ob31Base32Crockford::new(key_b64)?,
        )),
        #[cfg(feature = "ob31")]
        (Scheme::Ob31, Encoding::Base32Rfc) => {
            Ok(ObAny::Ob31Base32Rfc(Ob31Base32Rfc::new(key_b64)?))
        }
        #[cfg(feature = "ob31")]
        (Scheme::Ob31, Encoding::Base64) => Ok(ObAny::Ob31Base64(Ob31Base64::new(key_b64)?)),
        #[cfg(feature = "ob31")]
        (Scheme::Ob31, Encoding::Hex) => Ok(ObAny::Ob31Hex(Ob31Hex::new(key_b64)?)),
        #[cfg(feature = "ob31p")]
        (Scheme::Ob31p, Encoding::Base32Crockford) => Ok(ObAny::Ob31pBase32Crockford(
            Ob31pBase32Crockford::new(key_b64)?,
        )),
        #[cfg(feature = "ob31p")]
        (Scheme::Ob31p, Encoding::Base32Rfc) => {
            Ok(ObAny::Ob31pBase32Rfc(Ob31pBase32Rfc::new(key_b64)?))
        }
        #[cfg(feature = "ob31p")]
        (Scheme::Ob31p, Encoding::Base64) => Ok(ObAny::Ob31pBase64(Ob31pBase64::new(key_b64)?)),
        #[cfg(feature = "ob31p")]
        (Scheme::Ob31p, Encoding::Hex) => Ok(ObAny::Ob31pHex(Ob31pHex::new(key_b64)?)),
        #[cfg(feature = "ob32")]
        (Scheme::Ob32, Encoding::Base32Crockford) => Ok(ObAny::Ob32Base32Crockford(
            Ob32Base32Crockford::new(key_b64)?,
        )),
        #[cfg(feature = "ob32")]
        (Scheme::Ob32, Encoding::Base32Rfc) => {
            Ok(ObAny::Ob32Base32Rfc(Ob32Base32Rfc::new(key_b64)?))
        }
        #[cfg(feature = "ob32")]
        (Scheme::Ob32, Encoding::Base64) => Ok(ObAny::Ob32Base64(Ob32Base64::new(key_b64)?)),
        #[cfg(feature = "ob32")]
        (Scheme::Ob32, Encoding::Hex) => Ok(ObAny::Ob32Hex(Ob32Hex::new(key_b64)?)),
        #[cfg(feature = "ob32p")]
        (Scheme::Ob32p, Encoding::Base32Crockford) => Ok(ObAny::Ob32pBase32Crockford(
            Ob32pBase32Crockford::new(key_b64)?,
        )),
        #[cfg(feature = "ob32p")]
        (Scheme::Ob32p, Encoding::Base32Rfc) => {
            Ok(ObAny::Ob32pBase32Rfc(Ob32pBase32Rfc::new(key_b64)?))
        }
        #[cfg(feature = "ob32p")]
        (Scheme::Ob32p, Encoding::Base64) => Ok(ObAny::Ob32pBase64(Ob32pBase64::new(key_b64)?)),
        #[cfg(feature = "ob32p")]
        (Scheme::Ob32p, Encoding::Hex) => Ok(ObAny::Ob32pHex(Ob32pHex::new(key_b64)?)),
        // Testing
        #[cfg(feature = "ob70")]
        (Scheme::Ob70, Encoding::Base32Crockford) => Ok(ObAny::Ob70Base32Crockford(
            Ob70Base32Crockford::new(key_b64)?,
        )),
        #[cfg(feature = "ob70")]
        (Scheme::Ob70, Encoding::Base32Rfc) => {
            Ok(ObAny::Ob70Base32Rfc(Ob70Base32Rfc::new(key_b64)?))
        }
        #[cfg(feature = "ob70")]
        (Scheme::Ob70, Encoding::Base64) => Ok(ObAny::Ob70Base64(Ob70Base64::new(key_b64)?)),
        #[cfg(feature = "ob70")]
        (Scheme::Ob70, Encoding::Hex) => Ok(ObAny::Ob70Hex(Ob70Hex::new(key_b64)?)),
        #[cfg(feature = "ob71")]
        (Scheme::Ob71, Encoding::Base32Crockford) => Ok(ObAny::Ob71Base32Crockford(
            Ob71Base32Crockford::new(key_b64)?,
        )),
        #[cfg(feature = "ob71")]
        (Scheme::Ob71, Encoding::Base32Rfc) => {
            Ok(ObAny::Ob71Base32Rfc(Ob71Base32Rfc::new(key_b64)?))
        }
        #[cfg(feature = "ob71")]
        (Scheme::Ob71, Encoding::Base64) => Ok(ObAny::Ob71Base64(Ob71Base64::new(key_b64)?)),
        #[cfg(feature = "ob71")]
        (Scheme::Ob71, Encoding::Hex) => Ok(ObAny::Ob71Hex(Ob71Hex::new(key_b64)?)),
        // Legacy
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base32Crockford) => Ok(ObAny::Ob00Base32Crockford(
            Ob00Base32Crockford::new(key_b64)?,
        )),
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base32Rfc) => {
            Ok(ObAny::Ob00Base32Rfc(Ob00Base32Rfc::new(key_b64)?))
        }
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base64) => Ok(ObAny::Ob00Base64(Ob00Base64::new(key_b64)?)),
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Hex) => Ok(ObAny::Ob00Hex(Ob00Hex::new(key_b64)?)),
        #[allow(unreachable_patterns)]
        _ => Err(Error::UnknownScheme),
    }
}

#[cfg(any(feature = "keyless", feature = "bytes-keys", feature = "hex-keys"))]
fn from_bytes_with_format_internal(format: Format, key: &[u8; 64]) -> Result<ObAny, Error> {
    match (format.scheme(), format.encoding()) {
        #[cfg(feature = "ob01")]
        (Scheme::Ob01, Encoding::Base32Crockford) => Ok(ObAny::Ob01Base32Crockford(
            Ob01Base32Crockford::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob01")]
        (Scheme::Ob01, Encoding::Base32Rfc) => Ok(ObAny::Ob01Base32Rfc(
            Ob01Base32Rfc::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob01")]
        (Scheme::Ob01, Encoding::Base64) => {
            Ok(ObAny::Ob01Base64(Ob01Base64::from_bytes_internal(key)?))
        }
        #[cfg(feature = "ob01")]
        (Scheme::Ob01, Encoding::Hex) => Ok(ObAny::Ob01Hex(Ob01Hex::from_bytes_internal(key)?)),
        #[cfg(feature = "ob21p")]
        (Scheme::Ob21p, Encoding::Base32Crockford) => Ok(ObAny::Ob21pBase32Crockford(
            Ob21pBase32Crockford::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob21p")]
        (Scheme::Ob21p, Encoding::Base32Rfc) => Ok(ObAny::Ob21pBase32Rfc(
            Ob21pBase32Rfc::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob21p")]
        (Scheme::Ob21p, Encoding::Base64) => {
            Ok(ObAny::Ob21pBase64(Ob21pBase64::from_bytes_internal(key)?))
        }
        #[cfg(feature = "ob21p")]
        (Scheme::Ob21p, Encoding::Hex) => Ok(ObAny::Ob21pHex(Ob21pHex::from_bytes_internal(key)?)),
        #[cfg(feature = "ob31")]
        (Scheme::Ob31, Encoding::Base32Crockford) => Ok(ObAny::Ob31Base32Crockford(
            Ob31Base32Crockford::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob31")]
        (Scheme::Ob31, Encoding::Base32Rfc) => Ok(ObAny::Ob31Base32Rfc(
            Ob31Base32Rfc::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob31")]
        (Scheme::Ob31, Encoding::Base64) => {
            Ok(ObAny::Ob31Base64(Ob31Base64::from_bytes_internal(key)?))
        }
        #[cfg(feature = "ob31")]
        (Scheme::Ob31, Encoding::Hex) => Ok(ObAny::Ob31Hex(Ob31Hex::from_bytes_internal(key)?)),
        #[cfg(feature = "ob31p")]
        (Scheme::Ob31p, Encoding::Base32Crockford) => Ok(ObAny::Ob31pBase32Crockford(
            Ob31pBase32Crockford::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob31p")]
        (Scheme::Ob31p, Encoding::Base32Rfc) => Ok(ObAny::Ob31pBase32Rfc(
            Ob31pBase32Rfc::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob31p")]
        (Scheme::Ob31p, Encoding::Base64) => {
            Ok(ObAny::Ob31pBase64(Ob31pBase64::from_bytes_internal(key)?))
        }
        #[cfg(feature = "ob31p")]
        (Scheme::Ob31p, Encoding::Hex) => Ok(ObAny::Ob31pHex(Ob31pHex::from_bytes_internal(key)?)),
        #[cfg(feature = "ob32")]
        (Scheme::Ob32, Encoding::Base32Crockford) => Ok(ObAny::Ob32Base32Crockford(
            Ob32Base32Crockford::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob32")]
        (Scheme::Ob32, Encoding::Base32Rfc) => Ok(ObAny::Ob32Base32Rfc(
            Ob32Base32Rfc::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob32")]
        (Scheme::Ob32, Encoding::Base64) => {
            Ok(ObAny::Ob32Base64(Ob32Base64::from_bytes_internal(key)?))
        }
        #[cfg(feature = "ob32")]
        (Scheme::Ob32, Encoding::Hex) => Ok(ObAny::Ob32Hex(Ob32Hex::from_bytes_internal(key)?)),
        #[cfg(feature = "ob32p")]
        (Scheme::Ob32p, Encoding::Base32Crockford) => Ok(ObAny::Ob32pBase32Crockford(
            Ob32pBase32Crockford::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob32p")]
        (Scheme::Ob32p, Encoding::Base32Rfc) => Ok(ObAny::Ob32pBase32Rfc(
            Ob32pBase32Rfc::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob32p")]
        (Scheme::Ob32p, Encoding::Base64) => {
            Ok(ObAny::Ob32pBase64(Ob32pBase64::from_bytes_internal(key)?))
        }
        #[cfg(feature = "ob32p")]
        (Scheme::Ob32p, Encoding::Hex) => Ok(ObAny::Ob32pHex(Ob32pHex::from_bytes_internal(key)?)),
        // Testing
        #[cfg(feature = "ob70")]
        (Scheme::Ob70, Encoding::Base32Crockford) => Ok(ObAny::Ob70Base32Crockford(
            Ob70Base32Crockford::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob70")]
        (Scheme::Ob70, Encoding::Base32Rfc) => Ok(ObAny::Ob70Base32Rfc(
            Ob70Base32Rfc::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob70")]
        (Scheme::Ob70, Encoding::Base64) => {
            Ok(ObAny::Ob70Base64(Ob70Base64::from_bytes_internal(key)?))
        }
        #[cfg(feature = "ob70")]
        (Scheme::Ob70, Encoding::Hex) => Ok(ObAny::Ob70Hex(Ob70Hex::from_bytes_internal(key)?)),
        #[cfg(feature = "ob71")]
        (Scheme::Ob71, Encoding::Base32Crockford) => Ok(ObAny::Ob71Base32Crockford(
            Ob71Base32Crockford::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob71")]
        (Scheme::Ob71, Encoding::Base32Rfc) => Ok(ObAny::Ob71Base32Rfc(
            Ob71Base32Rfc::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob71")]
        (Scheme::Ob71, Encoding::Base64) => {
            Ok(ObAny::Ob71Base64(Ob71Base64::from_bytes_internal(key)?))
        }
        #[cfg(feature = "ob71")]
        (Scheme::Ob71, Encoding::Hex) => Ok(ObAny::Ob71Hex(Ob71Hex::from_bytes_internal(key)?)),
        // Legacy
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base32Crockford) => Ok(ObAny::Ob00Base32Crockford(
            Ob00Base32Crockford::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base32Rfc) => Ok(ObAny::Ob00Base32Rfc(
            Ob00Base32Rfc::from_bytes_internal(key)?,
        )),
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base64) => {
            Ok(ObAny::Ob00Base64(Ob00Base64::from_bytes_internal(key)?))
        }
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Hex) => Ok(ObAny::Ob00Hex(Ob00Hex::from_bytes_internal(key)?)),
        #[allow(unreachable_patterns)]
        _ => Err(Error::UnknownScheme),
    }
}

#[cfg(feature = "hex-keys")]
fn from_hex_key_with_format_internal(format: Format, key_hex: &str) -> Result<ObAny, Error> {
    let key_vec = hex::decode(key_hex)?;
    let key_arr: [u8; 64] = key_vec.try_into().map_err(|_| Error::InvalidKeyLength)?;
    from_bytes_with_format_internal(format, &key_arr)
}

/// Create an encoder from a format string and raw bytes.
#[cfg(feature = "hex-keys")]
pub fn from_hex_key(fmt: &str, key_hex: &str) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    from_hex_key_with_format_internal(format, key_hex)
}

/// Create an encoder from a pre-parsed Format and raw bytes.
#[cfg(feature = "hex-keys")]
pub fn from_hex_key_with_format(format: Format, key_hex: &str) -> Result<ObAny, Error> {
    from_hex_key_with_format_internal(format, key_hex)
}

/// Create an encoder from a format string and raw bytes.
#[cfg(feature = "bytes-keys")]
pub fn from_bytes(fmt: &str, key: &[u8; 64]) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    from_bytes_with_format_internal(format, &key)
}

/// Create an encoder from a pre-parsed Format and raw bytes.
#[cfg(feature = "bytes-keys")]
pub fn from_bytes_with_format(format: Format, key: &[u8; 64]) -> Result<ObAny, Error> {
    from_bytes_with_format_internal(format, key)
}

/// Create an encoder from a format string using the hardcoded key (testing only).
#[cfg(feature = "keyless")]
pub fn new_keyless(fmt: &str) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    from_bytes_with_format_internal(format, &HARDCODED_KEY_BYTES)
}

/// Create an encoder from a pre-parsed Format using the hardcoded key (testing only).
#[cfg(feature = "keyless")]
pub fn new_keyless_with_format(format: Format) -> Result<ObAny, Error> {
    from_bytes_with_format_internal(format, &HARDCODED_KEY_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_format_all_combinations() {
        // let key = "0".repeat(86);
        let key = crate::generate_key();

        // Define all schemes
        let schemes = vec![
            #[cfg(feature = "ob01")]
            Scheme::Ob01,
            #[cfg(feature = "ob21p")]
            Scheme::Ob21p,
            #[cfg(feature = "ob31")]
            Scheme::Ob31,
            #[cfg(feature = "ob31p")]
            Scheme::Ob31p,
            #[cfg(feature = "ob32")]
            Scheme::Ob32,
            #[cfg(feature = "ob32p")]
            Scheme::Ob32p,
            // Testing
            #[cfg(feature = "ob70")]
            Scheme::Ob70,
            #[cfg(feature = "ob71")]
            Scheme::Ob71,
            // Legacy
            #[cfg(feature = "ob00")]
            Scheme::Ob00,
        ];

        // Define all encodings
        let encodings = vec![
            Encoding::Base32Crockford,
            Encoding::Base32Rfc,
            Encoding::Base64,
            Encoding::Hex,
        ];

        for scheme in &schemes {
            for encoding in &encodings {
                let format = Format::new(*scheme, *encoding);
                let result = new_with_format(format, &key);

                assert!(
                    result.is_ok(),
                    "Failed to create Oboron implementation for {:?}:{:?}",
                    scheme,
                    encoding
                );

                let ob = result.unwrap();
                assert_eq!(
                    ob.scheme(),
                    *scheme,
                    "Scheme mismatch for {:?}:{:?}",
                    scheme,
                    encoding
                );
                assert_eq!(
                    ob.encoding(),
                    *encoding,
                    "Encoding mismatch for {:?}:{:?}",
                    scheme,
                    encoding
                );
            }
        }
    }

    #[test]
    fn test_new_from_format_string_all_combinations() {
        let key = crate::generate_key();

        // Define all schemes
        let schemes = vec![
            Scheme::Ob71,
            Scheme::Ob70,
            #[cfg(feature = "ob00")]
            Scheme::Ob00,
            #[cfg(feature = "ob01")]
            Scheme::Ob01,
            #[cfg(feature = "ob21p")]
            Scheme::Ob21p,
            #[cfg(feature = "ob31")]
            Scheme::Ob31,
            #[cfg(feature = "ob31p")]
            Scheme::Ob31p,
            #[cfg(feature = "ob32")]
            Scheme::Ob32,
            #[cfg(feature = "ob32p")]
            Scheme::Ob32p,
        ];

        // Define all encodings
        let encodings = vec![
            Encoding::Base32Crockford,
            Encoding::Base32Rfc,
            Encoding::Base64,
            Encoding::Hex,
        ];

        for scheme in schemes {
            for encoding in &encodings {
                let format_str = format!("{}:{}", scheme.as_str(), encoding.as_short_str());
                let result = new(format_str.as_str(), &key);

                assert!(
                    result.is_ok(),
                    "Failed to create Oboron implementation from format string: {}",
                    format_str
                );

                let ob = result.unwrap();
                assert_eq!(
                    ob.scheme(),
                    scheme,
                    "Scheme mismatch for format string: {}",
                    format_str
                );
                assert_eq!(
                    ob.encoding(),
                    *encoding,
                    "Encoding mismatch for format string: {}",
                    format_str
                );
            }
        }
    }

    #[test]
    fn test_roundtrip_all_combinations() {
        let key = crate::generate_key();
        let plaintext = "hello world";

        // Define all schemes
        let schemes = vec![
            Scheme::Ob71,
            Scheme::Ob70,
            #[cfg(feature = "ob01")]
            Scheme::Ob01,
            #[cfg(feature = "ob31")]
            Scheme::Ob31,
            #[cfg(feature = "ob32")]
            Scheme::Ob32,
        ];

        // Define all encodings
        let encodings = vec![
            Encoding::Base32Crockford,
            Encoding::Base32Rfc,
            Encoding::Base64,
            Encoding::Hex,
        ];

        for scheme in &schemes {
            // Skip probabilistic schemes for this test (they can't roundtrip with the same output)
            if scheme.is_probabilistic() {
                continue;
            }

            for encoding in &encodings {
                let format = Format::new(*scheme, *encoding);
                let ob = new_with_format(format, &key).unwrap();

                let ot = ob.enc(&plaintext).unwrap();
                let pt2 = ob.dec_strict(&ot).unwrap();

                assert_eq!(
                    pt2, plaintext,
                    "Roundtrip failed for {:?}:{:?}",
                    scheme, encoding
                );
            }
        }
    }
}
