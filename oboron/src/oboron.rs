//! Trait-based interface for scheme-specific Oboron implementations.
#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{error::Error, Encoding, Format, Keychain, Scheme};

/// Core trait for Oboron encryption+encoding/decoding+decryption implementations.
///
/// Each scheme+encoding combination (ZdcC32, ZdcB64, etc.) implements this trait
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
        $name:ident,           // Type name (e.g., ZdcC32)
        $scheme:expr,          // Scheme constant (e.g., Scheme::Zdc)
        $encoding:expr,        // Encoding constant (e.g., Encoding::Base32Crockford)
        $format_str:expr       // Format string for docs (e.g., "zdc:c32")
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
            pub fn new(key: &str) -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_base64(key)?,
                })
            }

            /// Create a new instance from a 64-byte key.
            #[inline]
            #[cfg(any(feature = "keyless", feature = "bytes-keys"))]
            fn from_bytes_internal(key_bytes: &[u8; 64]) -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_bytes(key_bytes)?,
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
            pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_bytes(key_bytes)?,
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
#[cfg(feature = "zdc")]
impl_oboron!(ZdcC32, Scheme::Zdc, Encoding::Base32Crockford, "zdc:c32");
#[cfg(feature = "upc")]
impl_oboron!(UpcC32, Scheme::Upc, Encoding::Base32Crockford, "upc:c32");
#[cfg(feature = "adgs")]
impl_oboron!(AdgsC32, Scheme::Adgs, Encoding::Base32Crockford, "adgs:c32");
#[cfg(feature = "apgs")]
impl_oboron!(ApgsC32, Scheme::Apgs, Encoding::Base32Crockford, "apgs:c32");
#[cfg(feature = "adsv")]
impl_oboron!(AdsvC32, Scheme::Adsv, Encoding::Base32Crockford, "adsv:c32");
#[cfg(feature = "apsv")]
impl_oboron!(ApsvC32, Scheme::Apsv, Encoding::Base32Crockford, "apsv:c32");

// Base32Rfc variants
#[cfg(feature = "zdc")]
impl_oboron!(ZdcB32, Scheme::Zdc, Encoding::Base32Rfc, "zdc:b32");
#[cfg(feature = "upc")]
impl_oboron!(UpcB32, Scheme::Upc, Encoding::Base32Rfc, "upc:b32");
#[cfg(feature = "adgs")]
impl_oboron!(AdgsB32, Scheme::Adgs, Encoding::Base32Rfc, "adgs:b32");
#[cfg(feature = "apgs")]
impl_oboron!(ApgsB32, Scheme::Apgs, Encoding::Base32Rfc, "apgs:b32");
#[cfg(feature = "adsv")]
impl_oboron!(AdsvB32, Scheme::Adsv, Encoding::Base32Rfc, "adsv:b32");
#[cfg(feature = "apsv")]
impl_oboron!(ApsvB32, Scheme::Apsv, Encoding::Base32Rfc, "apsv:b32");

// Base64 variants - with Base64 suffix
#[cfg(feature = "zdc")]
impl_oboron!(ZdcB64, Scheme::Zdc, Encoding::Base64, "zdc:b64");
#[cfg(feature = "upc")]
impl_oboron!(UpcB64, Scheme::Upc, Encoding::Base64, "upc:b64");
#[cfg(feature = "adgs")]
impl_oboron!(AdgsB64, Scheme::Adgs, Encoding::Base64, "adgs:b64");
#[cfg(feature = "apgs")]
impl_oboron!(ApgsB64, Scheme::Apgs, Encoding::Base64, "apgs:b64");
#[cfg(feature = "adsv")]
impl_oboron!(AdsvB64, Scheme::Adsv, Encoding::Base64, "adsv:b64");
#[cfg(feature = "apsv")]
impl_oboron!(ApsvB64, Scheme::Apsv, Encoding::Base64, "apsv:b64");

// Hex variants - with Hex suffix
#[cfg(feature = "zdc")]
impl_oboron!(ZdcHex, Scheme::Zdc, Encoding::Hex, "zdc:hex");
#[cfg(feature = "upc")]
impl_oboron!(UpcHex, Scheme::Upc, Encoding::Hex, "upc:hex");
#[cfg(feature = "adgs")]
impl_oboron!(AdgsHex, Scheme::Adgs, Encoding::Hex, "adgs:hex");
#[cfg(feature = "apgs")]
impl_oboron!(ApgsHex, Scheme::Apgs, Encoding::Hex, "apgs:hex");
#[cfg(feature = "adsv")]
impl_oboron!(AdsvHex, Scheme::Adsv, Encoding::Hex, "adsv:hex");
#[cfg(feature = "apsv")]
impl_oboron!(ApsvHex, Scheme::Apsv, Encoding::Hex, "apsv:hex");

// Testing

// tdi (identity scheme)
#[cfg(feature = "tdi")]
impl_oboron!(TdiC32, Scheme::Tdi, Encoding::Base32Crockford, "tdi:c32");
#[cfg(feature = "tdi")]
impl_oboron!(TdiB32, Scheme::Tdi, Encoding::Base32Rfc, "tdi:b32");
#[cfg(feature = "tdi")]
impl_oboron!(TdiB64, Scheme::Tdi, Encoding::Base64, "tdi:b64");
#[cfg(feature = "tdi")]
impl_oboron!(TdiHex, Scheme::Tdi, Encoding::Hex, "tdi:hex");

// tdr (reverse scheme)
#[cfg(feature = "tdr")]
impl_oboron!(TdrC32, Scheme::Tdr, Encoding::Base32Crockford, "tdr:c32");
#[cfg(feature = "tdr")]
impl_oboron!(TdrB32, Scheme::Tdr, Encoding::Base32Rfc, "tdr:b32");
#[cfg(feature = "tdr")]
impl_oboron!(TdrB64, Scheme::Tdr, Encoding::Base64, "tdr:b64");
#[cfg(feature = "tdr")]
impl_oboron!(TdrHex, Scheme::Tdr, Encoding::Hex, "tdr:hex");

/// Type-erased Oboron encoder that can hold any scheme+encoding combination.
///
/// This enum allows for runtime scheme selection without heap allocation.
/// It's returned by the `oboron::new()` factory function.
#[allow(non_camel_case_types)]
pub enum ObAny {
    #[cfg(feature = "zdc")]
    ZdcC32(ZdcC32),
    #[cfg(feature = "zdc")]
    ZdcB32(ZdcB32),
    #[cfg(feature = "zdc")]
    ZdcB64(ZdcB64),
    #[cfg(feature = "zdc")]
    ZdcHex(ZdcHex),
    #[cfg(feature = "upc")]
    UpcC32(UpcC32),
    #[cfg(feature = "upc")]
    UpcB32(UpcB32),
    #[cfg(feature = "upc")]
    UpcB64(UpcB64),
    #[cfg(feature = "upc")]
    UpcHex(UpcHex),
    #[cfg(feature = "adgs")]
    AdgsC32(AdgsC32),
    #[cfg(feature = "adgs")]
    AdgsB32(AdgsB32),
    #[cfg(feature = "adgs")]
    AdgsB64(AdgsB64),
    #[cfg(feature = "adgs")]
    AdgsHex(AdgsHex),
    #[cfg(feature = "apgs")]
    ApgsC32(ApgsC32),
    #[cfg(feature = "apgs")]
    ApgsB32(ApgsB32),
    #[cfg(feature = "apgs")]
    ApgsB64(ApgsB64),
    #[cfg(feature = "apgs")]
    ApgsHex(ApgsHex),
    #[cfg(feature = "adsv")]
    AdsvC32(AdsvC32),
    #[cfg(feature = "adsv")]
    AdsvB32(AdsvB32),
    #[cfg(feature = "adsv")]
    AdsvB64(AdsvB64),
    #[cfg(feature = "adsv")]
    AdsvHex(AdsvHex),
    #[cfg(feature = "apsv")]
    ApsvC32(ApsvC32),
    #[cfg(feature = "apsv")]
    ApsvB32(ApsvB32),
    #[cfg(feature = "apsv")]
    ApsvB64(ApsvB64),
    #[cfg(feature = "apsv")]
    ApsvHex(ApsvHex),
    // Testing
    #[cfg(feature = "tdi")]
    TdiC32(TdiC32),
    #[cfg(feature = "tdi")]
    TdiB32(TdiB32),
    #[cfg(feature = "tdi")]
    TdiHex(TdiHex),
    #[cfg(feature = "tdi")]
    TdiB64(TdiB64),
    #[cfg(feature = "tdr")]
    TdrC32(TdrC32),
    #[cfg(feature = "tdr")]
    TdrB32(TdrB32),
    #[cfg(feature = "tdr")]
    TdrHex(TdrHex),
    #[cfg(feature = "tdr")]
    TdrB64(TdrB64),
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
                #[cfg(feature = "zdc")]
                ObAny::ZdcC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "zdc")]
                ObAny::ZdcB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "zdc")]
                ObAny::ZdcB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "zdc")]
                ObAny::ZdcHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upc")]
                ObAny::UpcC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upc")]
                ObAny::UpcB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upc")]
                ObAny::UpcB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upc")]
                ObAny::UpcHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "adgs")]
                ObAny::AdgsC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "adgs")]
                ObAny::AdgsB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "adgs")]
                ObAny::AdgsB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "adgs")]
                ObAny::AdgsHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "adsv")]
                ObAny::AdsvC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "adsv")]
                ObAny::AdsvB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "adsv")]
                ObAny::AdsvB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "adsv")]
                ObAny::AdsvHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apsv")]
                ObAny::ApsvC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apsv")]
                ObAny::ApsvB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apsv")]
                ObAny::ApsvB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apsv")]
                ObAny::ApsvHex(ob) => ob.$method($($arg),*),
                // Testing
                #[cfg(feature = "tdi")]
                ObAny::TdiC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "tdi")]
                ObAny::TdiB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "tdi")]
                ObAny::TdiB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "tdi")]
                ObAny::TdiHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "tdr")]
                ObAny::TdrC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "tdr")]
                ObAny::TdrB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "tdr")]
                ObAny::TdrB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "tdr")]
                ObAny::TdrHex(ob) => ob.$method($($arg),*),
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
    /// Defaults to tdi:c32 format.
    pub fn new(key: &str) -> Result<Self, Error> {
        #[cfg(feature = "tdi")]
        return Ok(ObAny::TdiC32(TdiC32::new(key)?));
        #[cfg(feature = "tdr")]
        #[cfg(not(feature = "tdi"))]
        return Ok(ObAny::TdrC32(TdrC32::new(key)?));
        #[cfg(feature = "zdc")]
        #[cfg(not(any(feature = "tdi", feature = "tdr")))]
        return Ok(ObAny::ZdcC32(ZdcC32::new(key)?));
        #[cfg(feature = "upc")]
        #[cfg(not(any(feature = "tdi", feature = "tdr", feature = "zdc")))]
        return Ok(ObAny::UpcC32(UpcC32::new(key)?));
        #[cfg(feature = "adgs")]
        #[cfg(not(any(feature = "tdi", feature = "tdr", feature = "zdc", feature = "upc")))]
        return Ok(ObAny::AdgsC32(AdgsC32::new(key)?));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs"
        )))]
        return Ok(ObAny::ApgsC32(ApgsC32::new(key)?));
        #[cfg(feature = "adsv")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs"
        )))]
        return Ok(ObAny::AdsvC32(AdsvC32::new(key)?));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32::new(key)?));
        #[cfg(feature = "ob00")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv"
        )))]
        return Ok(ObAny::Ob00Base32Crockford(Ob00Base32Crockford::new(key)?));
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance from a 64-byte key.
    ///
    /// Defaults to tdi:c32 format.
    #[inline]
    #[cfg(feature = "bytes-keys")]
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        #[cfg(feature = "tdi")]
        return Ok(ObAny::TdiC32(TdiC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "tdr")]
        #[cfg(not(feature = "tdi"))]
        return Ok(ObAny::TdrC32(TdrC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "zdc")]
        #[cfg(not(any(feature = "tdi", feature = "tdr")))]
        return Ok(ObAny::ZdcC32(ZdcC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "upc")]
        #[cfg(not(any(feature = "tdi", feature = "tdr", feature = "zdc")))]
        return Ok(ObAny::UpcC32(UpcC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "adgs")]
        #[cfg(not(any(feature = "tdi", feature = "tdr", feature = "zdc", feature = "upc")))]
        return Ok(ObAny::AdgsC32(AdgsC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs"
        )))]
        return Ok(ObAny::ApgsC32(ApgsC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "adsv")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs"
        )))]
        return Ok(ObAny::AdsvC32(AdsvC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "ob00")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv"
        )))]
        return Ok(ObAny::Ob00Base32Crockford(Ob00Base32Crockford {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    #[cfg(feature = "hex-keys")]
    pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
        #[cfg(feature = "tdi")]
        return Ok(ObAny::TdiC32(TdiC32::from_hex_key(key_hex)?));
        #[cfg(feature = "tdr")]
        #[cfg(not(feature = "tdi"))]
        return Ok(ObAny::TdrC32(TdrC32::from_hex_key(key_hex)?));
        #[cfg(feature = "zdc")]
        #[cfg(not(any(feature = "tdi", feature = "tdr")))]
        return Ok(ObAny::ZdcC32(ZdcC32::from_hex_key(key_hex)?));
        #[cfg(feature = "upc")]
        #[cfg(not(any(feature = "tdi", feature = "tdr", feature = "zdc")))]
        return Ok(ObAny::UpcC32(UpcC32::from_hex_key(key_hex)?));
        #[cfg(feature = "adgs")]
        #[cfg(not(any(feature = "tdi", feature = "tdr", feature = "zdc", feature = "upc")))]
        return Ok(ObAny::AdgsC32(AdgsC32::from_hex_key(key_hex)?));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs"
        )))]
        return Ok(ObAny::ApgsC32(ApgsC32::from_hex_key(key_hex)?));
        #[cfg(feature = "adsv")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs"
        )))]
        return Ok(ObAny::AdsvC32(AdsvC32::from_hex_key(key_hex)?));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32::from_hex_key(key_hex)?));
        #[cfg(feature = "ob00")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv"
        )))]
        return Ok(ObAny::Ob00Base32Crockford(
            Ob00Base32Crockford::from_hex_key(key_hex)?,
        ));
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance with hardcoded key (testing only).
    ///
    /// Defaults to tdi:c32 format.
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        #[cfg(feature = "tdi")]
        return Ok(ObAny::TdiC32(TdiC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "tdr")]
        #[cfg(not(feature = "tdi"))]
        return Ok(ObAny::TdrC32(TdrC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "zdc")]
        #[cfg(not(any(feature = "tdi", feature = "tdr")))]
        return Ok(ObAny::ZdcC32(ZdcC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "upc")]
        #[cfg(not(any(feature = "tdi", feature = "tdr", feature = "zdc")))]
        return Ok(ObAny::UpcC32(UpcC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "adgs")]
        #[cfg(not(any(feature = "tdi", feature = "tdr", feature = "zdc", feature = "upc")))]
        return Ok(ObAny::AdgsC32(AdgsC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs"
        )))]
        return Ok(ObAny::ApgsC32(ApgsC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "adsv")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs"
        )))]
        return Ok(ObAny::AdsvC32(AdsvC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "ob00")]
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv"
        )))]
        return Ok(ObAny::Ob00Base32Crockford(Ob00Base32Crockford {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(not(any(
            feature = "tdi",
            feature = "tdr",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }
}

/// Create an encoder from a format string and base64 key.
pub fn new(fmt: &str, key: &str) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    new_with_format(format, key)
}

/// Create an encoder from a pre-parsed Format and base64 key.
pub fn new_with_format(format: Format, key: &str) -> Result<ObAny, Error> {
    match (format.scheme(), format.encoding()) {
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Base32Crockford) => Ok(ObAny::ZdcC32(ZdcC32::new(key)?)),
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Base32Rfc) => Ok(ObAny::ZdcB32(ZdcB32::new(key)?)),
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Base64) => Ok(ObAny::ZdcB64(ZdcB64::new(key)?)),
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Hex) => Ok(ObAny::ZdcHex(ZdcHex::new(key)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Base32Crockford) => Ok(ObAny::UpcC32(UpcC32::new(key)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Base32Rfc) => Ok(ObAny::UpcB32(UpcB32::new(key)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Base64) => Ok(ObAny::UpcB64(UpcB64::new(key)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Hex) => Ok(ObAny::UpcHex(UpcHex::new(key)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Base32Crockford) => Ok(ObAny::AdgsC32(AdgsC32::new(key)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Base32Rfc) => Ok(ObAny::AdgsB32(AdgsB32::new(key)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Base64) => Ok(ObAny::AdgsB64(AdgsB64::new(key)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Hex) => Ok(ObAny::AdgsHex(AdgsHex::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Base32Crockford) => Ok(ObAny::ApgsC32(ApgsC32::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Base32Rfc) => Ok(ObAny::ApgsB32(ApgsB32::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Base64) => Ok(ObAny::ApgsB64(ApgsB64::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Hex) => Ok(ObAny::ApgsHex(ApgsHex::new(key)?)),
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Base32Crockford) => Ok(ObAny::AdsvC32(AdsvC32::new(key)?)),
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Base32Rfc) => Ok(ObAny::AdsvB32(AdsvB32::new(key)?)),
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Base64) => Ok(ObAny::AdsvB64(AdsvB64::new(key)?)),
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Hex) => Ok(ObAny::AdsvHex(AdsvHex::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Base32Crockford) => Ok(ObAny::ApsvC32(ApsvC32::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Base32Rfc) => Ok(ObAny::ApsvB32(ApsvB32::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Base64) => Ok(ObAny::ApsvB64(ApsvB64::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Hex) => Ok(ObAny::ApsvHex(ApsvHex::new(key)?)),
        // Testing
        #[cfg(feature = "tdi")]
        (Scheme::Tdi, Encoding::Base32Crockford) => Ok(ObAny::TdiC32(TdiC32::new(key)?)),
        #[cfg(feature = "tdi")]
        (Scheme::Tdi, Encoding::Base32Rfc) => Ok(ObAny::TdiB32(TdiB32::new(key)?)),
        #[cfg(feature = "tdi")]
        (Scheme::Tdi, Encoding::Base64) => Ok(ObAny::TdiB64(TdiB64::new(key)?)),
        #[cfg(feature = "tdi")]
        (Scheme::Tdi, Encoding::Hex) => Ok(ObAny::TdiHex(TdiHex::new(key)?)),
        #[cfg(feature = "tdr")]
        (Scheme::Tdr, Encoding::Base32Crockford) => Ok(ObAny::TdrC32(TdrC32::new(key)?)),
        #[cfg(feature = "tdr")]
        (Scheme::Tdr, Encoding::Base32Rfc) => Ok(ObAny::TdrB32(TdrB32::new(key)?)),
        #[cfg(feature = "tdr")]
        (Scheme::Tdr, Encoding::Base64) => Ok(ObAny::TdrB64(TdrB64::new(key)?)),
        #[cfg(feature = "tdr")]
        (Scheme::Tdr, Encoding::Hex) => Ok(ObAny::TdrHex(TdrHex::new(key)?)),
        // Legacy
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base32Crockford) => {
            Ok(ObAny::Ob00Base32Crockford(Ob00Base32Crockford::new(key)?))
        }
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base32Rfc) => Ok(ObAny::Ob00Base32Rfc(Ob00Base32Rfc::new(key)?)),
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base64) => Ok(ObAny::Ob00Base64(Ob00Base64::new(key)?)),
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Hex) => Ok(ObAny::Ob00Hex(Ob00Hex::new(key)?)),
        #[allow(unreachable_patterns)]
        _ => Err(Error::UnknownScheme),
    }
}

#[cfg(any(feature = "keyless", feature = "bytes-keys", feature = "hex-keys"))]
fn from_bytes_with_format_internal(format: Format, key_bytes: &[u8; 64]) -> Result<ObAny, Error> {
    match (format.scheme(), format.encoding()) {
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Base32Crockford) => {
            Ok(ObAny::ZdcC32(ZdcC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Base32Rfc) => {
            Ok(ObAny::ZdcB32(ZdcB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Base64) => {
            Ok(ObAny::ZdcB64(ZdcB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Hex) => Ok(ObAny::ZdcHex(ZdcHex::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Base32Crockford) => {
            Ok(ObAny::UpcC32(UpcC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Base32Rfc) => {
            Ok(ObAny::UpcB32(UpcB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Base64) => {
            Ok(ObAny::UpcB64(UpcB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Hex) => Ok(ObAny::UpcHex(UpcHex::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Base32Crockford) => {
            Ok(ObAny::AdgsC32(AdgsC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Base32Rfc) => {
            Ok(ObAny::AdgsB32(AdgsB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Base64) => {
            Ok(ObAny::AdgsB64(AdgsB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Hex) => {
            Ok(ObAny::AdgsHex(AdgsHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Base32Crockford) => {
            Ok(ObAny::ApgsC32(ApgsC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Base32Rfc) => {
            Ok(ObAny::ApgsB32(ApgsB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Base64) => {
            Ok(ObAny::ApgsB64(ApgsB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Hex) => {
            Ok(ObAny::ApgsHex(ApgsHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Base32Crockford) => {
            Ok(ObAny::AdsvC32(AdsvC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Base32Rfc) => {
            Ok(ObAny::AdsvB32(AdsvB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Base64) => {
            Ok(ObAny::AdsvB64(AdsvB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Hex) => {
            Ok(ObAny::AdsvHex(AdsvHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Base32Crockford) => {
            Ok(ObAny::ApsvC32(ApsvC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Base32Rfc) => {
            Ok(ObAny::ApsvB32(ApsvB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Base64) => {
            Ok(ObAny::ApsvB64(ApsvB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Hex) => {
            Ok(ObAny::ApsvHex(ApsvHex::from_bytes_internal(key_bytes)?))
        }
        // Testing
        #[cfg(feature = "tdi")]
        (Scheme::Tdi, Encoding::Base32Crockford) => {
            Ok(ObAny::TdiC32(TdiC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "tdi")]
        (Scheme::Tdi, Encoding::Base32Rfc) => {
            Ok(ObAny::TdiB32(TdiB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "tdi")]
        (Scheme::Tdi, Encoding::Base64) => {
            Ok(ObAny::TdiB64(TdiB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "tdi")]
        (Scheme::Tdi, Encoding::Hex) => Ok(ObAny::TdiHex(TdiHex::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "tdr")]
        (Scheme::Tdr, Encoding::Base32Crockford) => {
            Ok(ObAny::TdrC32(TdrC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "tdr")]
        (Scheme::Tdr, Encoding::Base32Rfc) => {
            Ok(ObAny::TdrB32(TdrB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "tdr")]
        (Scheme::Tdr, Encoding::Base64) => {
            Ok(ObAny::TdrB64(TdrB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "tdr")]
        (Scheme::Tdr, Encoding::Hex) => Ok(ObAny::TdrHex(TdrHex::from_bytes_internal(key_bytes)?)),
        // Legacy
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base32Crockford) => Ok(ObAny::Ob00Base32Crockford(
            Ob00Base32Crockford::from_bytes_internal(key_bytes)?,
        )),
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base32Rfc) => Ok(ObAny::Ob00Base32Rfc(
            Ob00Base32Rfc::from_bytes_internal(key_bytes)?,
        )),
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Base64) => Ok(ObAny::Ob00Base64(Ob00Base64::from_bytes_internal(
            key_bytes,
        )?)),
        #[cfg(feature = "ob00")]
        (Scheme::Ob00, Encoding::Hex) => {
            Ok(ObAny::Ob00Hex(Ob00Hex::from_bytes_internal(key_bytes)?))
        }
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
pub fn from_bytes(fmt: &str, key_bytes: &[u8; 64]) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    from_bytes_with_format_internal(format, &key_bytes)
}

/// Create an encoder from a pre-parsed Format and raw bytes.
#[cfg(feature = "bytes-keys")]
pub fn from_bytes_with_format(format: Format, key_bytes: &[u8; 64]) -> Result<ObAny, Error> {
    from_bytes_with_format_internal(format, key_bytes)
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
            #[cfg(feature = "zdc")]
            Scheme::Zdc,
            #[cfg(feature = "upc")]
            Scheme::Upc,
            #[cfg(feature = "adgs")]
            Scheme::Adgs,
            #[cfg(feature = "apgs")]
            Scheme::Apgs,
            #[cfg(feature = "adsv")]
            Scheme::Adsv,
            #[cfg(feature = "apsv")]
            Scheme::Apsv,
            // Testing
            #[cfg(feature = "tdi")]
            Scheme::Tdi,
            #[cfg(feature = "tdr")]
            Scheme::Tdr,
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
            Scheme::Tdr,
            Scheme::Tdi,
            #[cfg(feature = "ob00")]
            Scheme::Ob00,
            #[cfg(feature = "zdc")]
            Scheme::Zdc,
            #[cfg(feature = "upc")]
            Scheme::Upc,
            #[cfg(feature = "adgs")]
            Scheme::Adgs,
            #[cfg(feature = "apgs")]
            Scheme::Apgs,
            #[cfg(feature = "adsv")]
            Scheme::Adsv,
            #[cfg(feature = "apsv")]
            Scheme::Apsv,
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
            Scheme::Tdr,
            Scheme::Tdi,
            #[cfg(feature = "zdc")]
            Scheme::Zdc,
            #[cfg(feature = "adgs")]
            Scheme::Adgs,
            #[cfg(feature = "adsv")]
            Scheme::Adsv,
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
