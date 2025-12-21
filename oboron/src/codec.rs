//! Trait-based interface for scheme-specific ObtextCodec implementations.
#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{error::Error, Encoding, Format, Keychain, Scheme};

/// Core trait for ObtextCodec encryption+encoding/decoding+decryption implementations.
///
/// Each scheme+encoding combination (ZdcC32, ZdcB64, etc.) implements this trait
/// to provide a consistent interface for encoding and decoding operations.
///
/// Note: Construction methods (`new`, `from_bytes`, `new_keyless`) are not part of
/// this trait.     Each type provides its own constructor with an appropriate signature.
pub trait ObtextCodec {
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

#[cfg(feature = "legacy")]
use crate::legacy::{LegacyB32, LegacyB64, LegacyC32, LegacyHex};

/// Macro to implement optimized ObtextCodec types with compile-time specialization.
///
/// This macro generates a complete ObtextCodec implementation with all overhead eliminated:
/// - No runtime scheme matching
/// - No method call overhead for byte()
/// - Direct function calls to encrypt/decrypt
/// - Encoding functions called directly (no dispatch)
/// - All constants baked in at compile time
macro_rules! impl_oboron {
    (
        $name:ident,           // Type name (e.g., ZdcC32)
        $scheme:expr,          // Scheme constant (e.g., Scheme::Zdc)
        $encoding:expr,        // Encoding constant (e.g., Encoding::C32)
        $format_str:expr       // Format string for docs (e.g., "zdc.c32")
    ) => {
        #[doc = concat!("ObtextCodec implementation for ", $format_str, " format.\n\n")]
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

        impl ObtextCodec for $name {
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

// C32 variants
#[cfg(feature = "zdc")]
impl_oboron!(ZdcC32, Scheme::Zdc, Encoding::C32, "zdc.c32");
#[cfg(feature = "upc")]
impl_oboron!(UpcC32, Scheme::Upc, Encoding::C32, "upc.c32");
#[cfg(feature = "adgs")]
impl_oboron!(AdgsC32, Scheme::Adgs, Encoding::C32, "adgs.c32");
#[cfg(feature = "apgs")]
impl_oboron!(ApgsC32, Scheme::Apgs, Encoding::C32, "apgs.c32");
#[cfg(feature = "adsv")]
impl_oboron!(AdsvC32, Scheme::Adsv, Encoding::C32, "adsv.c32");
#[cfg(feature = "apsv")]
impl_oboron!(ApsvC32, Scheme::Apsv, Encoding::C32, "apsv.c32");

// B32 variants
#[cfg(feature = "zdc")]
impl_oboron!(ZdcB32, Scheme::Zdc, Encoding::B32, "zdc.b32");
#[cfg(feature = "upc")]
impl_oboron!(UpcB32, Scheme::Upc, Encoding::B32, "upc.b32");
#[cfg(feature = "adgs")]
impl_oboron!(AdgsB32, Scheme::Adgs, Encoding::B32, "adgs.b32");
#[cfg(feature = "apgs")]
impl_oboron!(ApgsB32, Scheme::Apgs, Encoding::B32, "apgs.b32");
#[cfg(feature = "adsv")]
impl_oboron!(AdsvB32, Scheme::Adsv, Encoding::B32, "adsv.b32");
#[cfg(feature = "apsv")]
impl_oboron!(ApsvB32, Scheme::Apsv, Encoding::B32, "apsv.b32");

// B64 variants
#[cfg(feature = "zdc")]
impl_oboron!(ZdcB64, Scheme::Zdc, Encoding::B64, "zdc.b64");
#[cfg(feature = "upc")]
impl_oboron!(UpcB64, Scheme::Upc, Encoding::B64, "upc.b64");
#[cfg(feature = "adgs")]
impl_oboron!(AdgsB64, Scheme::Adgs, Encoding::B64, "adgs.b64");
#[cfg(feature = "apgs")]
impl_oboron!(ApgsB64, Scheme::Apgs, Encoding::B64, "apgs.b64");
#[cfg(feature = "adsv")]
impl_oboron!(AdsvB64, Scheme::Adsv, Encoding::B64, "adsv.b64");
#[cfg(feature = "apsv")]
impl_oboron!(ApsvB64, Scheme::Apsv, Encoding::B64, "apsv.b64");

// Hex variants
#[cfg(feature = "zdc")]
impl_oboron!(ZdcHex, Scheme::Zdc, Encoding::Hex, "zdc.hex");
#[cfg(feature = "upc")]
impl_oboron!(UpcHex, Scheme::Upc, Encoding::Hex, "upc.hex");
#[cfg(feature = "adgs")]
impl_oboron!(AdgsHex, Scheme::Adgs, Encoding::Hex, "adgs.hex");
#[cfg(feature = "apgs")]
impl_oboron!(ApgsHex, Scheme::Apgs, Encoding::Hex, "apgs.hex");
#[cfg(feature = "adsv")]
impl_oboron!(AdsvHex, Scheme::Adsv, Encoding::Hex, "adsv.hex");
#[cfg(feature = "apsv")]
impl_oboron!(ApsvHex, Scheme::Apsv, Encoding::Hex, "apsv.hex");

// Testing

// mock1 (identity scheme)
#[cfg(feature = "mock")]
impl_oboron!(Mock1C32, Scheme::Mock1, Encoding::C32, "mock1.c32");
#[cfg(feature = "mock")]
impl_oboron!(Mock1B32, Scheme::Mock1, Encoding::B32, "mock1.b32");
#[cfg(feature = "mock")]
impl_oboron!(Mock1B64, Scheme::Mock1, Encoding::B64, "mock1.b64");
#[cfg(feature = "mock")]
impl_oboron!(Mock1Hex, Scheme::Mock1, Encoding::Hex, "mock1.hex");

// mock2 (reverse scheme)
#[cfg(feature = "mock")]
impl_oboron!(Mock2C32, Scheme::Mock2, Encoding::C32, "mock2.c32");
#[cfg(feature = "mock")]
impl_oboron!(Mock2B32, Scheme::Mock2, Encoding::B32, "mock2.b32");
#[cfg(feature = "mock")]
impl_oboron!(Mock2B64, Scheme::Mock2, Encoding::B64, "mock2.b64");
#[cfg(feature = "mock")]
impl_oboron!(Mock2Hex, Scheme::Mock2, Encoding::Hex, "mock2.hex");

/// Type-erased ObtextCodec encoder that can hold any scheme+encoding combination.
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
    #[cfg(feature = "mock")]
    Mock1C32(Mock1C32),
    #[cfg(feature = "mock")]
    Mock1B32(Mock1B32),
    #[cfg(feature = "mock")]
    Mock1Hex(Mock1Hex),
    #[cfg(feature = "mock")]
    Mock1B64(Mock1B64),
    #[cfg(feature = "mock")]
    Mock2C32(Mock2C32),
    #[cfg(feature = "mock")]
    Mock2B32(Mock2B32),
    #[cfg(feature = "mock")]
    Mock2Hex(Mock2Hex),
    #[cfg(feature = "mock")]
    Mock2B64(Mock2B64),
    // Legacy
    #[cfg(feature = "legacy")]
    LegacyC32(LegacyC32),
    #[cfg(feature = "legacy")]
    LegacyB32(LegacyB32),
    #[cfg(feature = "legacy")]
    LegacyB64(LegacyB64),
    #[cfg(feature = "legacy")]
    LegacyHex(LegacyHex),
}

// Macro to delegate ObtextCodec methods to the inner type
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
                #[cfg(feature = "mock")]
                ObAny::Mock1C32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock1B32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock1B64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock1Hex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock2C32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock2B32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock2B64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock2Hex(ob) => ob.$method($($arg),*),
                // Legacy
                #[cfg(feature = "legacy")]
                ObAny::LegacyC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "legacy")]
                ObAny::LegacyB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "legacy")]
                ObAny::LegacyB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "legacy")]
                ObAny::LegacyHex(ob) => ob.$method($($arg),*),
            }
        }
    };
}

impl ObtextCodec for ObAny {
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
    /// Defaults to mock1.c32 format.
    pub fn new(key: &str) -> Result<Self, Error> {
        #[cfg(feature = "mock")]
        return Ok(ObAny::Mock1C32(Mock1C32::new(key)?));
        #[cfg(feature = "zdc")]
        #[cfg(not(feature = "mock"))]
        return Ok(ObAny::ZdcC32(ZdcC32::new(key)?));
        #[cfg(feature = "upc")]
        #[cfg(not(any(feature = "mock", feature = "zdc")))]
        return Ok(ObAny::UpcC32(UpcC32::new(key)?));
        #[cfg(feature = "adgs")]
        #[cfg(not(any(feature = "mock", feature = "zdc", feature = "upc")))]
        return Ok(ObAny::AdgsC32(AdgsC32::new(key)?));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(feature = "mock", feature = "zdc", feature = "upc", feature = "adgs")))]
        return Ok(ObAny::ApgsC32(ApgsC32::new(key)?));
        #[cfg(feature = "adsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs"
        )))]
        return Ok(ObAny::AdsvC32(AdsvC32::new(key)?));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32::new(key)?));
        #[cfg(feature = "legacy")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv"
        )))]
        return Ok(ObAny::LegacyC32(LegacyC32::new(key)?));
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv",
            feature = "legacy"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance from a 64-byte key.
    ///
    /// Defaults to mock1.c32 format.
    #[inline]
    #[cfg(feature = "bytes-keys")]
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        #[cfg(feature = "mock")]
        return Ok(ObAny::Mock1C32(Mock1C32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "zdc")]
        #[cfg(not(feature = "mock"))]
        return Ok(ObAny::ZdcC32(ZdcC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "upc")]
        #[cfg(not(any(feature = "mock", feature = "zdc")))]
        return Ok(ObAny::UpcC32(UpcC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "adgs")]
        #[cfg(not(any(feature = "mock", feature = "zdc", feature = "upc")))]
        return Ok(ObAny::AdgsC32(AdgsC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(feature = "mock", feature = "zdc", feature = "upc", feature = "adgs")))]
        return Ok(ObAny::ApgsC32(ApgsC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "adsv")]
        #[cfg(not(any(
            feature = "mock",
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
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "legacy")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv"
        )))]
        return Ok(ObAny::LegacyC32(LegacyC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv",
            feature = "legacy"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    #[cfg(feature = "hex-keys")]
    pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
        #[cfg(feature = "mock")]
        return Ok(ObAny::Mock1C32(Mock1C32::from_hex_key(key_hex)?));
        #[cfg(feature = "zdc")]
        #[cfg(not(feature = "mock"))]
        return Ok(ObAny::ZdcC32(ZdcC32::from_hex_key(key_hex)?));
        #[cfg(feature = "upc")]
        #[cfg(not(any(feature = "mock", feature = "zdc")))]
        return Ok(ObAny::UpcC32(UpcC32::from_hex_key(key_hex)?));
        #[cfg(feature = "adgs")]
        #[cfg(not(any(feature = "mock", feature = "zdc", feature = "upc")))]
        return Ok(ObAny::AdgsC32(AdgsC32::from_hex_key(key_hex)?));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(feature = "mock", feature = "zdc", feature = "upc", feature = "adgs")))]
        return Ok(ObAny::ApgsC32(ApgsC32::from_hex_key(key_hex)?));
        #[cfg(feature = "adsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs"
        )))]
        return Ok(ObAny::AdsvC32(AdsvC32::from_hex_key(key_hex)?));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32::from_hex_key(key_hex)?));
        #[cfg(feature = "legacy")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv"
        )))]
        return Ok(ObAny::LegacyC32(LegacyC32::from_hex_key(key_hex)?));
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv",
            feature = "legacy"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance with hardcoded key (testing only).
    ///
    /// Defaults to mock1.c32 format.
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        #[cfg(feature = "mock")]
        return Ok(ObAny::Mock1C32(Mock1C32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "zdc")]
        #[cfg(not(feature = "mock"))]
        return Ok(ObAny::ZdcC32(ZdcC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "upc")]
        #[cfg(not(any(feature = "mock", feature = "zdc")))]
        return Ok(ObAny::UpcC32(UpcC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "adgs")]
        #[cfg(not(any(feature = "mock", feature = "zdc", feature = "upc")))]
        return Ok(ObAny::AdgsC32(AdgsC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(feature = "mock", feature = "zdc", feature = "upc", feature = "adgs")))]
        return Ok(ObAny::ApgsC32(ApgsC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "adsv")]
        #[cfg(not(any(
            feature = "mock",
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
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "legacy")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv"
        )))]
        return Ok(ObAny::LegacyC32(LegacyC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(not(any(
            feature = "mock",
            feature = "zdc",
            feature = "upc",
            feature = "adgs",
            feature = "apgs",
            feature = "adsv",
            feature = "apsv",
            feature = "legacy"
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
        (Scheme::Zdc, Encoding::C32) => Ok(ObAny::ZdcC32(ZdcC32::new(key)?)),
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::B32) => Ok(ObAny::ZdcB32(ZdcB32::new(key)?)),
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::B64) => Ok(ObAny::ZdcB64(ZdcB64::new(key)?)),
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Hex) => Ok(ObAny::ZdcHex(ZdcHex::new(key)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::C32) => Ok(ObAny::UpcC32(UpcC32::new(key)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::B32) => Ok(ObAny::UpcB32(UpcB32::new(key)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::B64) => Ok(ObAny::UpcB64(UpcB64::new(key)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Hex) => Ok(ObAny::UpcHex(UpcHex::new(key)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::C32) => Ok(ObAny::AdgsC32(AdgsC32::new(key)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::B32) => Ok(ObAny::AdgsB32(AdgsB32::new(key)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::B64) => Ok(ObAny::AdgsB64(AdgsB64::new(key)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Hex) => Ok(ObAny::AdgsHex(AdgsHex::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::C32) => Ok(ObAny::ApgsC32(ApgsC32::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B32) => Ok(ObAny::ApgsB32(ApgsB32::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B64) => Ok(ObAny::ApgsB64(ApgsB64::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Hex) => Ok(ObAny::ApgsHex(ApgsHex::new(key)?)),
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::C32) => Ok(ObAny::AdsvC32(AdsvC32::new(key)?)),
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::B32) => Ok(ObAny::AdsvB32(AdsvB32::new(key)?)),
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::B64) => Ok(ObAny::AdsvB64(AdsvB64::new(key)?)),
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Hex) => Ok(ObAny::AdsvHex(AdsvHex::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::C32) => Ok(ObAny::ApsvC32(ApsvC32::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::B32) => Ok(ObAny::ApsvB32(ApsvB32::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::B64) => Ok(ObAny::ApsvB64(ApsvB64::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Hex) => Ok(ObAny::ApsvHex(ApsvHex::new(key)?)),
        // Testing
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::C32) => Ok(ObAny::Mock1C32(Mock1C32::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::B32) => Ok(ObAny::Mock1B32(Mock1B32::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::B64) => Ok(ObAny::Mock1B64(Mock1B64::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::Hex) => Ok(ObAny::Mock1Hex(Mock1Hex::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::C32) => Ok(ObAny::Mock2C32(Mock2C32::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::B32) => Ok(ObAny::Mock2B32(Mock2B32::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::B64) => Ok(ObAny::Mock2B64(Mock2B64::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::Hex) => Ok(ObAny::Mock2Hex(Mock2Hex::new(key)?)),
        // Legacy
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, Encoding::C32) => Ok(ObAny::LegacyC32(LegacyC32::new(key)?)),
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, Encoding::B32) => Ok(ObAny::LegacyB32(LegacyB32::new(key)?)),
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, Encoding::B64) => Ok(ObAny::LegacyB64(LegacyB64::new(key)?)),
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, Encoding::Hex) => Ok(ObAny::LegacyHex(LegacyHex::new(key)?)),
        #[allow(unreachable_patterns)]
        _ => Err(Error::UnknownScheme),
    }
}

#[cfg(any(feature = "keyless", feature = "bytes-keys", feature = "hex-keys"))]
fn from_bytes_with_format_internal(format: Format, key_bytes: &[u8; 64]) -> Result<ObAny, Error> {
    match (format.scheme(), format.encoding()) {
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::C32) => Ok(ObAny::ZdcC32(ZdcC32::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::B32) => Ok(ObAny::ZdcB32(ZdcB32::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::B64) => Ok(ObAny::ZdcB64(ZdcB64::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "zdc")]
        (Scheme::Zdc, Encoding::Hex) => Ok(ObAny::ZdcHex(ZdcHex::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::C32) => Ok(ObAny::UpcC32(UpcC32::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::B32) => Ok(ObAny::UpcB32(UpcB32::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::B64) => Ok(ObAny::UpcB64(UpcB64::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "upc")]
        (Scheme::Upc, Encoding::Hex) => Ok(ObAny::UpcHex(UpcHex::from_bytes_internal(key_bytes)?)),
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::C32) => {
            Ok(ObAny::AdgsC32(AdgsC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::B32) => {
            Ok(ObAny::AdgsB32(AdgsB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::B64) => {
            Ok(ObAny::AdgsB64(AdgsB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adgs")]
        (Scheme::Adgs, Encoding::Hex) => {
            Ok(ObAny::AdgsHex(AdgsHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::C32) => {
            Ok(ObAny::ApgsC32(ApgsC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B32) => {
            Ok(ObAny::ApgsB32(ApgsB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B64) => {
            Ok(ObAny::ApgsB64(ApgsB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Hex) => {
            Ok(ObAny::ApgsHex(ApgsHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::C32) => {
            Ok(ObAny::AdsvC32(AdsvC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::B32) => {
            Ok(ObAny::AdsvB32(AdsvB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::B64) => {
            Ok(ObAny::AdsvB64(AdsvB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "adsv")]
        (Scheme::Adsv, Encoding::Hex) => {
            Ok(ObAny::AdsvHex(AdsvHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::C32) => {
            Ok(ObAny::ApsvC32(ApsvC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::B32) => {
            Ok(ObAny::ApsvB32(ApsvB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::B64) => {
            Ok(ObAny::ApsvB64(ApsvB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Hex) => {
            Ok(ObAny::ApsvHex(ApsvHex::from_bytes_internal(key_bytes)?))
        }
        // Testing
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::C32) => {
            Ok(ObAny::Mock1C32(Mock1C32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::B32) => {
            Ok(ObAny::Mock1B32(Mock1B32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::B64) => {
            Ok(ObAny::Mock1B64(Mock1B64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::Hex) => {
            Ok(ObAny::Mock1Hex(Mock1Hex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::C32) => {
            Ok(ObAny::Mock2C32(Mock2C32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::B32) => {
            Ok(ObAny::Mock2B32(Mock2B32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::B64) => {
            Ok(ObAny::Mock2B64(Mock2B64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::Hex) => {
            Ok(ObAny::Mock2Hex(Mock2Hex::from_bytes_internal(key_bytes)?))
        }
        // Legacy
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, Encoding::C32) => {
            Ok(ObAny::LegacyC32(LegacyC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, Encoding::B32) => {
            Ok(ObAny::LegacyB32(LegacyB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, Encoding::B64) => {
            Ok(ObAny::LegacyB64(LegacyB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, Encoding::Hex) => {
            Ok(ObAny::LegacyHex(LegacyHex::from_bytes_internal(key_bytes)?))
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
            #[cfg(feature = "mock")]
            Scheme::Mock1,
            #[cfg(feature = "mock")]
            Scheme::Mock2,
            // Legacy
            #[cfg(feature = "legacy")]
            Scheme::Legacy,
        ];

        // Define all encodings
        let encodings = vec![Encoding::C32, Encoding::B32, Encoding::B64, Encoding::Hex];

        for scheme in &schemes {
            for encoding in &encodings {
                let format = Format::new(*scheme, *encoding);
                let result = new_with_format(format, &key);

                assert!(
                    result.is_ok(),
                    "Failed to create ObtextCodec implementation for {:?}:{:?}",
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
            Scheme::Mock2,
            Scheme::Mock1,
            #[cfg(feature = "legacy")]
            Scheme::Legacy,
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
        let encodings = vec![Encoding::C32, Encoding::B32, Encoding::B64, Encoding::Hex];

        for scheme in schemes {
            for encoding in &encodings {
                let format_str = format!("{}.{}", scheme.as_str(), encoding.as_str());
                let result = new(format_str.as_str(), &key);

                assert!(
                    result.is_ok(),
                    "Failed to create ObtextCodec implementation from format string: {}",
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
            Scheme::Mock2,
            Scheme::Mock1,
            #[cfg(feature = "zdc")]
            Scheme::Zdc,
            #[cfg(feature = "adgs")]
            Scheme::Adgs,
            #[cfg(feature = "adsv")]
            Scheme::Adsv,
        ];

        // Define all encodings
        let encodings = vec![Encoding::C32, Encoding::B32, Encoding::B64, Encoding::Hex];

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
