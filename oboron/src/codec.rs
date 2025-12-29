//! Trait-based interface for scheme-specific ObtextCodec implementations.
#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{error::Error, Encoding, Format, Keychain, Scheme};

/// Core trait for ObtextCodec encryption+encoding/decoding+decryption implementations.
///
/// Each scheme+encoding combination (ZrbcxC32, ZrbcxB64, etc.) implements this trait
/// to provide a consistent interface for encoding and decoding operations.
///
/// Note: Construction methods (`new`, `from_bytes`, `new_keyless`) are not part of
/// this trait.     Each type provides its own constructor with an appropriate signature.
pub trait ObtextCodec {
    /// Encode a plaintext string.
    fn enc(&self, plaintext: &str) -> Result<String, Error>;

    /// Decode an encoded string back to plaintext
    fn dec(&self, obtext: &str) -> Result<String, Error>;

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
macro_rules! impl_codec {
    (
        $name:ident,           // Type name (e.g., ZrbcxC32)
        $scheme:expr,          // Scheme constant (e.g., Scheme::Zrbcx)
        $encoding:expr,        // Encoding constant (e.g., Encoding::C32)
        $format_str:expr       // Format string for docs (e.g., "zrbcx.c32")
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

        // Add inherent methods that delegate to trait methods
        impl $name {
            /// Encrypt and encode plaintext
            #[inline]
            pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::enc(self, plaintext)
            }

            /// Decode and decrypt obtext (no scheme autodetection)
            #[inline]
            pub fn dec(&self, obtext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::dec(self, obtext)
            }

            /// Get the format
            #[inline]
            pub fn format(&self) -> Format {
                <Self as ObtextCodec>::format(self)
            }

            /// Get the scheme
            #[inline]
            pub fn scheme(&self) -> Scheme {
                <Self as ObtextCodec>::scheme(self)
            }

            /// Get the encoding
            #[inline]
            pub fn encoding(&self) -> Encoding {
                <Self as ObtextCodec>::encoding(self)
            }

            /// Get the key as base64
            #[inline]
            pub fn key(&self) -> String {
                <Self as ObtextCodec>::key(self)
            }

            #[cfg(feature = "hex-keys")]
            #[inline]
            pub fn key_hex(&self) -> String {
                <Self as ObtextCodec>::key_hex(self)
            }

            #[cfg(feature = "bytes-keys")]
            #[inline]
            pub fn key_bytes(&self) -> &[u8; 64] {
                <Self as ObtextCodec>::key_bytes(self)
            }
        }
    };
}

/// Macro for z-tier (insecure obfuscation-only) schemes.
///
/// These schemes use a hardcoded key and provide no real security.
/// Only :: new_keyless() constructor is available - no custom keys allowed.
#[cfg(feature = "zrbcx")]
macro_rules! impl_ztier_codec {
    (
        $name: ident,           // Type name (e.g., ZrbcxC32)
        $scheme:expr,          // Scheme constant (e.g., Scheme::Zrbcx)
        $encoding:expr,        // Encoding constant (e.g., Encoding::C32)
        $format_str:expr       // Format string for docs (e.g., "zrbcx.c32")
    ) => {
        #[doc = concat! ("**INSECURE OBFUSCATION-ONLY** ObtextCodec for ", $format_str, ".\n\n")]
        #[doc = "⚠️ This scheme uses a hardcoded key and provides no security.\n"]
        #[doc = "Use only for obfuscation, never for actual encryption.\n\n"]
        #[doc = concat!("Corresponds to format string: `\"", $format_str, "\"`")]
        #[allow(non_camel_case_types)]
        pub struct $name {
            keychain: Keychain,
        }

        impl $name {
            /// Create a new instance with hardcoded key (obfuscation only).
            ///
            /// **WARNING**: This uses a publicly available hardcoded key and provides no security.
            #[inline]
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
                })
            }

            /// Internal constructor used by factory functions.
            #[inline]
            #[cfg(any(feature = "keyless", feature = "bytes-keys"))]
            fn from_bytes_internal(key_bytes: &[u8; 64]) -> Result<Self, Error> {
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

        // Add inherent methods that delegate to trait methods
        impl $name {
            #[inline]
            pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::enc(self, plaintext)
            }

            #[inline]
            pub fn dec(&self, obtext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::dec(self, obtext)
            }

            #[inline]
            pub fn format(&self) -> Format {
                <Self as ObtextCodec>::format(self)
            }

            #[inline]
            pub fn scheme(&self) -> Scheme {
                <Self as ObtextCodec>::scheme(self)
            }

            #[inline]
            pub fn encoding(&self) -> Encoding {
                <Self as ObtextCodec>::encoding(self)
            }

            #[inline]
            pub fn key(&self) -> String {
                <Self as ObtextCodec>::key(self)
            }

            #[cfg(feature = "hex-keys")]
            #[inline]
            pub fn key_hex(&self) -> String {
                <Self as ObtextCodec>::key_hex(self)
            }

            #[cfg(feature = "bytes-keys")]
            #[inline]
            pub fn key_bytes(&self) -> &[u8; 64] {
                <Self as ObtextCodec>::key_bytes(self)
            }
        }
    };
}

// Generate all scheme+encoding combinations using the optimized macro

// aags variants
#[cfg(feature = "aags")]
impl_codec!(AagsB32, Scheme::Aags, Encoding::B32, "aags.b32");
#[cfg(feature = "aags")]
impl_codec!(AagsC32, Scheme::Aags, Encoding::C32, "aags.c32");
#[cfg(feature = "aags")]
impl_codec!(AagsB64, Scheme::Aags, Encoding::B64, "aags.b64");
#[cfg(feature = "aags")]
impl_codec!(AagsHex, Scheme::Aags, Encoding::Hex, "aags.hex");

// aasv variants
#[cfg(feature = "aasv")]
impl_codec!(AasvB32, Scheme::Aasv, Encoding::B32, "aasv.b32");
#[cfg(feature = "aasv")]
impl_codec!(AasvC32, Scheme::Aasv, Encoding::C32, "aasv.c32");
#[cfg(feature = "aasv")]
impl_codec!(AasvB64, Scheme::Aasv, Encoding::B64, "aasv.b64");
#[cfg(feature = "aasv")]
impl_codec!(AasvHex, Scheme::Aasv, Encoding::Hex, "aasv.hex");

// apgs variants
#[cfg(feature = "apgs")]
impl_codec!(ApgsB32, Scheme::Apgs, Encoding::B32, "apgs.b32");
#[cfg(feature = "apgs")]
impl_codec!(ApgsC32, Scheme::Apgs, Encoding::C32, "apgs.c32");
#[cfg(feature = "apgs")]
impl_codec!(ApgsB64, Scheme::Apgs, Encoding::B64, "apgs.b64");
#[cfg(feature = "apgs")]
impl_codec!(ApgsHex, Scheme::Apgs, Encoding::Hex, "apgs.hex");

// apsv variants
#[cfg(feature = "apsv")]
impl_codec!(ApsvB32, Scheme::Apsv, Encoding::B32, "apsv.b32");
#[cfg(feature = "apsv")]
impl_codec!(ApsvC32, Scheme::Apsv, Encoding::C32, "apsv.c32");
#[cfg(feature = "apsv")]
impl_codec!(ApsvB64, Scheme::Apsv, Encoding::B64, "apsv.b64");
#[cfg(feature = "apsv")]
impl_codec!(ApsvHex, Scheme::Apsv, Encoding::Hex, "apsv.hex");

// upbc variants
#[cfg(feature = "upbc")]
impl_codec!(UpbcB32, Scheme::Upbc, Encoding::B32, "upbc.b32");
#[cfg(feature = "upbc")]
impl_codec!(UpbcC32, Scheme::Upbc, Encoding::C32, "upbc.c32");
#[cfg(feature = "upbc")]
impl_codec!(UpbcB64, Scheme::Upbc, Encoding::B64, "upbc.b64");
#[cfg(feature = "upbc")]
impl_codec!(UpbcHex, Scheme::Upbc, Encoding::Hex, "upbc.hex");

// zrbcx variants
#[cfg(feature = "zrbcx")]
impl_ztier_codec!(ZrbcxB32, Scheme::Zrbcx, Encoding::B32, "zrbcx.b32");
#[cfg(feature = "zrbcx")]
impl_ztier_codec!(ZrbcxC32, Scheme::Zrbcx, Encoding::C32, "zrbcx.c32");
#[cfg(feature = "zrbcx")]
impl_ztier_codec!(ZrbcxB64, Scheme::Zrbcx, Encoding::B64, "zrbcx.b64");
#[cfg(feature = "zrbcx")]
impl_ztier_codec!(ZrbcxHex, Scheme::Zrbcx, Encoding::Hex, "zrbcx.hex");

// Testing

// mock1 (identity scheme)
#[cfg(feature = "mock")]
impl_codec!(Mock1B32, Scheme::Mock1, Encoding::B32, "mock1.b32");
#[cfg(feature = "mock")]
impl_codec!(Mock1C32, Scheme::Mock1, Encoding::C32, "mock1.c32");
#[cfg(feature = "mock")]
impl_codec!(Mock1B64, Scheme::Mock1, Encoding::B64, "mock1.b64");
#[cfg(feature = "mock")]
impl_codec!(Mock1Hex, Scheme::Mock1, Encoding::Hex, "mock1.hex");

// mock2 (reverse scheme)
#[cfg(feature = "mock")]
impl_codec!(Mock2B32, Scheme::Mock2, Encoding::B32, "mock2.b32");
#[cfg(feature = "mock")]
impl_codec!(Mock2C32, Scheme::Mock2, Encoding::C32, "mock2.c32");
#[cfg(feature = "mock")]
impl_codec!(Mock2B64, Scheme::Mock2, Encoding::B64, "mock2.b64");
#[cfg(feature = "mock")]
impl_codec!(Mock2Hex, Scheme::Mock2, Encoding::Hex, "mock2.hex");

/// Type-erased ObtextCodec encoder that can hold any scheme+encoding combination.
///
/// This enum allows for runtime scheme selection without heap allocation.
/// It's returned by the `oboron::new()` factory function.
#[allow(non_camel_case_types)]
pub enum ObAny {
    #[cfg(feature = "zrbcx")]
    ZrbcxC32(ZrbcxC32),
    #[cfg(feature = "zrbcx")]
    ZrbcxB32(ZrbcxB32),
    #[cfg(feature = "zrbcx")]
    ZrbcxB64(ZrbcxB64),
    #[cfg(feature = "zrbcx")]
    ZrbcxHex(ZrbcxHex),
    #[cfg(feature = "upbc")]
    UpbcC32(UpbcC32),
    #[cfg(feature = "upbc")]
    UpbcB32(UpbcB32),
    #[cfg(feature = "upbc")]
    UpbcB64(UpbcB64),
    #[cfg(feature = "upbc")]
    UpbcHex(UpbcHex),
    #[cfg(feature = "aags")]
    AagsC32(AagsC32),
    #[cfg(feature = "aags")]
    AagsB32(AagsB32),
    #[cfg(feature = "aags")]
    AagsB64(AagsB64),
    #[cfg(feature = "aags")]
    AagsHex(AagsHex),
    #[cfg(feature = "apgs")]
    ApgsC32(ApgsC32),
    #[cfg(feature = "apgs")]
    ApgsB32(ApgsB32),
    #[cfg(feature = "apgs")]
    ApgsB64(ApgsB64),
    #[cfg(feature = "apgs")]
    ApgsHex(ApgsHex),
    #[cfg(feature = "aasv")]
    AasvC32(AasvC32),
    #[cfg(feature = "aasv")]
    AasvB32(AasvB32),
    #[cfg(feature = "aasv")]
    AasvB64(AasvB64),
    #[cfg(feature = "aasv")]
    AasvHex(AasvHex),
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
                #[cfg(feature = "zrbcx")]
                ObAny::ZrbcxC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "zrbcx")]
                ObAny::ZrbcxB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "zrbcx")]
                ObAny::ZrbcxB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "zrbcx")]
                ObAny::ZrbcxHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upbc")]
                ObAny::UpbcC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upbc")]
                ObAny::UpbcB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upbc")]
                ObAny::UpbcB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upbc")]
                ObAny::UpbcHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aags")]
                ObAny::AagsC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aags")]
                ObAny::AagsB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aags")]
                ObAny::AagsB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aags")]
                ObAny::AagsHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aasv")]
                ObAny::AasvC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aasv")]
                ObAny::AasvB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aasv")]
                ObAny::AasvB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aasv")]
                ObAny::AasvHex(ob) => ob.$method($($arg),*),
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
        #[cfg(feature = "zrbcx")]
        #[cfg(not(feature = "mock"))]
        return Ok(ObAny::ZrbcxC32(ZrbcxC32::new(key)?));
        #[cfg(feature = "upbc")]
        #[cfg(not(any(feature = "mock", feature = "zrbcx")))]
        return Ok(ObAny::UpbcC32(UpbcC32::new(key)?));
        #[cfg(feature = "aags")]
        #[cfg(not(any(feature = "mock", feature = "zrbcx", feature = "upbc")))]
        return Ok(ObAny::AagsC32(AagsC32::new(key)?));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags"
        )))]
        return Ok(ObAny::ApgsC32(ApgsC32::new(key)?));
        #[cfg(feature = "aasv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs"
        )))]
        return Ok(ObAny::AasvC32(AasvC32::new(key)?));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32::new(key)?));
        #[cfg(feature = "legacy")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
            feature = "apsv"
        )))]
        return Ok(ObAny::LegacyC32(LegacyC32::new(key)?));
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
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
        #[cfg(feature = "zrbcx")]
        #[cfg(not(feature = "mock"))]
        return Ok(ObAny::ZrbcxC32(ZrbcxC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "upbc")]
        #[cfg(not(any(feature = "mock", feature = "zrbcx")))]
        return Ok(ObAny::UpbcC32(UpbcC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "aags")]
        #[cfg(not(any(feature = "mock", feature = "zrbcx", feature = "upbc")))]
        return Ok(ObAny::AagsC32(AagsC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags"
        )))]
        return Ok(ObAny::ApgsC32(ApgsC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "aasv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs"
        )))]
        return Ok(ObAny::AasvC32(AasvC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "legacy")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
            feature = "apsv"
        )))]
        return Ok(ObAny::LegacyC32(LegacyC32 {
            keychain: Keychain::from_bytes(key_bytes)?,
        }));
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
            feature = "apsv",
            feature = "legacy"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    #[cfg(feature = "hex-keys")]
    pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
        #[cfg(feature = "mock")]
        return Ok(ObAny::Mock1C32(Mock1C32::from_hex_key(key_hex)?));
        #[cfg(feature = "zrbcx")]
        #[cfg(not(feature = "mock"))]
        return Ok(ObAny::ZrbcxC32(ZrbcxC32::from_hex_key(key_hex)?));
        #[cfg(feature = "upbc")]
        #[cfg(not(any(feature = "mock", feature = "zrbcx")))]
        return Ok(ObAny::UpbcC32(UpbcC32::from_hex_key(key_hex)?));
        #[cfg(feature = "aags")]
        #[cfg(not(any(feature = "mock", feature = "zrbcx", feature = "upbc")))]
        return Ok(ObAny::AagsC32(AagsC32::from_hex_key(key_hex)?));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags"
        )))]
        return Ok(ObAny::ApgsC32(ApgsC32::from_hex_key(key_hex)?));
        #[cfg(feature = "aasv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs"
        )))]
        return Ok(ObAny::AasvC32(AasvC32::from_hex_key(key_hex)?));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32::from_hex_key(key_hex)?));
        #[cfg(feature = "legacy")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
            feature = "apsv"
        )))]
        return Ok(ObAny::LegacyC32(LegacyC32::from_hex_key(key_hex)?));
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
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
        #[cfg(feature = "zrbcx")]
        #[cfg(not(feature = "mock"))]
        return Ok(ObAny::ZrbcxC32(ZrbcxC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "upbc")]
        #[cfg(not(any(feature = "mock", feature = "zrbcx")))]
        return Ok(ObAny::UpbcC32(UpbcC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "aags")]
        #[cfg(not(any(feature = "mock", feature = "zrbcx", feature = "upbc")))]
        return Ok(ObAny::AagsC32(AagsC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags"
        )))]
        return Ok(ObAny::ApgsC32(ApgsC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "aasv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs"
        )))]
        return Ok(ObAny::AasvC32(AasvC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "legacy")]
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
            feature = "apsv"
        )))]
        return Ok(ObAny::LegacyC32(LegacyC32 {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(not(any(
            feature = "mock",
            feature = "zrbcx",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
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
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, Encoding::C32) => Ok(ObAny::ZrbcxC32(ZrbcxC32::new_keyless()?)),
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, Encoding::B32) => Ok(ObAny::ZrbcxB32(ZrbcxB32::new_keyless()?)),
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, Encoding::B64) => Ok(ObAny::ZrbcxB64(ZrbcxB64::new_keyless()?)),
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, Encoding::Hex) => Ok(ObAny::ZrbcxHex(ZrbcxHex::new_keyless()?)),
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::C32) => Ok(ObAny::UpbcC32(UpbcC32::new(key)?)),
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::B32) => Ok(ObAny::UpbcB32(UpbcB32::new(key)?)),
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::B64) => Ok(ObAny::UpbcB64(UpbcB64::new(key)?)),
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::Hex) => Ok(ObAny::UpbcHex(UpbcHex::new(key)?)),
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::C32) => Ok(ObAny::AagsC32(AagsC32::new(key)?)),
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::B32) => Ok(ObAny::AagsB32(AagsB32::new(key)?)),
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::B64) => Ok(ObAny::AagsB64(AagsB64::new(key)?)),
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::Hex) => Ok(ObAny::AagsHex(AagsHex::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::C32) => Ok(ObAny::ApgsC32(ApgsC32::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B32) => Ok(ObAny::ApgsB32(ApgsB32::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B64) => Ok(ObAny::ApgsB64(ApgsB64::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Hex) => Ok(ObAny::ApgsHex(ApgsHex::new(key)?)),
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::C32) => Ok(ObAny::AasvC32(AasvC32::new(key)?)),
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::B32) => Ok(ObAny::AasvB32(AasvB32::new(key)?)),
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::B64) => Ok(ObAny::AasvB64(AasvB64::new(key)?)),
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::Hex) => Ok(ObAny::AasvHex(AasvHex::new(key)?)),
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
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, Encoding::C32) => {
            Ok(ObAny::ZrbcxC32(ZrbcxC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, Encoding::B32) => {
            Ok(ObAny::ZrbcxB32(ZrbcxB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, Encoding::B64) => {
            Ok(ObAny::ZrbcxB64(ZrbcxB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, Encoding::Hex) => {
            Ok(ObAny::ZrbcxHex(ZrbcxHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::C32) => {
            Ok(ObAny::UpbcC32(UpbcC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::B32) => {
            Ok(ObAny::UpbcB32(UpbcB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::B64) => {
            Ok(ObAny::UpbcB64(UpbcB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::Hex) => {
            Ok(ObAny::UpbcHex(UpbcHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::C32) => {
            Ok(ObAny::AagsC32(AagsC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::B32) => {
            Ok(ObAny::AagsB32(AagsB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::B64) => {
            Ok(ObAny::AagsB64(AagsB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::Hex) => {
            Ok(ObAny::AagsHex(AagsHex::from_bytes_internal(key_bytes)?))
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
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::C32) => {
            Ok(ObAny::AasvC32(AasvC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::B32) => {
            Ok(ObAny::AasvB32(AasvB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::B64) => {
            Ok(ObAny::AasvB64(AasvB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::Hex) => {
            Ok(ObAny::AasvHex(AasvHex::from_bytes_internal(key_bytes)?))
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
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx,
            #[cfg(feature = "upbc")]
            Scheme::Upbc,
            #[cfg(feature = "aags")]
            Scheme::Aags,
            #[cfg(feature = "apgs")]
            Scheme::Apgs,
            #[cfg(feature = "aasv")]
            Scheme::Aasv,
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
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx,
            #[cfg(feature = "upbc")]
            Scheme::Upbc,
            #[cfg(feature = "aags")]
            Scheme::Aags,
            #[cfg(feature = "apgs")]
            Scheme::Apgs,
            #[cfg(feature = "aasv")]
            Scheme::Aasv,
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
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx,
            #[cfg(feature = "aags")]
            Scheme::Aags,
            #[cfg(feature = "aasv")]
            Scheme::Aasv,
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
                let pt2 = ob.dec(&ot).unwrap();

                assert_eq!(
                    pt2, plaintext,
                    "Roundtrip failed for {:?}:{:?}",
                    scheme, encoding
                );
            }
        }
    }
}
