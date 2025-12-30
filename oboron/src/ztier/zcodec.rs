//! Zrbcx codec implementations (z-tier, obfuscation-only)

#![cfg(feature = "zrbcx")]

use crate::{
    constants::HARDCODED_SECRET_BYTES, error::Error, Encoding, Format, Keychain, ObtextCodec,
    Scheme,
};

/// Macro to implement z-tier codec types (uses first 32 bytes of 64-byte key as secret)
macro_rules! impl_zcodec {
    ($name:ident, $encoding:expr, $format_str:expr) => {
        #[doc = concat!("**INSECURE OBFUSCATION-ONLY** Codec for ", $format_str, ".\n\n")]
        #[doc = "⚠️ This scheme provides no cryptographic security.\n"]
        #[doc = "Use only for obfuscation, never for actual encryption.\n\n"]
        #[doc = concat!("Format: `\"", $format_str, "\"`")]
        #[allow(non_camel_case_types)]
        pub struct $name {
            keychain: Keychain,
        }

        impl $name {
            /// Create with hardcoded secret (testing/obfuscation only)
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                // Create a 64-byte key with secret in first 32 bytes, zeros in last 32
                let mut key_bytes = [0u8; 64];
                key_bytes[0..32].copy_from_slice(&HARDCODED_SECRET_BYTES);
                Ok(Self {
                    keychain: Keychain::from_bytes(&key_bytes)?,
                })
            }

            /// Internal constructor from 64-byte key (uses first 32 bytes as secret)
            #[cfg(any(feature = "keyless", feature = "bytes-keys"))]
            pub(crate) fn from_bytes_internal(key_bytes: &[u8; 64]) -> Result<Self, Error> {
                Ok(Self {
                    keychain: Keychain::from_bytes(key_bytes)?,
                })
            }
        }

        impl ObtextCodec for $name {
            fn enc(&self, plaintext: &str) -> Result<String, Error> {
                let format = Format::new(Scheme::Zrbcx, $encoding);
                crate::enc::enc_to_format(plaintext, format, &self.keychain)
            }

            fn dec(&self, obtext: &str) -> Result<String, Error> {
                let format = Format::new(Scheme::Zrbcx, $encoding);
                crate::dec::dec_from_format(obtext, format, &self.keychain)
            }

            fn format(&self) -> Format {
                Format::new(Scheme::Zrbcx, $encoding)
            }

            fn scheme(&self) -> Scheme {
                Scheme::Zrbcx
            }

            fn encoding(&self) -> Encoding {
                $encoding
            }

            fn key(&self) -> String {
                self.keychain.key_base64()
            }

            #[cfg(feature = "hex-keys")]
            fn key_hex(&self) -> String {
                self.keychain.key_hex()
            }

            #[cfg(feature = "bytes-keys")]
            fn key_bytes(&self) -> &[u8; 64] {
                self.keychain.key_bytes()
            }
        }

        // Inherent methods
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

// Generate all zrbcx variants
impl_zcodec!(ZrbcxC32, Encoding::C32, "zrbcx.c32");
impl_zcodec!(ZrbcxB32, Encoding::B32, "zrbcx.b32");
impl_zcodec!(ZrbcxB64, Encoding::B64, "zrbcx.b64");
impl_zcodec!(ZrbcxHex, Encoding::Hex, "zrbcx.hex");
