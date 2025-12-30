//! Zrbcx codec implementations (z-tier, obfuscation-only)

#![cfg(feature = "ztier")]
#![cfg(feature = "zrbcx")]

use super::zkeychain::ZKeychain;
use crate::{
    constants::HARDCODED_SECRET_BYTES, error::Error, Encoding, ExtractedKey, Format, ObtextCodec,
    Scheme,
};

/// Macro to implement z-tier codec types (32-byte secrets, obfuscation-only)
macro_rules! impl_zcodec {
    ($name:ident, $encoding:expr, $format_str:expr) => {
        #[doc = concat! ("**INSECURE OBFUSCATION-ONLY** Codec for ", $format_str, ".\n\n")]
        #[doc = "⚠️ This scheme provides no cryptographic security.\n"]
        #[doc = "Use only for obfuscation, never for actual encryption.\n\n"]
        #[doc = concat!("Format:  `\"", $format_str, "\"`")]
        #[allow(non_camel_case_types)]
        pub struct $name {
            zkeychain: ZKeychain,
        }

        impl $name {
            /// Create with hardcoded secret (testing/obfuscation only)
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Ok(Self {
                    zkeychain: ZKeychain::from_bytes(&HARDCODED_SECRET_BYTES)?,
                })
            }

            /// Internal constructor from 64-byte key (uses first 32 bytes as secret)
            #[cfg(any(feature = "keyless", feature = "bytes-keys"))]
            pub(crate) fn from_bytes_internal(key_bytes: &[u8; 64]) -> Result<Self, Error> {
                let secret:  [u8; 32] = key_bytes[0..32].try_into().unwrap();
                Ok(Self {
                    zkeychain: ZKeychain::from_bytes(&secret)?,
                })
            }
        }

        impl ObtextCodec for $name {
            fn enc(&self, plaintext: &str) -> Result<String, Error> {
                let format = Format::new(Scheme::Zrbcx, $encoding);
                let secret = self.zkeychain.zrbcx();
                crate::enc::enc_to_format(plaintext, format, ExtractedKey::Key32(secret))
            }

            fn dec(&self, obtext: &str) -> Result<String, Error> {
                let format = Format::new(Scheme::Zrbcx, $encoding);
                let secret = self.zkeychain.zrbcx();
                crate::dec::dec_from_format(obtext, format, ExtractedKey::Key32(secret))
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
                use data_encoding::BASE64URL_NOPAD;
                // For z-tier, return the 32-byte secret padded to 64 bytes
                let mut key = [0u8; 64];
                key[0..32]. copy_from_slice(self. zkeychain.secret_bytes());
                BASE64URL_NOPAD.encode(&key)
            }

            #[cfg(feature = "hex-keys")]
            fn key_hex(&self) -> String {
                // For z-tier, return the 32-byte secret padded to 64 bytes
                let mut key = [0u8; 64];
                key[0..32].copy_from_slice(self.zkeychain. secret_bytes());
                hex::encode(&key)
            }

            #[cfg(feature = "bytes-keys")]
            fn key_bytes(&self) -> &[u8; 64] {
                panic!("Z-tier schemes use 32-byte secrets, not 64-byte keys.  Use secret_bytes() instead.")
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

            /// Get the secret as base64 (for z-tier compatibility)
            #[inline]
            pub fn secret(&self) -> String {
                use data_encoding::BASE64URL_NOPAD;
                BASE64URL_NOPAD.encode(self.zkeychain.secret_bytes())
            }

            #[cfg(feature = "bytes-keys")]
            #[inline]
            pub fn secret_bytes(&self) -> &[u8; 32] {
                self.zkeychain.secret_bytes()
            }
        }
    };
}

// Generate all zrbcx variants
impl_zcodec!(ZrbcxC32, Encoding::C32, "zrbcx.c32");
impl_zcodec!(ZrbcxB32, Encoding::B32, "zrbcx.b32");
impl_zcodec!(ZrbcxB64, Encoding::B64, "zrbcx.b64");
impl_zcodec!(ZrbcxHex, Encoding::Hex, "zrbcx.hex");
