//! Legacy AES-CBC scheme (ob00)
//!
//! **Deprecated**: This scheme exists only for compatibility with
//! existing deployments. New code should use `ob01` instead.
//!
//! Differences from `ob01`:
//! - Reverses obtext characters rather than payload bytes
//! - Uses different padding scheme
//! - Less optimal prefix entropy distribution
//!
//! This module contains fully the isolated implementation of the
//! deprecated `ob00` scheme.
//! This is maintained for backward compatibility but should not be used
//! for new code.
//!
//! **Architecture**: This module is intentionally self-contained, duplicating some
//! encoding/decoding logic to keep legacy code isolated from the main codebase.

#![cfg(feature = "ob00")]

use crate::{
    base32::BASE32_CROCKFORD,
    constants::HARDCODED_KEY_BYTES,
    error::Error,
    obcrypt::{decrypt_ob00, encrypt_ob00},
    oboron::Oboron,
    Encoding, Format, Keychain, Scheme,
};
use data_encoding::{BASE32, BASE64URL_NOPAD, HEXLOWER};

// ============================================================================
// Internal Helper Functions (ob00-specific encoding/decoding)
// ============================================================================

/// Encode raw ciphertext bytes to oboron ob00 string format.
fn encode_ciphertext_to_obtext(encoding: Encoding, ciphertext: &[u8]) -> String {
    let enc = match encoding {
        Encoding::Base32Crockford => {
            let encoded = BASE32_CROCKFORD.encode(ciphertext);
            // Trim Base32Rfc padding and lowercase
            let end = encoded.trim_end_matches('=').len();
            encoded[..end].to_string() // already lowercase
        }
        Encoding::Base32Rfc => {
            let encoded = BASE32.encode(ciphertext);
            // Trim Base32Rfc padding and lowercase
            let end = encoded.trim_end_matches('=').len();
            encoded[..end].to_ascii_lowercase()
        }
        Encoding::Base64 => {
            let encoded = BASE64URL_NOPAD.encode(ciphertext);
            // Trim Base64 padding
            let end = encoded.trim_end_matches('=').len();
            encoded[..end].to_string()
        }
        Encoding::Hex => HEXLOWER.encode(ciphertext),
    };

    // Step 3: Reverse (byte-based for performance)
    let mut result = enc.into_bytes();
    result.reverse();
    // SAFETY: Plaintext was originally valid UTF-8, and encryption preserves byte sequences
    unsafe { String::from_utf8_unchecked(result) }
}

/// Decode oboron ob00 string to raw ciphertext bytes.
fn decode_obtext_to_ciphertext(encoding: Encoding, obtext: &str) -> Result<Vec<u8>, Error> {
    match encoding {
        Encoding::Base32Crockford => {
            // Reverse the string first
            let reversed: Vec<u8> = obtext.as_bytes().iter().rev().copied().collect();
            BASE32_CROCKFORD
                .decode(&reversed)
                .map_err(|_| Error::InvalidBase32Crockford)
        }
        Encoding::Base32Rfc => {
            // Special handling for Base32Rfc: need to add padding
            let enc_len = obtext.len();
            let padding = (8 - (enc_len % 8)) % 8;

            // Reverse and uppercase (byte-based for performance)
            let mut buffer = Vec::with_capacity(enc_len + padding);
            for &b in obtext.as_bytes().iter().rev() {
                buffer.push(b.to_ascii_uppercase());
            }

            // Add Base32Rfc padding
            buffer.resize(enc_len + padding, b'=');

            // Base32Rfc decode
            BASE32.decode(&buffer).map_err(|_| Error::InvalidBase32Rfc)
        }
        Encoding::Base64 => {
            // Reverse the string first
            let reversed: Vec<u8> = obtext.as_bytes().iter().rev().copied().collect();
            BASE64URL_NOPAD
                .decode(&reversed)
                .map_err(|_| Error::InvalidBase64)
        }
        Encoding::Hex => {
            // Reverse the hex string first
            let reversed: String = obtext.chars().rev().collect();
            HEXLOWER
                .decode(reversed.as_bytes())
                .map_err(|_| Error::InvalidHex)
        }
    }
}

/// Decode ob00 format to plaintext (used by autodetection in dec_auto.rs).
pub(crate) fn dec_ob00(obtext: &str, format: Format, keychain: &Keychain) -> Result<String, Error> {
    assert_eq!(format.scheme(), Scheme::Ob00);
    let ciphertext = decode_obtext_to_ciphertext(format.encoding(), obtext)?;
    // SAFETY: Plaintext was originally valid UTF-8, and encryption preserves byte sequences
    Ok(unsafe { String::from_utf8_unchecked(decrypt_ob00(keychain, &ciphertext)?) })
}

// ============================================================================
// Public Oboron Implementations (Ob00Base32Crockford, Ob00Base32Rfc, Ob00Base64, Ob00Hex)
// ============================================================================

/// Macro to implement ob00 Oboron variants with different encodings.
macro_rules! impl_ob00_oboron {
    ($name:ident, $encoding:expr, $format_str:expr) => {
        #[doc = concat!("Legacy Ob00 Oboron implementation for ", $format_str, " format.\n\n")]
        #[doc = "**LEGACY**: This scheme is maintained for backward compatibility only.\n"]
        #[doc = "The ob00 scheme uses legacy AES-CBC encryption with custom padding.\n"]
        #[doc = "For new projects, consider using ob01 or more secure schemes like ob31/ob32.\n"]
        #[doc = concat!("\nCorresponds to format string: `\"", $format_str, "\"`")]
        #[allow(non_camel_case_types)]
        pub struct $name {
            keychain: Keychain,
            format: Format,
        }

        impl Oboron for $name {
            fn enc(&self, plaintext: &str) -> Result<String, Error> {
                let ciphertext = encrypt_ob00(&self.keychain, plaintext.as_bytes())?;
                Ok(encode_ciphertext_to_obtext(
                    self.format.encoding(),
                    &ciphertext,
                ))
            }

            fn dec(&self, obtext: &str) -> Result<String, Error> {
                // Use autodetection to handle any scheme format
                crate::dec_auto::dec_any_scheme(&self.keychain, self.format.encoding(), obtext)
            }

            fn dec_strict(&self, obtext: &str) -> Result<String, Error> {
                // Only decode ob00 format, no autodetection
                let ciphertext = decode_obtext_to_ciphertext(self.format.encoding(), obtext)?;
                Ok(unsafe {
                    // SAFETY: Plaintext was originally valid UTF-8, and encryption preserves byte sequences
                    String::from_utf8_unchecked(decrypt_ob00(&self.keychain, &ciphertext)?)
                })
            }

            fn format(&self) -> Format {
                self.format
            }

            fn scheme(&self) -> Scheme {
                self.format.scheme()
            }

            fn encoding(&self) -> Encoding {
                self.format.encoding()
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

        impl $name {
            /// Create a new instance from a base64-encoded key string.
            ///
            /// # Arguments
            ///
            /// * `key_b64` - A 86-character base64 string representing 64 bytes
            ///
            /// # Examples
            ///
            /// ```
            /// # use oboron::{Oboron, Ob00Base32Rfc};
            /// let key = oboron::generate_key();
            /// let ob = Ob00Base32Rfc::new(&key)? ;
            /// # Ok::<(), oboron::Error>(())
            /// ```
            pub fn new(key_b64: &str) -> Result<Self, Error> {
                let keychain = Keychain::from_base64(key_b64)?;
                Ok(Self {
                    keychain,
                    format: Format::new(Scheme::Ob00, $encoding),
                })
            }

            /// Create a new instance from a hex-encoded key string.
            ///
            /// # Arguments
            ///
            /// * `key_hex` - A 128-character hexadecimal string representing 64 bytes
            ///
            /// # Examples
            ///
            /// ```
            /// use oboron::{Oboron, Ob00Base32Rfc};
            ///
            /// let key_hex = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            /// let ob = Ob00Base32Rfc::from_hex_key(key_hex)? ;
            /// # Ok::<(), oboron::Error>(())
            /// ```
            #[cfg(feature = "hex-keys")]
            pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
                let keychain = Keychain::from_hex(key_hex)?;
                Ok(Self {
                    keychain,
                    format: Format::new(Scheme::Ob00, $encoding),
                })
            }

            /// Create a new instance from raw key bytes.
            ///
            /// # Arguments
            ///
            /// * `key` - A 64-byte array
            ///
            /// # Examples
            ///
            /// ```
            /// use oboron::{Oboron, Ob00Base32Rfc};
            ///
            /// let key = [0u8; 64];
            /// let ob = Ob00Base32Rfc::from_bytes(&key)?;
            /// # Ok::<(), oboron::Error>(())
            /// ```
            #[inline]
            #[cfg(feature = "bytes-keys")]
            pub fn from_bytes(key: &[u8; 64]) -> Result<Self, Error> {
                Self::from_bytes_internal(key)
            }

            pub(crate) fn from_bytes_internal(key: &[u8; 64]) -> Result<Self, Error> {
                let keychain = Keychain::from_bytes(key)?;
                Ok(Self {
                    keychain,
                    format: Format::new(Scheme::Ob00, $encoding),
                })
            }

            /// Create a new instance with hardcoded key (testing only).
            ///
            /// **WARNING**: This uses a publicly available hardcoded key and provides no security.
            /// Only use this for testing or when obfuscation (not encryption) is the goal.
            ///
            /// # Examples
            ///
            /// ```
            /// use oboron::{Oboron, Ob00Base32Rfc};
            ///
            /// let ob = Ob00Base32Rfc::new_keyless()?;
            /// let ot = ob.enc("test")?;
            /// # Ok::<(), oboron::Error>(())
            /// ```
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Self::from_bytes_internal(&HARDCODED_KEY_BYTES)
            }
        }
    };
}

// Generate all ob00 encoding variants
impl_ob00_oboron!(Ob00Base32Crockford, Encoding::Base32Crockford, "ob00:c32");
impl_ob00_oboron!(Ob00Base32Rfc, Encoding::Base32Rfc, "ob00:b32");
impl_ob00_oboron!(Ob00Base64, Encoding::Base64, "ob00:b64");
impl_ob00_oboron!(Ob00Hex, Encoding::Hex, "ob00:hex");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Oboron;

    #[test]
    #[cfg(feature = "keyless")]
    fn test_ob00_roundtrip() {
        let ob = Ob00Base32Rfc::new_keyless().unwrap();
        let pt = "hello world";
        let ot = ob.enc(pt).unwrap();
        let pt2 = ob.dec_strict(&ot).unwrap();
        assert_eq!(pt, pt2);
    }

    #[test]
    fn test_ob00_encoding_variants() {
        let pt = "test123";
        let key = [42u8; 64];

        let ob_c32 = Ob00Base32Crockford::from_bytes(&key).unwrap();
        let ob_b32 = Ob00Base32Rfc::from_bytes(&key).unwrap();
        let ob_b64 = Ob00Base64::from_bytes(&key).unwrap();
        let ob_hex = Ob00Hex::from_bytes(&key).unwrap();

        let ot_c32 = ob_c32.enc(pt).unwrap();
        let ot_b32 = ob_b32.enc(pt).unwrap();
        let ot_b64 = ob_b64.enc(pt).unwrap();
        let ot_hex = ob_hex.enc(pt).unwrap();

        // All should decode back to pt
        assert_eq!(ob_c32.dec_strict(&ot_c32).unwrap(), pt);
        assert_eq!(ob_b32.dec_strict(&ot_b32).unwrap(), pt);
        assert_eq!(ob_b64.dec_strict(&ot_b64).unwrap(), pt);
        assert_eq!(ob_hex.dec_strict(&ot_hex).unwrap(), pt);

        // Encodings should be different
        assert_ne!(ot_c32, ot_b64);
        assert_ne!(ot_c32, ot_hex);
        assert_ne!(ot_c32, ot_b32);
        assert_ne!(ot_b32, ot_b64);
        assert_ne!(ot_b32, ot_hex);
        assert_ne!(ot_b64, ot_hex);
    }

    #[test]
    #[cfg(feature = "keyless")]
    fn test_ob00_dec_with_autodetect() {
        let ob = Ob00Base32Rfc::new_keyless().unwrap();
        let pt = "autodetect test";
        let ot = ob.enc(pt).unwrap();

        // decode() should work (uses autodetection)
        let pt2 = ob.dec(&ot).unwrap();
        assert_eq!(pt, pt2);
    }
}
