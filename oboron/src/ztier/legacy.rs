#![cfg(feature = "legacy")]

use crate::constants::HARDCODED_SECRET_BYTES;
use crate::{error::Error, Encoding, Format, ObtextCodec, Scheme};

// Re-use ZKeychain from zcodec module
use super::constants::AES_BLOCK_SIZE;
use super::zkeychain::ZKeychain;

const LEGACY_PADDING_BYTE: u8 = b'=';

/// Legacy codec implementation
macro_rules! impl_legacy_codec {
    ($name: ident, $encoding:expr, $format_str:expr) => {
        #[doc = concat! ("**DEPRECATED** Legacy codec for ", $format_str, ".\n\n")]
        #[doc = "⚠️ This scheme exists for compatibility only.\n"]
        #[doc = "Use secure schemes for new code.\n\n"]
        #[doc = concat!("Format:  `\"", $format_str, "\"`")]
        #[allow(non_camel_case_types)]
        pub struct $name {
            zkeychain: ZKeychain,
        }

        impl $name {
            /// Create with a 43-character base64 secret string
            pub fn new(secret: &str) -> Result<Self, Error> {
                Ok(Self {
                    zkeychain: ZKeychain::from_base64(secret)?,
                })
            }

            /// Create with hardcoded secret (testing/obfuscation only)
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Ok(Self {
                    zkeychain: ZKeychain::from_bytes(&HARDCODED_SECRET_BYTES)?,
                })
            }

            /// Create from a 64-character hex secret string
            #[cfg(feature = "hex-keys")]
            pub fn from_hex_secret(secret_hex: &str) -> Result<Self, Error> {
                Ok(Self {
                    zkeychain: ZKeychain::from_hex(secret_hex)?,
                })
            }

            /// Create from a 32-byte secret
            #[cfg(feature = "bytes-keys")]
            pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
                Ok(Self {
                    zkeychain: ZKeychain::from_bytes(secret_bytes)?,
                })
            }

            pub fn secret(&self) -> String {
                self.zkeychain.secret_base64()
            }

            #[cfg(feature = "hex-keys")]
            pub fn secret_hex(&self) -> String {
                self.zkeychain.secret_hex()
            }

            #[cfg(feature = "bytes-keys")]
            pub fn secret_bytes(&self) -> &[u8; 32] {
                self.zkeychain.secret_bytes()
            }
        }

        impl ObtextCodec for $name {
            fn enc(&self, plaintext: &str) -> Result<String, Error> {
                let plaintext_bytes = plaintext.as_bytes();
                if plaintext_bytes.is_empty() {
                    return Err(Error::EmptyPlaintext);
                }

                // Encrypt using legacy AES-CBC
                let ciphertext = encrypt_legacy(self.zkeychain.secret_bytes(), plaintext_bytes)?;

                // Encode based on encoding type
                match $encoding {
                    Encoding::C32 => Ok(crate::base32::BASE32_CROCKFORD.encode(&ciphertext)),
                    Encoding::B32 => Ok(crate::base32::BASE32_RFC.encode(&ciphertext)),
                    Encoding::B64 => Ok(data_encoding::BASE64URL_NOPAD.encode(&ciphertext)),
                    Encoding::Hex => Ok(data_encoding::HEXLOWER.encode(&ciphertext)),
                }
            }

            fn dec(&self, obtext: &str) -> Result<String, Error> {
                // Decode based on encoding type
                let ciphertext = match $encoding {
                    Encoding::C32 => crate::base32::BASE32_CROCKFORD
                        .decode(obtext.as_bytes())
                        .map_err(|_| Error::InvalidC32)?,
                    Encoding::B32 => crate::base32::BASE32_RFC
                        .decode(obtext.as_bytes())
                        .map_err(|_| Error::InvalidB32)?,
                    Encoding::B64 => data_encoding::BASE64URL_NOPAD
                        .decode(obtext.as_bytes())
                        .map_err(|_| Error::InvalidB64)?,
                    Encoding::Hex => data_encoding::HEXLOWER
                        .decode(obtext.as_bytes())
                        .map_err(|_| Error::InvalidHex)?,
                };

                // Decrypt using legacy AES-CBC
                let plaintext_bytes = decrypt_legacy(self.zkeychain.secret_bytes(), &ciphertext)?;

                // Convert to string
                #[cfg(feature = "unchecked-utf8")]
                {
                    Ok(unsafe { String::from_utf8_unchecked(plaintext_bytes) })
                }

                #[cfg(not(feature = "unchecked-utf8"))]
                {
                    String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
                }
            }

            fn format(&self) -> Format {
                Format::new(Scheme::Legacy, $encoding)
            }

            fn scheme(&self) -> Scheme {
                Scheme::Legacy
            }

            fn encoding(&self) -> Encoding {
                $encoding
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
        }
    };
}

// Generate all legacy variants
impl_legacy_codec!(LegacyC32, Encoding::C32, "legacy.c32");
impl_legacy_codec!(LegacyB32, Encoding::B32, "legacy.b32");
impl_legacy_codec!(LegacyB64, Encoding::B64, "legacy.b64");
impl_legacy_codec!(LegacyHex, Encoding::Hex, "legacy.hex");

/// Encrypt plaintext bytes using legacy AES-CBC
#[inline(always)]
pub(crate) fn encrypt_legacy(secret: &[u8; 32], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::Aes128;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use cbc::Encryptor;

    type Aes128CbcEnc = Encryptor<Aes128>;

    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Calculate padding to align to block size
    let data_len = plaintext_bytes.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    // Allocate once with the correct size
    let mut buffer = Vec::with_capacity(total_len);
    buffer.extend_from_slice(plaintext_bytes);
    buffer.resize(total_len, LEGACY_PADDING_BYTE);

    // Encrypt in-place
    let cipher = Aes128CbcEnc::new(secret[0..16].into(), secret[16..32].into());
    cipher
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer, total_len)
        .map_err(|_| Error::EncryptionFailed)?;

    Ok(buffer)
}

/// Decrypt ciphertext using legacy AES-CBC
#[inline(always)]
pub(crate) fn decrypt_legacy(secret: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::Aes128;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;

    type Aes128CbcDec = Decryptor<Aes128>;

    // Decrypt with AES-128-CBC
    if data.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidBlockLength);
    }

    let cipher = Aes128CbcDec::new(secret[0..16].into(), secret[16..32].into());
    let mut buffer = data.to_vec();

    cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer)
        .map_err(|_| Error::DecryptionFailed)?;

    // Remove '=' padding by finding the end and truncating
    let end = buffer
        .iter()
        .rposition(|&b| b != LEGACY_PADDING_BYTE)
        .map_or(0, |i| i + 1);
    buffer.truncate(end);

    Ok(buffer)
}
