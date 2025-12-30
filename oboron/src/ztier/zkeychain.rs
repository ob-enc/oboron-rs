//!  Keychain for z-tier schemes (32-byte secrets, obfuscation-only)

use crate::Error;
use data_encoding::BASE64URL_NOPAD;

/// Keychain for z-tier schemes (obfuscation-only, 32-byte secrets)
///
/// **WARNING**: Z-tier schemes provide NO cryptographic security.
/// Use only for obfuscation, never for actual encryption.
pub struct ZKeychain {
    secret: [u8; 32],
}

impl ZKeychain {
    /// Create a new ZKeychain from a 32-byte secret.
    pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(ZKeychain {
            secret: *secret_bytes,
        })
    }

    /// Create a new ZKeychain from a 43-character base64 string secret.
    pub fn from_base64(secret_base64: &str) -> Result<Self, Error> {
        let secret: [u8; 32] = BASE64URL_NOPAD
            .decode(secret_base64.as_bytes())
            .map_err(|_| Error::InvalidB64)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&secret)
    }

    /// Create a new ZKeychain from a 64-character hex string.
    #[cfg(feature = "hex-keys")]
    pub fn from_hex(secret_hex: &str) -> Result<Self, Error> {
        let secret_bytes: [u8; 32] = hex::decode(secret_hex)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&secret_bytes)
    }

    /// Get the secret as base64 string.
    #[inline]
    pub fn secret_base64(&self) -> String {
        BASE64URL_NOPAD.encode(&self.secret)
    }

    /// Get the secret as raw bytes.
    #[inline]
    #[cfg(feature = "bytes-keys")]
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Get the secret as hex string.
    #[inline]
    #[cfg(feature = "hex-keys")]
    pub fn secret_hex(&self) -> String {
        hex::encode(&self.secret)
    }

    // Secret extraction for specific schemes
    // ========================================

    /// Get secret for zrbcx scheme (AES-128 key + IV, first 32 bytes)
    #[inline]
    #[cfg(feature = "zrbcx")]
    pub(crate) fn zrbcx(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Get secret for legacy scheme (AES-128 key + IV, first 32 bytes)
    #[inline]
    #[cfg(feature = "legacy")]
    pub(crate) fn legacy(&self) -> &[u8; 32] {
        &self.secret
    }
}
