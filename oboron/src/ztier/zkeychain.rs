//! Keychain for z-tier schemes (32-byte secrets, obfuscation-only)

#![cfg(feature = "ztier")]

use crate::{Error, ExtractedKey, Scheme};
use data_encoding::BASE64URL_NOPAD;

/// Keychain for z-tier schemes (obfuscation-only, 32-byte secrets)
///
/// **WARNING**:  Z-tier schemes provide NO cryptographic security.
/// Use only for obfuscation, never for actual encryption.
pub(crate) struct ZKeychain {
    secret: [u8; 32],
}

impl ZKeychain {
    /// Create a new ZKeychain from a 32-byte secret.
    #[inline]
    pub(crate) fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(ZKeychain {
            secret: *secret_bytes,
        })
    }

    /// Create a new ZKeychain from a 43-character base64 string secret.
    #[inline]
    #[allow(dead_code)] // Used by Zob constructors
    pub(crate) fn from_base64(secret_base64: &str) -> Result<Self, Error> {
        let secret: [u8; 32] = BASE64URL_NOPAD
            .decode(secret_base64.as_bytes())
            .map_err(|_| Error::InvalidB64)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&secret)
    }

    /// Create a new ZKeychain from a 64-character hex string.
    #[inline]
    #[allow(dead_code)] // Used by Zob constructors
    #[cfg(feature = "hex-keys")]
    pub(crate) fn from_hex(secret_hex: &str) -> Result<Self, Error> {
        let secret_bytes: [u8; 32] = hex::decode(secret_hex)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&secret_bytes)
    }

    /// Get the secret as base64 string.
    #[inline]
    #[allow(dead_code)] // Used by Zob.key() method
    pub(crate) fn secret_base64(&self) -> String {
        BASE64URL_NOPAD.encode(&self.secret)
    }

    /// Get the secret as raw bytes.
    #[inline]
    #[allow(dead_code)] // Used by Zob.key_bytes()
    #[cfg(feature = "bytes-keys")]
    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Get the secret as hex string.
    #[inline]
    #[allow(dead_code)] // Used by Zob.key_hex()
    #[cfg(feature = "hex-keys")]
    pub(crate) fn secret_hex(&self) -> String {
        hex::encode(&self.secret)
    }

    // Secret extraction for specific schemes
    // ========================================

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn extract_secret(&self, scheme: Scheme) -> Result<ExtractedKey<'_>, Error> {
        match scheme {
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx => Ok(ExtractedKey::Key32(self.zrbcx())),
            #[cfg(feature = "legacy")]
            Scheme::Legacy => Ok(ExtractedKey::Key32(self.legacy())),
            // other schemes should use Keychain, not ZKeychain
            #[cfg(feature = "aags")]
            Scheme::Aags => Err(Error::InvalidScheme),
            #[cfg(feature = "apgs")]
            Scheme::Apgs => Err(Error::InvalidScheme),
            #[cfg(feature = "aasv")]
            Scheme::Aasv => Err(Error::InvalidScheme),
            #[cfg(feature = "apsv")]
            Scheme::Apsv => Err(Error::InvalidScheme),
            #[cfg(feature = "upbc")]
            Scheme::Upbc => Err(Error::InvalidScheme),
            #[cfg(feature = "mock")]
            Scheme::Mock1 => Err(Error::InvalidScheme),
            #[cfg(feature = "mock")]
            Scheme::Mock2 => Err(Error::InvalidScheme),
        }
    }

    /// Get secret for zrbcx scheme (all 32 bytes)
    #[inline]
    #[cfg(feature = "zrbcx")]
    pub(crate) fn zrbcx(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Get secret for legacy scheme (all 32 bytes)
    #[inline]
    #[cfg(feature = "legacy")]
    #[allow(dead_code)] // Used by zdec_auto fallback
    pub(crate) fn legacy(&self) -> &[u8; 32] {
        &self.secret
    }
}
