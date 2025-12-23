use crate::Error; // Use top-level error
use data_encoding::BASE64URL_NOPAD;

pub struct Keychain {
    key: [u8; 64],
}

impl Keychain {
    /// Create a new Keychain from a 64-byte key.
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        Ok(Keychain { key: *key_bytes })
    }

    /// Create a new Keychain from a 86-character base64 string key.
    pub fn from_base64(key_base64: &str) -> Result<Self, Error> {
        let key: [u8; 64] = BASE64URL_NOPAD
            .decode(key_base64.as_bytes())
            .map_err(|_| Error::InvalidB64)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&key)
    }

    /// Create a new Keychain from a 128-character hex string.
    #[cfg(feature = "hex-keys")]
    pub fn from_hex(key_hex: &str) -> Result<Self, Error> {
        let key_bytes: [u8; 64] = hex::decode(key_hex)? // Uses From<FromHexError>
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&key_bytes)
    }

    // Formatted keys - Convenience method for higher level

    #[inline]
    pub fn key_base64(&self) -> String {
        BASE64URL_NOPAD.encode(&self.key)
    }

    #[inline]
    #[cfg(feature = "bytes-keys")]
    pub fn key_bytes(&self) -> &[u8; 64] {
        &self.key
    }

    #[inline]
    #[cfg(feature = "hex-keys")]
    pub fn key_hex(&self) -> String {
        hex::encode(&self.key)
    }

    // Key derivation ==================================================

    // AES-128 key for AES-CBC (first 16 bytes)
    // Used in legacy, zfbcx, upbc schemes
    #[inline]
    #[cfg(any(feature = "legacy", feature = "zfbcx", feature = "upbc"))]
    pub(crate) fn cbc(&self) -> &[u8; 16] {
        self.key[..16].try_into().unwrap()
    }

    // Constant IV for deterministic AES-CBC (second 16 bytes)
    // Used in legacy and zfbcx schemes
    #[inline]
    #[cfg(any(feature = "legacy", feature = "zfbcx"))]
    pub(crate) fn cbc_iv(&self) -> &[u8; 16] {
        self.key[16..32].try_into().unwrap()
    }

    // AES-256 key for AES-GCM-SIV (second 32 bytes)
    // Used in adgs and apgs schemes
    #[inline]
    #[cfg(any(feature = "adgs", feature = "apgs"))]
    pub(crate) fn gcm_siv(&self) -> &[u8; 32] {
        self.key[32..64].try_into().unwrap()
    }

    // Double AES-256 key for AES-SIV (first 64 bytes)
    // (one 256-bit key for CMAC authentication, another for CTR encryption)
    // Used in adsv and apsv schemes
    #[inline]
    #[cfg(any(feature = "adsv", feature = "apsv"))]
    pub(crate) fn siv(&self) -> &[u8; 64] {
        &self.key
    }
}
