use crate::Error; // Use top-level error
use data_encoding::BASE64URL_NOPAD;

pub struct Keychain {
    key: [u8; 64],
}

impl Keychain {
    /// Create a new Keychain from a 64-byte key.
    pub fn from_bytes(key: &[u8; 64]) -> Result<Self, Error> {
        Ok(Keychain { key: *key })
    }

    /// Create a new Keychain from a 86-character base64 string key.
    pub fn from_base64(key_b64: &str) -> Result<Self, Error> {
        let key: [u8; 64] = BASE64URL_NOPAD
            .decode(key_b64.as_bytes())
            .map_err(|_| Error::InvalidBase64)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&key)
    }

    /// Create a new Keychain from a 128-character hex string.
    #[cfg(feature = "hex-keys")]
    pub fn from_hex(key_hex: &str) -> Result<Self, Error> {
        let key: [u8; 64] = hex::decode(key_hex)? // Uses From<FromHexError>
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&key)
    }

    // Formatted keys - Convenience method for higher level

    pub fn key_base64(&self) -> String {
        BASE64URL_NOPAD.encode(&self.key)
    }

    #[cfg(feature = "bytes-keys")]
    pub fn key_bytes(&self) -> &[u8; 64] {
        &self.key
    }

    #[cfg(feature = "hex-keys")]
    pub fn key_hex(&self) -> String {
        hex::encode(&self.key)
    }

    // Key derivation ==================================================

    // AES-128 key for AES-CBC (first 16 bytes)
    // Used in ob00, ob01, ob21p schemes
    #[inline]
    #[cfg(any(feature = "ob00", feature = "ob01", feature = "ob21p"))]
    pub(crate) fn cbc(&self) -> &[u8; 16] {
        self.key[..16].try_into().unwrap()
    }

    // Constant IV for deterministic AES-CBC (second 16 bytes)
    // Used in ob00 and ob01 schemes
    #[inline]
    #[cfg(any(feature = "ob00", feature = "ob01"))]
    pub(crate) fn cbc_iv(&self) -> &[u8; 16] {
        self.key[16..32].try_into().unwrap()
    }

    // AES-256 key for AES-GCM-SIV (second 32 bytes)
    // Used in ob31 and ob31p schemes
    #[inline]
    #[cfg(any(feature = "ob31", feature = "ob31p"))]
    pub(crate) fn gcm_siv(&self) -> &[u8; 32] {
        self.key[32..64].try_into().unwrap()
    }

    // Double AES-256 key for AES-SIV (first 64 bytes)
    // (one 256-bit key for CMAC authentication, another for CTR encryption)
    // Used in ob32 and ob32p schemes
    #[inline]
    #[cfg(any(feature = "ob32", feature = "ob32p"))]
    pub(crate) fn siv(&self) -> &[u8; 64] {
        &self.key
    }
}
