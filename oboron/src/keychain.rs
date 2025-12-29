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

    // Key extraction ==================================================

    // aags key - AES-256 key for AES-GCM-SIV (second 32 bytes)
    #[inline]
    #[cfg(feature = "aags")]
    pub(crate) fn aags(&self) -> &[u8; 32] {
        self.key[32..64].try_into().unwrap()
    }

    // apgs key - AES-256 key for AES-GCM-SIV (second 32 bytes)
    #[inline]
    #[cfg(feature = "apgs")]
    pub(crate) fn apgs(&self) -> &[u8; 32] {
        self.key[32..64].try_into().unwrap()
    }

    // aasv key - Double AES-256 key for AES-SIV (all 64 bytes)
    // (one 256-bit key for CMAC authentication, another for CTR encryption)
    #[inline]
    #[cfg(feature = "aasv")]
    pub(crate) fn aasv(&self) -> &[u8; 64] {
        &self.key
    }

    // apsv key - Double AES-256 key for AES-SIV (all 64 bytes)
    // (one 256-bit key for CMAC authentication, another for CTR encryption)
    #[inline]
    #[cfg(feature = "apsv")]
    pub(crate) fn apsv(&self) -> &[u8; 64] {
        &self.key
    }

    // upbc key - AES-128 key for AES-CBC (first 16 bytes)
    #[inline]
    #[cfg(any(feature = "upbc"))]
    pub(crate) fn upbc(&self) -> &[u8; 32] {
        self.key[8..40].try_into().unwrap()
    }

    // zrbcx secret - AES-128 key + IV for AES-CBC (first 16+16 bytes)
    // Note: This combines the cryptographic key and IV in a static way,
    // which is an antipattern.  Use for obfuscation only, not secure encryption.
    #[inline]
    #[cfg(any(feature = "zrbcx"))]
    pub(crate) fn zrbcx(&self) -> &[u8; 32] {
        self.key[..32].try_into().unwrap()
    }

    // legacy secret - AES-128 key + IV for AES-CBC (first 16+16 bytes)
    // Note: This combines the cryptographic key and IV in a static way,
    // which is an antipattern.  Use for obfuscation only, not secure encryption.
    #[inline]
    #[cfg(any(feature = "legacy"))]
    pub(crate) fn legacy(&self) -> &[u8; 32] {
        self.key[..32].try_into().unwrap()
    }

    // mock1 - no actual key needed
    #[inline]
    #[cfg(any(feature = "mock"))]
    pub(crate) fn mock1(&self) -> &[u8; 32] {
        &[0u8; 32]
    }

    // mock2 - no actual key needed
    #[inline]
    #[cfg(any(feature = "mock"))]
    pub(crate) fn mock2(&self) -> &[u8; 32] {
        &[0u8; 32]
    }
}
