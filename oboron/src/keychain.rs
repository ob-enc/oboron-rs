use crate::{Error, Scheme};
use data_encoding::BASE64URL_NOPAD;

pub struct Keychain {
    key: [u8; 64],
}

pub(crate) enum ExtractedKey<'a> {
    Key32(&'a [u8; 32]),
    Key64(&'a [u8; 64]),
}

impl Keychain {
    /// Create a new Keychain from a 64-byte key.
    #[inline]
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        Ok(Keychain { key: *key_bytes })
    }

    /// Create a new Keychain from a 86-character base64 string key.
    #[inline]
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
    #[inline]
    pub fn from_hex(key_hex: &str) -> Result<Self, Error> {
        let key_bytes: [u8; 64] = hex::decode(key_hex)? // Uses From<hex::FromHexError>
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

    #[inline]
    pub(crate) fn extract_key(&self, scheme: Scheme) -> Result<ExtractedKey<'_>, Error> {
        match scheme {
            #[cfg(feature = "aags")]
            Scheme::Aags => Ok(ExtractedKey::Key32(self.aags())),
            #[cfg(feature = "apgs")]
            Scheme::Apgs => Ok(ExtractedKey::Key32(self.apgs())),
            #[cfg(feature = "aasv")]
            Scheme::Aasv => Ok(ExtractedKey::Key64(self.aasv())),
            #[cfg(feature = "apsv")]
            Scheme::Apsv => Ok(ExtractedKey::Key64(self.apsv())),
            #[cfg(feature = "upbc")]
            Scheme::Upbc => Ok(ExtractedKey::Key32(self.upbc())),
            #[cfg(feature = "mock")]
            Scheme::Mock1 => Ok(ExtractedKey::Key32(self.mock1())),
            #[cfg(feature = "mock")]
            Scheme::Mock2 => Ok(ExtractedKey::Key32(self.mock2())),
            // Z-tier schemes should use ZKeychain, not Keychain
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx => Err(Error::InvalidScheme),
            #[cfg(feature = "zmock")]
            Scheme::Zmock1 => Err(Error::InvalidScheme),
            #[cfg(feature = "legacy")]
            Scheme::Legacy => Err(Error::InvalidScheme),
        }
    }

    // aags key - AES-256 key for AES-GCM-SIV (second 32 bytes)
    #[inline(always)]
    #[cfg(feature = "aags")]
    pub(crate) fn aags(&self) -> &[u8; 32] {
        // SAFETY: slice is guaranteed to be 32 bytes
        unsafe { &*(self.key[32..64].as_ptr() as *const [u8; 32]) }
    }

    // apgs key - AES-256 key for AES-GCM-SIV (second 32 bytes)
    #[inline(always)]
    #[cfg(feature = "apgs")]
    pub(crate) fn apgs(&self) -> &[u8; 32] {
        // SAFETY: slice is guaranteed to be 32 bytes
        unsafe { &*(self.key[32..64].as_ptr() as *const [u8; 32]) }
    }

    // aasv key - Double AES-256 key for AES-SIV (all 64 bytes)
    // (one 256-bit key for CMAC authentication, another for CTR encryption)
    #[inline(always)]
    #[cfg(feature = "aasv")]
    pub(crate) fn aasv(&self) -> &[u8; 64] {
        &self.key
    }

    // apsv key - Double AES-256 key for AES-SIV (all 64 bytes)
    // (one 256-bit key for CMAC authentication, another for CTR encryption)
    #[inline(always)]
    #[cfg(feature = "apsv")]
    pub(crate) fn apsv(&self) -> &[u8; 64] {
        &self.key
    }

    // upbc key - AES-256 key for AES-CBC (bytes 8-40)
    #[inline(always)]
    #[cfg(any(feature = "upbc"))]
    pub(crate) fn upbc(&self) -> &[u8; 32] {
        // SAFETY: slice is guaranteed to be 32 bytes
        unsafe { &*(self.key[8..40].as_ptr() as *const [u8; 32]) }
    }

    // mock1 - no actual key needed
    #[inline(always)]
    #[cfg(any(feature = "mock"))]
    pub(crate) fn mock1(&self) -> &[u8; 32] {
        // Return a const reference to avoid allocation
        const MOCK_KEY: [u8; 32] = [0u8; 32];
        &MOCK_KEY
    }

    // mock2 - no actual key needed
    #[inline(always)]
    #[cfg(any(feature = "mock"))]
    pub(crate) fn mock2(&self) -> &[u8; 32] {
        // Return a const reference to avoid allocation
        const MOCK_KEY: [u8; 32] = [0u8; 32];
        &MOCK_KEY
    }
}
