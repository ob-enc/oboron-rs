use crate::{Error, Scheme};
use data_encoding::BASE64URL_NOPAD;

pub struct Keychain {
    key: [u8; 64],
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

    // Direct key extraction - returns raw slices, no enum
    // ====================================================

    /// Get 32-byte key for schemes that need it
    #[inline(always)]
    pub(crate) fn get_key32(&self, scheme: Scheme) -> Result<&[u8; 32], Error> {
        match scheme {
            #[cfg(feature = "aags")]
            Scheme::Aags => Ok(unsafe { &*(self.key[32..64].as_ptr() as *const [u8; 32]) }),
            #[cfg(feature = "apgs")]
            Scheme::Apgs => Ok(unsafe { &*(self.key[32..64].as_ptr() as *const [u8; 32]) }),
            #[cfg(feature = "upbc")]
            Scheme::Upbc => Ok(unsafe { &*(self.key[8..40].as_ptr() as *const [u8; 32]) }),
            #[cfg(feature = "mock")]
            Scheme::Mock1 | Scheme::Mock2 => {
                const MOCK_KEY: [u8; 32] = [0u8; 32];
                Ok(&MOCK_KEY)
            }
            // Other schemes use 64-byte keys -> get_key64
            #[cfg(feature = "aasv")]
            Scheme::Aasv => Err(Error::InvalidKeyLength),
            #[cfg(feature = "apsv")]
            Scheme::Apsv => Err(Error::InvalidKeyLength),
            // Z-tier uses ZKeychain, not Keychain
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx => Err(Error::InvalidScheme),
            #[cfg(feature = "zmock")]
            Scheme::Zmock1 => Err(Error::InvalidScheme),
            #[cfg(feature = "legacy")]
            Scheme::Legacy => Err(Error::InvalidScheme),
        }
    }

    /// Get 64-byte key for schemes that need it
    #[inline(always)]
    pub(crate) fn get_key64(&self, scheme: Scheme) -> Result<&[u8; 64], Error> {
        match scheme {
            #[cfg(feature = "aasv")]
            Scheme::Aasv => Ok(&self.key),
            #[cfg(feature = "apsv")]
            Scheme::Apsv => Ok(&self.key),
            // Other schemes use 32-byte keys -> get_key32
            #[cfg(feature = "aags")]
            Scheme::Aags => Err(Error::InvalidKeyLength),
            #[cfg(feature = "apgs")]
            Scheme::Apgs => Err(Error::InvalidKeyLength),
            #[cfg(feature = "upbc")]
            Scheme::Upbc => Err(Error::InvalidKeyLength),
            #[cfg(feature = "mock")]
            Scheme::Mock1 | Scheme::Mock2 => Err(Error::InvalidKeyLength),
            // Z-tier uses ZKeychain, not Keychain
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
        self.key[32..64].try_into().unwrap()
    }

    // apgs key - AES-256 key for AES-GCM-SIV (second 32 bytes)
    #[inline(always)]
    #[cfg(feature = "apgs")]
    pub(crate) fn apgs(&self) -> &[u8; 32] {
        self.key[32..64].try_into().unwrap()
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

    // upbc key - AES-128 key for AES-CBC (first 16 bytes)
    #[inline(always)]
    #[cfg(any(feature = "upbc"))]
    pub(crate) fn upbc(&self) -> &[u8; 32] {
        self.key[8..40].try_into().unwrap()
    }

    // mock1 - no actual key needed
    #[inline(always)]
    #[cfg(any(feature = "mock"))]
    pub(crate) fn mock1(&self) -> &[u8; 32] {
        &[0u8; 32]
    }

    // mock2 - no actual key needed
    #[inline(always)]
    #[cfg(any(feature = "mock"))]
    pub(crate) fn mock2(&self) -> &[u8; 32] {
        &[0u8; 32]
    }
}
