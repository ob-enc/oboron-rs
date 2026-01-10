use crate::Error;
use data_encoding::BASE64URL_NOPAD;

pub struct MasterKey {
    key: [u8; 64],
}

impl MasterKey {
    /// Create a new MasterKey from a 64-byte key.
    #[inline]
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        Ok(MasterKey { key: *key_bytes })
    }

    /// Create a new MasterKey from a 86-character base64 string key.
    #[inline]
    pub fn from_base64(key_base64: &str) -> Result<Self, Error> {
        let key: [u8; 64] = BASE64URL_NOPAD
            .decode(key_base64.as_bytes())
            .map_err(|_| Error::InvalidB64)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&key)
    }

    /// Create a new MasterKey from a 128-character hex string.
    #[cfg(feature = "hex-keys")]
    #[inline]
    pub fn from_hex(key_hex: &str) -> Result<Self, Error> {
        let key_bytes: [u8; 64] = hex::decode(key_hex)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&key_bytes)
    }

    #[inline]
    pub fn key_base64(&self) -> String {
        BASE64URL_NOPAD.encode(&self.key)
    }

    #[inline]
    #[cfg(feature = "bytes-keys")]
    pub(crate) fn key_bytes(&self) -> &[u8; 64] {
        &self.key
    }

    #[inline]
    #[cfg(feature = "hex-keys")]
    pub fn key_hex(&self) -> String {
        hex::encode(&self.key)
    }

    #[inline(always)]
    pub(crate) fn key(&self) -> &[u8; 64] {
        &self.key
    }
}
