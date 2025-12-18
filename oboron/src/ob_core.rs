#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{Encoding, Error, Format, Keychain, Oboron, Scheme};

/// Low-level encoder/decoder implementation.
///
/// This is an internal implementation detail.
/// Most users should use the public-facing types like `Ob`, `ObFlex`, or specific scheme types.
pub(crate) struct ObCore {
    pub(crate) keychain: Keychain,
    pub(crate) format: Format,
}

impl ObCore {
    /// Create a new ObCore with the specified format string and base64 key.
    pub(crate) fn new(fmt: &str, key: &str) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_base64(key)?,
            format: Format::from_str(fmt)?,
        })
    }

    // Alt constructors ================================================
    //
    // 1. Alt format input ---
    //
    /// Create a new ObCore with a pre-parsed Format and base64 key.
    pub(crate) fn new_with_format(format: Format, key: &str) -> Result<Self, Error> {
        Ok(Self {
            format,
            keychain: Keychain::from_base64(key)?,
        })
    }

    // 2. Keyless (using HARDCODED_KEY_BYTES) ---
    //
    /// Create a new ObCore with hardcoded key (testing only).
    #[inline]
    #[cfg(feature = "keyless")]
    pub(crate) fn new_keyless(fmt: &str) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
            format: Format::from_str(fmt)?,
        })
    }

    /// Create a new ObCore with pre-parsed Format and hardcoded key (testing only).
    #[inline]
    #[cfg(feature = "keyless")]
    pub(crate) fn new_keyless_with_format(format: Format) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
            format,
        })
    }

    // 3. Alt key input ---
    //
    //
    // 3.a Bytes key input is used internally to avoid decoding hex/base64
    //     It is also used by public methods behind the "bytes-keys" feature
    //
    /// Create a new ObCore from the specified format string and raw bytes.
    #[inline]
    #[cfg(feature = "bytes-keys")]
    pub(crate) fn from_bytes(fmt: &str, key_bytes: &[u8; 64]) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_bytes(key_bytes)?,
            format: Format::from_str(fmt)?,
        })
    }

    /// Create a new ObCore from a pre-parsed Format and raw bytes.
    #[inline]
    #[cfg(feature = "bytes-keys")]
    pub(crate) fn from_bytes_with_format(
        format: Format,
        key_bytes: &[u8; 64],
    ) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_bytes(key_bytes)?,
            format,
        })
    }

    // 3.b Hex keys are a feature convenience offered as alternative to the default base64 keys.
    //     Public methods behind this feature call these internal ObCore methods.
    //
    /// Create a new ObCore with the specified format string and hex key.
    #[inline]
    #[cfg(feature = "hex-keys")]
    pub(crate) fn from_hex_key(fmt: &str, key_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_hex(key_hex)?,
            format: Format::from_str(fmt)?,
        })
    }

    /// Create a new ObCore with a pre-parsed Format and hex key.
    #[inline]
    #[cfg(feature = "hex-keys")]
    pub(crate) fn from_hex_key_with_format(format: Format, key_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_hex(key_hex)?,
            format,
        })
    }
}

impl Oboron for ObCore {
    fn enc(&self, plaintext: &str) -> Result<String, Error> {
        crate::enc::enc_to_format(plaintext, self.format, &self.keychain)
    }

    fn dec(&self, obtext: &str) -> Result<String, Error> {
        crate::dec_auto::dec_any_scheme(&self.keychain, self.format.encoding(), obtext)
    }

    fn dec_strict(&self, obtext: &str) -> Result<String, Error> {
        crate::dec::dec_from_format(obtext, self.format, &self.keychain)
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

    // This is only avaiable for the public feature-gated methods.
    // (Unline the from_bytes() constructor which is also needed internally.)
    //
    #[cfg(feature = "bytes-keys")]
    fn key_bytes(&self) -> &[u8; 64] {
        self.keychain.key_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "ob70")]
    fn test_obcore_basic() {
        // 86-character base64 key
        let key = crate::generate_key();
        let core = ObCore::new("ob70:c32", &key).unwrap();

        let ot = core.enc("hello").unwrap();
        let pt2 = core.dec(&ot).unwrap();
        assert_eq!(pt2, "hello");
    }

    #[test]
    #[cfg(feature = "ob70")]
    #[cfg(feature = "keyless")]
    fn test_obcore_keyless() {
        let core = ObCore::new_keyless("ob70:c32").unwrap();

        let ot = core.enc("test").unwrap();
        let pt2 = core.dec(&ot).unwrap();
        assert_eq!(pt2, "test");
    }
}
