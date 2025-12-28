#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{Error, Format, Keychain};

/// An ObtextCodec implementation that takes format on enc operation and autodetects on dec operation.
/// Unlike all other implementations (Ob, ObFlex, ZrbcxC32, .. .) it does not have
/// a format stored internally.
///
/// This struct allows specifying the format (scheme + encoding) at enc call time,
/// and automatically detects both scheme and encoding on dec calls.
/// It is the only ObtextCodec implementation that does full format autodetection,
/// all other implementations can only autodetect the scheme (e.g., upbc),
/// but not the encoding (e.g., base32 or base64).
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(all(feature = "aasv", feature="mock"))]
/// # {
/// # use oboron::{ObMulti, MOCK1_B64};
/// # let key = oboron::generate_key();
/// let obm = ObMulti::new(&key)?;
///
/// // Encode with explicit format
/// let ot1 = obm.enc_with_format_str("hello", "aasv.c32")?; // using explicit string
/// let ot2 = obm.enc_with_format("world", MOCK1_B64)?; // using format constant
///
/// // autodec detects both scheme and encoding
/// let pt1 = obm.autodec(&ot1)?;
/// let pt2 = obm.autodec(&ot2)?;
/// # }
/// # Ok(())
/// # }
/// ```
pub struct ObMulti {
    keychain: Keychain,
}

impl ObMulti {
    /// Create a new ObMulti instance with a base64 key.
    pub fn new(key_b64: &str) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_base64(key_b64)?,
        })
    }

    /// Create a new ObMulti instance with hardcoded key (testing only).
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        Self::from_bytes(&HARDCODED_KEY_BYTES)
    }

    /// Encrypt+encode with a specific format string.
    ///
    /// Accepts format strings like "zrbcx.c32", "aags.b64", etc.
    /// For pre-parsed Format instances, use [`enc_with_format`](Self::enc_with_format).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature="mock"))]
    /// # {
    /// # use oboron::ObMulti;
    /// let key = oboron::generate_key();
    /// let obm = ObMulti::new(&key)?;
    ///
    /// let ot = obm.enc_with_format_str("hello", "aasv.c32")?;
    /// let ot2 = obm.enc_with_format_str("world", "mock1.b64")?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn enc_with_format_str(&self, plaintext: &str, fmt: &str) -> Result<String, Error> {
        let format = Format::from_str(fmt)?;
        crate::enc::enc_to_format(plaintext, format, &self.keychain)
    }

    /// Encrypt+encode with a pre-parsed Format.
    ///
    /// This method is most efficient when the same format is used repeatedly,
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{ObMulti, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// # let obm = ObMulti::new(&key)?;
    /// let format = Format::new(Scheme::Aasv, Encoding::C32);
    ///
    /// // Reuse format across multiple calls
    /// let ot1 = obm.enc_with_format("hello", format)? ;
    /// let ot2 = obm.enc_with_format("world", format)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn enc_with_format(&self, plaintext: &str, format: Format) -> Result<String, Error> {
        crate::enc::enc_to_format(plaintext, format, &self.keychain)
    }

    /// Decode+decrypt with an explicitly provided format string.
    ///
    /// For pre-parsed Format instances, use [`dec_with_format`](Self::dec_with_format).
    /// For automatic format detection, use [`autodec`](Self::autodec).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::ObMulti;
    /// # let key = oboron::generate_key();
    /// # let obm = ObMulti::new(&key)?;
    /// let ot = obm.enc_with_format_str("hello", "aasv.b64")?;
    /// let pt2 = obm.dec_with_format_str(&ot, "aasv.b64")? ;
    /// assert_eq!(pt2, "hello");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn dec_with_format_str(&self, obtext: &str, fmt: &str) -> Result<String, Error> {
        let format = Format::from_str(fmt)?;
        crate::dec::dec_from_format(obtext, format, &self.keychain)
    }

    /// Decode+decrypt with a pre-parsed Format.
    ///
    /// Re-uses the same format is used repeatedly.   Even though strings are matched, not parsed,
    /// this saves a function call overhead on each call.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{ObMulti, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// # let obm = ObMulti::new(&key)?;
    /// let format = Format::new(Scheme::Aasv, Encoding::B64);
    ///
    /// let ot = obm.enc_with_format("hello", format)?;
    /// let pt2 = obm.dec_with_format(&ot, format)?;
    /// assert_eq!(pt2, "hello");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn dec_with_format(&self, obtext: &str, format: Format) -> Result<String, Error> {
        crate::dec::dec_from_format(obtext, format, &self.keychain)
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::ObMulti;
    /// # let key = oboron::generate_key();
    /// # let obm = ObMulti::new(&key)?;
    /// let ot = obm.enc_with_format_str("hello", "aasv.b64")?;
    /// let pt2 = obm.autodec(&ot)?;  // Autodetects aasv.b64
    /// assert_eq!(pt2, "hello");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn autodec(&self, obtext: &str) -> Result<String, Error> {
        crate::dec_auto::dec_any_format(&self.keychain, obtext)
    }

    /// Get the key used by this instance.
    pub fn key(&self) -> String {
        self.keychain.key_base64()
    }

    #[cfg(feature = "hex-keys")]
    pub fn key_hex(&self) -> String {
        self.keychain.key_hex()
    }

    #[cfg(feature = "bytes-keys")]
    pub fn key_bytes(&self) -> &[u8; 64] {
        self.keychain.key_bytes()
    }

    // Alt input constructors ==========================================

    /// Create a new ObMulti instance with a hex key.
    #[cfg(feature = "hex-keys")]
    pub fn from_key_hex(key_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_hex(key_hex)?,
        })
    }

    /// Create a new ObMulti instance from raw bytes.
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        Ok(Self {
            keychain: Keychain::from_bytes(key_bytes)?,
        })
    }
}
