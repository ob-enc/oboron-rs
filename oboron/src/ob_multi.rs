#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{Error, Format, Keychain};

/// An Oboron implementation that takes format on enc operation and autodetects on dec operation.
/// Unlike all other implementations (Ob, ObFlex, Ob01, .. .) it does not have
/// a format stored internally.
///
/// This struct allows specifying the format (scheme + encoding) at enc call time,
/// and automatically detects both scheme and encoding on dec calls.
/// It is the only Oboron implementation that does full format autodetection,
/// all other implementations can only autodetect the scheme (e.g., ob21p),
/// but not the encoding (e.g., base32 or base64).
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(all(feature = "ob32", feature="non-crypto"))]
/// # {
/// # use oboron::{ObMulti, OB70_B64};
/// # let key = oboron::generate_key();
/// let ob = ObMulti::new(&key)?;
///
/// // Encode with explicit format
/// let ot1 = ob.enc("hello", "ob32:c32")?; // using explicit string
/// let ot2 = ob.enc("world", OB70_B64)?; // using string constant
///
/// // autodec detects both scheme and encoding
/// let pt1 = ob.autodec(&ot1)?;
/// let pt2 = ob.autodec(&ot2)?;
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
    /// Accepts format strings like "ob01:c32", "ob31:b64", etc.
    /// For pre-parsed Format instances, use [`enc_with_format`](Self::enc_with_format).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature="non-crypto"))]
    /// # {
    /// # use oboron::ObMulti;
    /// let key = oboron::generate_key();
    /// let ob = ObMulti::new(&key)?;
    ///
    /// let ot = ob.enc("hello", "ob32:c32")?;
    /// let ot2 = ob.enc("world", "ob70:b64")?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn enc(&self, plaintext: &str, fmt: &str) -> Result<String, Error> {
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
    /// # #[cfg(feature = "ob32")]
    /// # {
    /// # use oboron::{ObMulti, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// # let ob = ObMulti::new(&key)?;
    /// let format = Format::new(Scheme::Ob32, Encoding::Base32Crockford);
    ///
    /// // Reuse format across multiple calls
    /// let ot1 = ob.enc_with_format("hello", format)? ;
    /// let ot2 = ob.enc_with_format("world", format)?;
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
    /// # #[cfg(feature = "ob32")]
    /// # {
    /// # use oboron::ObMulti;
    /// # let key = oboron::generate_key();
    /// # let ob = ObMulti::new(&key)?;
    /// let ot = ob.enc("hello", "ob32:b64")?;
    /// let pt2 = ob.dec(&ot, "ob32:b64")? ;
    /// assert_eq!(pt2, "hello");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn dec(&self, obtext: &str, fmt: &str) -> Result<String, Error> {
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
    /// # #[cfg(feature = "ob32")]
    /// # {
    /// # use oboron::{ObMulti, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// # let ob = ObMulti::new(&key)?;
    /// let format = Format::new(Scheme::Ob32, Encoding::Base64);
    ///
    /// let ot = ob.enc_with_format("hello", format)?;
    /// let pt2 = ob.dec_with_format(&ot, format)?;
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
    /// # #[cfg(feature = "ob32")]
    /// # {
    /// # use oboron::ObMulti;
    /// # let key = oboron::generate_key();
    /// # let ob = ObMulti::new(&key)?;
    /// let ot = ob.enc("hello", "ob32:b64")?;
    /// let pt2 = ob.autodec(&ot)?;  // Autodetects ob32:b64
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
