#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{format::IntoFormat, Error, MasterKey};

/// An ObtextCodec implementation that takes format on enc operation and autodetects on dec operation.
/// Unlike all other implementations (Ob, ZrbcxC32, .. .) it does not have
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
/// # use oboron::{Omnib, MOCK1_B64};
/// # let key = oboron::generate_key();
/// let omb = Omnib::new(&key)?;
///
/// // Encode with explicit format
/// let ot1 = omb.enc("hello", "aasv.c32")?; // using explicit string
/// let ot2 = omb.enc("world", MOCK1_B64)?; // using format constant
///
/// // autodec detects both scheme and encoding
/// let pt1 = omb.autodec(&ot1)?;
/// let pt2 = omb.autodec(&ot2)?;
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Omnib {
    masterkey: MasterKey,
}

impl Omnib {
    /// Create a new Omnib instance with a base64 key.
    pub fn new(key_b64: &str) -> Result<Self, Error> {
        Ok(Self {
            masterkey: MasterKey::from_base64(key_b64)?,
        })
    }

    /// Create a new Omnib instance with hardcoded key (testing only).
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        Self::from_bytes(&HARDCODED_KEY_BYTES)
    }

    /// Encrypt and encode plaintext with the specified format.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Omnib, Format, Scheme, Encoding, AASV_B64};
    /// # let key = oboron::generate_key();
    /// let omb = Omnib::new(&key)?;
    ///
    /// // Using format string
    /// let ot1 = omb.enc("hello", "aasv.b64")?;
    ///
    /// // Using Format instance
    /// let ot2 = omb.enc("hello", Format::new(Scheme::Aasv, Encoding::B64))?;
    ///
    /// // Using format constant
    /// let ot3 = omb.enc("hello", AASV_B64)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn enc(&self, plaintext: &str, format: impl IntoFormat) -> Result<String, Error> {
        let format = format.into_format()?;
        crate::enc::enc_to_format(plaintext, format, self.masterkey.key())
    }

    /// Decode and decrypt obtext with the specified format.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Omnib, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// # let omb = Omnib::new(&key)?;
    /// # let ot = omb.enc("test", "aasv.b64")?;
    /// // Using format string
    /// let pt1 = omb.dec(&ot, "aasv.b64")?;
    ///
    /// // Using Format instance
    /// let pt2 = omb.dec(&ot, Format::new(Scheme::Aasv, Encoding::B64))?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn dec(&self, obtext: &str, format: impl IntoFormat) -> Result<String, Error> {
        let format = format.into_format()?;
        crate::dec::dec_from_format(obtext, format, self.masterkey.key())
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::Omnib;
    /// # let key = oboron::generate_key();
    /// # let omb = Omnib::new(&key)?;
    /// let ot = omb.enc("hello", "aasv.b64")?;
    /// let pt2 = omb.autodec(&ot)?;  // Autodetects ob:aasv.b64
    /// assert_eq!(pt2, "hello");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn autodec(&self, obtext: &str) -> Result<String, Error> {
        crate::dec_auto::dec_any_format(&self.masterkey, obtext)
    }

    /// Get the key used by this instance.
    pub fn key(&self) -> String {
        self.masterkey.key_base64()
    }

    #[cfg(feature = "hex-keys")]
    pub fn key_hex(&self) -> String {
        self.masterkey.key_hex()
    }

    #[cfg(feature = "bytes-keys")]
    pub fn key_bytes(&self) -> &[u8; 64] {
        self.masterkey.key_bytes()
    }

    // Alt input constructors ==========================================

    /// Create a new Omnib instance with a hex key.
    #[cfg(feature = "hex-keys")]
    pub fn from_key_hex(key_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            masterkey: MasterKey::from_hex(key_hex)?,
        })
    }

    /// Create a new Omnib instance from raw bytes.
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        Ok(Self {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        })
    }
}
