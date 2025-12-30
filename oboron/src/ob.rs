#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{Encoding, Error, Format, Keychain, ObtextCodec, Scheme};

/// A flexible ObtextCodec implementation with runtime format selection.
///
/// `Ob` allows you to specify any format at runtime via constructor parameters,
/// and provides methods to change the format after construction if needed.
///
/// This provides a unified interface for all runtime format needs, from
/// immutable configurations to dynamic format switching.
///
/// # Examples
///
/// ## Basic usage with immutable format
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "aasv")]
/// # {
/// # use oboron::{Ob, generate_key};
/// # let key = generate_key();
/// let ob = Ob::new("aasv.b64", &key)?;
/// let ot = ob.enc("hello")?; // obtext
/// let pt2 = ob.dec(&ot)?; // recovered plaintext
/// assert_eq!(pt2, "hello");
/// # }
/// # Ok(())
/// # }
/// ```
///
/// ## Dynamic format switching
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(all(feature = "aasv", feature = "mock"))]
/// # {
/// # use oboron::{Ob, Scheme, Encoding, Format, AASV_B64};
/// # let key = oboron::generate_key();
/// let mut ob = Ob::new("aasv.c32", &key)?;
/// let ot1 = ob.enc("hello")?; // aasv.c32 format
///
/// // Change format at runtime
/// ob.set_scheme(Scheme::Mock1)?;
/// let ot2 = ob.enc("hello")?; // mock1. c32 format
///
/// // Change encoding
/// ob.set_encoding(Encoding::B64)?; // now mock1.b64
///
/// // Set entire format at once
/// ob.set_format("aasv.hex")?; // now aasv.hex
/// ob.set_format(AASV_B64)?;   // now aasv.b64 (using constant)
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Ob {
    keychain: Keychain,
    format: Format,
}

impl Ob {
    /// Create a new Ob with the specified format and base64 key.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// // Using format string
    /// let ob1 = Ob::new("aasv.b64", &key)?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme:: Aasv, Encoding::B64);
    /// let ob2 = Ob::new(format, &key)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(format: impl IntoFormat, key: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            keychain: Keychain::from_base64(key)?,
            format,
        })
    }

    /// Get the current format.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// let ob = Ob::new("aasv.b64", &key)?;
    /// let format = ob.format();
    /// assert_eq!(format.scheme(), Scheme::Aasv);
    /// assert_eq!(format.encoding(), Encoding::B64);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn format(&self) -> Format {
        self.format
    }

    /// Set the format to a new value.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature = "mock"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// let mut ob = Ob:: new("aasv.c32", &key)?;
    /// ob.set_format("mock1.b64")?; // switch using string
    /// ob.set_format(Format::new(Scheme::Mock2, Encoding:: Hex))?; // switch using Format
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_format(&mut self, format: impl IntoFormat) -> Result<(), Error> {
        self.format = format.into_format()?;
        Ok(())
    }

    /// Set the scheme while keeping the current encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature = "mock"))]
    /// # {
    /// # use oboron::{Ob, Scheme};
    /// # let key = oboron::generate_key();
    /// let mut ob = Ob::new("aasv.c32", &key)?;
    /// ob.set_scheme(Scheme::Mock1)?; // switch to mock1, keeping c32 encoding
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_scheme(&mut self, scheme: Scheme) -> Result<(), Error> {
        self.format = Format::new(scheme, self.format.encoding());
        Ok(())
    }

    /// Set the encoding while keeping the current scheme.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Encoding};
    /// # let key = oboron::generate_key();
    /// let mut ob = Ob::new("aasv.c32", &key)?;
    /// ob.set_encoding(Encoding::B64)?; // switch to b64, keeping aasv scheme
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_encoding(&mut self, encoding: Encoding) -> Result<(), Error> {
        self.format = Format::new(self.format.scheme(), encoding);
        Ok(())
    }

    /// Decode and decrypt obtext with scheme autodetection.
    ///
    /// Uses the current encoding but automatically detects the scheme from the payload.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature = "mock"))]
    /// # {
    /// # use oboron:: Ob;
    /// # let key = oboron::generate_key();
    /// let mut ob = Ob::new("aasv.b64", &key)?;
    /// let ot = ob.enc("test")?;
    ///
    /// // Change scheme - dec_auto_scheme will still work
    /// ob.set_scheme(oboron::Scheme::Mock1)?;
    /// let pt2 = ob.dec_auto_scheme(&ot)?;
    /// assert_eq!(pt2, "test");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn dec_auto_scheme(&self, obtext: &str) -> Result<String, Error> {
        crate::dec_auto::dec_any_scheme(&self.keychain, self.format.encoding(), obtext)
    }

    // Alt constructors ================================================

    /// Create a new Ob with hardcoded key (testing only).
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature="keyless"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// // Using format string
    /// let ob1 = Ob::new_keyless("aasv.c32")?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Aasv, Encoding::C32);
    /// let ob2 = Ob::new_keyless(format)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "keyless")]
    pub fn new_keyless(format: impl IntoFormat) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            keychain: Keychain::from_bytes(&HARDCODED_KEY_BYTES)?,
            format,
        })
    }

    /// Create a new Ob with the specified format and hex key.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature = "hex-keys"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// let key_hex = oboron::generate_key_hex();
    /// // Using format string
    /// let ob1 = Ob::from_hex_key("aasv.b64", &key_hex)?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Aasv, Encoding::B64);
    /// let ob2 = Ob:: from_hex_key(format, &key_hex)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "hex-keys")]
    pub fn from_hex_key(format: impl IntoFormat, key_hex: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            keychain: Keychain::from_hex(key_hex)?,
            format,
        })
    }

    /// Create a new Ob from the specified format and raw key bytes.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature = "bytes-keys"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// let key_bytes = oboron::generate_key_bytes();
    /// let ob1 = Ob::from_bytes("aasv.b64", &key_bytes)?; // using format string
    /// let format = Format::new(Scheme:: Aasv, Encoding:: B64); // using Format
    /// let ob2 = Ob::from_bytes(format, &key_bytes)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "bytes-keys")]
    pub fn from_bytes(format: impl IntoFormat, key: &[u8; 64]) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            keychain: Keychain::from_bytes(key)?,
            format,
        })
    }
}

impl ObtextCodec for Ob {
    fn enc(&self, plaintext: &str) -> Result<String, Error> {
        crate::enc::enc_to_format(plaintext, self.format, &self.keychain)
    }

    fn dec(&self, obtext: &str) -> Result<String, Error> {
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

    #[cfg(feature = "bytes-keys")]
    fn key_bytes(&self) -> &[u8; 64] {
        self.keychain.key_bytes()
    }
}

// Add inherent methods that delegate to trait methods
impl Ob {
    /// Encrypt and encode plaintext
    #[inline]
    pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::enc(self, plaintext)
    }

    /// Decode and decrypt obtext (no scheme autodetection)
    #[inline]
    pub fn dec(&self, obtext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::dec(self, obtext)
    }

    /// Get the scheme
    #[inline]
    pub fn scheme(&self) -> Scheme {
        <Self as ObtextCodec>::scheme(self)
    }

    /// Get the encoding
    #[inline]
    pub fn encoding(&self) -> Encoding {
        <Self as ObtextCodec>::encoding(self)
    }

    /// Get the key as base64
    #[inline]
    pub fn key(&self) -> String {
        <Self as ObtextCodec>::key(self)
    }

    #[cfg(feature = "hex-keys")]
    #[inline]
    pub fn key_hex(&self) -> String {
        <Self as ObtextCodec>::key_hex(self)
    }

    #[cfg(feature = "bytes-keys")]
    #[inline]
    pub fn key_bytes(&self) -> &[u8; 64] {
        <Self as ObtextCodec>::key_bytes(self)
    }
}

/// Trait for types that can be converted into a Format.
///
/// This trait is sealed and only implemented for `&str`, `Format`, and `&Format`.
pub trait IntoFormat: private::Sealed {
    /// Convert into a Format, possibly returning an error.
    fn into_format(self) -> Result<Format, Error>;
}

impl IntoFormat for &str {
    fn into_format(self) -> Result<Format, Error> {
        Format::from_str(self)
    }
}

impl IntoFormat for Format {
    fn into_format(self) -> Result<Format, Error> {
        Ok(self)
    }
}

impl IntoFormat for &Format {
    fn into_format(self) -> Result<Format, Error> {
        Ok(*self)
    }
}

// Seal the trait to prevent external implementations
mod private {
    pub trait Sealed {}
    impl Sealed for &str {}
    impl Sealed for super::Format {}
    impl Sealed for &super::Format {}
}
