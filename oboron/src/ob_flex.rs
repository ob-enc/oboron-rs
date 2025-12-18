use crate::{ob_core::ObCore, Encoding, Error, Format, Oboron, Scheme};

/// A flexible Oboron implementation that allows changing schemes at runtime.
///
/// Unlike the scheme-specific types (`Ob01`, `Ob31Base64`, etc.) which are locked to
/// a single scheme+encoding at construction, `ObFlex` allows you to change the
/// scheme and encoding after creation using `set_format()`, `set_scheme()`, or `set_encoding()`.
///
/// This is useful for testing, comparison, or applications that need to switch
/// between schemes dynamically.
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(all(feature = "ob32", feature = "non-crypto"))]
/// # {
/// # use oboron::{Oboron, ObFlex, Scheme, Encoding, Format, OB32_HEX};
/// # let key = oboron::generate_key();
/// let mut ob = ObFlex::new("ob32:c32", &key)?;
/// let obtext = ob.enc("hello")?; // ob32:c32 format
///
/// // Switch to ob70 scheme (format remains c32)
/// ob.set_scheme(Scheme::Ob70)?;
/// let obtext = ob.enc("hello")?; // ob70:c32 format
///
/// // Switch to ob71:b64 using Format instance
/// ob.set_format(Format::new(Scheme::Ob71, Encoding::Base64))?;
/// let obtext = ob.enc("hello")?; // ob71:b64 format
///
/// // Switch to ob32:hex using string constant
/// ob.set_format(OB32_HEX)?;
/// let obtext = ob.enc("hello")?; // ob32:hex format
/// # }
/// # Ok(())
/// # }
///
/// ```
pub struct ObFlex {
    core: ObCore,
}

impl ObFlex {
    /// Create a new ObFlex with the specified format and base64 key.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "ob32")]
    /// # {
    /// # use oboron::{ObFlex, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// // Using format string
    /// let ob1 = ObFlex::new("ob32:b64", &key)?;
    ///
    /// // Same, using Format
    /// let format = Format::new(Scheme::Ob32, Encoding::Base64);
    /// let ob2 = ObFlex::new(format, &key)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(format: impl IntoFormat, key: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            core: ObCore::new_with_format(format, key)?,
        })
    }

    /// Create a new ObFlex with hardcoded key (testing only).
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature="keyless"))]
    /// # {
    /// # use oboron::{ObFlex, Format, Scheme, Encoding};
    /// // Using format string
    /// let ob1 = ObFlex::new_keyless("ob32:c32")?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Ob32, Encoding::Base32Crockford);
    /// let ob2 = ObFlex::new_keyless(format)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "keyless")]
    pub fn new_keyless(format: impl IntoFormat) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            core: ObCore::new_keyless_with_format(format)?,
        })
    }

    /// Get the current format.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "ob32")]
    /// # {
    /// # use oboron::{ObFlex, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// let ob = ObFlex::new("ob32:b64", &key)?;
    /// let format = ob.format();
    /// assert_eq!(format.scheme(), Scheme::Ob32);
    /// assert_eq!(format.encoding(), Encoding::Base64);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn format(&self) -> Format {
        self.core.format
    }

    /// Set the format to a new value.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature = "non-crypto"))]
    /// # {
    /// # use oboron::{ObFlex, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// let mut ob = ObFlex::new("ob32:c32", &key)?;
    /// ob.set_format("ob70:b64")?; // switch using string
    /// ob.set_format(Format::new(Scheme::Ob71, Encoding::Hex))?; // switch using Format
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_format(&mut self, format: impl IntoFormat) -> Result<(), Error> {
        self.core.format = format.into_format()?;
        Ok(())
    }

    /// Set the scheme while keeping the current encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature = "non-crypto"))]
    /// # {
    /// # use oboron::{ObFlex, Scheme};
    /// # let key = oboron::generate_key();
    /// let mut ob = ObFlex::new("ob32:c32", &key)? ;
    /// ob.set_scheme(Scheme::Ob70)?; // switch to ob70, keeping c32 encoding
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_scheme(&mut self, scheme: Scheme) -> Result<(), Error> {
        self.core.format = Format::new(scheme, self.core.format.encoding());
        Ok(())
    }

    /// Set the encoding while keeping the current scheme.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "ob32")]
    /// # {
    /// # use oboron::{ObFlex, Encoding};
    /// # let key = oboron::generate_key();
    /// let mut ob = ObFlex::new("ob32:c32", &key)?;
    /// ob.set_encoding(Encoding::Base64)?; // switch to b64, keeping ob32 scheme
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_encoding(&mut self, encoding: Encoding) -> Result<(), Error> {
        self.core.format = Format::new(self.core.format.scheme(), encoding);
        Ok(())
    }

    // Alt constructors ================================================

    /// Create a new ObFlex with the specified format and hex key.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature = "hex-keys"))]
    /// # {
    /// # use oboron::{ObFlex, Format, Scheme, Encoding};
    /// let key_hex = oboron::generate_key_hex();
    /// // Using format string
    /// let ob1 = ObFlex::from_hex_key("ob32:b64", &key_hex)?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Ob32, Encoding::Base64);
    /// let ob2 = ObFlex::from_hex_key(format, &key_hex)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "hex-keys")]
    pub fn from_hex_key(format: impl IntoFormat, key_hex: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            core: ObCore::from_hex_key_with_format(format, &key_hex)?,
        })
    }

    /// Create a new ObFlex from the specified format and raw key bytes.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature = "bytes-keys"))]
    /// # {
    /// # use oboron::{ObFlex, Format, Scheme, Encoding};
    /// let key_bytes = oboron::generate_key_bytes();
    /// let ob1 = ObFlex::from_bytes("ob32:b64", &key_bytes)?; // using format string
    /// let format = Format::new(Scheme::Ob32, Encoding::Base64); // using Format
    /// let ob2 = ObFlex::from_bytes(format, &key_bytes)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "bytes-keys")]
    pub fn from_bytes(format: impl IntoFormat, key: &[u8; 64]) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            core: ObCore::from_bytes_with_format(format, key)?,
        })
    }
}

impl Oboron for ObFlex {
    fn enc(&self, plaintext: &str) -> Result<String, Error> {
        self.core.enc(plaintext)
    }

    fn dec(&self, obtext: &str) -> Result<String, Error> {
        self.core.dec(obtext)
    }

    fn dec_strict(&self, obtext: &str) -> Result<String, Error> {
        self.core.dec_strict(obtext)
    }

    fn format(&self) -> Format {
        self.core.format()
    }

    fn scheme(&self) -> Scheme {
        self.core.scheme()
    }

    fn encoding(&self) -> Encoding {
        self.core.encoding()
    }

    fn key(&self) -> String {
        self.core.key()
    }

    #[cfg(feature = "hex-keys")]
    fn key_hex(&self) -> String {
        self.core.key_hex()
    }

    #[cfg(feature = "bytes-keys")]
    fn key_bytes(&self) -> &[u8; 64] {
        self.core.key_bytes()
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
