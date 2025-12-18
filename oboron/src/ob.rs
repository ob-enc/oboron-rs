use crate::{ob_core::ObCore, Encoding, Error, Format, Oboron, Scheme};

/// An Oboron implementation with runtime format selection, fixed at construction.
///
/// Unlike scheme-specific types (`Ob32`, `Ob32Base64`) which embed the format
/// statically, `Ob` allows you to specify any format at runtime via
/// a constructor parameter.   However, unlike `ObFlex`, the format cannot be
/// changed after construction - `Ob` is immutable by design.
///
/// This provides a middle ground between compile-time format selection
/// (scheme-specific types) and full runtime flexibility (`ObFlex`).
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "ob32")]
/// # {
/// # use oboron::{Ob, Oboron, generate_key};
/// # let key = generate_key();
/// let ob = Ob::new("ob32:b64", &key)?;
/// let ot = ob.enc("hello")?; // obtext
/// let pt2 = ob.dec(&ot)?; // recovered plaintext
/// assert_eq!(pt2, "hello");
/// # }
/// # Ok(())
/// # }
/// ```
///
/// # Comparison with other types
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(all(feature = "ob32", feature = "non-crypto"))]
/// # {
/// # use oboron::{Ob, Ob32Base64, ObFlex, Oboron};
/// # let key = oboron::generate_key();
/// // Compile-time format (fastest, type-safe)
/// let ob32 = Ob32Base64::new(&key)?;
///
/// // Runtime format, immutable (flexible, still efficient)
/// let ob = Ob::new("ob32:b64", &key)?;
/// // assert!(ob.set_format("ob70:64").is_err()); // <- doesn't work! - format is locked
///
/// // Runtime format, mutable (maximum flexibility)
/// let mut flex = ObFlex::new("ob32:b64", &key)?;
/// flex.set_format("ob70:hex")?; // <- Can change format
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Ob {
    core: ObCore,
}

impl Ob {
    /// Create a new Ob with the specified format string and base64 key.
    ///
    /// The format is locked at construction and cannot be changed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "ob32")]
    /// # {
    /// # use oboron::Ob;
    /// # let key = oboron::generate_key();
    /// let ob = Ob::new("ob32:b64", &key)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(fmt: &str, key: &str) -> Result<Self, Error> {
        Ok(Self {
            core: ObCore::new(fmt, key)?,
        })
    }

    /// Get the format used by this Oboron instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "ob32")]
    /// # {
    /// # use oboron::{Ob, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// let ob = Ob::new("ob32:b64", &key)?;
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

    // Alt constructors ================================================
    //
    // 1. Alt format input ---
    //
    /// Create a new Ob with a borrowed Format and base64 key.
    ///
    /// This is most efficient when the same format is used repeatedly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature="keyless"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// let format = Format::new(Scheme::Ob32, Encoding::Base64);
    /// let ob = Ob::new_with_format(format, &key)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_with_format(format: Format, key: &str) -> Result<Self, Error> {
        Ok(Self {
            core: ObCore::new_with_format(format, key)?,
        })
    }

    // 1. Keyless (using HARDCODED_KEY_BYTES) ---
    //
    /// Create a new Ob with hardcoded key (testing only).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature="keyless"))]
    /// # {
    /// # use oboron::Ob;
    /// let ob = Ob::new_keyless("ob32:c32")?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "keyless")]
    pub fn new_keyless(fmt: &str) -> Result<Self, Error> {
        Ok(Self {
            core: ObCore::new_keyless(fmt)?,
        })
    }

    /// Create a new Ob with pre-parsed Format and hardcoded key (testing only).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature="keyless"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// let format = Format::new(Scheme::Ob32, Encoding::Base32Crockford);
    /// let ob = Ob::new_keyless_with_format(format)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "keyless")]
    pub fn new_keyless_with_format(format: Format) -> Result<Self, Error> {
        Ok(Self {
            core: ObCore::new_keyless_with_format(format)?,
        })
    }

    // 2. Alt key input
    //
    /// Create a new Ob with the specified format string and hex key.
    ///
    /// The format is locked at construction and cannot be changed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature="hex-keys"))]
    /// # {
    /// # use oboron::Ob;
    /// let key_hex = oboron::generate_key_hex();
    /// let ob = Ob::from_hex_key("ob32:b64", &key_hex)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "hex-keys")]
    pub fn from_hex_key(fmt: &str, key_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            core: ObCore::from_hex_key(fmt, key_hex)?,
        })
    }

    /// Create a new Ob from the specified format string and raw bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature="bytes-keys"))]
    /// # {
    /// # use oboron::Ob;
    /// let key_bytes = oboron::generate_key_bytes();
    /// let ob = Ob::from_bytes("ob32:b64", &key_bytes)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "bytes-keys")]
    pub fn from_bytes(fmt: &str, key: &[u8; 64]) -> Result<Self, Error> {
        Ok(Self {
            core: ObCore::from_bytes(fmt, key)?,
        })
    }

    /// Create a new Ob with a borrowed Format and hex key.
    ///
    /// This is most efficient when the same format is used repeatedly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature="hex-keys"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// let key_hex = oboron::generate_key_hex();
    /// let format = Format::new(Scheme::Ob32, Encoding::Base64);
    /// let ob = Ob::from_hex_key_with_format(format, &key_hex)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "hex-keys")]
    pub fn from_hex_key_with_format(format: Format, key_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            core: ObCore::from_hex_key_with_format(format, key_hex)?,
        })
    }

    /// Create a new Ob from a pre-parsed Format and raw bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "ob32", feature="bytes-keys"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// let key_bytes = oboron::generate_key_bytes();
    /// let format = Format::new(Scheme::Ob32, Encoding::Base64);
    /// let ob = Ob::from_bytes_with_format(format, &key_bytes)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "bytes-keys")]
    pub fn from_bytes_with_format(format: Format, key: &[u8; 64]) -> Result<Self, Error> {
        Ok(Self {
            core: ObCore::from_bytes_with_format(format, key)?,
        })
    }
}

impl Oboron for Ob {
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
