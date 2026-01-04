//! Oz - Flexible z-tier codec with runtime format selection
//!
//! ⚠️ **WARNING**: Z-tier schemes provide NO cryptographic security.
//! Use only for obfuscation, never for actual encryption.

#![cfg(feature = "ztier")]

#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_SECRET_BYTES;
use crate::{format::IntoFormat, Encoding, Error, Format, ObtextCodec, Scheme};

use super::zdec_auto;
use super::zkeychain::ZKeychain;

/// A flexible z-tier codec with runtime format selection.
///
/// `Oz` is the z-tier equivalent of `Ob`, allowing runtime format selection
/// for obfuscation-only schemes (zrbcx, legacy).
///
/// **WARNING**: Z-tier schemes provide NO cryptographic security.
/// Use only for obfuscation, never for actual encryption.
///
/// # Examples
///
/// ## Basic usage with immutable format
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "zrbcx")]
/// # {
/// # use oboron::ztier::Oz;
/// # let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
/// let oz = Oz::new("zrbcx.b64", secret)?;
/// let ot = oz.enc("hello")?;
/// let pt2 = oz.dec(&ot)?;
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
/// # #[cfg(all(feature = "zrbcx", feature = "zmock"))]
/// # {
/// # use oboron::ztier::Oz;
/// # use oboron::{Scheme, Encoding, Format};
/// # let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// let mut oz = Oz::new("zrbcx.c32", secret)?;
/// let ot1 = oz.enc("hello")?;
///
/// // Change format at runtime
/// oz.set_scheme(Scheme::Zmock1)?;
/// let ot2 = oz.enc("hello")?; // now zmock1.c32
///
/// // Change encoding
/// oz.set_encoding(Encoding::B64)?; // now zmock1.b64
///
/// // Set entire format at once
/// oz.set_format("zrbcx.hex")?; // now zrbcx.hex
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Oz {
    zkeychain: ZKeychain,
    format: Format,
}

impl Oz {
    /// Create a new Oz with the specified format and base64 secret.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Oz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// # let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// // Using format string
    /// let oz1 = Oz::new("zrbcx.b64", secret)?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Zrbcx, Encoding::B64);
    /// let oz2 = Oz::new(format, secret)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(format: impl IntoFormat, secret: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        Ok(Self {
            zkeychain: ZKeychain::from_base64(secret)?,
            format,
        })
    }

    /// Get the current format.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Oz;
    /// # use oboron::{Scheme, Encoding};
    /// # let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// let oz = Oz::new("zrbcx.b64", secret)?;
    /// let format = oz.format();
    /// assert_eq!(format.scheme(), Scheme::Zrbcx);
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
    /// # #[cfg(all(feature = "zrbcx", feature = "legacy"))]
    /// # {
    /// # use oboron::ztier::Oz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// # let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// let mut oz = Oz::new("zrbcx.c32", secret)?;
    /// oz.set_format("legacy.b64")?; // switch using string
    /// oz.set_format(Format::new(Scheme::Zrbcx, Encoding::Hex))?; // switch using Format
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_format(&mut self, format: impl IntoFormat) -> Result<(), Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        self.format = format;
        Ok(())
    }

    /// Set the scheme while keeping the current encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx", feature = "legacy"))]
    /// # {
    /// # use oboron::ztier::Oz;
    /// # use oboron::Scheme;
    /// # let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// let mut oz = Oz::new("zrbcx.c32", secret)?;
    /// oz.set_scheme(Scheme::Legacy)?; // switch to legacy, keeping c32 encoding
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_scheme(&mut self, scheme: Scheme) -> Result<(), Error> {
        validate_ztier_scheme(scheme)?;
        self.format = Format::new(scheme, self.format.encoding());
        Ok(())
    }

    /// Set the encoding while keeping the current scheme.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Oz;
    /// # use oboron::Encoding;
    /// # let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// let mut oz = Oz::new("zrbcx.c32", secret)?;
    /// oz.set_encoding(Encoding::B64)?; // switch to b64, keeping zrbcx scheme
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
    /// Falls back to legacy decoding if scheme detection fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx"))]
    /// # {
    /// # use oboron::ztier::Oz;
    /// # let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// let mut oz = Oz::new("zrbcx.b64", secret)?;
    /// let ot = oz.enc("test")?;
    /// let pt2 = oz.autodec(&ot)?;
    /// assert_eq!(pt2, "test");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn autodec(&self, obtext: &str) -> Result<String, Error> {
        // Fast path: try current encoding first
        if let Ok(result) =
            zdec_auto::dec_any_scheme_ztier(&self.zkeychain, self.format.encoding(), obtext)
        {
            return Ok(result);
        }
        zdec_auto::dec_any_format_ztier(&self.zkeychain, obtext)
    }

    // Alt constructors ================================================

    /// Create a new Oz with hardcoded secret (testing only).
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx", feature = "keyless"))]
    /// # {
    /// # use oboron::ztier::Oz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// // Using format string
    /// let oz1 = Oz::new_keyless("zrbcx.c32")?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Zrbcx, Encoding::C32);
    /// let oz2 = Oz::new_keyless(format)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "keyless")]
    pub fn new_keyless(format: impl IntoFormat) -> Result<Self, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        Ok(Self {
            zkeychain: ZKeychain::from_bytes(&HARDCODED_SECRET_BYTES)?,
            format,
        })
    }

    /// Create a new Oz with the specified format and hex secret.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx", feature = "hex-keys"))]
    /// # {
    /// # use oboron::ztier::Oz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// let secret_hex = "0". repeat(64); // 32 bytes as hex
    /// // Using format string
    /// let oz1 = Oz::from_hex_key("zrbcx.b64", &secret_hex)?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Zrbcx, Encoding::B64);
    /// let oz2 = Oz::from_hex_key(format, &secret_hex)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "hex-keys")]
    pub fn from_hex_key(format: impl IntoFormat, secret_hex: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        Ok(Self {
            zkeychain: ZKeychain::from_hex(secret_hex)?,
            format,
        })
    }

    /// Create a new Oz from the specified format and raw secret bytes.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx", feature = "bytes-keys"))]
    /// # {
    /// # use oboron::ztier::Oz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// let secret_bytes = [0u8; 32];
    /// let oz1 = Oz::from_bytes("zrbcx.b64", &secret_bytes)?; // using format string
    /// let format = Format::new(Scheme::Zrbcx, Encoding::B64); // using Format
    /// let oz2 = Oz::from_bytes(format, &secret_bytes)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "bytes-keys")]
    pub fn from_bytes(format: impl IntoFormat, secret: &[u8; 32]) -> Result<Self, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        Ok(Self {
            zkeychain: ZKeychain::from_bytes(secret)?,
            format,
        })
    }

    /// Get the secret as base64 (z-tier specific, 32 bytes)
    #[inline]
    pub fn secret(&self) -> String {
        self.zkeychain.secret_base64()
    }

    /// Get the secret as hex (z-tier specific, 32 bytes)
    #[inline]
    #[cfg(feature = "hex-keys")]
    pub fn secret_hex(&self) -> String {
        self.zkeychain.secret_hex()
    }

    /// Get the secret as bytes (z-tier specific, 32 bytes)
    #[inline]
    #[cfg(feature = "bytes-keys")]
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.zkeychain.secret_bytes()
    }
}

impl ObtextCodec for Oz {
    fn enc(&self, plaintext: &str) -> Result<String, Error> {
        let extracted_key = self.zkeychain.extract_secret(self.scheme())?;
        crate::enc::enc_to_format(plaintext, self.format, extracted_key)
    }

    fn dec(&self, obtext: &str) -> Result<String, Error> {
        let extracted_key = self.zkeychain.extract_secret(self.format.scheme())?;
        crate::dec::dec_from_format(obtext, self.format, extracted_key)
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
}

// Add inherent methods that delegate to trait methods
impl Oz {
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
}

/// Helper function to validate that a scheme is a z-tier scheme
fn validate_ztier_scheme(scheme: Scheme) -> Result<(), Error> {
    match scheme {
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => Ok(()),
        #[cfg(feature = "zmock")]
        Scheme::Zmock1 => Ok(()),
        #[cfg(feature = "legacy")]
        Scheme::Legacy => Ok(()),
        _ => Err(Error::InvalidScheme),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_oz_basic() {
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
        let oz = Oz::new("zrbcx.b64", secret).unwrap();

        let plaintext = "hello world";
        let ot = oz.enc(plaintext).unwrap();
        let pt2 = oz.dec(&ot).unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_oz_format_switching() {
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut oz = Oz::new("zrbcx.c32", secret).unwrap();

        assert_eq!(oz.encoding(), Encoding::C32);

        oz.set_encoding(Encoding::B64).unwrap();
        assert_eq!(oz.encoding(), Encoding::B64);
    }

    #[test]
    #[cfg(all(feature = "zrbcx", feature = "legacy"))]
    fn test_oz_scheme_switching() {
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut oz = Oz::new("zrbcx.b64", secret).unwrap();

        assert_eq!(oz.scheme(), Scheme::Zrbcx);

        oz.set_scheme(Scheme::Legacy).unwrap();
        assert_eq!(oz.scheme(), Scheme::Legacy);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_oz_rejects_non_ztier_scheme() {
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        #[cfg(feature = "aasv")]
        {
            let result = Oz::new("aasv.b64", secret);
            assert!(result.is_err());
        }
    }
}
