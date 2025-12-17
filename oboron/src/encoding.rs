//! Text encoding identifiers for oboron output.

use crate::error::Error;

/// Encoding identifier for text representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Base32Rfc,
    Base32Crockford,
    Base64,
    Hex,
}

impl Encoding {
    /// Convert encoding to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Encoding::Base32Crockford => "base32crockford",
            Encoding::Base32Rfc => "base32rfc",
            Encoding::Base64 => "base64",
            Encoding::Hex => "hex",
        }
    }

    /// Convert encoding to abbreviated string representation (for format strings).
    pub fn as_short_str(&self) -> &'static str {
        match self {
            Encoding::Base32Crockford => "c32",
            Encoding::Base32Rfc => "b32",
            Encoding::Base64 => "b64",
            Encoding::Hex => "hex",
        }
    }

    /// Parse encoding from string.
    pub fn from_str(s: &str) -> Result<Self, Error> {
        s.parse()
    }
}

impl std::str::FromStr for Encoding {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            // Full names
            "base32crockford" => Ok(Encoding::Base32Crockford),
            "base32rfc" => Ok(Encoding::Base32Rfc),
            "base64" => Ok(Encoding::Base64),
            "hex" => Ok(Encoding::Hex),
            // Abbreviations (for format strings)
            "b32" => Ok(Encoding::Base32Rfc),
            "c32" => Ok(Encoding::Base32Crockford),
            "b64" => Ok(Encoding::Base64),
            _ => Err(Error::UnknownEncoding),
        }
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
