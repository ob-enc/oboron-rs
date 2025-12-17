//! Scheme identifiers for oboron encryption schemes.

use crate::{constants, error::Error};

/// Scheme identifier for oboron encoding schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    #[cfg(feature = "ob01")]
    Ob01,
    #[cfg(feature = "ob21p")]
    Ob21p,
    #[cfg(feature = "ob31")]
    Ob31,
    #[cfg(feature = "ob31p")]
    Ob31p,
    #[cfg(feature = "ob32")]
    Ob32,
    #[cfg(feature = "ob32p")]
    Ob32p,
    // Testing
    #[cfg(feature = "ob70")]
    Ob70,
    #[cfg(feature = "ob71")]
    Ob71,
    // Legacy
    #[cfg(feature = "ob00")]
    Ob00,
}

impl Scheme {
    /// Convert scheme to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            #[cfg(feature = "ob01")]
            Scheme::Ob01 => "ob01",
            #[cfg(feature = "ob21p")]
            Scheme::Ob21p => "ob21p",
            #[cfg(feature = "ob31")]
            Scheme::Ob31 => "ob31",
            #[cfg(feature = "ob31p")]
            Scheme::Ob31p => "ob31p",
            #[cfg(feature = "ob32")]
            Scheme::Ob32 => "ob32",
            #[cfg(feature = "ob32p")]
            Scheme::Ob32p => "ob32p",
            // Testing
            #[cfg(feature = "ob70")]
            Scheme::Ob70 => "ob70",
            #[cfg(feature = "ob71")]
            Scheme::Ob71 => "ob71",
            // Legacy
            #[cfg(feature = "ob00")]
            Scheme::Ob00 => "ob00",
        }
    }

    /// Parse scheme from string.
    pub fn from_str(s: &str) -> Result<Self, Error> {
        s.parse()
    }

    /// Check if this scheme is deterministic (produces the same output for the same input).
    pub fn is_deterministic(&self) -> bool {
        match self {
            #[cfg(feature = "ob01")]
            Scheme::Ob01 => true,
            #[cfg(feature = "ob21p")]
            Scheme::Ob21p => false,
            #[cfg(feature = "ob31")]
            Scheme::Ob31 => true,
            #[cfg(feature = "ob31p")]
            Scheme::Ob31p => false,
            #[cfg(feature = "ob32")]
            Scheme::Ob32 => true,
            #[cfg(feature = "ob32p")]
            Scheme::Ob32p => false,
            // Testing
            #[cfg(feature = "ob70")]
            Scheme::Ob70 => true,
            #[cfg(feature = "ob71")]
            Scheme::Ob71 => true,
            // Legacy
            #[cfg(feature = "ob00")]
            Scheme::Ob00 => true,
        }
    }

    /// Check if this scheme is probabilistic (produces different output each time).
    pub fn is_probabilistic(&self) -> bool {
        !self.is_deterministic()
    }

    /// Only schemes that need byte reversal for prefix entropy maximization use it
    pub fn is_ciphertext_reversed(&self) -> bool {
        constants::REVERSED_SCHEME_BYTES.contains(&self.byte())
    }

    /// Get the tail byte for this scheme.
    pub fn byte(&self) -> u8 {
        match self {
            #[cfg(feature = "ob01")]
            Scheme::Ob01 => constants::OB01_BYTE,
            #[cfg(feature = "ob21p")]
            Scheme::Ob21p => constants::OB21P_BYTE,
            #[cfg(feature = "ob31")]
            Scheme::Ob31 => constants::OB31_BYTE,
            #[cfg(feature = "ob31p")]
            Scheme::Ob31p => constants::OB31P_BYTE,
            #[cfg(feature = "ob32")]
            Scheme::Ob32 => constants::OB32_BYTE,
            #[cfg(feature = "ob32p")]
            Scheme::Ob32p => constants::OB32P_BYTE,
            // Testing
            #[cfg(feature = "ob70")]
            Scheme::Ob70 => constants::OB70_BYTE,
            #[cfg(feature = "ob71")]
            Scheme::Ob71 => constants::OB71_BYTE,
            // Legacy
            #[cfg(feature = "ob00")]
            Scheme::Ob00 => unreachable!("ob00 does not use a scheme byte"),
        }
    }
}

impl std::str::FromStr for Scheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "ob01")]
            "ob01" => Ok(Scheme::Ob01),
            #[cfg(feature = "ob21p")]
            "ob21p" => Ok(Scheme::Ob21p),
            #[cfg(feature = "ob31")]
            "ob31" => Ok(Scheme::Ob31),
            #[cfg(feature = "ob31p")]
            "ob31p" => Ok(Scheme::Ob31p),
            #[cfg(feature = "ob32")]
            "ob32" => Ok(Scheme::Ob32),
            #[cfg(feature = "ob32p")]
            "ob32p" => Ok(Scheme::Ob32p),
            // Testing
            #[cfg(feature = "ob70")]
            "ob70" => Ok(Scheme::Ob70),
            #[cfg(feature = "ob71")]
            "ob71" => Ok(Scheme::Ob71),
            // Legacy
            #[cfg(feature = "ob00")]
            "ob00" => Ok(Scheme::Ob00),
            _ => Err(Error::UnknownScheme),
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
