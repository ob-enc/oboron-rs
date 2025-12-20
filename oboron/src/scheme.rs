//! Scheme identifiers for oboron encryption schemes.

use crate::{constants, error::Error};

/// Scheme identifier for oboron encoding schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    #[cfg(feature = "zdc")]
    Zdc,
    #[cfg(feature = "upc")]
    Upc,
    #[cfg(feature = "adgs")]
    Adgs,
    #[cfg(feature = "apgs")]
    Apgs,
    #[cfg(feature = "adsv")]
    Adsv,
    #[cfg(feature = "apsv")]
    Apsv,
    // Testing
    #[cfg(feature = "tdi")]
    Tdi,
    #[cfg(feature = "tdr")]
    Tdr,
    // Legacy
    #[cfg(feature = "ob00")]
    Ob00,
}

impl Scheme {
    /// Convert scheme to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            #[cfg(feature = "zdc")]
            Scheme::Zdc => "zdc",
            #[cfg(feature = "upc")]
            Scheme::Upc => "upc",
            #[cfg(feature = "adgs")]
            Scheme::Adgs => "adgs",
            #[cfg(feature = "apgs")]
            Scheme::Apgs => "apgs",
            #[cfg(feature = "adsv")]
            Scheme::Adsv => "adsv",
            #[cfg(feature = "apsv")]
            Scheme::Apsv => "apsv",
            // Testing
            #[cfg(feature = "tdi")]
            Scheme::Tdi => "tdi",
            #[cfg(feature = "tdr")]
            Scheme::Tdr => "tdr",
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
            #[cfg(feature = "zdc")]
            Scheme::Zdc => true,
            #[cfg(feature = "upc")]
            Scheme::Upc => false,
            #[cfg(feature = "adgs")]
            Scheme::Adgs => true,
            #[cfg(feature = "apgs")]
            Scheme::Apgs => false,
            #[cfg(feature = "adsv")]
            Scheme::Adsv => true,
            #[cfg(feature = "apsv")]
            Scheme::Apsv => false,
            // Testing
            #[cfg(feature = "tdi")]
            Scheme::Tdi => true,
            #[cfg(feature = "tdr")]
            Scheme::Tdr => true,
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
            #[cfg(feature = "zdc")]
            Scheme::Zdc => constants::ZDC_BYTE,
            #[cfg(feature = "upc")]
            Scheme::Upc => constants::UPC_BYTE,
            #[cfg(feature = "adgs")]
            Scheme::Adgs => constants::ADGS_BYTE,
            #[cfg(feature = "apgs")]
            Scheme::Apgs => constants::APGS_BYTE,
            #[cfg(feature = "adsv")]
            Scheme::Adsv => constants::ADSV_BYTE,
            #[cfg(feature = "apsv")]
            Scheme::Apsv => constants::APSV_BYTE,
            // Testing
            #[cfg(feature = "tdi")]
            Scheme::Tdi => constants::TDI_BYTE,
            #[cfg(feature = "tdr")]
            Scheme::Tdr => constants::TDR_BYTE,
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
            #[cfg(feature = "zdc")]
            "zdc" => Ok(Scheme::Zdc),
            #[cfg(feature = "upc")]
            "upc" => Ok(Scheme::Upc),
            #[cfg(feature = "adgs")]
            "adgs" => Ok(Scheme::Adgs),
            #[cfg(feature = "apgs")]
            "apgs" => Ok(Scheme::Apgs),
            #[cfg(feature = "adsv")]
            "adsv" => Ok(Scheme::Adsv),
            #[cfg(feature = "apsv")]
            "apsv" => Ok(Scheme::Apsv),
            // Testing
            #[cfg(feature = "tdi")]
            "tdi" => Ok(Scheme::Tdi),
            #[cfg(feature = "tdr")]
            "tdr" => Ok(Scheme::Tdr),
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
