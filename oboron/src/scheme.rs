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
    #[cfg(feature = "mock")]
    Mock1,
    #[cfg(feature = "mock")]
    Mock2,
    // Legacy
    #[cfg(feature = "legacy")]
    Legacy,
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
            #[cfg(feature = "mock")]
            Scheme::Mock1 => "mock1",
            #[cfg(feature = "mock")]
            Scheme::Mock2 => "mock2",
            // Legacy
            #[cfg(feature = "legacy")]
            Scheme::Legacy => "legacy",
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
            #[cfg(feature = "mock")]
            Scheme::Mock1 => true,
            #[cfg(feature = "mock")]
            Scheme::Mock2 => true,
            // Legacy
            #[cfg(feature = "legacy")]
            Scheme::Legacy => true,
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
            #[cfg(feature = "mock")]
            Scheme::Mock1 => constants::MOCK1_BYTE,
            #[cfg(feature = "mock")]
            Scheme::Mock2 => constants::MOCK2_BYTE,
            // Legacy
            #[cfg(feature = "legacy")]
            Scheme::Legacy => unreachable!("legacy does not use a scheme byte"),
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
            #[cfg(feature = "mock")]
            "mock1" => Ok(Scheme::Mock1),
            #[cfg(feature = "mock")]
            "mock2" => Ok(Scheme::Mock2),
            // Legacy
            #[cfg(feature = "legacy")]
            "legacy" => Ok(Scheme::Legacy),
            _ => Err(Error::UnknownScheme),
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
