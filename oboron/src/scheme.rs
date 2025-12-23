//! Scheme identifiers for oboron encryption schemes.

use crate::{constants, error::Error};

/// Scheme identifier for oboron encoding schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    #[cfg(feature = "zrbcx")]
    Zrbcx,
    #[cfg(feature = "upbc")]
    Upbc,
    #[cfg(feature = "aags")]
    Aags,
    #[cfg(feature = "apgs")]
    Apgs,
    #[cfg(feature = "aasv")]
    Aasv,
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
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx => "zrbcx",
            #[cfg(feature = "upbc")]
            Scheme::Upbc => "upbc",
            #[cfg(feature = "aags")]
            Scheme::Aags => "aags",
            #[cfg(feature = "apgs")]
            Scheme::Apgs => "apgs",
            #[cfg(feature = "aasv")]
            Scheme::Aasv => "aasv",
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
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx => true,
            #[cfg(feature = "upbc")]
            Scheme::Upbc => false,
            #[cfg(feature = "aags")]
            Scheme::Aags => true,
            #[cfg(feature = "apgs")]
            Scheme::Apgs => false,
            #[cfg(feature = "aasv")]
            Scheme::Aasv => true,
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
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx => constants::ZRBCX_BYTE,
            #[cfg(feature = "upbc")]
            Scheme::Upbc => constants::UPBC_BYTE,
            #[cfg(feature = "aags")]
            Scheme::Aags => constants::AAGS_BYTE,
            #[cfg(feature = "apgs")]
            Scheme::Apgs => constants::APGS_BYTE,
            #[cfg(feature = "aasv")]
            Scheme::Aasv => constants::AASV_BYTE,
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
            #[cfg(feature = "zrbcx")]
            "zrbcx" => Ok(Scheme::Zrbcx),
            #[cfg(feature = "upbc")]
            "upbc" => Ok(Scheme::Upbc),
            #[cfg(feature = "aags")]
            "aags" => Ok(Scheme::Aags),
            #[cfg(feature = "apgs")]
            "apgs" => Ok(Scheme::Apgs),
            #[cfg(feature = "aasv")]
            "aasv" => Ok(Scheme::Aasv),
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
