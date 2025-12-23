//! Format combines a scheme (encryption method) with an encoding (text representation).  

use crate::constants;
use crate::{encoding::Encoding, error::Error, scheme::Scheme};

/// Format combines a scheme (encryption method) with an encoding (text representation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Format {
    scheme: Scheme,
    encoding: Encoding,
}

impl Format {
    /// Create a new format with the specified scheme and encoding.
    pub fn new(scheme: Scheme, encoding: Encoding) -> Self {
        Self { scheme, encoding }
    }

    /// Create a format with the specified scheme and default Base32 encoding.
    pub fn with_scheme(scheme: Scheme) -> Self {
        Self::new(scheme, Encoding::C32)
    }

    /// Get the scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Get the encoding.
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Parse format from compact string representation (e.g., "zrbcx.c32", "aags.b64")
    ///
    /// This uses fast match-based parsing for maximum performance.
    pub fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            #[cfg(feature = "zrbcx")]
            constants::ZRBCX_C32 => Format::new(Scheme::Zrbcx, Encoding::C32),
            #[cfg(feature = "zrbcx")]
            constants::ZRBCX_B32 => Format::new(Scheme::Zrbcx, Encoding::B32),
            #[cfg(feature = "zrbcx")]
            constants::ZRBCX_B64 => Format::new(Scheme::Zrbcx, Encoding::B64),
            #[cfg(feature = "zrbcx")]
            constants::ZRBCX_HEX => Format::new(Scheme::Zrbcx, Encoding::Hex),

            #[cfg(feature = "upbc")]
            constants::UPBC_C32 => Format::new(Scheme::Upbc, Encoding::C32),
            #[cfg(feature = "upbc")]
            constants::UPBC_B32 => Format::new(Scheme::Upbc, Encoding::B32),
            #[cfg(feature = "upbc")]
            constants::UPBC_B64 => Format::new(Scheme::Upbc, Encoding::B64),
            #[cfg(feature = "upbc")]
            constants::UPBC_HEX => Format::new(Scheme::Upbc, Encoding::Hex),

            #[cfg(feature = "aags")]
            constants::AAGS_C32 => Format::new(Scheme::Aags, Encoding::C32),
            #[cfg(feature = "aags")]
            constants::AAGS_B32 => Format::new(Scheme::Aags, Encoding::B32),
            #[cfg(feature = "aags")]
            constants::AAGS_B64 => Format::new(Scheme::Aags, Encoding::B64),
            #[cfg(feature = "aags")]
            constants::AAGS_HEX => Format::new(Scheme::Aags, Encoding::Hex),

            #[cfg(feature = "apgs")]
            constants::APGS_C32 => Format::new(Scheme::Apgs, Encoding::C32),
            #[cfg(feature = "apgs")]
            constants::APGS_B32 => Format::new(Scheme::Apgs, Encoding::B32),
            #[cfg(feature = "apgs")]
            constants::APGS_B64 => Format::new(Scheme::Apgs, Encoding::B64),
            #[cfg(feature = "apgs")]
            constants::APGS_HEX => Format::new(Scheme::Apgs, Encoding::Hex),

            #[cfg(feature = "aasv")]
            constants::AASV_C32 => Format::new(Scheme::Aasv, Encoding::C32),
            #[cfg(feature = "aasv")]
            constants::AASV_B32 => Format::new(Scheme::Aasv, Encoding::B32),
            #[cfg(feature = "aasv")]
            constants::AASV_B64 => Format::new(Scheme::Aasv, Encoding::B64),
            #[cfg(feature = "aasv")]
            constants::AASV_HEX => Format::new(Scheme::Aasv, Encoding::Hex),

            #[cfg(feature = "apsv")]
            constants::APSV_C32 => Format::new(Scheme::Apsv, Encoding::C32),
            #[cfg(feature = "apsv")]
            constants::APSV_B32 => Format::new(Scheme::Apsv, Encoding::B32),
            #[cfg(feature = "apsv")]
            constants::APSV_B64 => Format::new(Scheme::Apsv, Encoding::B64),
            #[cfg(feature = "apsv")]
            constants::APSV_HEX => Format::new(Scheme::Apsv, Encoding::Hex),

            // Testing

            // mock1 variants
            #[cfg(feature = "mock")]
            constants::MOCK1_C32 => Format::new(Scheme::Mock1, Encoding::C32),
            #[cfg(feature = "mock")]
            constants::MOCK1_B32 => Format::new(Scheme::Mock1, Encoding::B32),
            #[cfg(feature = "mock")]
            constants::MOCK1_B64 => Format::new(Scheme::Mock1, Encoding::B64),
            #[cfg(feature = "mock")]
            constants::MOCK1_HEX => Format::new(Scheme::Mock1, Encoding::Hex),

            // mock2 variants
            #[cfg(feature = "mock")]
            constants::MOCK2_C32 => Format::new(Scheme::Mock2, Encoding::C32),
            #[cfg(feature = "mock")]
            constants::MOCK2_B32 => Format::new(Scheme::Mock2, Encoding::B32),
            #[cfg(feature = "mock")]
            constants::MOCK2_B64 => Format::new(Scheme::Mock2, Encoding::B64),
            #[cfg(feature = "mock")]
            constants::MOCK2_HEX => Format::new(Scheme::Mock2, Encoding::Hex),

            // Legacy

            // legacy variants
            #[cfg(feature = "legacy")]
            constants::LEGACY_C32 => Format::new(Scheme::Legacy, Encoding::C32),
            #[cfg(feature = "legacy")]
            constants::LEGACY_B32 => Format::new(Scheme::Legacy, Encoding::B32),
            #[cfg(feature = "legacy")]
            constants::LEGACY_B64 => Format::new(Scheme::Legacy, Encoding::B64),
            #[cfg(feature = "legacy")]
            constants::LEGACY_HEX => Format::new(Scheme::Legacy, Encoding::Hex),

            _ => return Err(Error::InvalidFormat),
        })
    }
}

impl std::str::FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Format::from_str(s)
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.scheme.as_str(), self.encoding.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_from_str_all_combinations() {
        // Define all schemes
        let schemes = vec![
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx,
            #[cfg(feature = "upbc")]
            Scheme::Upbc,
            #[cfg(feature = "aags")]
            Scheme::Aags,
            #[cfg(feature = "apgs")]
            Scheme::Apgs,
            #[cfg(feature = "aasv")]
            Scheme::Aasv,
            #[cfg(feature = "apsv")]
            Scheme::Apsv,
            // Testing
            #[cfg(feature = "mock")]
            Scheme::Mock1,
            #[cfg(feature = "mock")]
            Scheme::Mock2,
            // Legacy
            #[cfg(feature = "legacy")]
            Scheme::Legacy,
        ];

        // Define all encodings
        let encodings = vec![Encoding::C32, Encoding::B32, Encoding::B64, Encoding::Hex];

        for scheme in &schemes {
            for encoding in &encodings {
                // Test short string identifiers (e.g., "zrbcx.c32", "zrbcx.b32")
                let format_str = format!("{}.{}", scheme.as_str(), encoding.as_str());
                let result = Format::from_str(&format_str);
                assert!(result.is_ok(), "Failed to parse: {}", format_str);
                let format = result.unwrap();
                assert_eq!(
                    format.scheme(),
                    *scheme,
                    "Scheme mismatch for {}",
                    format_str
                );
                assert_eq!(
                    format.encoding(),
                    *encoding,
                    "Encoding mismatch for {}",
                    format_str
                );
            }
        }
    }

    #[test]
    fn test_format_from_str_invalid() {
        // Test invalid format strings
        assert!(Format::from_str("invalid").is_err());
        assert!(Format::from_str("zrbcx").is_err());
        assert!(Format::from_str("zrbcx.").is_err());
        assert!(Format::from_str(".b64").is_err());
        assert!(Format::from_str("mock1:invalid").is_err());
    }

    #[test]
    fn test_format_to_string_roundtrip() {
        // Define test cases: (scheme, encoding, expected_string)
        #[cfg(feature = "mock")]
        let mut test_cases = vec![
            (Scheme::Mock2, Encoding::C32, "mock2.c32"),
            (Scheme::Mock2, Encoding::B32, "mock2.b32"),
            (Scheme::Mock2, Encoding::B64, "mock2.b64"),
            (Scheme::Mock2, Encoding::Hex, "mock2.hex"),
            (Scheme::Mock1, Encoding::C32, "mock1.c32"),
            (Scheme::Mock1, Encoding::B32, "mock1.b32"),
            (Scheme::Mock1, Encoding::B64, "mock1.b64"),
            (Scheme::Mock1, Encoding::Hex, "mock1.hex"),
        ];

        #[cfg(feature = "legacy")]
        test_cases.extend(vec![
            (Scheme::Legacy, Encoding::C32, "legacy.c32"),
            (Scheme::Legacy, Encoding::B32, "legacy.b32"),
            (Scheme::Legacy, Encoding::B64, "legacy.b64"),
            (Scheme::Legacy, Encoding::Hex, "legacy.hex"),
        ]);

        #[cfg(feature = "zrbcx")]
        test_cases.extend(vec![
            (Scheme::Zrbcx, Encoding::C32, "zrbcx.c32"),
            (Scheme::Zrbcx, Encoding::B32, "zrbcx.b32"),
            (Scheme::Zrbcx, Encoding::B64, "zrbcx.b64"),
            (Scheme::Zrbcx, Encoding::Hex, "zrbcx.hex"),
        ]);

        #[cfg(feature = "upbc")]
        test_cases.extend(vec![
            (Scheme::Upbc, Encoding::C32, "upbc.c32"),
            (Scheme::Upbc, Encoding::B32, "upbc.b32"),
            (Scheme::Upbc, Encoding::B64, "upbc.b64"),
            (Scheme::Upbc, Encoding::Hex, "upbc.hex"),
        ]);

        #[cfg(feature = "aags")]
        test_cases.extend(vec![
            (Scheme::Aags, Encoding::C32, "aags.c32"),
            (Scheme::Aags, Encoding::B32, "aags.b32"),
            (Scheme::Aags, Encoding::B64, "aags.b64"),
            (Scheme::Aags, Encoding::Hex, "aags.hex"),
        ]);

        #[cfg(feature = "apgs")]
        test_cases.extend(vec![
            (Scheme::Apgs, Encoding::C32, "apgs.c32"),
            (Scheme::Apgs, Encoding::B32, "apgs.b32"),
            (Scheme::Apgs, Encoding::B64, "apgs.b64"),
            (Scheme::Apgs, Encoding::Hex, "apgs.hex"),
        ]);

        #[cfg(feature = "aasv")]
        test_cases.extend(vec![
            (Scheme::Aasv, Encoding::C32, "aasv.c32"),
            (Scheme::Aasv, Encoding::B32, "aasv.b32"),
            (Scheme::Aasv, Encoding::B64, "aasv.b64"),
            (Scheme::Aasv, Encoding::Hex, "aasv.hex"),
        ]);

        #[cfg(feature = "apsv")]
        test_cases.extend(vec![
            (Scheme::Apsv, Encoding::C32, "apsv.c32"),
            (Scheme::Apsv, Encoding::B32, "apsv.b32"),
            (Scheme::Apsv, Encoding::B64, "apsv.b64"),
            (Scheme::Apsv, Encoding::Hex, "apsv.hex"),
        ]);

        for (scheme, encoding, expected_str) in test_cases {
            // Test Format::to_string()
            let format = Format::new(scheme, encoding);
            let format_str = format.to_string();
            assert_eq!(
                format_str, expected_str,
                "Format string mismatch for {:? }.{:? }",
                scheme, encoding
            );

            // Test roundtrip: parse it back
            let parsed = Format::from_str(&format_str).unwrap();
            assert_eq!(
                parsed.scheme(),
                scheme,
                "Scheme mismatch after roundtrip for {}",
                format_str
            );
            assert_eq!(
                parsed.encoding(),
                encoding,
                "Encoding mismatch after roundtrip for {}",
                format_str
            );
        }
    }

    #[test]
    #[cfg(feature = "legacy")]
    fn test_legacy_supports_both_base32_variants() {
        // legacy should support both B32 and C32
        let format_rfc = Format::from_str("legacy.b32").unwrap();
        assert_eq!(format_rfc.scheme(), Scheme::Legacy);
        assert_eq!(format_rfc.encoding(), Encoding::B32);

        let format_crock = Format::from_str("legacy.c32").unwrap();
        assert_eq!(format_crock.scheme(), Scheme::Legacy);
        assert_eq!(format_crock.encoding(), Encoding::C32);
    }

    #[test]
    #[cfg(all(feature = "all-schemes", feature = "mock"))]
    fn test_all_schemes_support_both_base32_variants() {
        // All schemes should support both RFC 4648 base32 (b32) and Crockford base32 (c32)
        let schemes = vec![
            "zrbcx", "upbc", "aags", "apgs", "aasv", "apsv", "mock1", "mock2",
        ];

        for scheme_str in schemes {
            // Test Crockford base32 (c32)
            let format_str_crock = format!("{}.c32", scheme_str);
            let result_crock = Format::from_str(&format_str_crock);
            if result_crock.is_ok() {
                // Only test if feature is enabled
                assert_eq!(
                    result_crock.unwrap().encoding(),
                    Encoding::C32,
                    "{} should support c32",
                    scheme_str
                );
            }

            // Test RFC 4648 base32 (b32)
            let format_str_rfc = format!("{}.b32", scheme_str);
            let result_rfc = Format::from_str(&format_str_rfc);
            if result_rfc.is_ok() {
                // Only test if feature is enabled
                assert_eq!(
                    result_rfc.unwrap().encoding(),
                    Encoding::B32,
                    "{} should support b32",
                    scheme_str
                );
            }
        }
    }
}
