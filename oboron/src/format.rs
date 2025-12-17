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
        Self::new(scheme, Encoding::Base32Crockford)
    }

    /// Get the scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Get the encoding.
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Parse format from compact string representation (e.g., "ob01:c32", "ob31:b64")
    ///
    /// This uses fast match-based parsing for maximum performance.
    pub fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            #[cfg(feature = "ob01")]
            constants::OB01_C32 => Format::new(Scheme::Ob01, Encoding::Base32Crockford),
            #[cfg(feature = "ob01")]
            constants::OB01_B32 => Format::new(Scheme::Ob01, Encoding::Base32Rfc),
            #[cfg(feature = "ob01")]
            constants::OB01_B64 => Format::new(Scheme::Ob01, Encoding::Base64),
            #[cfg(feature = "ob01")]
            constants::OB01_HEX => Format::new(Scheme::Ob01, Encoding::Hex),

            #[cfg(feature = "ob21p")]
            constants::OB21P_C32 => Format::new(Scheme::Ob21p, Encoding::Base32Crockford),
            #[cfg(feature = "ob21p")]
            constants::OB21P_B32 => Format::new(Scheme::Ob21p, Encoding::Base32Rfc),
            #[cfg(feature = "ob21p")]
            constants::OB21P_B64 => Format::new(Scheme::Ob21p, Encoding::Base64),
            #[cfg(feature = "ob21p")]
            constants::OB21P_HEX => Format::new(Scheme::Ob21p, Encoding::Hex),

            #[cfg(feature = "ob31")]
            constants::OB31_C32 => Format::new(Scheme::Ob31, Encoding::Base32Crockford),
            #[cfg(feature = "ob31")]
            constants::OB31_B32 => Format::new(Scheme::Ob31, Encoding::Base32Rfc),
            #[cfg(feature = "ob31")]
            constants::OB31_B64 => Format::new(Scheme::Ob31, Encoding::Base64),
            #[cfg(feature = "ob31")]
            constants::OB31_HEX => Format::new(Scheme::Ob31, Encoding::Hex),

            #[cfg(feature = "ob31p")]
            constants::OB31P_C32 => Format::new(Scheme::Ob31p, Encoding::Base32Crockford),
            #[cfg(feature = "ob31p")]
            constants::OB31P_B32 => Format::new(Scheme::Ob31p, Encoding::Base32Rfc),
            #[cfg(feature = "ob31p")]
            constants::OB31P_B64 => Format::new(Scheme::Ob31p, Encoding::Base64),
            #[cfg(feature = "ob31p")]
            constants::OB31P_HEX => Format::new(Scheme::Ob31p, Encoding::Hex),

            #[cfg(feature = "ob32")]
            constants::OB32_C32 => Format::new(Scheme::Ob32, Encoding::Base32Crockford),
            #[cfg(feature = "ob32")]
            constants::OB32_B32 => Format::new(Scheme::Ob32, Encoding::Base32Rfc),
            #[cfg(feature = "ob32")]
            constants::OB32_B64 => Format::new(Scheme::Ob32, Encoding::Base64),
            #[cfg(feature = "ob32")]
            constants::OB32_HEX => Format::new(Scheme::Ob32, Encoding::Hex),

            #[cfg(feature = "ob32p")]
            constants::OB32P_C32 => Format::new(Scheme::Ob32p, Encoding::Base32Crockford),
            #[cfg(feature = "ob32p")]
            constants::OB32P_B32 => Format::new(Scheme::Ob32p, Encoding::Base32Rfc),
            #[cfg(feature = "ob32p")]
            constants::OB32P_B64 => Format::new(Scheme::Ob32p, Encoding::Base64),
            #[cfg(feature = "ob32p")]
            constants::OB32P_HEX => Format::new(Scheme::Ob32p, Encoding::Hex),

            // Testing

            // ob70 variants
            #[cfg(feature = "ob70")]
            constants::OB70_C32 => Format::new(Scheme::Ob70, Encoding::Base32Crockford),
            #[cfg(feature = "ob70")]
            constants::OB70_B32 => Format::new(Scheme::Ob70, Encoding::Base32Rfc),
            #[cfg(feature = "ob70")]
            constants::OB70_B64 => Format::new(Scheme::Ob70, Encoding::Base64),
            #[cfg(feature = "ob70")]
            constants::OB70_HEX => Format::new(Scheme::Ob70, Encoding::Hex),

            // ob71 variants
            #[cfg(feature = "ob71")]
            constants::OB71_C32 => Format::new(Scheme::Ob71, Encoding::Base32Crockford),
            #[cfg(feature = "ob71")]
            constants::OB71_B32 => Format::new(Scheme::Ob71, Encoding::Base32Rfc),
            #[cfg(feature = "ob71")]
            constants::OB71_B64 => Format::new(Scheme::Ob71, Encoding::Base64),
            #[cfg(feature = "ob71")]
            constants::OB71_HEX => Format::new(Scheme::Ob71, Encoding::Hex),

            // Legacy

            // ob00 variants
            #[cfg(feature = "ob00")]
            constants::OB00_C32 => Format::new(Scheme::Ob00, Encoding::Base32Crockford),
            #[cfg(feature = "ob00")]
            constants::OB00_B32 => Format::new(Scheme::Ob00, Encoding::Base32Rfc),
            #[cfg(feature = "ob00")]
            constants::OB00_B64 => Format::new(Scheme::Ob00, Encoding::Base64),
            #[cfg(feature = "ob00")]
            constants::OB00_HEX => Format::new(Scheme::Ob00, Encoding::Hex),

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
        write!(
            f,
            "{}:{}",
            self.scheme.as_str(),
            self.encoding.as_short_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_from_str_all_combinations() {
        // Define all schemes
        let schemes = vec![
            #[cfg(feature = "ob01")]
            Scheme::Ob01,
            #[cfg(feature = "ob21p")]
            Scheme::Ob21p,
            #[cfg(feature = "ob31")]
            Scheme::Ob31,
            #[cfg(feature = "ob31p")]
            Scheme::Ob31p,
            #[cfg(feature = "ob32")]
            Scheme::Ob32,
            #[cfg(feature = "ob32p")]
            Scheme::Ob32p,
            // Testing
            #[cfg(feature = "ob70")]
            Scheme::Ob70,
            #[cfg(feature = "ob71")]
            Scheme::Ob71,
            // Legacy
            #[cfg(feature = "ob00")]
            Scheme::Ob00,
        ];

        // Define all encodings
        let encodings = vec![
            Encoding::Base32Crockford,
            Encoding::Base32Rfc,
            Encoding::Base64,
            Encoding::Hex,
        ];

        for scheme in &schemes {
            for encoding in &encodings {
                // Test short string identifiers (e.g., "ob01:c32", "ob01:b32")
                let format_str = format!("{}:{}", scheme.as_str(), encoding.as_short_str());
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
        assert!(Format::from_str("ob01").is_err());
        assert!(Format::from_str("ob01:").is_err());
        assert!(Format::from_str(":b64").is_err());
        assert!(Format::from_str("ob70:invalid").is_err());
    }

    #[test]
    fn test_format_to_string_roundtrip() {
        // Define test cases: (scheme, encoding, expected_string)
        #[cfg(feature = "non-crypto")]
        let mut test_cases = vec![
            (Scheme::Ob71, Encoding::Base32Crockford, "ob71:c32"),
            (Scheme::Ob71, Encoding::Base32Rfc, "ob71:b32"),
            (Scheme::Ob71, Encoding::Base64, "ob71:b64"),
            (Scheme::Ob71, Encoding::Hex, "ob71:hex"),
            (Scheme::Ob70, Encoding::Base32Crockford, "ob70:c32"),
            (Scheme::Ob70, Encoding::Base32Rfc, "ob70:b32"),
            (Scheme::Ob70, Encoding::Base64, "ob70:b64"),
            (Scheme::Ob70, Encoding::Hex, "ob70:hex"),
        ];

        #[cfg(feature = "ob00")]
        test_cases.extend(vec![
            (Scheme::Ob00, Encoding::Base32Crockford, "ob00:c32"),
            (Scheme::Ob00, Encoding::Base32Rfc, "ob00:b32"),
            (Scheme::Ob00, Encoding::Base64, "ob00:b64"),
            (Scheme::Ob00, Encoding::Hex, "ob00:hex"),
        ]);

        #[cfg(feature = "ob01")]
        test_cases.extend(vec![
            (Scheme::Ob01, Encoding::Base32Crockford, "ob01:c32"),
            (Scheme::Ob01, Encoding::Base32Rfc, "ob01:b32"),
            (Scheme::Ob01, Encoding::Base64, "ob01:b64"),
            (Scheme::Ob01, Encoding::Hex, "ob01:hex"),
        ]);

        #[cfg(feature = "ob21p")]
        test_cases.extend(vec![
            (Scheme::Ob21p, Encoding::Base32Crockford, "ob21p:c32"),
            (Scheme::Ob21p, Encoding::Base32Rfc, "ob21p:b32"),
            (Scheme::Ob21p, Encoding::Base64, "ob21p:b64"),
            (Scheme::Ob21p, Encoding::Hex, "ob21p:hex"),
        ]);

        #[cfg(feature = "ob31")]
        test_cases.extend(vec![
            (Scheme::Ob31, Encoding::Base32Crockford, "ob31:c32"),
            (Scheme::Ob31, Encoding::Base32Rfc, "ob31:b32"),
            (Scheme::Ob31, Encoding::Base64, "ob31:b64"),
            (Scheme::Ob31, Encoding::Hex, "ob31:hex"),
        ]);

        #[cfg(feature = "ob31p")]
        test_cases.extend(vec![
            (Scheme::Ob31p, Encoding::Base32Crockford, "ob31p:c32"),
            (Scheme::Ob31p, Encoding::Base32Rfc, "ob31p:b32"),
            (Scheme::Ob31p, Encoding::Base64, "ob31p:b64"),
            (Scheme::Ob31p, Encoding::Hex, "ob31p:hex"),
        ]);

        #[cfg(feature = "ob32")]
        test_cases.extend(vec![
            (Scheme::Ob32, Encoding::Base32Crockford, "ob32:c32"),
            (Scheme::Ob32, Encoding::Base32Rfc, "ob32:b32"),
            (Scheme::Ob32, Encoding::Base64, "ob32:b64"),
            (Scheme::Ob32, Encoding::Hex, "ob32:hex"),
        ]);

        #[cfg(feature = "ob32p")]
        test_cases.extend(vec![
            (Scheme::Ob32p, Encoding::Base32Crockford, "ob32p:c32"),
            (Scheme::Ob32p, Encoding::Base32Rfc, "ob32p:b32"),
            (Scheme::Ob32p, Encoding::Base64, "ob32p:b64"),
            (Scheme::Ob32p, Encoding::Hex, "ob32p:hex"),
        ]);

        for (scheme, encoding, expected_str) in test_cases {
            // Test Format::to_string()
            let format = Format::new(scheme, encoding);
            let format_str = format.to_string();
            assert_eq!(
                format_str, expected_str,
                "Format string mismatch for {:? }:{:? }",
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
    #[cfg(feature = "ob00")]
    fn test_ob00_supports_both_base32_variants() {
        // ob00 should support both Base32Rfc and Base32Crockford
        let format_rfc = Format::from_str("ob00:b32").unwrap();
        assert_eq!(format_rfc.scheme(), Scheme::Ob00);
        assert_eq!(format_rfc.encoding(), Encoding::Base32Rfc);

        let format_crock = Format::from_str("ob00:c32").unwrap();
        assert_eq!(format_crock.scheme(), Scheme::Ob00);
        assert_eq!(format_crock.encoding(), Encoding::Base32Crockford);
    }

    #[test]
    #[cfg(all(feature = "all-schemes", feature = "non-crypto"))]
    fn test_all_schemes_support_both_base32_variants() {
        // All schemes should support both Base32Rfc (b32) and Base32Crockford (c32)
        let schemes = vec![
            "ob01", "ob21p", "ob31", "ob31p", "ob32", "ob32p", "ob70", "ob71",
        ];

        for scheme_str in schemes {
            // Test Base32Crockford (c32)
            let format_str_crock = format!("{}:c32", scheme_str);
            let result_crock = Format::from_str(&format_str_crock);
            if result_crock.is_ok() {
                // Only test if feature is enabled
                assert_eq!(
                    result_crock.unwrap().encoding(),
                    Encoding::Base32Crockford,
                    "{} should support c32",
                    scheme_str
                );
            }

            // Test Base32Rfc (b32)
            let format_str_rfc = format!("{}:b32", scheme_str);
            let result_rfc = Format::from_str(&format_str_rfc);
            if result_rfc.is_ok() {
                // Only test if feature is enabled
                assert_eq!(
                    result_rfc.unwrap().encoding(),
                    Encoding::Base32Rfc,
                    "{} should support b32",
                    scheme_str
                );
            }
        }
    }
}
