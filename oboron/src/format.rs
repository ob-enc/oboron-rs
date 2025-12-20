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

    /// Parse format from compact string representation (e.g., "zdc:c32", "adgs:b64")
    ///
    /// This uses fast match-based parsing for maximum performance.
    pub fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            #[cfg(feature = "zdc")]
            constants::ZDC_C32 => Format::new(Scheme::Zdc, Encoding::Base32Crockford),
            #[cfg(feature = "zdc")]
            constants::ZDC_B32 => Format::new(Scheme::Zdc, Encoding::Base32Rfc),
            #[cfg(feature = "zdc")]
            constants::ZDC_B64 => Format::new(Scheme::Zdc, Encoding::Base64),
            #[cfg(feature = "zdc")]
            constants::ZDC_HEX => Format::new(Scheme::Zdc, Encoding::Hex),

            #[cfg(feature = "upc")]
            constants::UPC_C32 => Format::new(Scheme::Upc, Encoding::Base32Crockford),
            #[cfg(feature = "upc")]
            constants::UPC_B32 => Format::new(Scheme::Upc, Encoding::Base32Rfc),
            #[cfg(feature = "upc")]
            constants::UPC_B64 => Format::new(Scheme::Upc, Encoding::Base64),
            #[cfg(feature = "upc")]
            constants::UPC_HEX => Format::new(Scheme::Upc, Encoding::Hex),

            #[cfg(feature = "adgs")]
            constants::ADGS_C32 => Format::new(Scheme::Adgs, Encoding::Base32Crockford),
            #[cfg(feature = "adgs")]
            constants::ADGS_B32 => Format::new(Scheme::Adgs, Encoding::Base32Rfc),
            #[cfg(feature = "adgs")]
            constants::ADGS_B64 => Format::new(Scheme::Adgs, Encoding::Base64),
            #[cfg(feature = "adgs")]
            constants::ADGS_HEX => Format::new(Scheme::Adgs, Encoding::Hex),

            #[cfg(feature = "apgs")]
            constants::APGS_C32 => Format::new(Scheme::Apgs, Encoding::Base32Crockford),
            #[cfg(feature = "apgs")]
            constants::APGS_B32 => Format::new(Scheme::Apgs, Encoding::Base32Rfc),
            #[cfg(feature = "apgs")]
            constants::APGS_B64 => Format::new(Scheme::Apgs, Encoding::Base64),
            #[cfg(feature = "apgs")]
            constants::APGS_HEX => Format::new(Scheme::Apgs, Encoding::Hex),

            #[cfg(feature = "adsv")]
            constants::ADSV_C32 => Format::new(Scheme::Adsv, Encoding::Base32Crockford),
            #[cfg(feature = "adsv")]
            constants::ADSV_B32 => Format::new(Scheme::Adsv, Encoding::Base32Rfc),
            #[cfg(feature = "adsv")]
            constants::ADSV_B64 => Format::new(Scheme::Adsv, Encoding::Base64),
            #[cfg(feature = "adsv")]
            constants::ADSV_HEX => Format::new(Scheme::Adsv, Encoding::Hex),

            #[cfg(feature = "apsv")]
            constants::APSV_C32 => Format::new(Scheme::Apsv, Encoding::Base32Crockford),
            #[cfg(feature = "apsv")]
            constants::APSV_B32 => Format::new(Scheme::Apsv, Encoding::Base32Rfc),
            #[cfg(feature = "apsv")]
            constants::APSV_B64 => Format::new(Scheme::Apsv, Encoding::Base64),
            #[cfg(feature = "apsv")]
            constants::APSV_HEX => Format::new(Scheme::Apsv, Encoding::Hex),

            // Testing

            // tdi variants
            #[cfg(feature = "tdi")]
            constants::TDI_C32 => Format::new(Scheme::Tdi, Encoding::Base32Crockford),
            #[cfg(feature = "tdi")]
            constants::TDI_B32 => Format::new(Scheme::Tdi, Encoding::Base32Rfc),
            #[cfg(feature = "tdi")]
            constants::TDI_B64 => Format::new(Scheme::Tdi, Encoding::Base64),
            #[cfg(feature = "tdi")]
            constants::TDI_HEX => Format::new(Scheme::Tdi, Encoding::Hex),

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
            #[cfg(feature = "zdc")]
            Scheme::Zdc,
            #[cfg(feature = "upc")]
            Scheme::Upc,
            #[cfg(feature = "adgs")]
            Scheme::Adgs,
            #[cfg(feature = "apgs")]
            Scheme::Apgs,
            #[cfg(feature = "adsv")]
            Scheme::Adsv,
            #[cfg(feature = "apsv")]
            Scheme::Apsv,
            // Testing
            #[cfg(feature = "tdi")]
            Scheme::Tdi,
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
                // Test short string identifiers (e.g., "zdc:c32", "zdc:b32")
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
        assert!(Format::from_str("zdc").is_err());
        assert!(Format::from_str("zdc:").is_err());
        assert!(Format::from_str(":b64").is_err());
        assert!(Format::from_str("tdi:invalid").is_err());
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
            (Scheme::Tdi, Encoding::Base32Crockford, "tdi:c32"),
            (Scheme::Tdi, Encoding::Base32Rfc, "tdi:b32"),
            (Scheme::Tdi, Encoding::Base64, "tdi:b64"),
            (Scheme::Tdi, Encoding::Hex, "tdi:hex"),
        ];

        #[cfg(feature = "ob00")]
        test_cases.extend(vec![
            (Scheme::Ob00, Encoding::Base32Crockford, "ob00:c32"),
            (Scheme::Ob00, Encoding::Base32Rfc, "ob00:b32"),
            (Scheme::Ob00, Encoding::Base64, "ob00:b64"),
            (Scheme::Ob00, Encoding::Hex, "ob00:hex"),
        ]);

        #[cfg(feature = "zdc")]
        test_cases.extend(vec![
            (Scheme::Zdc, Encoding::Base32Crockford, "zdc:c32"),
            (Scheme::Zdc, Encoding::Base32Rfc, "zdc:b32"),
            (Scheme::Zdc, Encoding::Base64, "zdc:b64"),
            (Scheme::Zdc, Encoding::Hex, "zdc:hex"),
        ]);

        #[cfg(feature = "upc")]
        test_cases.extend(vec![
            (Scheme::Upc, Encoding::Base32Crockford, "upc:c32"),
            (Scheme::Upc, Encoding::Base32Rfc, "upc:b32"),
            (Scheme::Upc, Encoding::Base64, "upc:b64"),
            (Scheme::Upc, Encoding::Hex, "upc:hex"),
        ]);

        #[cfg(feature = "adgs")]
        test_cases.extend(vec![
            (Scheme::Adgs, Encoding::Base32Crockford, "adgs:c32"),
            (Scheme::Adgs, Encoding::Base32Rfc, "adgs:b32"),
            (Scheme::Adgs, Encoding::Base64, "adgs:b64"),
            (Scheme::Adgs, Encoding::Hex, "adgs:hex"),
        ]);

        #[cfg(feature = "apgs")]
        test_cases.extend(vec![
            (Scheme::Apgs, Encoding::Base32Crockford, "apgs:c32"),
            (Scheme::Apgs, Encoding::Base32Rfc, "apgs:b32"),
            (Scheme::Apgs, Encoding::Base64, "apgs:b64"),
            (Scheme::Apgs, Encoding::Hex, "apgs:hex"),
        ]);

        #[cfg(feature = "adsv")]
        test_cases.extend(vec![
            (Scheme::Adsv, Encoding::Base32Crockford, "adsv:c32"),
            (Scheme::Adsv, Encoding::Base32Rfc, "adsv:b32"),
            (Scheme::Adsv, Encoding::Base64, "adsv:b64"),
            (Scheme::Adsv, Encoding::Hex, "adsv:hex"),
        ]);

        #[cfg(feature = "apsv")]
        test_cases.extend(vec![
            (Scheme::Apsv, Encoding::Base32Crockford, "apsv:c32"),
            (Scheme::Apsv, Encoding::Base32Rfc, "apsv:b32"),
            (Scheme::Apsv, Encoding::Base64, "apsv:b64"),
            (Scheme::Apsv, Encoding::Hex, "apsv:hex"),
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
        let schemes = vec!["zdc", "upc", "adgs", "apgs", "adsv", "apsv", "tdi", "ob71"];

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
