//! Integration tests for feature flag combinations

use oboron::ObtextCodec;

// Test that compiles with any feature combination
#[test]
fn test_available_schemes() {
    let key = oboron::generate_key();

    // Test each scheme if its feature is enabled

    #[cfg(feature = "zfbcx")]
    {
        let ob = oboron::ZfbcxC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "upc")]
    {
        let ob = oboron::UpcC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "adgs")]
    {
        let ob = oboron::AdgsC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "apgs")]
    {
        let ob = oboron::ApgsC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "adsv")]
    {
        let ob = oboron::AdsvC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "apsv")]
    {
        let ob = oboron::ApsvC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }
}

#[test]
fn test_format_string_parsing() {
    // Test parsing format strings for enabled schemes
    #[cfg(feature = "adsv")]
    {
        use oboron::Format;
        let format = Format::from_str("adsv.c32").unwrap();
        assert_eq!(format.to_string(), "adsv.c32");
    }

    // Test that disabled schemes return error
    #[cfg(not(feature = "zfbcx"))]
    {
        use oboron::Format;
        assert!(Format::from_str("zfbcx.c32").is_err());
    }
}

#[test]
fn test_ob_any_default() {
    // ObAny::new() should work with any feature combination
    let key = oboron::generate_key();
    let ob = oboron::ObAny::new(&key).unwrap();
    let enc = ob.enc("test data").unwrap();
    assert_eq!(ob.dec(&enc).unwrap(), "test data");
}

// Cross-scheme decoding test (only if multiple schemes enabled)
#[cfg(all(feature = "adgs", feature = "adsv"))]
#[test]
fn test_cross_scheme_decoding() {
    let key = oboron::generate_key();
    let adgs = oboron::AdgsC32::new(&key).unwrap();
    let adsv = oboron::AdsvC32::new(&key).unwrap();

    let enc31 = adgs.enc("hello").unwrap();
    let enc32 = adsv.enc("world").unwrap();

    // Auto-detection should work across schemes
    assert_eq!(adgs.dec(&enc32).unwrap(), "world");
    assert_eq!(adsv.dec(&enc31).unwrap(), "hello");

    // Strict decoding should fail
    assert!(adgs.dec_strict(&enc32).is_err());
    assert!(adsv.dec_strict(&enc31).is_err());
}
