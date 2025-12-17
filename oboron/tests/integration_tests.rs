//! Integration tests for feature flag combinations

use oboron::Oboron;

// Test that compiles with any feature combination
#[test]
fn test_available_schemes() {
    let key = oboron::generate_key();

    // Test each scheme if its feature is enabled

    #[cfg(feature = "ob01")]
    {
        let ob = oboron::Ob01::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "ob21p")]
    {
        let ob = oboron::Ob21p::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "ob31")]
    {
        let ob = oboron::Ob31::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "ob31p")]
    {
        let ob = oboron::Ob31p::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "ob32")]
    {
        let ob = oboron::Ob32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "ob32p")]
    {
        let ob = oboron::Ob32p::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }
}

#[test]
fn test_format_string_parsing() {
    // Test parsing format strings for enabled schemes
    #[cfg(feature = "ob32")]
    {
        use oboron::Format;
        let format = Format::from_str("ob32:c32").unwrap();
        assert_eq!(format.to_string(), "ob32:c32");
    }

    // Test that disabled schemes return error
    #[cfg(not(feature = "ob01"))]
    {
        use oboron::Format;
        assert!(Format::from_str("ob01:c32").is_err());
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
#[cfg(all(feature = "ob31", feature = "ob32"))]
#[test]
fn test_cross_scheme_decoding() {
    let key = oboron::generate_key();
    let ob31 = oboron::Ob31::new(&key).unwrap();
    let ob32 = oboron::Ob32::new(&key).unwrap();

    let enc31 = ob31.enc("hello").unwrap();
    let enc32 = ob32.enc("world").unwrap();

    // Auto-detection should work across schemes
    assert_eq!(ob31.dec(&enc32).unwrap(), "world");
    assert_eq!(ob32.dec(&enc31).unwrap(), "hello");

    // Strict decoding should fail
    assert!(ob31.dec_strict(&enc32).is_err());
    assert!(ob32.dec_strict(&enc31).is_err());
}
