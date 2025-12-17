//! Tests for ob70 (identity scheme)
//!
//! ob70 is a non-encrypting identity scheme that's always available.
//! It should be tested first since it has no crypto dependencies.

use oboron::{Encoding, Format, Oboron, Scheme};

#[test]
fn test_ob70_basic_roundtrip() {
    let key = oboron::generate_key();
    let ob = oboron::Ob70::new(&key).unwrap();

    let plaintext = "hello world";
    let encd = ob.enc(plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_all_encodings() {
    let key = oboron::generate_key();

    // Base32Crockford (default)
    let ob_b32 = oboron::Ob70::new(&key).unwrap();
    let enc_b32 = ob_b32.enc("test").unwrap();
    assert_eq!(ob_b32.dec(&enc_b32).unwrap(), "test");

    // Base64
    let ob_b64 = oboron::Ob70Base64::new(&key).unwrap();
    let enc_b64 = ob_b64.enc("test").unwrap();
    assert_eq!(ob_b64.dec(&enc_b64).unwrap(), "test");

    // Hex
    let ob_hex = oboron::Ob70Hex::new(&key).unwrap();
    let enc_hex = ob_hex.enc("test").unwrap();
    assert_eq!(ob_hex.dec(&enc_hex).unwrap(), "test");
}

#[test]
fn test_ob70_deterministic() {
    let key = oboron::generate_key();
    let ob = oboron::Ob70::new(&key).unwrap();

    let plaintext = "deterministic test";
    let enc1 = ob.enc(plaintext).unwrap();
    let enc2 = ob.enc(plaintext).unwrap();

    // ob70 should be deterministic
    assert_eq!(enc1, enc2);
}

#[test]
fn test_ob70_empty_string() {
    let key = oboron::generate_key();
    let ob = oboron::Ob70::new(&key).unwrap();

    // Empty string should fail
    let result = ob.enc("");
    assert!(result.is_err());
}

#[test]
fn test_ob70_special_characters() {
    let key = oboron::generate_key();
    let ob = oboron::Ob70::new(&key).unwrap();

    let test_cases = vec![
        "Hello, World!",
        "UTF-8: こんにちは",
        "Emoji: 🚀🔥💯",
        "Newlines:\n\nMultiple",
        "Tabs:\t\tMultiple",
        "Mixed: abc123! @#$%^&*()",
    ];

    for plaintext in test_cases {
        let encd = ob.enc(plaintext).unwrap();
        let decd = ob.dec(&encd).unwrap();
        assert_eq!(decd, plaintext, "Failed for: {}", plaintext);
    }
}

#[test]
fn test_ob70_long_string() {
    let key = oboron::generate_key();
    let ob = oboron::Ob70::new(&key).unwrap();

    // Test with a long string
    let plaintext = "a".repeat(10000);
    let encd = ob.enc(&plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_keyless() {
    let ob = oboron::Ob70::new_keyless().unwrap();

    let plaintext = "hardcoded key test";
    let encd = ob.enc(plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_dec_strict() {
    let key = oboron::generate_key();
    let ob70 = oboron::Ob70::new(&key).unwrap();

    let plaintext = "strict dec test";
    let encd = ob70.enc(plaintext).unwrap();

    // Strict dec should work with matching scheme
    assert_eq!(ob70.dec_strict(&encd).unwrap(), plaintext);
}

#[test]
#[cfg(feature = "ob32")]
fn test_ob70_cannot_dec_other_schemes_strict() {
    let key = oboron::generate_key();
    let ob70 = oboron::Ob70::new(&key).unwrap();
    let ob32 = oboron::Ob32::new(&key).unwrap();

    let plaintext = "cross-scheme test";
    let encd_ob32 = ob32.enc(plaintext).unwrap();

    // Strict dec should fail when scheme doesn't match
    assert!(ob70.dec_strict(&encd_ob32).is_err());

    // But regular dec (with autodetection) should work
    assert_eq!(ob70.dec(&encd_ob32).unwrap(), plaintext);
}

#[test]
fn test_ob70_scheme_info() {
    let key = oboron::generate_key();
    let ob = oboron::Ob70::new(&key).unwrap();

    assert_eq!(ob.scheme(), Scheme::Ob70);
    assert_eq!(ob.encoding(), Encoding::Base32Crockford);
    assert!(ob.scheme().is_deterministic());
}

#[test]
fn test_ob70_format_string() {
    let key = oboron::generate_key();

    // Test creating via format string
    let ob = oboron::new("ob70:c32", &key).unwrap();
    let encd = ob.enc("format test").unwrap();
    let decd = ob.dec(&encd).unwrap();
    assert_eq!(decd, "format test");

    // Test all format strings
    let formats = vec!["ob70:c32", "ob70:b64", "ob70:hex"];
    for format_str in formats {
        let ob = oboron::new(format_str, &key).unwrap();
        assert_eq!(ob.scheme(), Scheme::Ob70);
    }
}

#[test]
fn test_ob70_from_bytes() {
    let key_bytes = [0u8; 64];
    let ob = oboron::Ob70::from_bytes(&key_bytes).unwrap();

    let plaintext = "from bytes test";
    let encd = ob.enc(plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_factory_from_bytes() {
    let key_bytes = [0u8; 64];
    let ob = oboron::from_bytes("ob70:c32", &key_bytes).unwrap();

    let plaintext = "factory from bytes";
    let encd = ob.enc(plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_convenience_functions() {
    let key = oboron::generate_key();

    // Test enc/dec convenience functions
    let plaintext = "convenience test";
    let encd = oboron::enc(plaintext, "ob70:c32", &key).unwrap();
    let decd = oboron::dec(&encd, "ob70:c32", &key).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_autodec() {
    let key = oboron::generate_key();

    let plaintext = "autodec test";
    let encd = oboron::enc(plaintext, "ob70:c32", &key).unwrap();

    // Autodec should work without specifying format
    let decd = oboron::autodec(&encd, &key).unwrap();
    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_keyless_functions() {
    let plaintext = "keyless convenience";

    let encd = oboron::enc_keyless(plaintext, "ob70:c32").unwrap();
    let decd = oboron::dec_keyless(&encd, "ob70:c32").unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_ob_any_default() {
    let key = oboron::generate_key();

    // ObAny should default to ob70 now
    let ob = oboron::ObAny::new(&key).unwrap();
    assert_eq!(ob.scheme(), Scheme::Ob70);

    let plaintext = "ObAny default test";
    let encd = ob.enc(plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_multiple_instances_same_key() {
    let key = oboron::generate_key();

    let ob1 = oboron::Ob70::new(&key).unwrap();
    let ob2 = oboron::Ob70::new(&key).unwrap();

    let plaintext = "multi-instance test";
    let enc1 = ob1.enc(plaintext).unwrap();
    let dec2 = ob2.dec(&enc1).unwrap();

    assert_eq!(dec2, plaintext);
}

#[test]
fn test_ob70_different_keys() {
    let key1 = oboron::generate_key();
    let key2 = oboron::generate_key();

    let ob1 = oboron::Ob70::new(&key1).unwrap();
    let ob2 = oboron::Ob70::new(&key2).unwrap();

    let plaintext = "different keys test";
    let encd = ob1.enc(plaintext).unwrap();

    // Since ob70 is identity, the key doesn't matter for decoding
    // (though in production this would be a security issue for real crypto)
    let decd = ob2.dec(&encd).unwrap();
    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_invalid_hex_key() {
    // Invalid hex key (not 128 chars)
    let result = oboron::Ob70::new("invalid");
    assert!(result.is_err());

    // Invalid hex characters
    let bad_key = "Z".repeat(128);
    let result = oboron::Ob70::new(&bad_key);
    assert!(result.is_err());
}

#[test]
fn test_ob70_key_getter() {
    let key_bytes = [42u8; 64];
    let ob = oboron::Ob70::from_bytes(&key_bytes).unwrap();

    assert_eq!(ob.key_bytes(), &key_bytes);
}

#[test]
fn test_ob70_encoding_mismatch() {
    let key = oboron::generate_key();

    let ob_b32 = oboron::Ob70::new(&key).unwrap();
    let ob_b64 = oboron::Ob70Base64::new(&key).unwrap();

    let plaintext = "encoding mismatch";
    let enc_b32 = ob_b32.enc(plaintext).unwrap();

    // Strict dec with wrong encoding should fail
    assert!(ob_b64.dec_strict(&enc_b32).is_err());

    // But autodetect dec won't work across encodings
    // (autodetect only handles scheme, not encoding)
    assert!(ob_b64.dec(&enc_b32).is_err());
}

#[test]
fn test_ob70_scheme_string() {
    let scheme = Scheme::Ob70;

    assert_eq!(scheme.as_str(), "ob70");
    assert_eq!(scheme.to_string(), "ob70");
}

#[test]
fn test_ob70_parse_scheme() {
    let scheme: Scheme = "ob70".parse().unwrap();
    assert_eq!(scheme, Scheme::Ob70);

    let scheme: Scheme = "OB70".parse().unwrap(); // case insensitive
    assert_eq!(scheme, Scheme::Ob70);
}

#[test]
fn test_ob70_format_parsing() {
    let format = Format::from_str("ob70:c32").unwrap();
    assert_eq!(format.scheme(), Scheme::Ob70);
    assert_eq!(format.encoding(), Encoding::Base32Crockford);

    let format = Format::from_str("ob70:b64").unwrap();
    assert_eq!(format.scheme(), Scheme::Ob70);
    assert_eq!(format.encoding(), Encoding::Base64);

    let format = Format::from_str("ob70:hex").unwrap();
    assert_eq!(format.scheme(), Scheme::Ob70);
    assert_eq!(format.encoding(), Encoding::Hex);
}

#[test]
fn test_ob70_binary_data_in_string() {
    let key = oboron::generate_key();
    let ob = oboron::Ob70::new(&key).unwrap();

    // Test with string containing various byte values
    let plaintext = "Binary: \x01\x02\x03\x7F";
    let encd = ob.enc(plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob70_sequential_operations() {
    let key = oboron::generate_key();
    let ob = oboron::Ob70::new(&key).unwrap();

    // Encode multiple values in sequence
    let values = vec!["first", "second", "third"];
    let mut encd_values = vec![];

    for value in &values {
        encd_values.push(ob.enc(value).unwrap());
    }

    // Decode in sequence
    for (i, encd) in encd_values.iter().enumerate() {
        let decd = ob.dec(encd).unwrap();
        assert_eq!(decd, values[i]);
    }
}

#[test]
fn test_ob70_is_deterministic() {
    // ob70 should report as deterministic
    assert!(Scheme::Ob70.is_deterministic());
}
