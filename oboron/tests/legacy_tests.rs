//! Tests for legacy schemes (ob00)
//!
//! These tests are isolated from main tests to ensure legacy functionality works independently.
//!
//! **Note**: ObMulti and convenience functions (enc_keyless, dec_keyless) will NOT work
//! with ob00 scheme. Use the Ob00 struct directly instead:
//!
//! ```ignore
//! use oboron::{Oboron, Ob00};
//!
//! let ob = Ob00::new_keyless()?;
//! let ot = ob.enc("test")?;
//! let pt2 = ob.dec(&ot)?;
//! ```

#![cfg(feature = "ob00")]

use oboron::{Ob00, Ob00Base64, Ob00Hex, Oboron};

// 128 hex characters = 64 bytes
const HEX_KEY: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn test_ob00_basic() {
    let pt = "hello world";
    let ob = Ob00::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(pt, pt2);
    assert!(ot.len() > 0);
}

#[test]
fn test_ob00_autodetect() {
    let pt = "autodetect test";
    let ob = Ob00::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_ob00_with_equals_padding() {
    let pt = "test==";
    let ob = Ob00::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    // ob00 strips trailing '='
    assert_eq!("test", pt2);
}

#[test]
fn test_ob00_custom_keys() {
    let key = [1u8; 64];
    let pt = "custom keys test";

    let ob = Ob00::from_bytes(&key).unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_ob00_different_key_fails() {
    let key1 = [1u8; 64];
    let key2 = [2u8; 64];
    let pt = "different keys";

    let ob1 = Ob00::from_bytes(&key1).unwrap();
    let ob2 = Ob00::from_bytes(&key2).unwrap();

    let ot = ob1.enc(pt).unwrap();
    let pt2 = ob2.dec_strict(&ot);

    // Should fail or produce garbage (not the pt)
    assert!(pt2.is_err() || pt2.unwrap() != pt);
}

#[test]
fn test_ob00_all_encodings() {
    let pt = "encoding test";
    let key = [42u8; 64];

    let ob_b32 = Ob00::from_bytes(&key).unwrap();
    let ob_b64 = Ob00Base64::from_bytes(&key).unwrap();
    let ob_hex = Ob00Hex::from_bytes(&key).unwrap();

    let enc_b32 = ob_b32.enc(pt).unwrap();
    let enc_b64 = ob_b64.enc(pt).unwrap();
    let enc_hex = ob_hex.enc(pt).unwrap();

    // All should dec back to pt
    assert_eq!(ob_b32.dec_strict(&enc_b32).unwrap(), pt);
    assert_eq!(ob_b64.dec_strict(&enc_b64).unwrap(), pt);
    assert_eq!(ob_hex.dec_strict(&enc_hex).unwrap(), pt);

    // Encodings should be different
    assert_ne!(enc_b32, enc_b64);
    assert_ne!(enc_b32, enc_hex);
    assert_ne!(enc_b64, enc_hex);

    // Cross-scheme getter tests
    assert_eq!(ob_b32.scheme(), oboron::Scheme::Ob00);
    assert_eq!(ob_b64.encoding(), oboron::Encoding::Base64);
    assert_eq!(ob_hex.encoding(), oboron::Encoding::Hex);
}

#[test]
fn test_ob00_long_string() {
    let pt = "a".repeat(1000);
    let ob = Ob00::new_keyless().unwrap();
    let ot = ob.enc(&pt).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_ob00_special_characters() {
    let pt = "hello\nworld\t!  @#$%^&*()";
    let ob = Ob00::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_ob00_unicode() {
    let pt = "Hello 世界 🌍";
    let ob = Ob00::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_ob00_empty_string_fails() {
    let ob = Ob00::new_keyless().unwrap();
    assert!(ob.enc("").is_err());
}

#[test]
fn test_ob00_hex_key() {
    let hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let pt = "hex key test";

    let ob = Ob00::from_hex_key(hex_key).unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_ob00_invalid_hex_key() {
    let invalid_hex = "not a hex string";
    assert!(Ob00::new(invalid_hex).is_err());
}

#[test]
fn test_ob00_short_hex_key() {
    let short_hex = "00112233"; // Too short
    assert!(Ob00::from_hex_key(short_hex).is_err());
}

#[test]
fn test_ob00_vector_test() {
    let ob = Ob00::from_hex_key(HEX_KEY).unwrap();
    let plaintext = "test";

    // First enc to see what we actually get
    let ot = ob.enc(plaintext).unwrap();
    println!("Encoded '{}' as: {}", plaintext, ot);

    // Then verify roundtrip
    let pt2 = ob.dec_strict(&ot).unwrap();
    assert_eq!(pt2, plaintext);
}

#[test]
fn test_ob00_backward_compatibility() {
    // Test that we can still dec legacy ob00 strings
    // Note: These test vectors need to be generated with the actual implementation
    // For now, we'll do a roundtrip test to ensure encoding/decoding works

    let ob = Ob00::from_hex_key(HEX_KEY).unwrap();

    let test_plaintexts = vec!["test", "hello", "world"];

    for plaintext in test_plaintexts {
        let ot = ob.enc(plaintext).unwrap();
        let pt2 = ob.dec(&ot).unwrap();
        assert_eq!(pt2, plaintext, "Roundtrip failed for: {}", plaintext);
    }
}

#[test]
fn test_ob00_roundtrip_vectors() {
    let ob = Ob00::from_hex_key(HEX_KEY).unwrap();

    let test_cases = vec![
        "test",
        "hello",
        "a",
        "ab",
        "abc",
        "1234567890",
        "The quick brown fox",
    ];

    for plaintext in test_cases {
        let ot = ob.enc(plaintext).unwrap();
        let pt2 = ob.dec_strict(&ot).unwrap();
        assert_eq!(pt2, plaintext, "Roundtrip failed for: {}", plaintext);
    }
}

#[test]
fn test_ob00_keyless_encoding() {
    // Generate test vectors using hardcoded key for documentation
    let ob = Ob00::new_keyless().unwrap();

    let test_cases = vec!["test", "hello world", "123"];

    for plaintext in test_cases {
        let ot = ob.enc(plaintext).unwrap();
        println!("Public key ot '{}' as: {}", plaintext, ot);

        let pt2 = ob.dec_strict(&ot).unwrap();
        assert_eq!(pt2, plaintext);
    }
}

// If you have actual legacy ot strings, add them here:
#[test]
#[ignore] // Remove this when you have actual legacy vectors
fn test_specific_legacy_vectors() {
    // let ob = Ob00::new_keyless().unwrap();

    // Example format (uncomment and add real vectors when available):
    // let vectors = vec![
    //     ("ot_string_1", "expected_plaintext_1"),
    //     ("ot_string_2", "expected_plaintext_2"),
    // ];
    //
    // for (ot, expected) in vectors {
    //     let pt2 = ob.dec(ot).unwrap();
    //     assert_eq!(pt2, expected, "Failed to dec legacy vector: {}", ot);
    // }
}
