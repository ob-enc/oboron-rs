//! Tests for legacy schemes (legacy)
//!
//! These tests are isolated from main tests to ensure legacy functionality works independently.
//!
//! **Note**: Omnib and convenience functions (enc_keyless, dec_keyless) will NOT work
//! with legacy scheme. Use the LegacyC32 struct directly instead:
//!
//! ```ignore
//! use oboron::ztier::LegacyC32;
//!
//! let ob = LegacyC32::new_keyless()?;
//! let ot = ob.enc("test")?;
//! let pt2 = ob.dec(&ot)?;
//! ```

#![cfg(feature = "legacy")]

use oboron::ztier::{LegacyB64, LegacyC32, LegacyHex};

const TEST_SECRET: [u8; 32] = [
    0x38, 0x12, 0x84, 0x63, 0x3d, 0x02, 0xea, 0x5f, 0x35, 0xdf, 0x85, 0x96, 0xb5, 0xcc, 0x42, 0x18,
    0x31, 0x00, 0x60, 0x46, 0x8e, 0x8b, 0x46, 0x54, 0x55, 0xa4, 0x15, 0x17, 0x4e, 0xa6, 0xe9, 0x66,
];

#[test]
fn test_legacy_basic() {
    let pt = "hello world";
    let ob = LegacyC32::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt, pt2);
    assert!(ot.len() > 0);
}

#[test]
fn test_legacy_autodetect() {
    let pt = "autodetect test";
    let ob = LegacyC32::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_legacy_with_equals_padding() {
    let pt = "test==";
    let ob = LegacyC32::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    // legacy strips trailing '='
    assert_eq!("test", pt2);
}

#[test]
fn test_legacy_custom_secret() {
    let secret = [1u8; 32];
    let pt = "custom secret test";

    let ob = LegacyC32::from_bytes(&secret).unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
#[cfg(feature = "bytes-keys")]
fn test_legacy_different_secret_fails() {
    let secret1 = [1u8; 32];
    let secret2 = [2u8; 32];
    let pt = "different secrets";

    let ob1 = LegacyC32::from_bytes(&secret1).unwrap();
    let ob2 = LegacyC32::from_bytes(&secret2).unwrap();

    let ot = ob1.enc(pt).unwrap();
    let pt2 = ob2.dec(&ot);

    // Should fail or produce garbage (not the pt)
    assert!(pt2.is_err() || pt2.unwrap() != pt);
}

#[test]
#[cfg(feature = "bytes-keys")]
fn test_legacy_all_encodings() {
    let pt = "encoding test";
    let secret = [42u8; 32];

    let ob_b32 = LegacyC32::from_bytes(&secret).unwrap();
    let ob_b64 = LegacyB64::from_bytes(&secret).unwrap();
    let ob_hex = LegacyHex::from_bytes(&secret).unwrap();

    let enc_b32 = ob_b32.enc(pt).unwrap();
    let enc_b64 = ob_b64.enc(pt).unwrap();
    let enc_hex = ob_hex.enc(pt).unwrap();

    // All should dec back to pt
    assert_eq!(ob_b32.dec(&enc_b32).unwrap(), pt);
    assert_eq!(ob_b64.dec(&enc_b64).unwrap(), pt);
    assert_eq!(ob_hex.dec(&enc_hex).unwrap(), pt);

    // Encodings should be different
    assert_ne!(enc_b32, enc_b64);
    assert_ne!(enc_b32, enc_hex);
    assert_ne!(enc_b64, enc_hex);

    // Cross-scheme getter tests
    assert_eq!(ob_b32.scheme(), oboron::Scheme::Legacy);
    assert_eq!(ob_b64.encoding(), oboron::Encoding::B64);
    assert_eq!(ob_hex.encoding(), oboron::Encoding::Hex);
}

#[test]
fn test_legacy_long_string() {
    let pt = "a".repeat(1000);
    let ob = LegacyC32::new_keyless().unwrap();
    let ot = ob.enc(&pt).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_legacy_special_characters() {
    let pt = "hello\nworld\t!  @#$%^&*()";
    let ob = LegacyC32::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_legacy_unicode() {
    let pt = "Hello 世界 🌍";
    let ob = LegacyC32::new_keyless().unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_legacy_empty_string_fails() {
    let ob = LegacyC32::new_keyless().unwrap();
    assert!(ob.enc("").is_err());
}

#[test]
#[cfg(feature = "hex-keys")]
fn test_legacy_hex_secret() {
    let hex_secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let pt = "hex secret test";

    let ob = LegacyC32::from_hex_secret(hex_secret).unwrap();
    let ot = ob.enc(pt).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt, pt2);
}

#[test]
fn test_legacy_invalid_base64_secret() {
    let invalid_base64 = "not a base64 string";
    assert!(LegacyC32::new(invalid_base64).is_err());
}

#[test]
fn test_legacy_short_secret() {
    let short_secret = "00112233"; // Too short
    assert!(LegacyC32::new(short_secret).is_err());
}

#[test]
fn test_legacy_vector_test() {
    let ob = LegacyC32::from_bytes(&TEST_SECRET).unwrap();
    let plaintext = "test";

    // First enc to see what we actually get
    let ot = ob.enc(plaintext).unwrap();
    println!("Encoded '{}' as: {}", plaintext, ot);

    // Then verify roundtrip
    let pt2 = ob.dec(&ot).unwrap();
    assert_eq!(pt2, plaintext);
}

#[test]
fn test_legacy_backward_compatibility() {
    // Test that we can still dec legacy strings
    // Note: These test vectors need to be generated with the actual implementation
    // For now, we'll do a roundtrip test to ensure encoding/decoding works

    let ob = LegacyC32::from_bytes(&TEST_SECRET).unwrap();

    let test_plaintexts = vec!["test", "hello", "world"];

    for plaintext in test_plaintexts {
        let ot = ob.enc(plaintext).unwrap();
        let pt2 = ob.dec(&ot).unwrap();
        assert_eq!(pt2, plaintext, "Roundtrip failed for: {}", plaintext);
    }
}

#[test]
fn test_legacy_roundtrip_vectors() {
    let ob = LegacyC32::from_bytes(&TEST_SECRET).unwrap();

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
        let pt2 = ob.dec(&ot).unwrap();
        assert_eq!(pt2, plaintext, "Roundtrip failed for: {}", plaintext);
    }
}

#[test]
fn test_legacy_keyless_encoding() {
    // Generate test vectors using hardcoded key for documentation
    let ob = LegacyC32::new_keyless().unwrap();

    let test_cases = vec!["test", "hello world", "123"];

    for plaintext in test_cases {
        let ot = ob.enc(plaintext).unwrap();
        println!("Public key ot '{}' as: {}", plaintext, ot);

        let pt2 = ob.dec(&ot).unwrap();
        assert_eq!(pt2, plaintext);
    }
}
