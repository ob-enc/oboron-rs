//! Tests for tdr (reverse scheme)
//!
//! tdr reverses the plaintext and is always available for testing.

use oboron::{Encoding, Format, Oboron, Scheme};

#[test]
fn test_tdr_basic_roundtrip() {
    let key = oboron::generate_key();
    let ob = oboron::TdrC32::new(&key).unwrap();

    let plaintext = "hello world";
    let encd = ob.enc(plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_tdr_reverses_plaintext() {
    let key = oboron::generate_key();

    let plaintext = "abc123";

    // The underlying ciphertext should contain reversed text
    // We can't easily test this directly, but we can verify behavior
    let tdr_direct = oboron::TdrC32::new(&key).unwrap();
    let tdi_direct = oboron::TdiC32::new(&key).unwrap();

    let ot71 = tdr_direct.enc(plaintext).unwrap();
    let ot70 = tdi_direct.enc(plaintext).unwrap();

    // tdr and tdi should produce different outputs
    assert_ne!(ot71, ot70);
}

#[test]
fn test_tdr_all_encodings() {
    let key = oboron::generate_key();

    // Base32Crockford (default)
    let ob_b32 = oboron::TdrC32::new(&key).unwrap();
    let enc_b32 = ob_b32.enc("test").unwrap();
    assert_eq!(ob_b32.dec(&enc_b32).unwrap(), "test");

    // Base64
    let ob_b64 = oboron::TdrB64::new(&key).unwrap();
    let enc_b64 = ob_b64.enc("test").unwrap();
    assert_eq!(ob_b64.dec(&enc_b64).unwrap(), "test");

    // Hex
    let ob_hex = oboron::TdrHex::new(&key).unwrap();
    let enc_hex = ob_hex.enc("test").unwrap();
    assert_eq!(ob_hex.dec(&enc_hex).unwrap(), "test");
}

#[test]
fn test_tdr_deterministic() {
    let key = oboron::generate_key();
    let ob = oboron::TdrC32::new(&key).unwrap();

    let plaintext = "deterministic test";
    let enc1 = ob.enc(plaintext).unwrap();
    let enc2 = ob.enc(plaintext).unwrap();

    // tdr should be deterministic
    assert_eq!(enc1, enc2);
}

#[test]
fn test_tdr_cross_scheme_with_tdi() {
    let key = oboron::generate_key();
    let tdr = oboron::TdrC32::new(&key).unwrap();
    let tdi = oboron::TdiC32::new(&key).unwrap();

    let plaintext = "cross-scheme test";
    let ot71 = tdr.enc(plaintext).unwrap();
    let ot70 = tdi.enc(plaintext).unwrap();

    // Strict dec should fail across schemes
    assert!(tdr.dec_strict(&ot70).is_err());
    assert!(tdi.dec_strict(&ot71).is_err());

    // But auto-detect dec should work
    assert_eq!(tdr.dec(&ot70).unwrap(), plaintext);
    assert_eq!(tdi.dec(&ot71).unwrap(), plaintext);
}

#[test]
fn test_tdr_utf8() {
    let key = oboron::generate_key();
    let ob = oboron::TdrC32::new(&key).unwrap();

    let test_cases = vec!["UTF-8: こんにちは", "Emoji: 🚀🔥💯", "Mixed: Hello世界! "];

    for plaintext in test_cases {
        let encd = ob.enc(plaintext).unwrap();
        let decd = ob.dec(&encd).unwrap();
        assert_eq!(decd, plaintext, "Failed for: {}", plaintext);
    }
}

#[test]
fn test_tdr_palindrome() {
    let key = oboron::generate_key();
    let ob = oboron::TdrC32::new(&key).unwrap();

    // Palindromes should still roundtrip correctly
    let plaintext = "racecar";
    let encd = ob.enc(plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}

#[test]
fn test_tdr_empty_string() {
    let key = oboron::generate_key();
    let ob = oboron::TdrC32::new(&key).unwrap();

    // Empty string should fail
    let result = ob.enc("");
    assert!(result.is_err());
}

#[test]
fn test_tdr_scheme_info() {
    let key = oboron::generate_key();
    let ob = oboron::TdrC32::new(&key).unwrap();

    assert_eq!(ob.scheme(), Scheme::Tdr);
    assert_eq!(ob.encoding(), Encoding::Base32Crockford);
    assert!(ob.scheme().is_deterministic());
}

#[test]
fn test_tdr_parse_scheme() {
    let scheme: Scheme = "tdr".parse().unwrap();
    assert_eq!(scheme, Scheme::Tdr);

    let scheme: Scheme = "TDR".parse().unwrap(); // case insensitive
    assert_eq!(scheme, Scheme::Tdr);
}

#[test]
fn test_tdr_format_parsing() {
    let format = Format::from_str("tdr:c32").unwrap();
    assert_eq!(format.scheme(), Scheme::Tdr);
    assert_eq!(format.encoding(), Encoding::Base32Crockford);

    let format = Format::from_str("tdr:b64").unwrap();
    assert_eq!(format.scheme(), Scheme::Tdr);
    assert_eq!(format.encoding(), Encoding::Base64);

    let format = Format::from_str("tdr:hex").unwrap();
    assert_eq!(format.scheme(), Scheme::Tdr);
    assert_eq!(format.encoding(), Encoding::Hex);
}

#[test]
fn test_tdr_long_string() {
    let key = oboron::generate_key();
    let ob = oboron::TdrC32::new(&key).unwrap();

    let plaintext = "a".repeat(10000);
    let encd = ob.enc(&plaintext).unwrap();
    let decd = ob.dec(&encd).unwrap();

    assert_eq!(decd, plaintext);
}
