#[cfg(feature = "adgs")]
use oboron::AdgsB64;
#[cfg(feature = "upc")]
use oboron::UpcB64;
#[cfg(feature = "zdc")]
use oboron::ZdcB64;
#[cfg(feature = "apgs")]
use oboron::{Apgs, ApgsB64, ApgsHex};
#[cfg(feature = "apsv")]
use oboron::{ApsvB64, ApsvC32, ApsvHex};
use oboron::{Encoding, ObFlex, Oboron, Scheme};
#[cfg(feature = "ob32")]
use oboron::{Ob32, Ob32Base64, Ob32Hex};

#[test]
#[cfg(feature = "apgs")]
fn test_apgs_basic() {
    let key = [0u8; 64];
    let ob = Apgs::from_bytes(&key).expect("Failed to create Apgs");

    let plaintext = "Hello, World!";
    let encd1 = ob.enc(plaintext).expect("Failed to enc");
    let encd2 = ob.enc(plaintext).expect("Failed to enc");

    // Apgs is probabilistic, so two encodings should be different
    assert_ne!(
        encd1, encd2,
        "Apgs should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let decd1 = ob.dec(&encd1).expect("Failed to dec first encoding");
    let decd2 = ob.dec(&encd2).expect("Failed to dec second encoding");

    assert_eq!(decd1, plaintext);
    assert_eq!(decd2, plaintext);

    eprintln!("✓ Apgs basic test passed");
}

#[test]
#[cfg(feature = "apgs")]
fn test_apgs_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test apgs with different encodings";

    // Base32Crockford (default)
    let ob_b32 = Apgs::from_bytes(&key).expect("Failed to create Apgs with base32");
    let encd = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let decd = ob_b32.dec(&encd).expect("Failed to dec with base32");
    assert_eq!(decd, plaintext, "Decoding mismatch for base32");

    // Base64
    let ob_b64 = ApgsB64::from_bytes(&key).expect("Failed to create Apgs with base64");
    let encd = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let decd = ob_b64.dec(&encd).expect("Failed to dec with base64");
    assert_eq!(decd, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = ApgsHex::from_bytes(&key).expect("Failed to create Apgs with hex");
    let encd = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let decd = ob_hex.dec(&encd).expect("Failed to dec with hex");
    assert_eq!(decd, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Apgs all encodings test passed");
}

#[test]
#[cfg(feature = "ob32")]
fn test_ob32_basic() {
    let key = [0u8; 64];
    let ob = Ob32::from_bytes(&key).expect("Failed to create Ob32");

    let plaintext = "Testing Ob32 scheme";
    let encd1 = ob.enc(plaintext).expect("Failed to enc");
    let encd2 = ob.enc(plaintext).expect("Failed to enc");

    // Ob32 is deterministic, so two encodings should be the same
    assert_eq!(
        encd1, encd2,
        "Ob32 should produce identical ciphertexts for the same plaintext"
    );

    let decd = ob.dec(&encd1).expect("Failed to dec");
    assert_eq!(decd, plaintext);

    eprintln!("✓ Ob32 basic test passed");
}

#[test]
#[cfg(feature = "ob32")]
fn test_ob32_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test ob32 with different encodings";

    // Base32Crockford (default)
    let ob_b32 = Ob32::from_bytes(&key).expect("Failed to create Ob32 with base32");
    let encd = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let decd = ob_b32.dec(&encd).expect("Failed to dec with base32");
    assert_eq!(decd, plaintext, "Decoding mismatch for base32");

    // Base64
    let ob_b64 = Ob32Base64::from_bytes(&key).expect("Failed to create Ob32 with base64");
    let encd = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let decd = ob_b64.dec(&encd).expect("Failed to dec with base64");
    assert_eq!(decd, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = Ob32Hex::from_bytes(&key).expect("Failed to create Ob32 with hex");
    let encd = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let decd = ob_hex.dec(&encd).expect("Failed to dec with hex");
    assert_eq!(decd, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Ob32 all encodings test passed");
}

#[test]
#[cfg(feature = "apsv")]
fn test_apsv_basic() {
    let key = [0u8; 64];
    let ob = ApsvC32::from_bytes(&key).expect("Failed to create ApsvC32");

    let plaintext = "Testing ApsvC32 scheme";
    let encd1 = ob.enc(plaintext).expect("Failed to enc");
    let encd2 = ob.enc(plaintext).expect("Failed to enc");

    // ApsvC32 is probabilistic, so two encodings should be different
    assert_ne!(
        encd1, encd2,
        "ApsvC32 should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let decd1 = ob.dec(&encd1).expect("Failed to dec first encoding");
    let decd2 = ob.dec(&encd2).expect("Failed to dec second encoding");

    assert_eq!(decd1, plaintext);
    assert_eq!(decd2, plaintext);

    eprintln!("✓ ApsvC32 basic test passed");
}

#[test]
#[cfg(feature = "apsv")]
fn test_apsv_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test apsv with different encodings";

    // Base32Crockford (default)
    let ob_b32 = ApsvC32::from_bytes(&key).expect("Failed to create ApsvC32");
    let encd = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let decd = ob_b32.dec(&encd).expect("Failed to dec with base32");
    assert_eq!(decd, plaintext, "Decoding mismatch for base32");

    // Base64
    let ob_b64 = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let encd = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let decd = ob_b64.dec(&encd).expect("Failed to dec with base64");
    assert_eq!(decd, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = ApsvHex::from_bytes(&key).expect("Failed to create ApsvHex");
    let encd = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let decd = ob_hex.dec(&encd).expect("Failed to dec with hex");
    assert_eq!(decd, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ ApsvC32 all encodings test passed");
}

#[test]
#[cfg(feature = "zdc")]
#[cfg(feature = "upc")]
#[cfg(feature = "adgs")]
#[cfg(feature = "apgs")]
#[cfg(feature = "ob32")]
#[cfg(feature = "apsv")]
fn test_obflex_basic() {
    let key = [0u8; 64];
    let mut ob = ObFlex::from_bytes("zdc:c32", &key).expect("Failed to create ObFlex");

    let plaintext = "Testing ObFlex";

    // Test with different schemes
    for scheme in &[
        Scheme::Zdc,
        Scheme::Upc,
        Scheme::Adgs,
        Scheme::Apgs,
        Scheme::Ob32,
        Scheme::Apsv,
    ] {
        ob.set_scheme(*scheme)
            .expect(&format!("Failed to set scheme {:?}", scheme));

        let encd = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {:?}", scheme));
        let decd = ob
            .dec(&encd)
            .expect(&format!("Failed to dec with {:?}", scheme));

        assert_eq!(decd, plaintext, "Decoding mismatch for scheme {:?}", scheme);
    }

    eprintln!("✓ ObFlex basic test passed");
}

#[test]
#[cfg(feature = "zdc")]
#[cfg(feature = "upc")]
#[cfg(feature = "adgs")]
#[cfg(feature = "apgs")]
#[cfg(feature = "ob32")]
#[cfg(feature = "apsv")]
fn test_obflex_all_formats() {
    let key = [0u8; 64];
    let mut ob = ObFlex::from_bytes("zdc:c32", &key).expect("Failed to create ObFlex");

    let plaintext = "Testing all ObFlex formats";

    let formats = [
        "zdc:c32", "zdc:b64", "zdc:hex", "upc:c32", "upc:b64", "upc:hex", "adgs:c32", "adgs:b64",
        "adgs:hex", "apgs:c32", "apgs:b64", "apgs:hex", "ob32:c32", "ob32:b64", "ob32:hex",
        "apsv:c32", "apsv:b64", "apsv:hex",
    ];

    for format in &formats {
        ob.set_format(*format)
            .expect(&format!("Failed to set format {}", format));

        let encd = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {}", format));
        let decd = ob
            .dec(&encd)
            .expect(&format!("Failed to dec with {}", format));

        assert_eq!(decd, plaintext, "Decoding mismatch for format {}", format);
    }

    eprintln!("✓ ObFlex all formats test passed ({})", formats.len());
}

#[test]
#[cfg(feature = "adgs")]
fn test_obflex_encoding_changes() {
    let key = [0u8; 64];
    let mut ob = ObFlex::from_bytes("adgs:c32", &key).expect("Failed to create ObFlex");

    let plaintext = "Testing encoding changes";

    for encoding in &[Encoding::Base32Crockford, Encoding::Base64, Encoding::Hex] {
        ob.set_encoding(*encoding)
            .expect(&format!("Failed to set encoding {:?}", encoding));

        let encd = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {:?}", encoding));
        let decd = ob
            .dec(&encd)
            .expect(&format!("Failed to dec with {:?}", encoding));

        assert_eq!(
            decd, plaintext,
            "Decoding mismatch for encoding {:?}",
            encoding
        );
    }

    eprintln!("✓ ObFlex encoding changes test passed");
}

#[test]
#[cfg(feature = "apgs")]
#[cfg(feature = "ob32")]
#[cfg(feature = "apsv")]
fn test_all_schemes_special_characters() {
    let key = [0u8; 64];
    let plaintext = "Special: !@#$%^&*(){}[]|\\:;\"'<>,.?/~`±§";

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create ApgsB64");
    let encd = apgs.enc(plaintext).expect("Failed to enc with apgs");
    let decd = apgs.dec(&encd).expect("Failed to dec with apgs");
    assert_eq!(
        decd, plaintext,
        "Special characters decoding mismatch for apgs"
    );

    // Test Ob32
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create Ob32");
    let encd = ob32.enc(plaintext).expect("Failed to enc with ob32");
    let decd = ob32.dec(&encd).expect("Failed to dec with ob32");
    assert_eq!(
        decd, plaintext,
        "Special characters decoding mismatch for ob32"
    );

    // Test Apsv
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let encd = apsv.enc(plaintext).expect("Failed to enc with apsv");
    let decd = apsv.dec(&encd).expect("Failed to dec with apsv");
    assert_eq!(
        decd, plaintext,
        "Special characters decoding mismatch for apsv"
    );

    eprintln!("✓ All schemes special characters test passed");
}

#[test]
#[cfg(feature = "apgs")]
#[cfg(feature = "ob32")]
#[cfg(feature = "apsv")]
fn test_all_schemes_empty_string() {
    let key = [0u8; 64];
    let plaintext = "";

    // Empty strings cannot be encd - this is expected behavior
    // Test that all schemes correctly reject empty strings

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create ApgsB64");
    let result = apgs.enc(plaintext);
    assert!(result.is_err(), "ApgsB64 should reject empty string");

    // Test Ob32
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create Ob32");
    let result = ob32.enc(plaintext);
    assert!(result.is_err(), "Ob32 should reject empty string");

    // Test Apsv
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let result = apsv.enc(plaintext);
    assert!(result.is_err(), "ApsvB64 should reject empty string");

    eprintln!("✓ All schemes correctly reject empty strings");
}

#[test]
#[cfg(feature = "apgs")]
#[cfg(feature = "ob32")]
#[cfg(feature = "apsv")]
fn test_all_schemes_long_string() {
    let key = [0u8; 64];
    let plaintext = "a".repeat(10000);

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create Apgs");
    let encd = apgs
        .enc(&plaintext)
        .expect("Failed to enc long string with apgs");
    let decd = apgs
        .dec(&encd)
        .expect("Failed to dec long string with apgs");
    assert_eq!(decd, plaintext, "Long string decoding mismatch for apgs");

    // Test Ob32
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create Ob32");
    let encd = ob32
        .enc(&plaintext)
        .expect("Failed to enc long string with ob32");
    let decd = ob32
        .dec(&encd)
        .expect("Failed to dec long string with ob32");
    assert_eq!(decd, plaintext, "Long string decoding mismatch for ob32");

    // Test ApsvB64
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let encd = apsv
        .enc(&plaintext)
        .expect("Failed to enc long string with apsv");
    let decd = apsv
        .dec(&encd)
        .expect("Failed to dec long string with apsv");
    assert_eq!(decd, plaintext, "Long string decoding mismatch for apsv");

    eprintln!("✓ All schemes long string test passed");
}

#[test]
#[cfg(feature = "adgs")]
#[cfg(feature = "ob32")]
fn test_cross_scheme_decoding_should_fail() {
    let key = [0u8; 64];
    let plaintext = "Test cross-scheme decoding";

    // Encode with adgs
    let adgs = AdgsB64::from_bytes(&key).expect("Failed to create adgs");
    let encd_adgs = adgs.enc(plaintext).expect("Failed to enc with adgs");

    // Try to dec with ob32 using dec_strict (should fail)
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create ob32");
    let result = ob32.dec_strict(&encd_adgs);

    assert!(
        result.is_err(),
        "dec_strict should fail when decoding adgs ciphertext with ob32 decr"
    );

    eprintln!("✓ Cross-scheme decoding failure test passed");
}

#[test]
#[cfg(feature = "upc")]
#[cfg(feature = "apgs")]
#[cfg(feature = "apsv")]
fn test_probabilistic_schemes_uniqueness() {
    let key = [0u8; 64];
    let plaintext = "Testing probabilistic uniqueness";
    let iterations = 100;

    // Test Upc
    let upc = UpcB64::from_bytes(&key).expect("Failed to create upc");
    let mut encodings = std::collections::HashSet::new();
    for _ in 0..iterations {
        let encd = upc.enc(plaintext).expect("Failed to enc with upc");
        encodings.insert(encd);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "UpcB64 should produce {} unique obtexts",
        iterations
    );

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create apgs");
    encodings.clear();
    for _ in 0..iterations {
        let encd = apgs.enc(plaintext).expect("Failed to enc with apgs");
        encodings.insert(encd);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "ApgsB64 should produce {} unique ciphertexts",
        iterations
    );

    // Test ApsvB64
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    encodings.clear();
    for _ in 0..iterations {
        let encd = apsv.enc(plaintext).expect("Failed to enc with ApsvB64");
        encodings.insert(encd);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "ApsvB64 should produce {} unique ciphertexts",
        iterations
    );

    eprintln!(
        "✓ Probabilistic schemes uniqueness test passed ({} iterations per scheme)",
        iterations
    );
}

#[test]
#[cfg(feature = "zdc")]
#[cfg(feature = "adgs")]
#[cfg(feature = "ob32")]
fn test_deterministic_schemes_consistency() {
    let key = [0u8; 64];
    let plaintext = "Testing deterministic consistency";
    let iterations = 100;

    // Test Zdc
    let zdc = ZdcB64::from_bytes(&key).expect("Failed to create zdc");
    let first = zdc.enc(plaintext).expect("Failed to enc with zdc");
    for _ in 0..iterations {
        let encd = zdc.enc(plaintext).expect("Failed to enc with zdc");
        assert_eq!(encd, first, "ZdcB64 should produce identical obtexts");
    }

    // Test Adgs
    let adgs = AdgsB64::from_bytes(&key).expect("Failed to create adgs");
    let first = adgs.enc(plaintext).expect("Failed to enc with adgs");
    for _ in 0..iterations {
        let encd = adgs.enc(plaintext).expect("Failed to enc with adgs");
        assert_eq!(encd, first, "Adgs should produce identical obtexts");
    }

    // Test Ob32
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create ob32");
    let first = ob32.enc(plaintext).expect("Failed to enc with ob32");
    for _ in 0..iterations {
        let encd = ob32.enc(plaintext).expect("Failed to enc with ob32");
        assert_eq!(encd, first, "Ob32 should produce identical obtexts");
    }

    eprintln!(
        "✓ Deterministic schemes consistency test passed ({} iterations per scheme)",
        iterations
    );
}
