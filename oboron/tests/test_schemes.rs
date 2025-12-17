#[cfg(feature = "ob01")]
use oboron::Ob01Base64;
#[cfg(feature = "ob21p")]
use oboron::Ob21pBase64;
#[cfg(feature = "ob31")]
use oboron::Ob31Base64;
use oboron::{Encoding, ObFlex, Oboron, Scheme};
#[cfg(feature = "ob31p")]
use oboron::{Ob31p, Ob31pBase64, Ob31pHex};
#[cfg(feature = "ob32")]
use oboron::{Ob32, Ob32Base64, Ob32Hex};
#[cfg(feature = "ob32p")]
use oboron::{Ob32p, Ob32pBase64, Ob32pHex};

#[test]
#[cfg(feature = "ob31p")]
fn test_ob31p_basic() {
    let key = [0u8; 64];
    let ob = Ob31p::from_bytes(&key).expect("Failed to create Ob31p");

    let plaintext = "Hello, World!";
    let encd1 = ob.enc(plaintext).expect("Failed to enc");
    let encd2 = ob.enc(plaintext).expect("Failed to enc");

    // Ob31p is probabilistic, so two encodings should be different
    assert_ne!(
        encd1, encd2,
        "Ob31p should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let decd1 = ob.dec(&encd1).expect("Failed to dec first encoding");
    let decd2 = ob.dec(&encd2).expect("Failed to dec second encoding");

    assert_eq!(decd1, plaintext);
    assert_eq!(decd2, plaintext);

    eprintln!("✓ Ob31p basic test passed");
}

#[test]
#[cfg(feature = "ob31p")]
fn test_ob31p_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test ob31p with different encodings";

    // Base32Crockford (default)
    let ob_b32 = Ob31p::from_bytes(&key).expect("Failed to create Ob31p with base32");
    let encd = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let decd = ob_b32.dec(&encd).expect("Failed to dec with base32");
    assert_eq!(decd, plaintext, "Decoding mismatch for base32");

    // Base64
    let ob_b64 = Ob31pBase64::from_bytes(&key).expect("Failed to create Ob31p with base64");
    let encd = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let decd = ob_b64.dec(&encd).expect("Failed to dec with base64");
    assert_eq!(decd, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = Ob31pHex::from_bytes(&key).expect("Failed to create Ob31p with hex");
    let encd = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let decd = ob_hex.dec(&encd).expect("Failed to dec with hex");
    assert_eq!(decd, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Ob31p all encodings test passed");
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
#[cfg(feature = "ob32p")]
fn test_ob32p_basic() {
    let key = [0u8; 64];
    let ob = Ob32p::from_bytes(&key).expect("Failed to create Ob32p");

    let plaintext = "Testing Ob32p scheme";
    let encd1 = ob.enc(plaintext).expect("Failed to enc");
    let encd2 = ob.enc(plaintext).expect("Failed to enc");

    // Ob32p is probabilistic, so two encodings should be different
    assert_ne!(
        encd1, encd2,
        "Ob32p should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let decd1 = ob.dec(&encd1).expect("Failed to dec first encoding");
    let decd2 = ob.dec(&encd2).expect("Failed to dec second encoding");

    assert_eq!(decd1, plaintext);
    assert_eq!(decd2, plaintext);

    eprintln!("✓ Ob32p basic test passed");
}

#[test]
#[cfg(feature = "ob32p")]
fn test_ob32p_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test ob32p with different encodings";

    // Base32Crockford (default)
    let ob_b32 = Ob32p::from_bytes(&key).expect("Failed to create Ob32p with base32");
    let encd = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let decd = ob_b32.dec(&encd).expect("Failed to dec with base32");
    assert_eq!(decd, plaintext, "Decoding mismatch for base32");

    // Base64
    let ob_b64 = Ob32pBase64::from_bytes(&key).expect("Failed to create Ob32p with base64");
    let encd = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let decd = ob_b64.dec(&encd).expect("Failed to dec with base64");
    assert_eq!(decd, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = Ob32pHex::from_bytes(&key).expect("Failed to create Ob32p with hex");
    let encd = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let decd = ob_hex.dec(&encd).expect("Failed to dec with hex");
    assert_eq!(decd, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Ob32p all encodings test passed");
}

#[test]
#[cfg(feature = "ob01")]
#[cfg(feature = "ob21p")]
#[cfg(feature = "ob31")]
#[cfg(feature = "ob31p")]
#[cfg(feature = "ob32")]
#[cfg(feature = "ob32p")]
fn test_obflex_basic() {
    let key = [0u8; 64];
    let mut ob = ObFlex::from_bytes("ob01:c32", &key).expect("Failed to create ObFlex");

    let plaintext = "Testing ObFlex";

    // Test with different schemes
    for scheme in &[
        Scheme::Ob01,
        Scheme::Ob21p,
        Scheme::Ob31,
        Scheme::Ob31p,
        Scheme::Ob32,
        Scheme::Ob32p,
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
#[cfg(feature = "ob01")]
#[cfg(feature = "ob21p")]
#[cfg(feature = "ob31")]
#[cfg(feature = "ob31p")]
#[cfg(feature = "ob32")]
#[cfg(feature = "ob32p")]
fn test_obflex_all_formats() {
    let key = [0u8; 64];
    let mut ob = ObFlex::from_bytes("ob01:c32", &key).expect("Failed to create ObFlex");

    let plaintext = "Testing all ObFlex formats";

    let formats = [
        "ob01:c32",
        "ob01:b64",
        "ob01:hex",
        "ob21p:c32",
        "ob21p:b64",
        "ob21p:hex",
        "ob31:c32",
        "ob31:b64",
        "ob31:hex",
        "ob31p:c32",
        "ob31p:b64",
        "ob31p:hex",
        "ob32:c32",
        "ob32:b64",
        "ob32:hex",
        "ob32p:c32",
        "ob32p:b64",
        "ob32p:hex",
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
#[cfg(feature = "ob31")]
fn test_obflex_encoding_changes() {
    let key = [0u8; 64];
    let mut ob = ObFlex::from_bytes("ob31:c32", &key).expect("Failed to create ObFlex");

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
#[cfg(feature = "ob31p")]
#[cfg(feature = "ob32")]
#[cfg(feature = "ob32p")]
fn test_all_schemes_special_characters() {
    let key = [0u8; 64];
    let plaintext = "Special: !@#$%^&*(){}[]|\\:;\"'<>,.?/~`±§";

    // Test Ob31p
    let ob31p = Ob31pBase64::from_bytes(&key).expect("Failed to create Ob31p");
    let encd = ob31p.enc(plaintext).expect("Failed to enc with ob31p");
    let decd = ob31p.dec(&encd).expect("Failed to dec with ob31p");
    assert_eq!(
        decd, plaintext,
        "Special characters decoding mismatch for ob31p"
    );

    // Test Ob32
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create Ob32");
    let encd = ob32.enc(plaintext).expect("Failed to enc with ob32");
    let decd = ob32.dec(&encd).expect("Failed to dec with ob32");
    assert_eq!(
        decd, plaintext,
        "Special characters decoding mismatch for ob32"
    );

    // Test Ob32p
    let ob32p = Ob32pBase64::from_bytes(&key).expect("Failed to create Ob32p");
    let encd = ob32p.enc(plaintext).expect("Failed to enc with ob32p");
    let decd = ob32p.dec(&encd).expect("Failed to dec with ob32p");
    assert_eq!(
        decd, plaintext,
        "Special characters decoding mismatch for ob32p"
    );

    eprintln!("✓ All schemes special characters test passed");
}

#[test]
#[cfg(feature = "ob31p")]
#[cfg(feature = "ob32")]
#[cfg(feature = "ob32p")]
fn test_all_schemes_empty_string() {
    let key = [0u8; 64];
    let plaintext = "";

    // Empty strings cannot be encd - this is expected behavior
    // Test that all schemes correctly reject empty strings

    // Test Ob31p
    let ob31p = Ob31pBase64::from_bytes(&key).expect("Failed to create Ob31p");
    let result = ob31p.enc(plaintext);
    assert!(result.is_err(), "Ob31p should reject empty string");

    // Test Ob32
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create Ob32");
    let result = ob32.enc(plaintext);
    assert!(result.is_err(), "Ob32 should reject empty string");

    // Test Ob32p
    let ob32p = Ob32pBase64::from_bytes(&key).expect("Failed to create Ob32p");
    let result = ob32p.enc(plaintext);
    assert!(result.is_err(), "Ob32p should reject empty string");

    eprintln!("✓ All schemes correctly reject empty strings");
}

#[test]
#[cfg(feature = "ob31p")]
#[cfg(feature = "ob32")]
#[cfg(feature = "ob32p")]
fn test_all_schemes_long_string() {
    let key = [0u8; 64];
    let plaintext = "a".repeat(10000);

    // Test Ob31p
    let ob31p = Ob31pBase64::from_bytes(&key).expect("Failed to create Ob31p");
    let encd = ob31p
        .enc(&plaintext)
        .expect("Failed to enc long string with ob31p");
    let decd = ob31p
        .dec(&encd)
        .expect("Failed to dec long string with ob31p");
    assert_eq!(decd, plaintext, "Long string decoding mismatch for ob31p");

    // Test Ob32
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create Ob32");
    let encd = ob32
        .enc(&plaintext)
        .expect("Failed to enc long string with ob32");
    let decd = ob32
        .dec(&encd)
        .expect("Failed to dec long string with ob32");
    assert_eq!(decd, plaintext, "Long string decoding mismatch for ob32");

    // Test Ob32p
    let ob32p = Ob32pBase64::from_bytes(&key).expect("Failed to create Ob32p");
    let encd = ob32p
        .enc(&plaintext)
        .expect("Failed to enc long string with ob32p");
    let decd = ob32p
        .dec(&encd)
        .expect("Failed to dec long string with ob32p");
    assert_eq!(decd, plaintext, "Long string decoding mismatch for ob32p");

    eprintln!("✓ All schemes long string test passed");
}

#[test]
#[cfg(feature = "ob31")]
#[cfg(feature = "ob32")]
fn test_cross_scheme_decoding_should_fail() {
    let key = [0u8; 64];
    let plaintext = "Test cross-scheme decoding";

    // Encode with ob31
    let ob31 = Ob31Base64::from_bytes(&key).expect("Failed to create ob31");
    let encd_ob31 = ob31.enc(plaintext).expect("Failed to enc with ob31");

    // Try to dec with ob32 using dec_strict (should fail)
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create ob32");
    let result = ob32.dec_strict(&encd_ob31);

    assert!(
        result.is_err(),
        "dec_strict should fail when decoding ob31 ciphertext with ob32 decr"
    );

    eprintln!("✓ Cross-scheme decoding failure test passed");
}

#[test]
#[cfg(feature = "ob21p")]
#[cfg(feature = "ob31p")]
#[cfg(feature = "ob32p")]
fn test_probabilistic_schemes_uniqueness() {
    let key = [0u8; 64];
    let plaintext = "Testing probabilistic uniqueness";
    let iterations = 100;

    // Test Ob21p
    let ob21p = Ob21pBase64::from_bytes(&key).expect("Failed to create ob21p");
    let mut encodings = std::collections::HashSet::new();
    for _ in 0..iterations {
        let encd = ob21p.enc(plaintext).expect("Failed to enc with ob21p");
        encodings.insert(encd);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "Ob21p should produce {} unique ciphertexts",
        iterations
    );

    // Test Ob31p
    let ob31p = Ob31pBase64::from_bytes(&key).expect("Failed to create ob31p");
    encodings.clear();
    for _ in 0..iterations {
        let encd = ob31p.enc(plaintext).expect("Failed to enc with ob31p");
        encodings.insert(encd);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "Ob31p should produce {} unique ciphertexts",
        iterations
    );

    // Test Ob32p
    let ob32p = Ob32pBase64::from_bytes(&key).expect("Failed to create ob32p");
    encodings.clear();
    for _ in 0..iterations {
        let encd = ob32p.enc(plaintext).expect("Failed to enc with ob32p");
        encodings.insert(encd);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "Ob32p should produce {} unique ciphertexts",
        iterations
    );

    eprintln!(
        "✓ Probabilistic schemes uniqueness test passed ({} iterations per scheme)",
        iterations
    );
}

#[test]
#[cfg(feature = "ob01")]
#[cfg(feature = "ob31")]
#[cfg(feature = "ob32")]
fn test_deterministic_schemes_consistency() {
    let key = [0u8; 64];
    let plaintext = "Testing deterministic consistency";
    let iterations = 100;

    // Test Ob01
    let ob01 = Ob01Base64::from_bytes(&key).expect("Failed to create ob01");
    let first = ob01.enc(plaintext).expect("Failed to enc with ob01");
    for _ in 0..iterations {
        let encd = ob01.enc(plaintext).expect("Failed to enc with ob01");
        assert_eq!(encd, first, "Ob01 should produce identical ciphertexts");
    }

    // Test Ob31
    let ob31 = Ob31Base64::from_bytes(&key).expect("Failed to create ob31");
    let first = ob31.enc(plaintext).expect("Failed to enc with ob31");
    for _ in 0..iterations {
        let encd = ob31.enc(plaintext).expect("Failed to enc with ob31");
        assert_eq!(encd, first, "Ob31 should produce identical ciphertexts");
    }

    // Test Ob32
    let ob32 = Ob32Base64::from_bytes(&key).expect("Failed to create ob32");
    let first = ob32.enc(plaintext).expect("Failed to enc with ob32");
    for _ in 0..iterations {
        let encd = ob32.enc(plaintext).expect("Failed to enc with ob32");
        assert_eq!(encd, first, "Ob32 should produce identical ciphertexts");
    }

    eprintln!(
        "✓ Deterministic schemes consistency test passed ({} iterations per scheme)",
        iterations
    );
}
