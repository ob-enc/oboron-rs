#[cfg(feature = "adgs")]
use oboron::AdgsB64;
#[cfg(feature = "upc")]
use oboron::UpcB64;
#[cfg(feature = "zdc")]
use oboron::ZdcB64;
#[cfg(feature = "adsv")]
use oboron::{AdsvB64, AdsvC32, AdsvHex};
#[cfg(feature = "apgs")]
use oboron::{Apgs, ApgsB64, ApgsHex};
#[cfg(feature = "apsv")]
use oboron::{ApsvB64, ApsvC32, ApsvHex};
use oboron::{Encoding, ObFlex, Oboron, Scheme};

#[test]
#[cfg(feature = "apgs")]
fn test_apgs_basic() {
    let key = [0u8; 64];
    let ob = Apgs::from_bytes(&key).expect("Failed to create Apgs");

    let plaintext = "Hello, World!";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // Apgs is probabilistic, so two encodings should be different
    assert_ne!(
        ot1, ot2,
        "Apgs should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let pt21 = ob.dec(&ot1).expect("Failed to dec first encoding");
    let pt22 = ob.dec(&ot2).expect("Failed to dec second encoding");

    assert_eq!(pt21, plaintext);
    assert_eq!(pt22, plaintext);

    eprintln!("✓ Apgs basic test passed");
}

#[test]
#[cfg(feature = "apgs")]
fn test_apgs_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test apgs with different encodings";

    // C32 (default)
    let ob_b32 = Apgs::from_bytes(&key).expect("Failed to create Apgs with base32");
    let ot = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let pt2 = ob_b32.dec(&ot).expect("Failed to dec with base32");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base32");

    // B64
    let ob_b64 = ApgsB64::from_bytes(&key).expect("Failed to create Apgs with base64");
    let ot = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let pt2 = ob_b64.dec(&ot).expect("Failed to dec with base64");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = ApgsHex::from_bytes(&key).expect("Failed to create Apgs with hex");
    let ot = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let pt2 = ob_hex.dec(&ot).expect("Failed to dec with hex");
    assert_eq!(pt2, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Apgs all encodings test passed");
}

#[test]
#[cfg(feature = "adsv")]
fn test_adsv_basic() {
    let key = [0u8; 64];
    let ob = AdsvC32::from_bytes(&key).expect("Failed to create AdsvC32");

    let plaintext = "Testing AdsvC32";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // AdsvC32 is deterministic, so two encodings should be the same
    assert_eq!(
        ot1, ot2,
        "AdsvC32 should produce identical ciphertexts for the same plaintext"
    );

    let pt2 = ob.dec(&ot1).expect("Failed to dec");
    assert_eq!(pt2, plaintext);

    eprintln!("✓ AdsvC32 basic test passed");
}

#[test]
#[cfg(feature = "adsv")]
fn test_adsv_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test adsv with different encodings";

    // C32 (default)
    let ob_b32 = AdsvC32::from_bytes(&key).expect("Failed to create AdsvC32");
    let ot = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let pt2 = ob_b32.dec(&ot).expect("Failed to dec with base32");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base32");

    // B64
    let ob_b64 = AdsvB64::from_bytes(&key).expect("Failed to create AdsvC32");
    let ot = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let pt2 = ob_b64.dec(&ot).expect("Failed to dec with base64");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = AdsvHex::from_bytes(&key).expect("Failed to create AdsvC32");
    let ot = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let pt2 = ob_hex.dec(&ot).expect("Failed to dec with hex");
    assert_eq!(pt2, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Adsv all encodings test passed");
}

#[test]
#[cfg(feature = "apsv")]
fn test_apsv_basic() {
    let key = [0u8; 64];
    let ob = ApsvC32::from_bytes(&key).expect("Failed to create ApsvC32");

    let plaintext = "Testing ApsvC32 scheme";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // ApsvC32 is probabilistic, so two encodings should be different
    assert_ne!(
        ot1, ot2,
        "ApsvC32 should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let pt21 = ob.dec(&ot1).expect("Failed to dec first encoding");
    let pt22 = ob.dec(&ot2).expect("Failed to dec second encoding");

    assert_eq!(pt21, plaintext);
    assert_eq!(pt22, plaintext);

    eprintln!("✓ ApsvC32 basic test passed");
}

#[test]
#[cfg(feature = "apsv")]
fn test_apsv_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test apsv with different encodings";

    // C32 (default)
    let ob_b32 = ApsvC32::from_bytes(&key).expect("Failed to create ApsvC32");
    let ot = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let pt2 = ob_b32.dec(&ot).expect("Failed to dec with base32");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base32");

    // B64
    let ob_b64 = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let ot = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let pt2 = ob_b64.dec(&ot).expect("Failed to dec with base64");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = ApsvHex::from_bytes(&key).expect("Failed to create ApsvHex");
    let ot = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let pt2 = ob_hex.dec(&ot).expect("Failed to dec with hex");
    assert_eq!(pt2, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ ApsvC32 all encodings test passed");
}

#[test]
#[cfg(feature = "zdc")]
#[cfg(feature = "upc")]
#[cfg(feature = "adgs")]
#[cfg(feature = "apgs")]
#[cfg(feature = "adsv")]
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
        Scheme::Adsv,
        Scheme::Apsv,
    ] {
        ob.set_scheme(*scheme)
            .expect(&format!("Failed to set scheme {:?}", scheme));

        let ot = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {:?}", scheme));
        let pt2 = ob
            .dec(&ot)
            .expect(&format!("Failed to dec with {:?}", scheme));

        assert_eq!(pt2, plaintext, "Decoding mismatch for scheme {:?}", scheme);
    }

    eprintln!("✓ ObFlex basic test passed");
}

#[test]
#[cfg(feature = "zdc")]
#[cfg(feature = "upc")]
#[cfg(feature = "adgs")]
#[cfg(feature = "apgs")]
#[cfg(feature = "adsv")]
#[cfg(feature = "apsv")]
fn test_obflex_all_formats() {
    let key = [0u8; 64];
    let mut ob = ObFlex::from_bytes("zdc:c32", &key).expect("Failed to create ObFlex");

    let plaintext = "Testing all ObFlex formats";

    let formats = [
        "zdc:c32", "zdc:b64", "zdc:hex", "upc:c32", "upc:b64", "upc:hex", "adgs:c32", "adgs:b64",
        "adgs:hex", "apgs:c32", "apgs:b64", "apgs:hex", "adsv:c32", "adsv:b64", "adsv:hex",
        "apsv:c32", "apsv:b64", "apsv:hex",
    ];

    for format in &formats {
        ob.set_format(*format)
            .expect(&format!("Failed to set format {}", format));

        let ot = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {}", format));
        let pt2 = ob
            .dec(&ot)
            .expect(&format!("Failed to dec with {}", format));

        assert_eq!(pt2, plaintext, "Decoding mismatch for format {}", format);
    }

    eprintln!("✓ ObFlex all formats test passed ({})", formats.len());
}

#[test]
#[cfg(feature = "adgs")]
fn test_obflex_encoding_changes() {
    let key = [0u8; 64];
    let mut ob = ObFlex::from_bytes("adgs:c32", &key).expect("Failed to create ObFlex");

    let plaintext = "Testing encoding changes";

    for encoding in &[Encoding::C32, Encoding::B64, Encoding::Hex] {
        ob.set_encoding(*encoding)
            .expect(&format!("Failed to set encoding {:?}", encoding));

        let ot = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {:?}", encoding));
        let pt2 = ob
            .dec(&ot)
            .expect(&format!("Failed to dec with {:?}", encoding));

        assert_eq!(
            pt2, plaintext,
            "Decoding mismatch for encoding {:?}",
            encoding
        );
    }

    eprintln!("✓ ObFlex encoding changes test passed");
}

#[test]
#[cfg(feature = "apgs")]
#[cfg(feature = "adsv")]
#[cfg(feature = "apsv")]
fn test_all_schemes_special_characters() {
    let key = [0u8; 64];
    let plaintext = "Special: !@#$%^&*(){}[]|\\:;\"'<>,.?/~`±§";

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create ApgsB64");
    let ot = apgs.enc(plaintext).expect("Failed to enc with apgs");
    let pt2 = apgs.dec(&ot).expect("Failed to dec with apgs");
    assert_eq!(
        pt2, plaintext,
        "Special characters decoding mismatch for apgs"
    );

    // Test Adsv
    let adsv = AdsvB64::from_bytes(&key).expect("Failed to create AdsvB64");
    let ot = adsv.enc(plaintext).expect("Failed to enc with adsv");
    let pt2 = adsv.dec(&ot).expect("Failed to dec with adsv");
    assert_eq!(
        pt2, plaintext,
        "Special characters decoding mismatch for adsv"
    );

    // Test Apsv
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let ot = apsv.enc(plaintext).expect("Failed to enc with apsv");
    let pt2 = apsv.dec(&ot).expect("Failed to dec with apsv");
    assert_eq!(
        pt2, plaintext,
        "Special characters decoding mismatch for apsv"
    );

    eprintln!("✓ All schemes special characters test passed");
}

#[test]
#[cfg(feature = "apgs")]
#[cfg(feature = "adsv")]
#[cfg(feature = "apsv")]
fn test_all_schemes_empty_string() {
    let key = [0u8; 64];
    let plaintext = "";

    // Empty strings cannot be ot - this is expected behavior
    // Test that all schemes correctly reject empty strings

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create ApgsB64");
    let result = apgs.enc(plaintext);
    assert!(result.is_err(), "ApgsB64 should reject empty string");

    // Test Adsv
    let adsv = AdsvB64::from_bytes(&key).expect("Failed to create AdsvB64");
    let result = adsv.enc(plaintext);
    assert!(result.is_err(), "AdsvB64 should reject empty string");

    // Test Apsv
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let result = apsv.enc(plaintext);
    assert!(result.is_err(), "ApsvB64 should reject empty string");

    eprintln!("✓ All schemes correctly reject empty strings");
}

#[test]
#[cfg(feature = "apgs")]
#[cfg(feature = "adsv")]
#[cfg(feature = "apsv")]
fn test_all_schemes_long_string() {
    let key = [0u8; 64];
    let plaintext = "a".repeat(10000);

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create Apgs");
    let ot = apgs
        .enc(&plaintext)
        .expect("Failed to enc long string with apgs");
    let pt2 = apgs.dec(&ot).expect("Failed to dec long string with apgs");
    assert_eq!(pt2, plaintext, "Long string decoding mismatch for apgs");

    // Test Adsv
    let adsv = AdsvB64::from_bytes(&key).expect("Failed to create AdsvB64");
    let ot = adsv
        .enc(&plaintext)
        .expect("Failed to enc long string with adsv");
    let pt2 = adsv.dec(&ot).expect("Failed to dec long string with adsv");
    assert_eq!(pt2, plaintext, "Long string decoding mismatch for adsv");

    // Test ApsvB64
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let ot = apsv
        .enc(&plaintext)
        .expect("Failed to enc long string with apsv");
    let pt2 = apsv.dec(&ot).expect("Failed to dec long string with apsv");
    assert_eq!(pt2, plaintext, "Long string decoding mismatch for apsv");

    eprintln!("✓ All schemes long string test passed");
}

#[test]
#[cfg(feature = "adgs")]
#[cfg(feature = "adsv")]
fn test_cross_scheme_decoding_should_fail() {
    let key = [0u8; 64];
    let plaintext = "Test cross-scheme decoding";

    // Encode with adgs
    let adgs = AdgsB64::from_bytes(&key).expect("Failed to create adgs");
    let ot_adgs = adgs.enc(plaintext).expect("Failed to enc with adgs");

    // Try to dec with adsv using dec_strict (should fail)
    let adsv = AdsvB64::from_bytes(&key).expect("Failed to create adsv");
    let result = adsv.dec_strict(&ot_adgs);

    assert!(
        result.is_err(),
        "dec_strict should fail when decoding adgs ciphertext with adsv decr"
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
        let ot = upc.enc(plaintext).expect("Failed to enc with upc");
        encodings.insert(ot);
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
        let ot = apgs.enc(plaintext).expect("Failed to enc with apgs");
        encodings.insert(ot);
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
        let ot = apsv.enc(plaintext).expect("Failed to enc with ApsvB64");
        encodings.insert(ot);
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
#[cfg(feature = "adsv")]
fn test_deterministic_schemes_consistency() {
    let key = [0u8; 64];
    let plaintext = "Testing deterministic consistency";
    let iterations = 100;

    // Test Zdc
    let zdc = ZdcB64::from_bytes(&key).expect("Failed to create zdc");
    let first = zdc.enc(plaintext).expect("Failed to enc with zdc");
    for _ in 0..iterations {
        let ot = zdc.enc(plaintext).expect("Failed to enc with zdc");
        assert_eq!(ot, first, "ZdcB64 should produce identical obtexts");
    }

    // Test Adgs
    let adgs = AdgsB64::from_bytes(&key).expect("Failed to create adgs");
    let first = adgs.enc(plaintext).expect("Failed to enc with adgs");
    for _ in 0..iterations {
        let ot = adgs.enc(plaintext).expect("Failed to enc with adgs");
        assert_eq!(ot, first, "Adgs should produce identical obtexts");
    }

    // Test Adsv
    let adsv = AdsvB64::from_bytes(&key).expect("Failed to create adsv");
    let first = adsv.enc(plaintext).expect("Failed to enc with adsv");
    for _ in 0..iterations {
        let ot = adsv.enc(plaintext).expect("Failed to enc with adsv");
        assert_eq!(ot, first, "AdsvB64 should produce identical obtexts");
    }

    eprintln!(
        "✓ Deterministic schemes consistency test passed ({} iterations per scheme)",
        iterations
    );
}
