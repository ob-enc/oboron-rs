use oboron::{Encoding, Ob, Oboron, Scheme};

#[test]
fn test_ob_basic_roundtrip() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("mock1.c32", &key).expect("Failed to create Ob");

    let plaintext = "Hello, Ob!";
    let encd = ob.enc(plaintext).expect("Failed to enc");
    let decd = ob.dec(&encd).expect("Failed to dec");

    assert_eq!(decd, plaintext);
}

#[test]
#[cfg(feature = "adsv")]
fn test_ob_deterministic() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("adsv.b64", &key).expect("Failed to create Ob with adsv");

    let plaintext = "Deterministic test";
    let encd1 = ob.enc(plaintext).expect("Failed to enc");
    let encd2 = ob.enc(plaintext).expect("Failed to enc");

    // Adsv is deterministic
    assert_eq!(encd1, encd2);
}

#[test]
#[cfg(feature = "apsv")]
fn test_ob_probabilistic() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("apsv.b64", &key).expect("Failed to create Ob with apsv");

    let plaintext = "Probabilistic test";
    let encd1 = ob.enc(plaintext).expect("Failed to enc");
    let encd2 = ob.enc(plaintext).expect("Failed to enc");

    // Apsv is probabilistic
    assert_ne!(encd1, encd2);

    // But both dec correctly
    assert_eq!(ob.dec(&encd1).unwrap(), plaintext);
    assert_eq!(ob.dec(&encd2).unwrap(), plaintext);
}

#[test]
fn test_ob_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test all encodings";

    for format in ["mock1.c32", "mock1.b64", "mock1.hex"] {
        let ob =
            Ob::from_bytes(format, &key).expect(&format!("Failed to create Ob with {}", format));

        let encd = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {}", format));
        let decd = ob
            .dec(&encd)
            .expect(&format!("Failed to dec with {}", format));

        assert_eq!(decd, plaintext, "Mismatch for format {}", format);
    }
}

#[test]
fn test_ob_from_hex_key() {
    let hex_key = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let ob = Ob::from_hex_key("mock1.c32", hex_key).expect("Failed to create Ob from hex");

    let plaintext = "Testing hex key";
    let encd = ob.enc(plaintext).expect("Failed to enc");
    let decd = ob.dec(&encd).expect("Failed to dec");

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob_with_format_instance() {
    let key = [0u8; 64];
    let format = "mock1.b64";
    let ob = Ob::from_bytes(format, &key).expect("Failed to create Ob with format string");

    assert_eq!(ob.scheme(), Scheme::Mock1);
    assert_eq!(ob.encoding(), Encoding::B64);
}

#[test]
fn test_ob_format_getter() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("mock1.b64", &key).expect("Failed to create Ob");

    let format = ob.format();
    assert_eq!(format.scheme(), Scheme::Mock1);
    assert_eq!(format.encoding(), Encoding::B64);
}

#[test]
fn test_ob_immutable_format() {
    // This test documents that Ob's format is immutable
    // Unlike ObFlex, there's no set_format() method
    let key = [0u8; 64];
    let ob = Ob::from_bytes("mock1.c32", &key).expect("Failed to create Ob");

    // Verify format is set
    assert_eq!(ob.scheme(), Scheme::Mock1);
    assert_eq!(ob.encoding(), Encoding::C32);

    // Format cannot be changed (no set_format method exists)
    // This is compile-time enforced, but we document the intent
}

#[test]
#[cfg(feature = "adsv")]
fn test_ob_scheme_autodetection() {
    let key = [0u8; 64];

    // Encode with adsv
    let adsv = Ob::from_bytes("adsv.b64", &key).expect("Failed to create Ob with adsv.b64 format");
    let encd = adsv.enc("test").expect("Failed to enc");

    // Decode with mock1 (different scheme, same encoding)
    let mock1 =
        Ob::from_bytes("mock1.b64", &key).expect("Failed to create Ob with mock1.b64 format");
    let decd = mock1.dec(&encd).expect("Failed to dec with autodetection");
    assert_eq!(decd, "test");

    // But dec_strict fails (scheme mismatch)
    assert!(mock1.dec_strict(&encd).is_err());
}

#[test]
fn test_ob_encoding_must_match() {
    let key = [0u8; 64];

    // Encode with C32
    let ob_b32 = Ob::from_bytes("mock1.c32", &key).expect("Failed to create Ob with b32");
    let encd = ob_b32.enc("test").expect("Failed to enc");

    // Try to dec with B64 (wrong encoding)
    let ob_b64 = Ob::from_bytes("mock1.b64", &key).expect("Failed to create Ob with b64");
    assert!(
        ob_b64.dec(&encd).is_err(),
        "Should fail with wrong encoding"
    );
}

#[test]
fn test_ob_key_getter() {
    let key =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let ob = Ob::new("mock1.c32", &key).expect("Failed to create Ob");

    assert_eq!(ob.key(), key);
}

#[test]
fn test_ob_special_characters() {
    let key =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let ob = Ob::new("mock1.b64", &key).expect("Failed to create Ob");

    let plaintext = "Special: !@#$%^&*(){}[]|\\:;\"'<>,.?/~`±§";
    let encd = ob.enc(plaintext).expect("Failed to enc");
    let decd = ob.dec(&encd).expect("Failed to dec");

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob_keyless() {
    let ob = Ob::new_keyless("mock1.c32").expect("Failed to create Ob with hardcoded key");

    let plaintext = "keyless test";
    let encd = ob.enc(plaintext).expect("Failed to enc");
    let decd = ob.dec(&encd).expect("Failed to dec");

    assert_eq!(decd, plaintext);
}

#[test]
fn test_ob_generic_usage() {
    // Test that Ob works with generic Oboron trait
    fn enc_with_oboron<O: Oboron>(ob: &O, data: &str) -> String {
        ob.enc(data).unwrap()
    }

    let key =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let ob = Ob::new("mock1.c32", key).expect("Failed to create Ob");

    let encd = enc_with_oboron(&ob, "generic test");
    assert!(encd.len() > 0);
}
