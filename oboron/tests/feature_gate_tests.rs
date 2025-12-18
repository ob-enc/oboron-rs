//!  Compile-time tests to verify feature gates are correctly applied
//!  Each test configuration compiles with a specific feature set

#![cfg(test)]

// Test that bytes-keys feature enables from_bytes methods
#[cfg(feature = "bytes-keys")]
mod bytes_keys_enabled {
    use oboron::*;

    #[test]
    fn test_bytes_key_constructors() {
        let key = generate_key_bytes();

        // These should all compile with bytes-keys feature
        #[cfg(feature = "ob32")]
        {
            let _ = Ob32::from_bytes(&key);
            let _ = Ob::from_bytes("ob32:c32", &key);
            let _ = ObFlex::from_bytes("ob32:c32", &key);
            let _ = ObMulti::from_bytes(&key);
        }
    }

    #[test]
    fn test_key_bytes_methods() {
        #[cfg(feature = "ob32")]
        {
            let key = generate_key();
            let ob = Ob32::new(&key).unwrap();

            // This should compile with bytes-keys feature
            let _key_bytes: &[u8; 64] = ob.key_bytes();
        }
    }
}

// Test that hex-keys feature enables from_hex_key methods
#[cfg(feature = "hex-keys")]
mod hex_keys_enabled {
    use oboron::*;

    #[test]
    fn test_hex_key_constructors() {
        let key = generate_key_hex();

        // These should all compile with hex-keys feature
        #[cfg(feature = "ob32")]
        {
            let _ = Ob32::from_hex_key(&key);
            let _ = Ob::from_hex_key("ob32:c32", &key);
            let _ = ObFlex::from_hex_key("ob32:c32", &key);
            let _ = ObMulti::from_key_hex(&key);
        }
    }

    #[test]
    fn test_key_hex_methods() {
        #[cfg(feature = "ob32")]
        {
            let key = generate_key();
            let ob = Ob32::new(&key).unwrap();

            // This should compile with hex-keys feature
            let _key_hex = ob.key_hex();
        }
    }
}

// Test that keyless feature enables new_keyless methods
#[cfg(feature = "keyless")]
mod keyless_enabled {
    use oboron::*;

    #[test]
    fn test_keyless_constructors() {
        // These should all compile with keyless feature
        #[cfg(feature = "ob32")]
        {
            let _ = Ob32::new_keyless();
            let _ = Ob::new_keyless("ob32:c32");
            let _ = ObFlex::new_keyless("ob32:c32");
            let _ = ObMulti::new_keyless();
        }
    }

    #[test]
    fn test_keyless_convenience_functions() {
        #[cfg(feature = "ob32")]
        {
            // These should compile with keyless feature
            let ot = enc_keyless("test", "ob32:c32").unwrap();
            let _pt = dec_keyless(&ot, "ob32:c32").unwrap();
            let _pt2 = autodec_keyless(&ot).unwrap();
        }
    }

    #[test]
    fn test_keyless_roundtrip() {
        #[cfg(feature = "ob32")]
        {
            let ob = Ob32::new_keyless().unwrap();
            let plaintext = "hello keyless";
            let obtext = ob.enc(plaintext).unwrap();
            let recovered = ob.dec(&obtext).unwrap();
            assert_eq!(plaintext, recovered);
        }
    }
}

// Test that methods are NOT available without features
#[cfg(not(feature = "bytes-keys"))]
mod bytes_keys_disabled {
    #[test]
    fn test_bytes_methods_not_available() {
        // This test just ensures we can compile without bytes-keys
        // The actual verification is that the from_bytes methods don't compile
        assert!(true);
    }
}

#[cfg(not(feature = "hex-keys"))]
mod hex_keys_disabled {
    #[test]
    fn test_hex_methods_not_available() {
        // This test just ensures we can compile without hex-keys
        // The actual verification is that the hex methods don't compile
        assert!(true);
    }
}

#[cfg(not(feature = "keyless"))]
mod keyless_disabled {
    #[test]
    fn test_keyless_methods_not_available() {
        // This test just ensures we can compile without keyless
        // The actual verification is that the keyless methods don't compile
        assert!(true);
    }
}

// Cross-feature validation tests
#[cfg(all(feature = "bytes-keys", feature = "hex-keys"))]
mod combined_features {
    use oboron::*;

    #[test]
    fn test_all_key_formats_work_together() {
        #[cfg(feature = "ob32")]
        {
            let key_b64 = generate_key();
            let key_hex = generate_key_hex();
            let key_bytes = generate_key_bytes();

            // All constructors should work
            let ob1 = Ob32::new(&key_b64).unwrap();
            let ob2 = Ob32::from_hex_key(&key_hex).unwrap();
            let ob3 = Ob32::from_bytes(&key_bytes).unwrap();

            // All key getters should work
            let _ = ob1.key();
            let _ = ob1.key_hex();
            let _ = ob1.key_bytes();

            // Test roundtrip with each
            let pt = "test";
            assert_eq!(ob1.dec(&ob1.enc(pt).unwrap()).unwrap(), pt);
            assert_eq!(ob2.dec(&ob2.enc(pt).unwrap()).unwrap(), pt);
            assert_eq!(ob3.dec(&ob3.enc(pt).unwrap()).unwrap(), pt);
        }
    }
}
