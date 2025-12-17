use oboron::{Format, ObMulti};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct TestVector {
    format: String,
    plaintext: String,
    obtext: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
}

fn load_test_vectors() -> Vec<TestVector> {
    let possible_paths = vec![
        PathBuf::from("tests/test-vectors.jsonl"),
        PathBuf::from("oboron/tests/test-vectors.jsonl"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test-vectors.jsonl"),
    ];

    for path in &possible_paths {
        if path.exists() {
            println!("Found test vectors at: {:?}", path);
            let data = fs::read_to_string(path).expect("Failed to read test-vectors. jsonl");
            return data
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("Failed to parse test vector"))
                .collect();
        }
    }

    panic!("test-vectors.jsonl not found");
}

#[test]
fn test_all_vectors() {
    let vectors = load_test_vectors();
    println!("Loaded {} test vectors", vectors.len());

    let ob = ObMulti::new_keyless().expect("Failed to create ObMulti");

    for vector in vectors {
        let format = Format::from_str(&vector.format)
            .unwrap_or_else(|e| panic!("Invalid format '{}': {:?}", vector.format, e));

        let is_probabilistic = format.scheme().is_probabilistic();

        if is_probabilistic {
            // For probabilistic schemes, we can only test decoding
            // (encoding produces different output each time)

            // Test decoding with format
            let decd = ob.dec(&vector.obtext, &vector.format).unwrap_or_else(|e| {
                panic!(
                    "Failed to dec '{}' with format '{}': {:?}",
                    vector.obtext, vector.format, e
                )
            });

            assert_eq!(
                decd, vector.plaintext,
                "Decoding mismatch for '{}' with format '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.format, vector.plaintext, decd
            );

            // Test autodetection
            let autodetected = ob
                .autodec(&vector.obtext)
                .unwrap_or_else(|e| panic!("Failed to autodetect '{}': {:?}", vector.obtext, e));

            assert_eq!(
                autodetected, vector.plaintext,
                "Autodetection mismatch for '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.plaintext, autodetected
            );

            // Test that we can enc and then dec (roundtrip)
            let new_encd = ob
                .enc(&vector.plaintext, &vector.format)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to enc '{}' with format '{}': {:?}",
                        vector.plaintext, vector.format, e
                    )
                });

            let roundtrip = ob.dec(&new_encd, &vector.format).unwrap_or_else(|e| {
                panic!(
                    "Failed to dec roundtrip '{}' with format '{}': {:?}",
                    new_encd, vector.format, e
                )
            });

            assert_eq!(
                roundtrip, vector.plaintext,
                "Roundtrip mismatch for '{}' with format '{}'",
                vector.plaintext, vector.format
            );
        } else {
            // For deterministic schemes, test both encoding and decoding

            // Test encoding
            let encd = ob
                .enc(&vector.plaintext, &vector.format)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to enc '{}' with format '{}': {:?}",
                        vector.plaintext, vector.format, e
                    )
                });

            assert_eq!(
                encd, vector.obtext,
                "Encoding mismatch for '{}' with format '{}'\nExpected: {}\nGot: {}",
                vector.plaintext, vector.format, vector.obtext, encd
            );

            // Test decoding
            let decd = ob.dec(&vector.obtext, &vector.format).unwrap_or_else(|e| {
                panic!(
                    "Failed to dec '{}' with format '{}': {:?}",
                    vector.obtext, vector.format, e
                )
            });

            assert_eq!(
                decd, vector.plaintext,
                "Decoding mismatch for '{}' with format '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.format, vector.plaintext, decd
            );

            // Test autodetection
            let autodetected = ob
                .autodec(&vector.obtext)
                .unwrap_or_else(|e| panic!("Failed to autodetect '{}': {:?}", vector.obtext, e));

            assert_eq!(
                autodetected, vector.plaintext,
                "Autodetection mismatch for '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.plaintext, autodetected
            );
        }
    }
}
