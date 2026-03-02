use assert_cmd::Command;
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

/// Strip only the trailing newline added by `println!`, preserving any internal whitespace.
fn strip_trailing_newline(s: String) -> String {
    if s.ends_with('\n') {
        let s = &s[..s.len() - 1];
        if s.ends_with('\r') {
            s[..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    } else {
        s
    }
}

fn load_test_vectors() -> Vec<TestVector> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/ztier-test-vectors.jsonl");
    let data = fs::read_to_string(&path).expect("Failed to read ztier-test-vectors.jsonl");
    data.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("Failed to parse test vector"))
        .collect()
}

fn is_deterministic(format: &str) -> bool {
    // Parse scheme from format string (e.g., "zrbcx.c32" → "zrbcx")
    let scheme = format.split('.').next().unwrap_or("");
    matches!(scheme, "zrbcx" | "zmock1")
}

#[test]
fn test_all_vectors() {
    let vectors = load_test_vectors();
    println!("Loaded {} test vectors", vectors.len());

    for vector in &vectors {
        let deterministic = is_deterministic(&vector.format);

        if !deterministic {
            // For probabilistic schemes: test decoding with explicit format
            let dec_output = Command::new("obz")
                .arg("dec")
                .arg("-K")
                .arg("--format")
                .arg(&vector.format)
                .arg("--")
                .arg(&vector.obtext)
                .output()
                .unwrap_or_else(|e| panic!("Failed to run obz dec: {}", e));

            assert!(
                dec_output.status.success(),
                "obz dec failed for '{}' with format '{}': {}",
                vector.obtext,
                vector.format,
                String::from_utf8_lossy(&dec_output.stderr)
            );
            let pt2 = strip_trailing_newline(String::from_utf8(dec_output.stdout).unwrap());
            assert_eq!(
                pt2, vector.plaintext,
                "Decoding mismatch for '{}' with format '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.format, vector.plaintext, pt2
            );

            // Roundtrip: enc then dec
            let enc_output = Command::new("obz")
                .arg("enc")
                .arg("-K")
                .arg("--format")
                .arg(&vector.format)
                .arg("--")
                .arg(&vector.plaintext)
                .output()
                .unwrap_or_else(|e| panic!("Failed to run obz enc: {}", e));

            assert!(
                enc_output.status.success(),
                "obz enc failed for '{}' with format '{}': {}",
                vector.plaintext,
                vector.format,
                String::from_utf8_lossy(&enc_output.stderr)
            );
            let new_obtext = strip_trailing_newline(String::from_utf8(enc_output.stdout).unwrap());

            let roundtrip_output = Command::new("obz")
                .arg("dec")
                .arg("-K")
                .arg("--format")
                .arg(&vector.format)
                .arg("--")
                .arg(&new_obtext)
                .output()
                .unwrap_or_else(|e| panic!("Failed to run obz dec (roundtrip): {}", e));

            assert!(
                roundtrip_output.status.success(),
                "obz dec roundtrip failed for '{}' with format '{}': {}",
                new_obtext,
                vector.format,
                String::from_utf8_lossy(&roundtrip_output.stderr)
            );
            let roundtrip =
                strip_trailing_newline(String::from_utf8(roundtrip_output.stdout).unwrap());
            assert_eq!(
                roundtrip, vector.plaintext,
                "Roundtrip mismatch for '{}' with format '{}'",
                vector.plaintext, vector.format
            );
        } else {
            // For deterministic schemes: test encoding (exact match) and decoding

            // Test encoding: plaintext → obtext (exact match)
            let enc_output = Command::new("obz")
                .arg("enc")
                .arg("-K")
                .arg("--format")
                .arg(&vector.format)
                .arg("--")
                .arg(&vector.plaintext)
                .output()
                .unwrap_or_else(|e| panic!("Failed to run obz enc: {}", e));

            assert!(
                enc_output.status.success(),
                "obz enc failed for '{}' with format '{}': {}",
                vector.plaintext,
                vector.format,
                String::from_utf8_lossy(&enc_output.stderr)
            );
            let ot = strip_trailing_newline(String::from_utf8(enc_output.stdout).unwrap());
            assert_eq!(
                ot, vector.obtext,
                "Encoding mismatch for '{}' with format '{}'\nExpected: {}\nGot: {}",
                vector.plaintext, vector.format, vector.obtext, ot
            );

            // Test decoding: obtext → plaintext
            let dec_output = Command::new("obz")
                .arg("dec")
                .arg("-K")
                .arg("--format")
                .arg(&vector.format)
                .arg("--")
                .arg(&vector.obtext)
                .output()
                .unwrap_or_else(|e| panic!("Failed to run obz dec: {}", e));

            assert!(
                dec_output.status.success(),
                "obz dec failed for '{}' with format '{}': {}",
                vector.obtext,
                vector.format,
                String::from_utf8_lossy(&dec_output.stderr)
            );
            let pt2 = strip_trailing_newline(String::from_utf8(dec_output.stdout).unwrap());
            assert_eq!(
                pt2, vector.plaintext,
                "Decoding mismatch for '{}' with format '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.format, vector.plaintext, pt2
            );
        }
    }
}
