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

#[derive(Debug, Deserialize)]
struct MetaEntry {
    #[serde(rename = "type")]
    entry_type: String,
    secret: Option<String>,
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

fn load_test_vectors() -> (String, Vec<TestVector>) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/legacy-test-vectors.jsonl");
    let data = fs::read_to_string(&path).expect("Failed to read legacy-test-vectors.jsonl");
    let mut lines = data.lines().filter(|line| !line.trim().is_empty());

    let first = lines.next().expect("Empty test vector file");
    let (secret, extra_vector) = if let Ok(meta) = serde_json::from_str::<MetaEntry>(first) {
        if meta.entry_type == "meta" {
            (
                meta.secret.expect("Meta entry missing secret"),
                None::<TestVector>,
            )
        } else {
            let v: TestVector = serde_json::from_str(first).expect("Failed to parse test vector");
            (String::new(), Some(v))
        }
    } else {
        let v: TestVector = serde_json::from_str(first).expect("Failed to parse test vector");
        (String::new(), Some(v))
    };

    let mut vectors: Vec<TestVector> = extra_vector.into_iter().collect();
    vectors.extend(
        lines.map(|line| serde_json::from_str(line).expect("Failed to parse test vector")),
    );

    (secret, vectors)
}

#[test]
fn test_all_vectors() {
    let (secret, vectors) = load_test_vectors();
    println!("Loaded {} test vectors", vectors.len());

    for vector in &vectors {
        // legacy scheme is deterministic: test exact enc and dec match

        // Test encoding: plaintext → obtext (exact match)
        let enc_output = Command::cargo_bin("obz")
            .unwrap()
            .arg("enc")
            .arg("-s")
            .arg(&secret)
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
        let dec_output = Command::cargo_bin("obz")
            .unwrap()
            .arg("dec")
            .arg("-s")
            .arg(&secret)
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
