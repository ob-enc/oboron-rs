#![allow(deprecated)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;

fn test_home_dir() -> PathBuf {
    let test_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();
    PathBuf::from(format!("./test_home_{}", test_id))
}

fn cleanup_test_home(dir: &PathBuf) {
    if dir.exists() {
        let _ = fs::remove_dir_all(dir);
    }
}

// Valid 86-character base64 key (64 bytes = 512 bits)
const TEST_KEY_B64: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TEST_KEY_B64_ALT: &str =
    "ZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn test_enc_keyless() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-z")
        .arg("--ob70")
        .arg("--base32rfc")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "ob01")]
#[test]
fn test_enc_keyless_ob01() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-z")
        .arg("--ob01")
        .arg("--base32rfc")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "ob01")]
#[test]
fn test_enc_dec_roundtrip_keyless() {
    let test_home = test_home_dir();

    // Encode
    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-z")
        .arg("--ob01")
        .arg("--base32rfc")
        .arg("hello_world")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    // Decode - use same scheme as enc for autodetection
    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-z")
        .arg("--ob01")
        .arg("--base32rfc")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));

    cleanup_test_home(&test_home);
}

#[test]
fn test_enc_with_explicit_key() {
    let test_home = test_home_dir();

    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--ob70")
        .arg("--base32rfc")
        .arg("test_data")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ob01")]
#[test]
fn test_enc_with_explicit_key_ob01() {
    let test_home = test_home_dir();

    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--ob01")
        .arg("--base32rfc")
        .arg("test_data")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());

    cleanup_test_home(&test_home);
}

#[test]
fn test_enc_dec_with_explicit_key() {
    let test_home = test_home_dir();

    // Encode with ob31
    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64_ALT)
        .arg("--ob70")
        .arg("--base32rfc")
        .arg("sensitive_data")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Decode - use same scheme as enc
    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("--key")
        .arg(TEST_KEY_B64_ALT)
        .arg("--ob70") // Use same scheme as enc
        .arg("--base32rfc")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("sensitive_data"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ob31")]
#[test]
fn test_enc_dec_with_explicit_key_ob31() {
    let test_home = test_home_dir();

    // Encode with ob31
    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64_ALT)
        .arg("--ob31")
        .arg("--base32rfc")
        .arg("sensitive_data")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    // Decode - use same scheme as enc
    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("--key")
        .arg(TEST_KEY_B64_ALT)
        .arg("--ob31") // Use same scheme as enc
        .arg("--base32rfc")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("sensitive_data"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ob01")]
#[cfg(feature = "ob31")]
#[cfg(feature = "ob32")]
#[cfg(feature = "ob21p")]
#[cfg(feature = "ob31p")]
#[cfg(feature = "ob32p")]
#[test]
fn test_enc_different_schemes() {
    let test_home = test_home_dir();
    let schemes = vec![
        "--ob01", "--ob31", "--ob32", "--ob21p", "--ob31p", "--ob32p",
    ];

    for scheme in schemes {
        let mut cmd = Command::cargo_bin("ob").unwrap();
        cmd.env("HOME", test_home.as_os_str())
            .arg("enc")
            .arg("-z")
            .arg(scheme)
            .arg("--base32rfc")
            .arg("test")
            .assert()
            .success();
    }

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ob01")]
#[test]
fn test_enc_different_encodings() {
    let test_home = test_home_dir();
    let encodings = vec!["--base32rfc", "--base64", "--hex"];

    for encoding in encodings {
        let mut cmd = Command::cargo_bin("ob").unwrap();
        cmd.env("HOME", test_home.as_os_str())
            .arg("enc")
            .arg("-z")
            .arg("--ob01")
            .arg(encoding)
            .arg("test")
            .assert()
            .success();
    }

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ob01")]
#[cfg(feature = "ob31")]
#[cfg(feature = "ob32")]
#[test]
fn test_enc_with_format_string() {
    let test_home = test_home_dir();
    let formats = vec!["ob01:b32", "ob31:b64", "ob32:hex"];

    for format in formats {
        let mut cmd = Command::cargo_bin("ob").unwrap();
        cmd.env("HOME", test_home.as_os_str())
            .arg("enc")
            .arg("-z")
            .arg("--format")
            .arg(format)
            .arg("test_format")
            .assert()
            .success();
    }

    cleanup_test_home(&test_home);
}
