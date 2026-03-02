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

// Valid 43-character base64url secret (32 bytes = 256 bits)
const TEST_SECRET: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TEST_SECRET_ALT: &str = "ZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_keyless() {
    let test_home = test_home_dir();
    let mut cmd = Command::new("obz");
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--b32")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_with_explicit_key() {
    let test_home = test_home_dir();
    let mut cmd = Command::new("obz");
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--secret")
        .arg(TEST_SECRET)
        .arg("--zrbcx")
        .arg("--b32")
        .arg("test_data")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_dec_roundtrip() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::new("obz");
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--b32")
        .arg("hello_obz")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::new("obz");
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_obz"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_dec_roundtrip_b64() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::new("obz");
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--b64")
        .arg("hello_b64")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::new("obz");
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--b64")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_b64"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_dec_roundtrip_hex() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::new("obz");
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--hex")
        .arg("hello_hex")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::new("obz");
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--hex")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_hex"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_dec_roundtrip_with_explicit_key() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::new("obz");
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--secret")
        .arg(TEST_SECRET)
        .arg("--zrbcx")
        .arg("--b32")
        .arg("hello_key")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::new("obz");
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("--secret")
        .arg(TEST_SECRET)
        .arg("--zrbcx")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_key"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_invalid_key_too_short() {
    let test_home = test_home_dir();
    let mut cmd = Command::new("obz");
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--secret")
        .arg("TOOSHORT")
        .arg("--zrbcx")
        .arg("--b32")
        .arg("hello")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_invalid_key_empty() {
    let test_home = test_home_dir();
    let mut cmd = Command::new("obz");
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--secret")
        .arg("")
        .arg("--zrbcx")
        .arg("--b32")
        .arg("hello")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_dec_garbage_input() {
    let test_home = test_home_dir();
    let mut cmd = Command::new("obz");
    cmd.env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--b32")
        .arg("notvalidobtext")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_missing_plaintext() {
    let test_home = test_home_dir();
    let mut cmd = Command::new("obz");
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--b32")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_different_keys_produce_different_output() {
    let test_home = test_home_dir();

    let mut enc_cmd_a = Command::new("obz");
    let enc_output_a = enc_cmd_a
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--secret")
        .arg(TEST_SECRET)
        .arg("--zrbcx")
        .arg("--b32")
        .arg("same_input")
        .output()
        .unwrap();
    assert!(enc_output_a.status.success());
    let encd_a = String::from_utf8(enc_output_a.stdout)
        .unwrap()
        .trim()
        .to_string();

    let mut enc_cmd_b = Command::new("obz");
    let enc_output_b = enc_cmd_b
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--secret")
        .arg(TEST_SECRET_ALT)
        .arg("--zrbcx")
        .arg("--b32")
        .arg("same_input")
        .output()
        .unwrap();
    assert!(enc_output_b.status.success());
    let encd_b = String::from_utf8(enc_output_b.stdout)
        .unwrap()
        .trim()
        .to_string();

    assert_ne!(encd_a, encd_b);

    cleanup_test_home(&test_home);
}

#[cfg(feature = "ztier")]
#[test]
fn test_obz_enc_empty_plaintext() {
    let test_home = test_home_dir();
    let mut cmd = Command::new("obz");
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--zrbcx")
        .arg("--b32")
        .arg("")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[test]
fn test_obz_help() {
    let mut cmd = Command::new("obz");
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}
