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

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_keyless_aasv() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--aasv")
        .arg("--b32")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "apsv")]
#[test]
fn test_ob_enc_keyless_apsv() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--apsv")
        .arg("--b32")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aags")]
#[test]
fn test_ob_enc_keyless_aags() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--aags")
        .arg("--b32")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "apgs")]
#[test]
fn test_ob_enc_keyless_apgs() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--apgs")
        .arg("--b32")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "upbc")]
#[test]
fn test_ob_enc_keyless_upbc() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--upbc")
        .arg("--b32")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_with_explicit_key_aasv() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--aasv")
        .arg("--b32")
        .arg("test_data")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aags")]
#[test]
fn test_ob_enc_with_explicit_key_aags() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--aags")
        .arg("--b32")
        .arg("test_data")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "apgs")]
#[test]
fn test_ob_enc_with_explicit_key_apgs() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--apgs")
        .arg("--b32")
        .arg("test_data")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "apsv")]
#[test]
fn test_ob_enc_with_explicit_key_apsv() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--apsv")
        .arg("--b32")
        .arg("test_data")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "upbc")]
#[test]
fn test_ob_enc_with_explicit_key_upbc() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--upbc")
        .arg("--b32")
        .arg("test_data")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_dec_roundtrip_aasv() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--aasv")
        .arg("--b32")
        .arg("hello_world")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--aasv")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "aags")]
#[test]
fn test_ob_enc_dec_roundtrip_aags() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64_ALT)
        .arg("--aags")
        .arg("--b32")
        .arg("hello_world")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("--key")
        .arg(TEST_KEY_B64_ALT)
        .arg("--aags")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "apgs")]
#[test]
fn test_ob_enc_dec_roundtrip_apgs() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--apgs")
        .arg("--b32")
        .arg("hello_world")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--apgs")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "apsv")]
#[test]
fn test_ob_enc_dec_roundtrip_apsv() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--apsv")
        .arg("--b32")
        .arg("hello_world")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--apsv")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "upbc")]
#[test]
fn test_ob_enc_dec_roundtrip_upbc() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--upbc")
        .arg("--b32")
        .arg("hello_world")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--upbc")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "aags")]
#[cfg(feature = "aasv")]
#[cfg(feature = "upbc")]
#[cfg(feature = "apgs")]
#[cfg(feature = "apsv")]
#[test]
fn test_ob_enc_all_schemes() {
    let test_home = test_home_dir();
    let schemes = vec!["--aags", "--aasv", "--upbc", "--apgs", "--apsv"];

    for scheme in schemes {
        let mut cmd = Command::cargo_bin("ob").unwrap();
        cmd.env("HOME", test_home.as_os_str())
            .arg("enc")
            .arg("-K")
            .arg(scheme)
            .arg("--b32")
            .arg("test")
            .assert()
            .success()
            .stdout(predicate::str::is_empty().not());
    }

    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_all_encodings() {
    let test_home = test_home_dir();
    let encodings = vec!["--b32", "--b64", "--hex"];

    for encoding in encodings {
        let mut cmd = Command::cargo_bin("ob").unwrap();
        cmd.env("HOME", test_home.as_os_str())
            .arg("enc")
            .arg("-K")
            .arg("--aasv")
            .arg(encoding)
            .arg("test")
            .assert()
            .success()
            .stdout(predicate::str::is_empty().not());
    }

    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_short_alias_aasv() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("-s")
        .arg("--b32")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "apsv")]
#[test]
fn test_ob_enc_short_alias_apsv() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("-S")
        .arg("--b32")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "upbc")]
#[test]
fn test_ob_enc_short_alias_upbc() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("-u")
        .arg("--b32")
        .arg("test123")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
    cleanup_test_home(&test_home);
}

#[cfg(feature = "upbc")]
#[test]
fn test_ob_dec_short_alias_upbc() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("-u")
        .arg("--b32")
        .arg("hello123")
        .output()
        .unwrap();
    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("-u")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello123"));
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_invalid_key_too_short() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg("TOOSHORT")
        .arg("--aasv")
        .arg("--b32")
        .arg("hello")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_invalid_key_empty() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg("")
        .arg("--aasv")
        .arg("--b32")
        .arg("hello")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_dec_garbage_input() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--aasv")
        .arg("--b32")
        .arg("notvalidobtext")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_missing_plaintext() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--aasv")
        .arg("--b32")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_dec_roundtrip_with_explicit_key_aasv() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--aasv")
        .arg("--b32")
        .arg("hello_key_world")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--aasv")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_key_world"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "apsv")]
#[test]
fn test_ob_enc_dec_roundtrip_with_explicit_key_apsv() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--apsv")
        .arg("--b32")
        .arg("hello_key_world")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--apsv")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_key_world"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "upbc")]
#[test]
fn test_ob_enc_dec_roundtrip_with_explicit_key_upbc() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--upbc")
        .arg("--b32")
        .arg("hello_key_world")
        .output()
        .unwrap();

    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!encd.is_empty());

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--upbc")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_key_world"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_dec_roundtrip_b64_aasv() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--aasv")
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

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--aasv")
        .arg("--b64")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_b64"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_dec_roundtrip_hex_aasv() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--aasv")
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

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("--aasv")
        .arg("--hex")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_hex"));

    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_dec_short_alias_aasv() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("-s")
        .arg("--b32")
        .arg("hello_alias_s")
        .output()
        .unwrap();
    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("-s")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_alias_s"));
    cleanup_test_home(&test_home);
}

#[cfg(feature = "apsv")]
#[test]
fn test_ob_dec_short_alias_apsv() {
    let test_home = test_home_dir();

    let mut enc_cmd = Command::cargo_bin("ob").unwrap();
    let enc_output = enc_cmd
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("-S")
        .arg("--b32")
        .arg("hello_alias_S")
        .output()
        .unwrap();
    assert!(enc_output.status.success());
    let encd = String::from_utf8(enc_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    let mut dec_cmd = Command::cargo_bin("ob").unwrap();
    dec_cmd
        .env("HOME", test_home.as_os_str())
        .arg("dec")
        .arg("-K")
        .arg("-S")
        .arg("--b32")
        .arg(&encd)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_alias_S"));
    cleanup_test_home(&test_home);
}

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_different_keys_produce_different_output() {
    let test_home = test_home_dir();

    let mut enc_cmd_a = Command::cargo_bin("ob").unwrap();
    let enc_output_a = enc_cmd_a
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64)
        .arg("--aasv")
        .arg("--b32")
        .arg("same_input")
        .output()
        .unwrap();
    assert!(enc_output_a.status.success());
    let encd_a = String::from_utf8(enc_output_a.stdout)
        .unwrap()
        .trim()
        .to_string();

    let mut enc_cmd_b = Command::cargo_bin("ob").unwrap();
    let enc_output_b = enc_cmd_b
        .env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("--key")
        .arg(TEST_KEY_B64_ALT)
        .arg("--aasv")
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

#[cfg(feature = "aasv")]
#[test]
fn test_ob_enc_empty_plaintext_aasv() {
    let test_home = test_home_dir();
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.env("HOME", test_home.as_os_str())
        .arg("enc")
        .arg("-K")
        .arg("--aasv")
        .arg("--b32")
        .arg("")
        .assert()
        .failure();
    cleanup_test_home(&test_home);
}

#[test]
fn test_ob_help() {
    let mut cmd = Command::cargo_bin("ob").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}
