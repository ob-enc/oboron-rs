#![cfg(feature = "aasv")]
use crate::Error;
use aes_siv::{aead::KeyInit, siv::Aes256Siv};

/// Encrypt plaintext bytes using deterministic AES-SIV (aasv scheme).
/// Returns raw ciphertext bytes with authentication tag.
pub fn encrypt(key: &[u8; 64], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Create AES-SIV cipher
    let mut cipher = Aes256Siv::new(key.into());

    // Use empty headers for deterministic encryption
    let headers: &[&[u8]] = &[];
    let ciphertext = cipher
        .encrypt(headers, plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)?;

    Ok(ciphertext)
}

/// Decrypt ciphertext using deterministic AES-SIV (aasv scheme).
/// Returns plaintext bytes after authentication verification.
pub fn decrypt(key: &[u8; 64], data: &[u8]) -> Result<Vec<u8>, Error> {
    // Minimum: 1 byte plaintext + 16 byte tag = 17 bytes
    if data.len() < 17 {
        return Err(Error::PayloadTooShort);
    }

    // Create AES-SIV cipher
    let mut cipher = Aes256Siv::new(key.into());

    // Use empty headers (same as encryption)
    let headers: &[&[u8]] = &[];
    let plaintext = cipher
        .decrypt(headers, data)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(plaintext)
}
