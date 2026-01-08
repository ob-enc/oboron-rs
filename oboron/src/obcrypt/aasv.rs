#![cfg(feature = "aasv")]
use crate::Error;
use aes_siv::{aead::KeyInit, siv::Aes256Siv};

const MIN_DATA_LEN: usize = 17; // Minimum:  1 byte ciphertext + 16 byte tag = 17 bytes

/// Encrypt plaintext bytes using deterministic AES-SIV (aasv scheme).
/// Returns raw ciphertext bytes with authentication tag.
#[inline]
pub fn encrypt(key: &[u8; 64], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Create AES-SIV cipher
    let mut cipher = Aes256Siv::new(key.into());

    // Use empty headers for deterministic encryption
    cipher
        .encrypt(&[], plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)
}

/// Decrypt ciphertext using deterministic AES-SIV (aasv scheme).
/// Returns plaintext bytes after authentication verification.
#[inline]
pub fn decrypt(key: &[u8; 64], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < MIN_DATA_LEN {
        return Err(Error::PayloadTooShort);
    }

    // Create AES-SIV cipher
    let mut cipher = Aes256Siv::new(key.into());

    // Use empty headers (same as encryption)
    cipher
        .decrypt(&[], data)
        .map_err(|_| Error::DecryptionFailed)
}
