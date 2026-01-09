#![cfg(feature = "aasv")]
use crate::Error;
use aes_siv::{aead::KeyInit, siv::Aes256Siv};

const MIN_DATA_LEN: usize = 17;

/// Encrypt plaintext bytes using deterministic AES-SIV (aasv scheme).
/// Takes the full 64-byte key directly.
#[inline]
pub fn encrypt(key: &[u8; 64], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let mut cipher = Aes256Siv::new(key.into());
    let headers: &[&[u8]] = &[];
    cipher
        .encrypt(headers, plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)
}

/// Decrypt ciphertext using deterministic AES-SIV (aasv scheme).
/// Takes the full 64-byte key directly.
#[inline]
pub fn decrypt(key: &[u8; 64], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < MIN_DATA_LEN {
        return Err(Error::PayloadTooShort);
    }

    let mut cipher = Aes256Siv::new(key.into());
    let headers: &[&[u8]] = &[];
    cipher
        .decrypt(headers, data)
        .map_err(|_| Error::DecryptionFailed)
}
