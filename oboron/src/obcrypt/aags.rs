#![cfg(feature = "aags")]
use crate::Error;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};

const NONCE_SIZE: usize = 12;
const MIN_DATA_LEN: usize = 17; // Minimum:  1 byte ciphertext + 16 byte tag = 17 bytes

/// Encrypt plaintext bytes using deterministic AES-GCM-SIV (aags scheme).
/// Returns raw ciphertext bytes with authentication tag (deterministic with zero nonce).
#[inline(always)]
pub fn encrypt(key: &[u8; 32], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Create AES-GCM-SIV cipher
    let cipher = Aes256GcmSiv::new(key.into());

    // Use zero nonce for deterministic encryption
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    // Encrypt (produces ciphertext + 16-byte authentication tag)
    cipher
        .encrypt(&nonce, plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)
}

/// Decrypt ciphertext using deterministic AES-GCM-SIV (aags scheme).
/// Returns plaintext bytes after authentication verification.
#[inline(always)]
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < MIN_DATA_LEN {
        return Err(Error::PayloadTooShort);
    }

    // Create AES-GCM-SIV cipher
    let cipher = Aes256GcmSiv::new(key.into());

    // Use zero nonce (same as encryption)
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    // Decrypt and verify
    cipher
        .decrypt(&nonce, data)
        .map_err(|_| Error::DecryptionFailed)
}
