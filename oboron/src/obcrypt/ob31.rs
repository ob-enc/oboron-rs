#![cfg(feature = "ob31")]
use super::keychain::Keychain;
use crate::Error;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};

const NONCE_SIZE: usize = 12;

/// Encrypt plaintext bytes using deterministic AES-GCM-SIV (ob31 scheme).
/// Returns raw ciphertext bytes with authentication tag (deterministic with zero nonce).
pub fn encrypt(keychain: &Keychain, plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Create AES-GCM-SIV cipher
    let cipher = Aes256GcmSiv::new(keychain.gcm_siv().into());

    // Use zero nonce for deterministic encryption
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    // Encrypt (produces ciphertext + 16-byte authentication tag)
    let ciphertext = cipher
        .encrypt(&nonce, plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)?;

    Ok(ciphertext)
}

/// Decrypt ciphertext using deterministic AES-GCM-SIV (ob31 scheme).
/// Returns plaintext bytes after authentication verification.
pub fn decrypt(keychain: &Keychain, data: &[u8]) -> Result<Vec<u8>, Error> {
    // Minimum: 1 byte plaintext + 16 byte tag = 17 bytes
    if data.len() < 17 {
        return Err(Error::PayloadTooShort);
    }

    // Create AES-GCM-SIV cipher
    let cipher = Aes256GcmSiv::new(keychain.gcm_siv().into());

    // Use zero nonce (same as encryption)
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    // Decrypt and verify
    let plaintext = cipher
        .decrypt(&nonce, data)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(plaintext)
}
