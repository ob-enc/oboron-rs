#![cfg(feature = "ob31p")]
use super::keychain::Keychain;
use crate::Error;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use rand::RngCore;

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

/// Encrypt plaintext bytes using probabilistic AES-GCM-SIV (ob31p scheme).
/// Returns raw ciphertext bytes with nonce prepended and authentication tag appended.
/// Structure: [nonce][ciphertext+tag]
pub fn encrypt(keychain: &Keychain, plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Allocate buffer and generate random nonce directly into it
    let ciphertext_len = plaintext_bytes.len() + TAG_SIZE;
    let mut buffer = Vec::with_capacity(NONCE_SIZE + ciphertext_len);
    buffer.resize(NONCE_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut buffer[..NONCE_SIZE]);

    // Create AES-GCM-SIV cipher
    let cipher = Aes256GcmSiv::new(keychain.gcm_siv().into());
    let nonce = Nonce::from(*<&[u8; NONCE_SIZE]>::try_from(&buffer[..NONCE_SIZE]).unwrap());

    // Encrypt (produces ciphertext + 16-byte authentication tag)
    let ciphertext_with_tag = cipher
        .encrypt(&nonce, plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)?;

    // Append ciphertext+tag: [nonce][ciphertext+tag]
    buffer.extend_from_slice(&ciphertext_with_tag);

    Ok(buffer)
}

/// Decrypt ciphertext using probabilistic AES-GCM-SIV (ob31p scheme).
/// Expects data structure: [nonce][ciphertext+tag].  Returns plaintext bytes after authentication verification.
pub fn decrypt(keychain: &Keychain, data: &[u8]) -> Result<Vec<u8>, Error> {
    // Minimum: 12 byte nonce + 1 byte plaintext + 16 byte tag = 29 bytes
    if data.len() < 29 {
        return Err(Error::PayloadTooShort);
    }

    // Extract components:  [nonce][ciphertext+tag]
    let nonce_bytes = &data[..NONCE_SIZE];
    let ciphertext_with_tag = &data[NONCE_SIZE..];

    // Create AES-GCM-SIV cipher
    let cipher = Aes256GcmSiv::new(keychain.gcm_siv().into());

    // Convert nonce slice to array
    let nonce = Nonce::from(*<&[u8; NONCE_SIZE]>::try_from(nonce_bytes).unwrap());

    // Decrypt and verify
    let plaintext = cipher
        .decrypt(&nonce, ciphertext_with_tag)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(plaintext)
}
