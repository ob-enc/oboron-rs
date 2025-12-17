#![cfg(feature = "ob32p")]
use super::keychain::Keychain;
use crate::Error;
use aes_siv::{aead::KeyInit, siv::Aes256Siv};
use rand::RngCore;

const NONCE_SIZE: usize = 16;
const TAG_SIZE: usize = 16;

/// Encrypt plaintext bytes using probabilistic AES-SIV (ob32p scheme).
/// Returns raw ciphertext bytes with nonce prepended and authentication tag included.  Structure: [nonce][ciphertext+tag].
pub fn encrypt(keychain: &Keychain, plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Allocate buffer and generate random nonce directly into it
    let ciphertext_len = plaintext_bytes.len() + TAG_SIZE;
    let mut buffer = Vec::with_capacity(NONCE_SIZE + ciphertext_len);
    buffer.resize(NONCE_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut buffer[..NONCE_SIZE]);

    // Create AES-SIV cipher
    let mut cipher = Aes256Siv::new(keychain.siv().into());

    // Use nonce as header (additional authenticated data) for probabilistic encryption
    let ciphertext_with_tag = cipher
        .encrypt(&[&buffer[..NONCE_SIZE]], plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)?;

    // Append ciphertext+tag: [nonce][ciphertext+tag]
    buffer.extend_from_slice(&ciphertext_with_tag);

    Ok(buffer)
}

/// Decrypt ciphertext using probabilistic AES-SIV (ob32p scheme).
/// Expects data structure: [nonce][ciphertext+tag].  Returns plaintext bytes after authentication verification.
pub fn decrypt(keychain: &Keychain, data: &[u8]) -> Result<Vec<u8>, Error> {
    // Minimum: 16 byte nonce + 1 byte plaintext + 16 byte tag = 33 bytes
    if data.len() < 33 {
        return Err(Error::PayloadTooShort);
    }

    // Extract components:  [nonce][ciphertext+tag]
    let nonce_bytes = &data[..NONCE_SIZE];
    let ciphertext_with_tag = &data[NONCE_SIZE..];

    // Create AES-SIV cipher
    let mut cipher = Aes256Siv::new(keychain.siv().into());

    // Use nonce as header (same as encryption)
    let plaintext = cipher
        .decrypt(&[nonce_bytes], ciphertext_with_tag)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(plaintext)
}
