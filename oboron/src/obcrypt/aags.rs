#![cfg(feature = "aags")]
use crate::Error;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};

const KEY_OFFSET: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_SIZE: usize = 12;
const MIN_DATA_LEN: usize = 17;

/// Encrypt plaintext bytes using deterministic AES-GCM-SIV (aags scheme).
/// Takes the full 64-byte key and extracts the second 32 bytes internally.
#[inline]
pub fn encrypt(master_key: &[u8; 64], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let key_slice = &master_key[KEY_OFFSET..KEY_OFFSET + KEY_LEN];
    let key: &[u8; 32] = key_slice.try_into().unwrap();

    let cipher = Aes256GcmSiv::new(key.into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    cipher
        .encrypt(&nonce, plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)
}

/// Decrypt ciphertext using deterministic AES-GCM-SIV (aags scheme).
/// Takes the full 64-byte key and extracts the second 32 bytes internally.
#[inline]
pub fn decrypt(master_key: &[u8; 64], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < MIN_DATA_LEN {
        return Err(Error::PayloadTooShort);
    }

    let key_slice = &master_key[KEY_OFFSET..KEY_OFFSET + KEY_LEN];
    let key: &[u8; 32] = key_slice.try_into().unwrap();

    let cipher = Aes256GcmSiv::new(key.into());
    let nonce = Nonce::from([0u8; NONCE_SIZE]);

    cipher
        .decrypt(&nonce, data)
        .map_err(|_| Error::DecryptionFailed)
}
