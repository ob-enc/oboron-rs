#![cfg(feature = "apsv")]
use crate::Error;
use aes_siv::{aead::KeyInit, siv::Aes256Siv};
use rand::RngCore;

const NONCE_SIZE: usize = 16;
const TAG_SIZE: usize = 16;

#[inline]
pub fn encrypt(key: &[u8; 64], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let ciphertext_len = plaintext_bytes.len() + TAG_SIZE;
    let mut buffer = Vec::with_capacity(NONCE_SIZE + ciphertext_len);
    buffer.resize(NONCE_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut buffer[..NONCE_SIZE]);

    let mut cipher = Aes256Siv::new(key.into());

    let ciphertext_with_tag = cipher
        .encrypt(&[&buffer[..NONCE_SIZE]], plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)?;

    buffer.extend_from_slice(&ciphertext_with_tag);
    Ok(buffer)
}

#[inline]
pub fn decrypt(key: &[u8; 64], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < 33 {
        return Err(Error::PayloadTooShort);
    }

    let nonce_bytes = &data[..NONCE_SIZE];
    let ciphertext_with_tag = &data[NONCE_SIZE..];

    let mut cipher = Aes256Siv::new(key.into());

    let plaintext = cipher
        .decrypt(&[nonce_bytes], ciphertext_with_tag)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(plaintext)
}
