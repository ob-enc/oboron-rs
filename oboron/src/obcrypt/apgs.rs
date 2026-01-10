#![cfg(feature = "apgs")]
use crate::Error;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use rand::RngCore;

const KEY_OFFSET: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const MIN_PAYLOAD_LEN: usize = NONCE_SIZE + 1 + TAG_SIZE;

#[inline]
pub fn encrypt(master_key: &[u8; 64], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let key_slice = &master_key[KEY_OFFSET..KEY_OFFSET + KEY_LEN];
    let key: &[u8; 32] = key_slice.try_into().unwrap();

    let ciphertext_len = plaintext_bytes.len() + TAG_SIZE;
    let mut buffer = Vec::with_capacity(NONCE_SIZE + ciphertext_len);
    buffer.resize(NONCE_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut buffer[..NONCE_SIZE]);

    let cipher = Aes256GcmSiv::new(key.into());
    let nonce = Nonce::from(*<&[u8; NONCE_SIZE]>::try_from(&buffer[..NONCE_SIZE]).unwrap());

    let ciphertext_with_tag = cipher
        .encrypt(&nonce, plaintext_bytes)
        .map_err(|_| Error::EncryptionFailed)?;

    buffer.extend_from_slice(&ciphertext_with_tag);
    Ok(buffer)
}

#[inline]
pub fn decrypt(master_key: &[u8; 64], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < MIN_PAYLOAD_LEN {
        return Err(Error::PayloadTooShort);
    }

    let key_slice = &master_key[KEY_OFFSET..KEY_OFFSET + KEY_LEN];
    let key: &[u8; 32] = key_slice.try_into().unwrap();

    let nonce_bytes = &data[..NONCE_SIZE];
    let ciphertext_with_tag = &data[NONCE_SIZE..];

    let cipher = Aes256GcmSiv::new(key.into());
    let nonce = Nonce::from(*<&[u8; NONCE_SIZE]>::try_from(nonce_bytes).unwrap());

    let plaintext = cipher
        .decrypt(&nonce, ciphertext_with_tag)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(plaintext)
}
