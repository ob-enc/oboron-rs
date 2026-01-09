#![cfg(feature = "upbc")]
use super::constants::{AES_BLOCK_SIZE, CBC_PADDING_BYTE};
use crate::Error;
use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const KEY_OFFSET: usize = 8;
const KEY_LEN: usize = 32;
const IV_SIZE: usize = 16;

#[inline]
pub fn encrypt(master_key: &[u8; 64], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let key_slice = &master_key[KEY_OFFSET..KEY_OFFSET + KEY_LEN];
    let key: &[u8; 32] = key_slice.try_into().unwrap();

    let data_len = plaintext_bytes.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    let mut buffer = Vec::with_capacity(IV_SIZE + total_len);
    buffer.resize(IV_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut buffer[..IV_SIZE]);

    buffer.extend_from_slice(plaintext_bytes);
    buffer.resize(IV_SIZE + total_len, CBC_PADDING_BYTE);

    let cipher = Aes256CbcEnc::new(key.into(), buffer[..IV_SIZE].into());
    cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer[IV_SIZE..], total_len)
        .map_err(|_| Error::EncryptionFailed)?;

    Ok(buffer)
}

#[inline]
pub fn decrypt(master_key: &[u8; 64], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < 32 {
        return Err(Error::PayloadTooShort);
    }

    let key_slice = &master_key[KEY_OFFSET..KEY_OFFSET + KEY_LEN];
    let key: &[u8; 32] = key_slice.try_into().unwrap();

    let iv = &data[..IV_SIZE];
    let ciphertext = &data[IV_SIZE..];

    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidBlockLength);
    }

    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    let mut plaintext = ciphertext.to_vec();

    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut plaintext)
        .map_err(|_| Error::DecryptionFailed)?;

    let mut end = plaintext.len();
    while end > 0 && plaintext[end - 1] == CBC_PADDING_BYTE {
        end -= 1;
    }
    plaintext.truncate(end);

    Ok(plaintext)
}
