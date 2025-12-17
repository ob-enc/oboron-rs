#![cfg(feature = "ob21p")]
use super::{
    constants::{AES_BLOCK_SIZE, CBC_PADDING_BYTE},
    keychain::Keychain,
};
use crate::Error;
use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

const IV_SIZE: usize = 16;

/// Encrypt plaintext bytes using probabilistic AES-CBC (ob21p scheme).
/// Returns raw ciphertext bytes with appended IV.  Structure: [IV][ciphertext].
pub fn encrypt(keychain: &Keychain, plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Calculate padding to align to block size
    let data_len = plaintext_bytes.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    // Allocate buffer and generate random random IV (16 bytes) directly into it
    let mut buffer = Vec::with_capacity(IV_SIZE + total_len);
    buffer.resize(IV_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut buffer[..IV_SIZE]);

    // Append plaintext and padding
    buffer.extend_from_slice(plaintext_bytes);
    buffer.resize(IV_SIZE + total_len, CBC_PADDING_BYTE);

    // buffer: [iv][plaintext]

    // Encrypt in-place (only the plaintext, not the IV)
    let cipher = Aes128CbcEnc::new(keychain.cbc().into(), buffer[..IV_SIZE].into());
    cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer[IV_SIZE..], total_len)
        .map_err(|_| Error::EncryptionFailed)?;

    // buffer: [iv][ciphertext]

    Ok(buffer)
}

/// Decrypt ciphertext using probabilistic AES-CBC (ob21p scheme).
/// Expects data structure: [IV][ciphertext].  Returns plaintext bytes with padding removed.
pub fn decrypt(keychain: &Keychain, data: &[u8]) -> Result<Vec<u8>, Error> {
    // Minimum: 16 bytes ciphertext + 16 bytes IV = 32 bytes
    if data.len() < 32 {
        return Err(Error::PayloadTooShort);
    }

    // Extract components
    let iv = &data[..IV_SIZE];
    let ciphertext = &data[IV_SIZE..];

    // Decrypt with AES-128-CBC
    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidBlockLength);
    }

    let cipher = Aes128CbcDec::new(keychain.cbc().into(), iv.into());
    let mut plaintext = ciphertext.to_vec();

    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut plaintext)
        .map_err(|_| Error::DecryptionFailed)?;

    // Remove CBC padding by finding the end and truncating
    let mut end = plaintext.len();
    while end > 0 && plaintext[end - 1] == CBC_PADDING_BYTE {
        end -= 1;
    }
    plaintext.truncate(end);

    Ok(plaintext)
}
