#![cfg(feature = "ob00")]
use super::{constants::AES_BLOCK_SIZE, keychain::Keychain};
use crate::Error;
use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

const OB00_PADDING_BYTE: u8 = b'='; // legacy - ob00 only

/// Encrypt plaintext bytes using legacy AES-CBC (ob00 scheme).
/// Returns raw ciphertext bytes with custom padding.
pub fn encrypt(keychain: &Keychain, plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Calculate padding to align to block size
    let data_len = plaintext_bytes.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    // Allocate once with the correct size
    let mut buffer = Vec::with_capacity(total_len);
    buffer.extend_from_slice(plaintext_bytes);
    buffer.resize(total_len, OB00_PADDING_BYTE);

    // Encrypt in-place
    let cipher = Aes128CbcEnc::new(keychain.cbc().into(), keychain.cbc_iv().into());
    cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer, total_len)
        .map_err(|_| Error::EncryptionFailed)?;

    Ok(buffer)
}

/// Decrypt ciphertext using legacy AES-CBC (ob00 scheme).
/// Returns plaintext bytes with custom padding removed.
pub fn decrypt(keychain: &Keychain, data: &[u8]) -> Result<Vec<u8>, Error> {
    // Decrypt with AES-128-CBC
    if data.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidBlockLength);
    }

    let cipher = Aes128CbcDec::new(keychain.cbc().into(), keychain.cbc_iv().into());
    let mut buffer = data.to_vec();

    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer)
        .map_err(|_| Error::DecryptionFailed)?;

    // Remove '=' padding by finding the end and truncating
    let end = buffer
        .iter()
        .rposition(|&b| b != OB00_PADDING_BYTE)
        .map_or(0, |i| i + 1);
    buffer.truncate(end);

    Ok(buffer)
}
