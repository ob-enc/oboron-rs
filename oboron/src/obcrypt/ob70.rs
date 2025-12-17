#![cfg(feature = "ob70")]
//! ob70 - Identity scheme (no encryption, testing only)
//!
//! This scheme performs no encryption and is available by default.
//! It exists for testing and as a no-op baseline.

use super::keychain::Keychain;
use crate::Error;

/// "Encrypt" plaintext bytes using identity scheme (ob70).
/// Returns the input unchanged (no actual encryption).
pub fn encrypt(_keychain: &Keychain, plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    Ok(plaintext_bytes.to_vec())
}

/// "Decrypt" ciphertext bytes using identity scheme (ob70).
/// Returns the input unchanged (no actual decryption).
pub fn decrypt(_keychain: &Keychain, data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Err(Error::EmptyPayload);
    }

    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ob70_roundtrip() {
        let key = [0u8; 64];
        let keychain = Keychain::from_bytes(&key).unwrap();

        let plaintext = b"hello world";
        let ciphertext = encrypt(&keychain, plaintext).unwrap();
        let decrypted = decrypt(&keychain, &ciphertext).unwrap();

        // Identity: everything should be the same
        assert_eq!(ciphertext, plaintext);
        assert_eq!(decrypted, plaintext);
    }
}
