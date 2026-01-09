#![cfg(feature = "mock")]
//! mock1 - Identity scheme (no encryption, testing only)
//!
//! This scheme performs no encryption and is available by default.
//! It exists for testing and as a no-op baseline.

use crate::Error;

/// "Encrypt" plaintext bytes using identity scheme (mock1).
/// Returns the input unchanged (no actual encryption).
#[inline]
pub fn encrypt(_key: &[u8; 64], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    Ok(plaintext_bytes.to_vec())
}

/// "Decrypt" ciphertext bytes using identity scheme (mock1).
/// Returns the input unchanged (no actual decryption).
#[inline]
pub fn decrypt(_key: &[u8; 64], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Err(Error::EmptyPayload);
    }

    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock1_roundtrip() {
        let key = [0u8; 64];

        let plaintext = b"hello world";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        // Identity: everything should be the same
        assert_eq!(ciphertext, plaintext);
        assert_eq!(decrypted, plaintext);
    }
}
