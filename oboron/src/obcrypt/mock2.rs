#![cfg(feature = "mock")]
//! mock2 - Reverse scheme (reverses plaintext, no encryption)
//!  
//! This scheme is always available and requires no crypto dependencies.
//!  It simply reverses the plaintext bytes.  Useful for testing cross-scheme
//!  functionality and as a fallback.

use crate::Error;

/// "Encrypt" plaintext bytes using reverse scheme (mock2).   
/// Simply returns the reversed bytes (no actual encryption).
#[inline]
pub fn encrypt(_key: &[u8; 64], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Reverse the bytes
    Ok(plaintext_bytes.iter().rev().copied().collect())
}

/// "Decrypt" ciphertext bytes using reverse scheme (mock2).
/// Simply reverses the bytes back (no actual decryption).
#[inline]
pub fn decrypt(_key: &[u8; 64], data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Err(Error::EmptyPayload);
    }

    // Reverse the bytes back
    Ok(data.iter().rev().copied().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock2_roundtrip() {
        let key = [0u8; 64];

        let plaintext = b"hello world";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        // Ciphertext should be reversed
        assert_eq!(ciphertext, b"dlrow olleh");
        // Decrypted should match original
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_mock2_utf8() {
        let key = [0u8; 64];

        let plaintext = "Hello 世界".as_bytes();
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_mock2_empty() {
        let key = [0u8; 64];

        assert!(encrypt(&key, b"").is_err());
    }
}
