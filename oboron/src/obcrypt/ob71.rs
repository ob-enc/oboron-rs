#![cfg(feature = "ob71")]
//! ob71 - Reverse scheme (reverses plaintext, no encryption)
//!  
//! This scheme is always available and requires no crypto dependencies.
//!  It simply reverses the plaintext bytes.  Useful for testing cross-scheme
//!  functionality and as a fallback.

use super::keychain::Keychain;
use crate::Error;

/// "Encrypt" plaintext bytes using reverse scheme (ob71).   
/// Simply returns the reversed bytes (no actual encryption).
pub fn encrypt(_keychain: &Keychain, plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Reverse the bytes
    Ok(plaintext_bytes.iter().rev().copied().collect())
}

/// "Decrypt" ciphertext bytes using reverse scheme (ob71).
/// Simply reverses the bytes back (no actual decryption).
pub fn decrypt(_keychain: &Keychain, data: &[u8]) -> Result<Vec<u8>, Error> {
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
    fn test_ob71_roundtrip() {
        let key = [0u8; 64];
        let keychain = Keychain::from_bytes(&key).unwrap();

        let plaintext = b"hello world";
        let ciphertext = encrypt(&keychain, plaintext).unwrap();
        let decrypted = decrypt(&keychain, &ciphertext).unwrap();

        // Ciphertext should be reversed
        assert_eq!(ciphertext, b"dlrow olleh");
        // Decrypted should match original
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ob71_utf8() {
        let key = [0u8; 64];
        let keychain = Keychain::from_bytes(&key).unwrap();

        let plaintext = "Hello 世界".as_bytes();
        let ciphertext = encrypt(&keychain, plaintext).unwrap();
        let decrypted = decrypt(&keychain, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ob71_empty() {
        let key = [0u8; 64];
        let keychain = Keychain::from_bytes(&key).unwrap();

        assert!(encrypt(&keychain, b"").is_err());
    }
}
