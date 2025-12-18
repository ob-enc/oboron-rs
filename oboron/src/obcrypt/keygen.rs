use data_encoding::BASE64URL_NOPAD;
use rand::RngCore;

/// Generate a cryptographically secure random 64-byte key and return it as a base64 string.
///
/// This is a convenience function that generates a key and encodes it as a base64 string,
/// useful for storage, display, or transmission.  The base64 string will be 86 characters long.
/// This function ensures the returned key does not contain any dashes
/// (to make it double-click-selectable in GUIs).
///
/// # Examples
///
/// ```
/// use oboron::generate_key_base64;
///
/// let key_hex = generate_key_base64();
/// assert_eq!(key_hex.len(), 86);
/// ```
#[must_use]
pub fn generate_key_base64() -> String {
    loop {
        let mut key_bytes = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key_base64 = BASE64URL_NOPAD.encode(&key_bytes);
        if !key_base64.contains('-') && !key_base64.contains('_') {
            return key_base64;
        }
    }
}

/// Generate a cryptographically secure random 64-byte key suitable for use with Keychain.
///
/// This function generates a random key using a cryptographically secure random number generator.
/// The key can be used directly with `Keychain::from_bytes()`.
///
/// # Examples
///
/// ```
/// use oboron::generate_key_bytes;
///
/// let key = generate_key_bytes();
/// assert_eq!(key.len(), 64);
/// ```
#[must_use]
pub fn generate_key_bytes() -> [u8; 64] {
    let decoded = BASE64URL_NOPAD
        .decode(generate_key_base64().as_bytes())
        .expect("Failed to decode base64");
    decoded.try_into().expect("Decoded key is not 64 bytes")
}

/// Generate a cryptographically secure random 64-byte key and return it as a hex string.
///
/// This is a convenience function that generates a key and encodes it as a hexadecimal string,
/// useful for storage, display, or transmission. The hex string will be 128 characters long.
///
/// # Examples
///
/// ```
/// use oboron::generate_key_hex;
///
/// let key_hex = generate_key_hex();
/// assert_eq!(key_hex.len(), 128); // 64 bytes * 2 hex chars per byte
/// ```
#[must_use]
pub fn generate_key_hex() -> String {
    hex::encode(&generate_key_bytes())
}
