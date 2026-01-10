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
/// use oboron::generate_key;
///
/// let key = generate_key();
/// assert_eq!(key.len(), 86);
/// ```
#[must_use]
pub fn generate_key() -> String {
    loop {
        let mut key_bytes = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key_base64 = BASE64URL_NOPAD.encode(&key_bytes);
        if !key_base64.contains('-') && !key_base64.contains('_') {
            return key_base64;
        }
    }
}

/// Generate a cryptographically secure random 64-byte key suitable for use with MasterKey.
///
/// This function generates a random key using a cryptographically secure random number generator.
/// The key can be used directly with `MasterKey::from_bytes()`.
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
#[cfg(feature = "bytes-keys")]
pub fn generate_key_bytes() -> [u8; 64] {
    let decoded = BASE64URL_NOPAD
        .decode(generate_key().as_bytes())
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
#[cfg(feature = "hex-keys")]
pub fn generate_key_hex() -> String {
    let decoded = BASE64URL_NOPAD
        .decode(generate_key().as_bytes())
        .expect("Failed to decode base64");
    let key_bytes: [u8; 64] = decoded.try_into().expect("Decoded key is not 64 bytes");
    hex::encode(&key_bytes)
}

/// Generate a random 32-byte secret and return it as a base64 string.
///
/// This is a convenience function that generates a key and encodes it as a base64 string,
/// useful for storage, display, or transmission.  The base64 string will be 32 characters long.
/// This function ensures the returned key does not contain any dashes
/// (to make it double-click-selectable in GUIs).
///
/// # Examples
///
/// ```
/// use oboron::generate_secret;
///
/// let secret = generate_secret();
/// assert_eq!(secret.len(), 43);
/// ```
#[must_use]
pub fn generate_secret() -> String {
    loop {
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key_base64 = BASE64URL_NOPAD.encode(&key_bytes);
        if !key_base64.contains('-') && !key_base64.contains('_') {
            return key_base64;
        }
    }
}

/// Generate a random 32-byte secret suitable for use with ZSecret.
///
/// This function generates a random secret using a cryptographically secure random number generator.
/// The key can be used directly with `ZSecret::from_bytes()`.
///
/// # Examples
///
/// ```
/// use oboron::generate_secret_bytes;
///
/// let secret_bytes = generate_secret_bytes();
/// assert_eq!(secret_bytes.len(), 32);
/// ```
#[must_use]
#[cfg(feature = "bytes-keys")]
pub fn generate_secret_bytes() -> [u8; 32] {
    let decoded = BASE64URL_NOPAD
        .decode(generate_secret().as_bytes())
        .expect("Failed to decode base64");
    decoded.try_into().expect("Decoded key is not 32 bytes")
}

/// Generate a cryptographically secure random 32-byte key and return it as a hex string.
///
/// This is a convenience function that generates a secret and encodes it as a hexadecimal string,
/// useful for storage, display, or transmission. The hex string will be 64 characters long.
///
/// # Examples
///
/// ```
/// use oboron::generate_secret_hex;
///
/// let secret_hex = generate_secret_hex();
/// assert_eq!(secret_hex.len(), 64); // 32 bytes * 2 hex chars per byte
/// ```
#[must_use]
#[cfg(feature = "hex-keys")]
pub fn generate_secret_hex() -> String {
    let decoded = BASE64URL_NOPAD
        .decode(generate_secret().as_bytes())
        .expect("Failed to decode base64");
    let secret_bytes: [u8; 32] = decoded.try_into().expect("Decoded secret is not 32 bytes");
    hex::encode(&secret_bytes)
}
