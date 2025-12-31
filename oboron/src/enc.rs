use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    constants::SCHEME_MARKER_SIZE,
    error::Error,
    Encoding, ExtractedKey, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

// Conditionally import encrypt functions based on features
#[cfg(feature = "aags")]
use crate::encrypt_aags;
#[cfg(feature = "aasv")]
use crate::encrypt_aasv;
#[cfg(feature = "apgs")]
use crate::encrypt_apgs;
#[cfg(feature = "apsv")]
use crate::encrypt_apsv;
#[cfg(feature = "upbc")]
use crate::encrypt_upbc;
#[cfg(feature = "zrbcx")]
use crate::encrypt_zrbcx;
// Testing
#[cfg(feature = "mock")]
use crate::encrypt_mock1;
#[cfg(feature = "mock")]
use crate::encrypt_mock2;

/// Generic encoding pipeline for all schemes (except legacy).
///
/// Steps:
/// 1. Call scheme-specific encrypt function (handles any scheme-specific transformations like reversal)
/// 2. Append 2-byte scheme marker to ciphertext payload
/// 3. XOR marker bytes with first two payload bytes for entropy
/// 4. Encode to specified format
pub(crate) fn enc_to_format(
    plaintext: &str,
    format: Format,
    extracted_key: ExtractedKey,
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Step 1: Encrypt using scheme-specific function
    let ciphertext = match (format.scheme(), extracted_key) {
        #[cfg(feature = "aags")]
        (Scheme::Aags, ExtractedKey::Key32(k)) => encrypt_aags(k, plaintext.as_bytes())?,
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, ExtractedKey::Key32(k)) => encrypt_apgs(k, plaintext.as_bytes())?,
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, ExtractedKey::Key64(k)) => encrypt_aasv(k, plaintext.as_bytes())?,
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, ExtractedKey::Key64(k)) => encrypt_apsv(k, plaintext.as_bytes())?,
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, ExtractedKey::Key32(k)) => encrypt_upbc(k, plaintext.as_bytes())?,
        // Z-tier
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, ExtractedKey::Key32(k)) => encrypt_zrbcx(k, plaintext.as_bytes())?,
        // Testing
        #[cfg(feature = "mock")]
        (Scheme::Mock1, ExtractedKey::Key32(k)) => encrypt_mock1(k, plaintext.as_bytes())?,
        #[cfg(feature = "mock")]
        (Scheme::Mock2, ExtractedKey::Key32(k)) => encrypt_mock2(k, plaintext.as_bytes())?,
        #[cfg(feature = "zmock")]
        (Scheme::Zmock1, ExtractedKey::Key32(k)) => encrypt_zmock1(k, plaintext.as_bytes())?,
        // Legacy - legacy does not use this call path
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, ExtractedKey::Key32(_k)) => {
            unreachable!("called generic enc function for legacy")
        }
        _ => return Err(Error::InvalidKeyLength),
    };

    // Step 2: Build payload with 2-byte scheme marker appended
    let marker = format.scheme().marker();
    let mut payload = Vec::with_capacity(ciphertext.len() + SCHEME_MARKER_SIZE);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&marker);

    // Step 3: XOR the scheme marker bytes with the first two bytes for entropy
    let len = payload.len();
    payload[len - 1] ^= payload[0];
    payload[len - 2] ^= payload[1];

    // Step 4: Encode to specified format
    match format.encoding() {
        Encoding::C32 => Ok(BASE32_CROCKFORD.encode(&payload)),
        Encoding::B32 => Ok(BASE32_RFC.encode(&payload)),
        Encoding::B64 => Ok(BASE64URL_NOPAD.encode(&payload)),
        Encoding::Hex => Ok(HEXLOWER.encode(&payload)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keychain, Scheme};

    #[test]
    fn test_enc_pipeline_mock1() {
        let format = Format::new(Scheme::Mock1, Encoding::C32);

        // Create a real keychain for testing
        let key = [0u8; 64];
        let keychain = Keychain::from_bytes(&key).unwrap();
        let extracted_key = keychain.extract_key(format.scheme()).unwrap();
        let result = enc_to_format("test", format, extracted_key).unwrap();
        assert!(!result.is_empty());
    }
}
