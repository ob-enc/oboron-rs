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
// Testing
#[cfg(feature = "zmock")]
use crate::encrypt_zmock1;

/// Generic encoding pipeline for all schemes (except legacy).
///
/// Steps:
/// 1. Call scheme-specific encrypt function (handles any scheme-specific transformations like reversal)
/// 2. Append 2-byte scheme marker to ciphertext payload
/// 3. XOR marker bytes with first two payload bytes for entropy
/// 4. Encode to specified format
#[inline]
pub(crate) fn enc_to_format(
    plaintext: &str,
    format: Format,
    extracted_key: ExtractedKey,
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Step 1: Encrypt using scheme-specific function
    let mut ciphertext = match (format.scheme(), extracted_key) {
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

    // Step 2 & 3: Append marker and XOR in one pass (optimized)
    let marker = format.scheme().marker();
    let first_byte = ciphertext[0];
    ciphertext.push(marker[0] ^ first_byte);
    ciphertext.push(marker[1] ^ first_byte);

    // Step 4: Encode to specified format
    Ok(match format.encoding() {
        Encoding::C32 => BASE32_CROCKFORD.encode(&ciphertext),
        Encoding::B32 => BASE32_RFC.encode(&ciphertext),
        Encoding::B64 => BASE64URL_NOPAD.encode(&ciphertext),
        Encoding::Hex => HEXLOWER.encode(&ciphertext),
    })
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
