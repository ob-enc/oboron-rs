use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    error::Error,
    Encoding, Format, Keychain, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

// Conditionally import encrypt functions based on features
#[cfg(feature = "adgs")]
use crate::encrypt_adgs;
#[cfg(feature = "adsv")]
use crate::encrypt_adsv;
#[cfg(feature = "apgs")]
use crate::encrypt_apgs;
#[cfg(feature = "apsv")]
use crate::encrypt_apsv;
#[cfg(feature = "upc")]
use crate::encrypt_upc;
#[cfg(feature = "zfbcx")]
use crate::encrypt_zfbcx;
// Testing
#[cfg(feature = "mock")]
use crate::encrypt_mock1;
#[cfg(feature = "mock")]
use crate::encrypt_mock2;

/// Generic encoding pipeline for all schemes (except legacy).
///
/// Steps:
/// 1. Call scheme-specific encrypt function
/// 2. Optionally Reverse the bytes
/// 3. Append scheme byte to ciphertext payload
/// 4. Encode to specified format
pub(crate) fn enc_to_format(
    plaintext: &str,
    format: Format,
    keychain: &Keychain,
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Step 1: Encrypt using scheme-specific function based on format
    let ciphertext = match format.scheme() {
        #[cfg(feature = "zfbcx")]
        Scheme::Zfbcx => encrypt_zfbcx(keychain, plaintext.as_bytes())?,
        #[cfg(feature = "upc")]
        Scheme::Upc => encrypt_upc(keychain, plaintext.as_bytes())?,
        #[cfg(feature = "adgs")]
        Scheme::Adgs => encrypt_adgs(keychain, plaintext.as_bytes())?,
        #[cfg(feature = "apgs")]
        Scheme::Apgs => encrypt_apgs(keychain, plaintext.as_bytes())?,
        #[cfg(feature = "adsv")]
        Scheme::Adsv => encrypt_adsv(keychain, plaintext.as_bytes())?,
        #[cfg(feature = "apsv")]
        Scheme::Apsv => encrypt_apsv(keychain, plaintext.as_bytes())?,
        // Testing
        #[cfg(feature = "mock")]
        Scheme::Mock1 => encrypt_mock1(keychain, plaintext.as_bytes())?,
        #[cfg(feature = "mock")]
        Scheme::Mock2 => encrypt_mock2(keychain, plaintext.as_bytes())?,
        // Legacy - legacy does not use this call path
        #[cfg(feature = "legacy")]
        Scheme::Legacy => unreachable!("called generic dec function for legacy"),
    };

    // Step 2+3: Build payload with scheme byte and conditionally reverse
    let mut payload = Vec::with_capacity(ciphertext.len() + 1);
    if format.scheme().is_ciphertext_reversed() {
        // Reversed schemes: prepend scheme byte, append ciphertext, then reverse in-place
        payload.push(format.scheme().byte());
        payload.extend_from_slice(&ciphertext);
        payload.reverse(); // scheme byte at tail
    } else {
        // Non-reversed schemes: append ciphertext, then scheme byte
        payload.extend_from_slice(&ciphertext);
        payload.push(format.scheme().byte()); // scheme byte at tail
    }
    // XOR the scheme byte with the first byte for entropy
    let len = payload.len();
    payload[len - 1] ^= payload[0];

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

        let result = enc_to_format("test", format, &keychain).unwrap();
        assert!(!result.is_empty());
    }
}
