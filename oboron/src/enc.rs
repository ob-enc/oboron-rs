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
#[cfg(feature = "zdc")]
use crate::encrypt_zdc;
// Testing
#[cfg(feature = "ob71")]
use crate::encrypt_ob71;
#[cfg(feature = "tdi")]
use crate::encrypt_tdi;

/// Generic encoding pipeline for all schemes (except ob00).
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
        #[cfg(feature = "zdc")]
        Scheme::Zdc => encrypt_zdc(keychain, plaintext.as_bytes())?,
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
        #[cfg(feature = "tdi")]
        Scheme::Tdi => encrypt_tdi(keychain, plaintext.as_bytes())?,
        #[cfg(feature = "ob71")]
        Scheme::Ob71 => encrypt_ob71(keychain, plaintext.as_bytes())?,
        // Legacy - ob00 does not use this call path
        #[cfg(feature = "ob00")]
        Scheme::Ob00 => unreachable!("called generic dec function for ob00"),
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
        Encoding::Base32Crockford => Ok(BASE32_CROCKFORD.encode(&payload)),
        Encoding::Base32Rfc => Ok(BASE32_RFC.encode(&payload)),
        Encoding::Base64 => Ok(BASE64URL_NOPAD.encode(&payload)),
        Encoding::Hex => Ok(HEXLOWER.encode(&payload)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keychain, Scheme};

    #[test]
    fn test_enc_pipeline_tdi() {
        let format = Format::new(Scheme::Tdi, Encoding::Base32Crockford);

        // Create a real keychain for testing
        let key = [0u8; 64];
        let keychain = Keychain::from_bytes(&key).unwrap();

        let result = enc_to_format("test", format, &keychain).unwrap();
        assert!(!result.is_empty());
    }
}
