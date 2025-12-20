use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    constants::REVERSED_SCHEME_BYTES,
    error::Error,
    Encoding, Format, Keychain, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

// Conditionally import decrypt functions based on features
#[cfg(feature = "adgs")]
use crate::decrypt_adgs;
#[cfg(feature = "adsv")]
use crate::decrypt_adsv;
#[cfg(feature = "apgs")]
use crate::decrypt_apgs;
#[cfg(feature = "apsv")]
use crate::decrypt_apsv;
#[cfg(feature = "upc")]
use crate::decrypt_upc;
#[cfg(feature = "zdc")]
use crate::decrypt_zdc;
// Testing
#[cfg(feature = "ob71")]
use crate::decrypt_ob71;
#[cfg(feature = "tdi")]
use crate::decrypt_tdi;

/// Generic decoding pipeline for all schemes (except ob00).
///
/// Steps:
/// 1. Decode obtext using format's encoding
/// 2. Extract and verify scheme byte
/// 3. Optionally reverse the bytes (select schemes only)
/// 4. Call scheme-specific decrypt function
/// 5. Convert to UTF-8 string
pub(crate) fn dec_from_format(
    obtext: &str,
    format: Format,
    keychain: &Keychain,
) -> Result<String, Error> {
    // Step 1: Decode obtext
    let mut buffer = decode_obtext_to_payload(obtext, format.encoding())?;

    if buffer.is_empty() {
        return Err(Error::EmptyPayload);
    }

    // Step 2: Get scheme byte
    // XOR the last byte with the first to undo mixing
    let len = buffer.len();
    buffer[len - 1] ^= buffer[0];
    // Extract the scheme byte from tail
    let scheme_byte = buffer.pop().unwrap();
    // Validate scheme tail byte
    if scheme_byte != format.scheme().byte() {
        return Err(Error::SchemeByteMismatch);
    }

    // Step 3: Reverse if needed to get original order
    if REVERSED_SCHEME_BYTES.contains(&scheme_byte) {
        buffer.reverse();
    }

    // Step 4: Decrypt using scheme-specific function based on format
    let plaintext_bytes = match format.scheme() {
        #[cfg(feature = "zdc")]
        Scheme::Zdc => decrypt_zdc(keychain, &buffer)?,
        #[cfg(feature = "upc")]
        Scheme::Upc => decrypt_upc(keychain, &buffer)?,
        #[cfg(feature = "adgs")]
        Scheme::Adgs => decrypt_adgs(keychain, &buffer)?,
        #[cfg(feature = "apgs")]
        Scheme::Apgs => decrypt_apgs(keychain, &buffer)?,
        #[cfg(feature = "adsv")]
        Scheme::Adsv => decrypt_adsv(keychain, &buffer)?,
        #[cfg(feature = "apsv")]
        Scheme::Apsv => decrypt_apsv(keychain, &buffer)?,
        // Testing
        #[cfg(feature = "tdi")]
        Scheme::Tdi => decrypt_tdi(keychain, &buffer)?,
        #[cfg(feature = "ob71")]
        Scheme::Ob71 => decrypt_ob71(keychain, &buffer)?,
        // Legacy - ob00 does not use this call path
        #[cfg(feature = "ob00")]
        Scheme::Ob00 => unreachable!("called generic dec function for ob00"),
    };

    // Step 5: Convert to string

    // Unchecked (Assuming plaintext was originally valid UTF-8, and correct key is used)
    #[cfg(feature = "unchecked-utf8")]
    {
        Ok(unsafe { String::from_utf8_unchecked(plaintext_bytes) })
    }

    #[cfg(not(feature = "unchecked-utf8"))]
    {
        String::from_utf8(plaintext_bytes).map_err(|_| Error::DecryptionFailed)
    }
}

/// Decode text encoding to raw bytes.
pub(crate) fn decode_obtext_to_payload(obtext: &str, encoding: Encoding) -> Result<Vec<u8>, Error> {
    match encoding {
        Encoding::Base32Rfc => BASE32_RFC
            .decode(&obtext.as_bytes())
            .map_err(|_| Error::InvalidBase32Rfc),
        Encoding::Base32Crockford => BASE32_CROCKFORD
            .decode(&obtext.as_bytes())
            .map_err(|_| Error::InvalidBase32Crockford),
        Encoding::Base64 => BASE64URL_NOPAD
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidBase64),
        Encoding::Hex => HEXLOWER
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dec_base32() {
        let encoded = "c5h66";
        let result = decode_obtext_to_payload(encoded, Encoding::Base32Crockford).unwrap();
        assert_eq!(result, b"abc");
    }

    #[test]
    fn test_decode_hex() {
        let encoded = "68656c6c6f";
        let result = decode_obtext_to_payload(encoded, Encoding::Hex).unwrap();
        assert_eq!(result, b"hello");
    }
}
