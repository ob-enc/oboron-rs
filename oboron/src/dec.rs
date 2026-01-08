use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    constants::SCHEME_MARKER_SIZE,
    error::Error,
    Encoding, ExtractedKey, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

// Conditionally import decrypt functions based on features
#[cfg(feature = "aags")]
use crate::decrypt_aags;
#[cfg(feature = "aasv")]
use crate::decrypt_aasv;
#[cfg(feature = "apgs")]
use crate::decrypt_apgs;
#[cfg(feature = "apsv")]
use crate::decrypt_apsv;
#[cfg(feature = "upbc")]
use crate::decrypt_upbc;
// Z-tier
#[cfg(feature = "zrbcx")]
use crate::decrypt_zrbcx;
// Testing
#[cfg(feature = "mock")]
use crate::decrypt_mock1;
#[cfg(feature = "mock")]
use crate::decrypt_mock2;
#[cfg(feature = "zmock")]
use crate::decrypt_zmock1;

/// Generic decoding pipeline for all schemes (except legacy).
///
/// Steps:
/// 1. Decode obtext using format's encoding
/// 2. XOR last two bytes with first two to undo entropy mixing
/// 3. Extract and verify 2-byte scheme marker
/// 4. Call scheme-specific decrypt function (handles any scheme-specific transformations like reversal)
/// 5. Convert to UTF-8 string
#[inline]
pub(crate) fn dec_from_format(
    obtext: &str,
    format: Format,
    extracted_key: ExtractedKey,
) -> Result<String, Error> {
    // Step 1: Decode obtext
    let mut buffer = decode_obtext_to_payload(obtext, format.encoding())?;

    if buffer.len() < SCHEME_MARKER_SIZE {
        return Err(Error::PayloadTooShort);
    }

    // Step 2 & 3: XOR and extract marker in optimized way
    let len = buffer.len();
    let first_byte = buffer[0];
    let scheme_marker = [buffer[len - 2] ^ first_byte, buffer[len - 1] ^ first_byte];

    // Validate scheme marker
    if scheme_marker != format.scheme().marker() {
        return Err(Error::SchemeMarkerMismatch);
    }

    // Truncate to remove marker
    buffer.truncate(len - SCHEME_MARKER_SIZE);

    // Step 4: Decrypt using scheme-specific function
    let plaintext_bytes = match (format.scheme(), extracted_key) {
        #[cfg(feature = "aags")]
        (Scheme::Aags, ExtractedKey::Key32(k)) => decrypt_aags(k, &buffer)?,
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, ExtractedKey::Key32(k)) => decrypt_apgs(k, &buffer)?,
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, ExtractedKey::Key64(k)) => decrypt_aasv(k, &buffer)?,
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, ExtractedKey::Key64(k)) => decrypt_apsv(k, &buffer)?,
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, ExtractedKey::Key32(k)) => decrypt_upbc(k, &buffer)?,
        // Z-tier
        #[cfg(feature = "zrbcx")]
        (Scheme::Zrbcx, ExtractedKey::Key32(k)) => decrypt_zrbcx(k, &buffer)?,
        // Testing
        #[cfg(feature = "mock")]
        (Scheme::Mock1, ExtractedKey::Key32(k)) => decrypt_mock1(k, &buffer)?,
        #[cfg(feature = "mock")]
        (Scheme::Mock2, ExtractedKey::Key32(k)) => decrypt_mock2(k, &buffer)?,
        #[cfg(feature = "zmock")]
        (Scheme::Zmock1, ExtractedKey::Key32(k)) => decrypt_zmock1(k, &buffer)?,
        // Legacy - legacy does not use this call path
        #[cfg(feature = "legacy")]
        (Scheme::Legacy, ExtractedKey::Key32(_k)) => {
            unreachable!("called generic dec function for legacy")
        }
        _ => return Err(Error::InvalidKeyLength),
    };

    // Step 5: Convert to string

    // Unchecked (Assuming plaintext was originally valid UTF-8, and correct key is used)
    #[cfg(feature = "unchecked-utf8")]
    {
        Ok(unsafe { String::from_utf8_unchecked(plaintext_bytes) })
    }

    #[cfg(not(feature = "unchecked-utf8"))]
    {
        String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
    }
}

/// Decode text encoding to raw bytes.
#[inline]
pub(crate) fn decode_obtext_to_payload(obtext: &str, encoding: Encoding) -> Result<Vec<u8>, Error> {
    match encoding {
        Encoding::B32 => BASE32_RFC
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidB32),
        Encoding::C32 => BASE32_CROCKFORD
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidC32),
        Encoding::B64 => BASE64URL_NOPAD
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidB64),
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
        let result = decode_obtext_to_payload(encoded, Encoding::C32).unwrap();
        assert_eq!(result, b"abc");
    }

    #[test]
    fn test_decode_hex() {
        let encoded = "68656c6c6f";
        let result = decode_obtext_to_payload(encoded, Encoding::Hex).unwrap();
        assert_eq!(result, b"hello");
    }
}
