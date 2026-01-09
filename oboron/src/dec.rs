use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    constants::SCHEME_MARKER_SIZE,
    error::Error,
    Encoding, Format, Scheme,
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
pub(crate) fn dec_from_format_32(
    obtext: &str,
    format: Format,
    key32: &[u8; 32],
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
    let plaintext_bytes = match format.scheme() {
        #[cfg(feature = "aags")]
        Scheme::Aags => decrypt_aags(key32, &buffer)?,
        #[cfg(feature = "apgs")]
        Scheme::Apgs => decrypt_apgs(key32, &buffer)?,
        #[cfg(feature = "upbc")]
        Scheme::Upbc => decrypt_upbc(key32, &buffer)?,
        // Z-tier
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => decrypt_zrbcx(key32, &buffer)?,
        // Testing
        #[cfg(feature = "mock")]
        Scheme::Mock1 => decrypt_mock1(key32, &buffer)?,
        #[cfg(feature = "mock")]
        Scheme::Mock2 => decrypt_mock2(key32, &buffer)?,
        #[cfg(feature = "zmock")]
        Scheme::Zmock1 => decrypt_zmock1(key32, &buffer)?,
        // 64-byte key schemes use enc_to_format_64
        #[cfg(feature = "aasv")]
        Scheme::Aasv => return Err(Error::InvalidKeyLength),
        #[cfg(feature = "apsv")]
        Scheme::Apsv => return Err(Error::InvalidKeyLength),
        // Legacy does not use this call path (separate implementation)
        #[cfg(feature = "legacy")]
        Scheme::Legacy => {
            unreachable!("called generic dec function for legacy")
        }
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

/// Generic decoding pipeline for all schemes (except legacy).
///
/// Steps:
/// 1. Decode obtext using format's encoding
/// 2. XOR last two bytes with first two to undo entropy mixing
/// 3. Extract and verify 2-byte scheme marker
/// 4. Call scheme-specific decrypt function (handles any scheme-specific transformations like reversal)
/// 5. Convert to UTF-8 string
#[inline]
pub(crate) fn dec_from_format_64(
    obtext: &str,
    format: Format,
    key64: &[u8; 64],
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
    let plaintext_bytes = match format.scheme() {
        #[cfg(feature = "aasv")]
        Scheme::Aasv => decrypt_aasv(key64, &buffer)?,
        #[cfg(feature = "apsv")]
        Scheme::Apsv => decrypt_apsv(key64, &buffer)?,
        // 32-byte key schemes use enc_to_format_32
        #[cfg(feature = "aags")]
        Scheme::Aags => return Err(Error::InvalidKeyLength),
        #[cfg(feature = "apgs")]
        Scheme::Apgs => return Err(Error::InvalidKeyLength),
        #[cfg(feature = "upbc")]
        Scheme::Upbc => return Err(Error::InvalidKeyLength),
        // Z-tier
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => return Err(Error::InvalidKeyLength),
        // Testing
        #[cfg(feature = "mock")]
        Scheme::Mock1 | Scheme::Mock2 => return Err(Error::InvalidKeyLength),
        #[cfg(feature = "zmock")]
        Scheme::Zmock1 => return Err(Error::InvalidKeyLength),
        // Legacy does not use this call path (separate implementation)
        #[cfg(feature = "legacy")]
        Scheme::Legacy => {
            unreachable!("called generic dec function for legacy")
        }
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
