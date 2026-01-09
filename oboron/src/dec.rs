use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    constants::SCHEME_MARKER_SIZE,
    error::Error,
    Encoding, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

// Conditionally import decrypt functions
#[cfg(feature = "aags")]
use crate::decrypt_aags;
#[cfg(feature = "aasv")]
use crate::decrypt_aasv;
#[cfg(feature = "apgs")]
use crate::decrypt_apgs;
#[cfg(feature = "apsv")]
use crate::decrypt_apsv;
#[cfg(feature = "mock")]
use crate::decrypt_mock1;
#[cfg(feature = "mock")]
use crate::decrypt_mock2;
#[cfg(feature = "upbc")]
use crate::decrypt_upbc;

/// Generic decoding pipeline - takes full 64-byte key, obcrypt functions extract what they need
///
/// Steps:
/// 1. Decode obtext using format's encoding
/// 2. XOR last two bytes with first two to undo entropy mixing
/// 3. Extract and verify 2-byte scheme marker
/// 4. Call scheme-specific decrypt function (handles any scheme-specific transformations like reversal)
/// 5. Convert to UTF-8 string
#[inline(always)]
pub(crate) fn dec_from_format(
    obtext: &str,
    format: Format,
    master_key: &[u8; 64],
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
        Scheme::Aags => decrypt_aags(master_key, &buffer)?,
        #[cfg(feature = "apgs")]
        Scheme::Apgs => decrypt_apgs(master_key, &buffer)?,
        #[cfg(feature = "aasv")]
        Scheme::Aasv => decrypt_aasv(master_key, &buffer)?,
        #[cfg(feature = "apsv")]
        Scheme::Apsv => decrypt_apsv(master_key, &buffer)?,
        #[cfg(feature = "upbc")]
        Scheme::Upbc => decrypt_upbc(master_key, &buffer)?,
        #[cfg(feature = "mock")]
        Scheme::Mock1 => decrypt_mock1(master_key, &buffer)?,
        #[cfg(feature = "mock")]
        Scheme::Mock2 => decrypt_mock2(master_key, &buffer)?,
        // Z-tier
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => unreachable!("ztier uses separate path"),
        #[cfg(feature = "zmock")]
        Scheme::Zmock1 => unreachable!("ztier uses separate path"),
        #[cfg(feature = "legacy")]
        Scheme::Legacy => unreachable!("legacy uses separate path"),
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
