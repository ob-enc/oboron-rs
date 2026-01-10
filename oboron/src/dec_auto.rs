use crate::{constants::SCHEME_MARKER_SIZE, error::Error, Encoding, MasterKey};

#[cfg(feature = "aags")]
use crate::{constants::AAGS_MARKER, decrypt_aags};
#[cfg(feature = "aasv")]
use crate::{constants::AASV_MARKER, decrypt_aasv};
#[cfg(feature = "apgs")]
use crate::{constants::APGS_MARKER, decrypt_apgs};
#[cfg(feature = "apsv")]
use crate::{constants::APSV_MARKER, decrypt_apsv};
#[cfg(feature = "upbc")]
use crate::{constants::UPBC_MARKER, decrypt_upbc};
// Testing
#[cfg(feature = "mock")]
use crate::{constants::MOCK1_MARKER, decrypt_mock1};
#[cfg(feature = "mock")]
use crate::{constants::MOCK2_MARKER, decrypt_mock2};

/// Decode the given encoding, then decrypt autodetecting the scheme (SECURE SCHEMES ONLY)
pub fn dec_any_scheme(
    masterkey: &MasterKey,
    encoding: Encoding,
    obtext: &str,
) -> Result<String, Error> {
    // Step 1: Decode obtext using encoding
    let mut buffer = crate::dec::decode_obtext_to_payload(obtext, encoding)?;

    if buffer.len() < SCHEME_MARKER_SIZE {
        return Err(Error::PayloadTooShort);
    }

    // Step 2: XOR the last two bytes with the first two to undo mixing
    let len = buffer.len();
    buffer[len - 1] ^= buffer[0];
    buffer[len - 2] ^= buffer[0];

    // Step 3: Extract 2-byte scheme marker from end
    let scheme_marker = [buffer[len - 2], buffer[len - 1]];
    buffer.truncate(len - SCHEME_MARKER_SIZE);

    // Step 4: Match scheme marker and decrypt with available SECURE schemes only
    let plaintext_bytes = match scheme_marker {
        #[cfg(feature = "upbc")]
        UPBC_MARKER => decrypt_upbc(masterkey.key(), &buffer)?,
        #[cfg(feature = "aags")]
        AAGS_MARKER => decrypt_aags(masterkey.key(), &buffer)?,
        #[cfg(feature = "apgs")]
        APGS_MARKER => decrypt_apgs(masterkey.key(), &buffer)?,
        #[cfg(feature = "aasv")]
        AASV_MARKER => decrypt_aasv(masterkey.key(), &buffer)?,
        #[cfg(feature = "apsv")]
        APSV_MARKER => decrypt_apsv(masterkey.key(), &buffer)?,
        // Testing
        #[cfg(feature = "mock")]
        MOCK1_MARKER => decrypt_mock1(masterkey.key(), &buffer)?,
        #[cfg(feature = "mock")]
        MOCK2_MARKER => decrypt_mock2(masterkey.key(), &buffer)?,
        _ => {
            // Unknown scheme marker - no fallback for secure schemes
            return Err(Error::UnknownScheme);
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

/// Decode c32, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_c32(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(masterkey, Encoding::C32, obtext)
}

/// Decode b32, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_b32(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(masterkey, Encoding::B32, obtext)
}

/// Decode b64, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_b64(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(masterkey, Encoding::B64, obtext)
}

/// Decode hex, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_hex(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(masterkey, Encoding::Hex, obtext)
}

/// Autodetect both the encoding and scheme, then decode accordingly (SECURE SCHEMES ONLY).
///
/// This function analyzes the characteristics of the input text to determine
/// the most likely encoding format, then delegates to the appropriate decoder.
/// If the most likely encoding fails, it falls back to trying other encodings.
///
/// Detection logic:
/// 1. If text contains '-', '_', or uppercase letters -> B64 (definitive)
/// 2. Else if text contains non-hex lowercase letters (g-z) -> Try Base32, fallback to B64
/// 3. Else -> Try Hex, fallback to Base32, then B64
pub fn dec_any_format(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    // Check for B64 indicators:   '-', '_', or mixed case letters (definitive)
    if obtext.contains('-')
        || obtext.contains('_')
        || (obtext.chars().any(|c| c.is_ascii_lowercase())
            && obtext.chars().any(|c| c.is_ascii_uppercase()))
    {
        if let Ok(result) = dec_any_scheme_b64(masterkey, obtext) {
            return Ok(result);
        }
    }

    // Check for uppercase letters, indicating B32
    if obtext.chars().any(|c| c.is_ascii_uppercase()) {
        // Try B32 first, fallback to B64 (no point trying hex)
        if let Ok(result) = dec_any_scheme_b32(masterkey, obtext) {
            return Ok(result);
        }
        if let Ok(result) = dec_any_scheme_b64(masterkey, obtext) {
            return Ok(result);
        }
    }

    // Check for non-hex lowercase letters (g-z), indicating C32
    if obtext.chars().any(|c| c.is_ascii_lowercase() && c > 'f') {
        // Try C32 first, fallback to B64 (no point trying hex)
        if let Ok(result) = dec_any_scheme_c32(masterkey, obtext) {
            return Ok(result);
        }
        if let Ok(result) = dec_any_scheme_b64(masterkey, obtext) {
            return Ok(result);
        }
    }

    // Likely hex - try Hex, then Base32, then B64
    if let Ok(result) = dec_any_scheme_hex(masterkey, obtext) {
        return Ok(result);
    }
    if let Ok(result) = dec_any_scheme_c32(masterkey, obtext) {
        return Ok(result);
    }
    dec_any_scheme_b64(masterkey, obtext)
}
