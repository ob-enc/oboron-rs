use crate::{error::Error, Encoding, Keychain};
#[cfg(feature = "legacy")]
use crate::{Format, Scheme};

// Always available
use crate::constants::REVERSED_SCHEME_BYTES;

#[cfg(feature = "adgs")]
use crate::{constants::ADGS_BYTE, decrypt_adgs};
#[cfg(feature = "adsv")]
use crate::{constants::ADSV_BYTE, decrypt_adsv};
#[cfg(feature = "apgs")]
use crate::{constants::APGS_BYTE, decrypt_apgs};
#[cfg(feature = "apsv")]
use crate::{constants::APSV_BYTE, decrypt_apsv};
#[cfg(feature = "upc")]
use crate::{constants::UPC_BYTE, decrypt_upc};
#[cfg(feature = "zdc")]
use crate::{constants::ZDC_BYTE, decrypt_zdc};
// Testing
#[cfg(feature = "mock")]
use crate::{constants::MOCK1_BYTE, decrypt_mock1};
#[cfg(feature = "mock")]
use crate::{constants::MOCK2_BYTE, decrypt_mock2};
// Legacy
#[cfg(feature = "legacy")]
use crate::legacy;

/// Decode the given encoding, then decrypt autodetecting the scheme
pub fn dec_any_scheme(
    keychain: &Keychain,
    encoding: Encoding,
    obtext: &str,
) -> Result<String, Error> {
    // Step 1: Decode obtext using encoding
    let mut buffer = match crate::dec::decode_obtext_to_payload(obtext, encoding) {
        Ok(ct) => ct,
        Err(decode_err) => {
            // Decoding failed - try legacy (legacy format with reversal applied to final encoding rather than bytes as in zdc)
            #[cfg(feature = "legacy")]
            {
                let format = Format::new(Scheme::Legacy, encoding);
                return legacy::dec_legacy(obtext, format, keychain).or(Err(decode_err));
            }
            #[cfg(not(feature = "legacy"))]
            return Err(decode_err);
        }
    };

    if buffer.is_empty() {
        return Err(Error::EmptyPayload);
    }

    // XOR last byte with first byte for unmixing the scheme byte
    let len = buffer.len();
    buffer[len - 1] ^= buffer[0];

    // Step 2: Extract scheme byte from end (last byte)
    let scheme_byte = buffer.pop().unwrap(); // Remove scheme byte in-place

    // Step 3: Reverse the ciphertext in-place to get original order
    if REVERSED_SCHEME_BYTES.contains(&scheme_byte) {
        buffer.reverse();
    }

    // At this point buffer = ciphertext, ready to be decrypted

    // Step 4: Match scheme byte and decrypt with available schemes
    let plaintext_bytes = match scheme_byte {
        #[cfg(feature = "zdc")]
        ZDC_BYTE => decrypt_zdc(keychain, &buffer)?,
        #[cfg(feature = "upc")]
        UPC_BYTE => decrypt_upc(keychain, &buffer)?,
        #[cfg(feature = "adgs")]
        ADGS_BYTE => decrypt_adgs(keychain, &buffer)?,
        #[cfg(feature = "apgs")]
        APGS_BYTE => decrypt_apgs(keychain, &buffer)?,
        #[cfg(feature = "adsv")]
        ADSV_BYTE => decrypt_adsv(keychain, &buffer)?,
        #[cfg(feature = "apsv")]
        APSV_BYTE => decrypt_apsv(keychain, &buffer)?,
        // Testing
        #[cfg(feature = "mock")]
        MOCK1_BYTE => decrypt_mock1(keychain, &buffer)?,
        #[cfg(feature = "mock")]
        MOCK2_BYTE => decrypt_mock2(keychain, &buffer)?,
        _ => {
            // Unknown scheme byte - try legacy as fallback
            #[cfg(feature = "legacy")]
            {
                let format = Format::new(Scheme::Legacy, encoding);
                let legacy_result = legacy::dec_legacy(obtext, format, keychain)?;
                // Only validate legacy fallback results to avoid false positives
                validate_legacy_output(&legacy_result)?;
                return Ok(legacy_result);
            }
            #[cfg(not(feature = "legacy"))]
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
        String::from_utf8(plaintext_bytes).map_err(|_| Error::DecryptionFailed)
    }
}

/// Validate legacy output to prevent false positives from encoding mismatches
#[cfg(feature = "legacy")]
fn validate_legacy_output(plaintext: &str) -> Result<(), Error> {
    let total_chars = plaintext.chars().count();
    if total_chars == 0 {
        return Ok(()); // Empty string is fine
    }

    let reasonable_count = plaintext
        .chars()
        .filter(|&c| {
            c.is_ascii_graphic()  // Printable ASCII
            || c.is_whitespace()   // Whitespace
            || (c >= '\u{0080}' && c <= '\u{FFFF}' && !c.is_control()) // Valid Unicode (not control chars)
        })
        .count();

    // Require at least 70% of characters to be reasonable (lowered threshold)
    if reasonable_count * 10 < total_chars * 7 {
        return Err(Error::InvalidLegacyOutput);
    }

    Ok(())
}

/// Decode c32, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_c32(keychain: &Keychain, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(keychain, Encoding::Base32Crockford, obtext)
}

/// Decode b32, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_b32(keychain: &Keychain, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(keychain, Encoding::Base32Rfc, obtext)
}

/// Decode b64, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_b64(keychain: &Keychain, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(keychain, Encoding::Base64, obtext)
}

/// Decode hex, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_hex(keychain: &Keychain, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(keychain, Encoding::Hex, obtext)
}

/// Autodetect both the encoding and scheme, then decode accordingly.
///
/// This function analyzes the characteristics of the input text to determine
/// the most likely encoding format, then delegates to the appropriate decoder.
/// If the most likely encoding fails, it falls back to trying other encodings.
///
/// Detection logic:
/// 1. If text contains '-', '_', or uppercase letters -> Base64 (definitive)
/// 2. Else if text contains non-hex lowercase letters (g-z) -> Try Base32, fallback to Base64
/// 3. Else -> Try Hex, fallback to Base32, then Base64
pub fn dec_any_format(keychain: &Keychain, obtext: &str) -> Result<String, Error> {
    // Check for Base64 indicators:  '-', '_', or mixed case letters (definitive)
    if obtext.contains('-')
        || obtext.contains('_')
        || (obtext.chars().any(|c| c.is_ascii_lowercase())
            && obtext.chars().any(|c| c.is_ascii_uppercase()))
    {
        if let Ok(result) = dec_any_scheme_b64(keychain, obtext) {
            return Ok(result);
        }
    }

    // Check for uppercase letters, indicating Base32Rfc
    if obtext.chars().any(|c| c.is_ascii_uppercase()) {
        // Try Base32Rfc first, fallback to Base64 (no point trying hex)
        if let Ok(result) = dec_any_scheme_b32(keychain, obtext) {
            return Ok(result);
        }
        if let Ok(result) = dec_any_scheme_b64(keychain, obtext) {
            return Ok(result);
        }
    }

    // Check for non-hex lowercase letters (g-z), indicating Base32Crockford
    if obtext.chars().any(|c| c.is_ascii_lowercase() && c > 'f') {
        // Try Base32Crockford first, fallback to Base64 (no point trying hex)
        if let Ok(result) = dec_any_scheme_c32(keychain, obtext) {
            return Ok(result);
        }
        if let Ok(result) = dec_any_scheme_b64(keychain, obtext) {
            return Ok(result);
        }
    }

    // Likely hex - try Hex, then Base32, then Base64
    if let Ok(result) = dec_any_scheme_hex(keychain, obtext) {
        return Ok(result);
    }
    if let Ok(result) = dec_any_scheme_c32(keychain, obtext) {
        return Ok(result);
    }
    dec_any_scheme_b64(keychain, obtext)
}
