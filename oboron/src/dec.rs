use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    constants::REVERSED_SCHEME_BYTES,
    error::Error,
    Encoding, Format, Keychain, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

// Conditionally import decrypt functions based on features
#[cfg(feature = "ob01")]
use crate::decrypt_ob01;
#[cfg(feature = "ob21p")]
use crate::decrypt_ob21p;
#[cfg(feature = "ob31")]
use crate::decrypt_ob31;
#[cfg(feature = "ob31p")]
use crate::decrypt_ob31p;
#[cfg(feature = "ob32")]
use crate::decrypt_ob32;
#[cfg(feature = "ob32p")]
use crate::decrypt_ob32p;
// Testing
#[cfg(feature = "ob70")]
use crate::decrypt_ob70;
#[cfg(feature = "ob71")]
use crate::decrypt_ob71;

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

    // Step 2: Extract the scheme byte from tail
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
        #[cfg(feature = "ob01")]
        Scheme::Ob01 => decrypt_ob01(keychain, &buffer)?,
        #[cfg(feature = "ob21p")]
        Scheme::Ob21p => decrypt_ob21p(keychain, &buffer)?,
        #[cfg(feature = "ob31")]
        Scheme::Ob31 => decrypt_ob31(keychain, &buffer)?,
        #[cfg(feature = "ob31p")]
        Scheme::Ob31p => decrypt_ob31p(keychain, &buffer)?,
        #[cfg(feature = "ob32")]
        Scheme::Ob32 => decrypt_ob32(keychain, &buffer)?,
        #[cfg(feature = "ob32p")]
        Scheme::Ob32p => decrypt_ob32p(keychain, &buffer)?,
        // Testing
        #[cfg(feature = "ob70")]
        Scheme::Ob70 => decrypt_ob70(keychain, &buffer)?,
        #[cfg(feature = "ob71")]
        Scheme::Ob71 => decrypt_ob71(keychain, &buffer)?,
        // Legacy - ob00 does not use this call path
        #[cfg(feature = "ob00")]
        Scheme::Ob00 => unreachable!("called generic dec function for ob00"),
    };

    // Step 5: Convert to string
    // SAFETY: Plaintext was originally valid UTF-8, and encryption preserves byte sequences
    Ok(unsafe { String::from_utf8_unchecked(plaintext_bytes) })
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
