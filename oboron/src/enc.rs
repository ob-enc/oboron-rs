use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    error::Error,
    Encoding, Format, Scheme,
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
#[cfg(feature = "zmock")]
use crate::encrypt_zmock1;

/// Generic encoding pipeline for all schemes (except legacy).
///
/// Steps:
/// 1. Call scheme-specific encrypt function (handles any scheme-specific transformations like reversal)
/// 2. Append 2-byte scheme marker to ciphertext payload
/// 3. XOR marker bytes with first payload byte for entropy
/// 4. Encode to specified format
#[inline(always)]
pub(crate) fn enc_to_format_32(
    plaintext: &str,
    format: Format,
    key32: &[u8; 32],
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Step 1: Encrypt using scheme-specific function
    let mut ciphertext = match format.scheme() {
        #[cfg(feature = "aags")]
        Scheme::Aags => encrypt_aags(key32, plaintext.as_bytes())?,
        #[cfg(feature = "apgs")]
        Scheme::Apgs => encrypt_apgs(key32, plaintext.as_bytes())?,
        #[cfg(feature = "upbc")]
        Scheme::Upbc => encrypt_upbc(key32, plaintext.as_bytes())?,
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => encrypt_zrbcx(key32, plaintext.as_bytes())?,
        #[cfg(feature = "mock")]
        Scheme::Mock1 => encrypt_mock1(key32, plaintext.as_bytes())?,
        #[cfg(feature = "mock")]
        Scheme::Mock2 => encrypt_mock2(key32, plaintext.as_bytes())?,
        #[cfg(feature = "zmock")]
        Scheme::Zmock1 => encrypt_zmock1(key32, plaintext.as_bytes())?,
        _ => return Err(Error::InvalidKeyLength),
    };

    // Step 2 & 3: Append marker and XOR
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

#[inline(always)]
pub(crate) fn enc_to_format_64(
    plaintext: &str,
    format: Format,
    key64: &[u8; 64],
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Step 1: Encrypt using scheme-specific function
    let mut ciphertext = match format.scheme() {
        #[cfg(feature = "aasv")]
        Scheme::Aasv => encrypt_aasv(key64, plaintext.as_bytes())?,
        #[cfg(feature = "apsv")]
        Scheme::Apsv => encrypt_apsv(key64, plaintext.as_bytes())?,
        _ => return Err(Error::InvalidKeyLength),
    };

    // Step 2 & 3: Append marker and XOR
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
