use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    error::Error,
    Encoding, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

// Conditionally import encrypt functions
#[cfg(feature = "aags")]
use crate::encrypt_aags;
#[cfg(feature = "aasv")]
use crate::encrypt_aasv;
#[cfg(feature = "apgs")]
use crate::encrypt_apgs;
#[cfg(feature = "apsv")]
use crate::encrypt_apsv;
#[cfg(feature = "mock")]
use crate::encrypt_mock1;
#[cfg(feature = "mock")]
use crate::encrypt_mock2;
#[cfg(feature = "upbc")]
use crate::encrypt_upbc;

/// Generic encoding pipeline - takes full 64-byte key, obcrypt functions extract what they need
///
/// Steps:
/// 1. Call scheme-specific encrypt function (handles any scheme-specific transformations like reversal)
/// 2. Append 2-byte scheme marker to ciphertext payload
/// 3. XOR marker bytes with first payload byte for entropy
/// 4. Encode to specified format
#[inline(always)]
pub(crate) fn enc_to_format(
    plaintext: &str,
    format: Format,
    master_key: &[u8; 64],
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Encrypt using scheme-specific function (they extract the key portion they need)
    let mut ciphertext: Vec<u8> = match format.scheme() {
        #[cfg(feature = "aags")]
        Scheme::Aags => encrypt_aags(master_key, plaintext.as_bytes())?,
        #[cfg(feature = "apgs")]
        Scheme::Apgs => encrypt_apgs(master_key, plaintext.as_bytes())?,
        #[cfg(feature = "aasv")]
        Scheme::Aasv => encrypt_aasv(master_key, plaintext.as_bytes())?,
        #[cfg(feature = "apsv")]
        Scheme::Apsv => encrypt_apsv(master_key, plaintext.as_bytes())?,
        #[cfg(feature = "upbc")]
        Scheme::Upbc => encrypt_upbc(master_key, plaintext.as_bytes())?,
        #[cfg(feature = "mock")]
        Scheme::Mock1 => encrypt_mock1(master_key, plaintext.as_bytes())?,
        #[cfg(feature = "mock")]
        Scheme::Mock2 => encrypt_mock2(master_key, plaintext.as_bytes())?,
        // Z-tier
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => unreachable!("ztier uses separate path"),
        #[cfg(feature = "zmock")]
        Scheme::Zmock1 => unreachable!("ztier uses separate path"),
        #[cfg(feature = "legacy")]
        Scheme::Legacy => unreachable!("legacy uses separate path"),
    };

    // Append marker and XOR
    let marker = format.scheme().marker();
    let first_byte = ciphertext[0];
    ciphertext.push(marker[0] ^ first_byte);
    ciphertext.push(marker[1] ^ first_byte);

    // Encode
    Ok(match format.encoding() {
        Encoding::C32 => BASE32_CROCKFORD.encode(&ciphertext),
        Encoding::B32 => BASE32_RFC.encode(&ciphertext),
        Encoding::B64 => BASE64URL_NOPAD.encode(&ciphertext),
        Encoding::Hex => HEXLOWER.encode(&ciphertext),
    })
}
