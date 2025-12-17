use thiserror::Error;

/// All errors that can occur in oboron operations.
#[derive(Debug, Error)]
pub enum Error {
    // Key errors
    // ----------
    #[error("key must be 64 bytes")]
    InvalidKeyLength,

    // Encoding errors
    // ---------------
    #[error("invalid hex encoding")]
    InvalidHex,

    #[error("invalid base64 encoding")]
    InvalidBase64,

    #[error("invalid base32rfc encoding")]
    InvalidBase32Rfc,

    #[error("invalid base32crockford encoding")]
    InvalidBase32Crockford,

    // Format/scheme errors
    // --------------------
    #[error("invalid format string")]
    InvalidFormat,

    #[error("unknown scheme")]
    UnknownScheme,

    #[error("unknown encoding")]
    UnknownEncoding,

    // Encryption errors
    // -----------------
    #[error("enc failed")]
    EncryptionFailed,

    #[error("enc failed: empty plaintext")]
    EmptyPlaintext,

    #[error("dec failed: empty payload")]
    EmptyPayload,

    #[error("dec failed: payload too short")]
    PayloadTooShort,

    // Decryption errors
    // -----------------
    #[error("decryption failed")]
    DecryptionFailed,

    #[error("invalid block length")]
    InvalidBlockLength,

    #[error("decoding failed: scheme byte mismatch")]
    SchemeByteMismatch,

    #[cfg(feature = "ob00")]
    #[error("ob00 fallback produced invalid output (likely encoding mismatch)")]
    InvalidOb00Output,
}

impl From<hex::FromHexError> for Error {
    fn from(_: hex::FromHexError) -> Self {
        Error::InvalidHex
    }
}
