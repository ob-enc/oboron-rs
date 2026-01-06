use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Macro to generate Python wrapper classes for fixed-format ObtextCodec types
macro_rules! impl_codec_class {
    ($py_name:ident, $rust_type:ty, $doc:expr) => {
        #[doc = $doc]
        #[pyclass]
        #[allow(non_camel_case_types)]
        struct $py_name {
            inner: $rust_type,
        }

        #[pymethods]
        impl $py_name {
            /// Create a new codec instance.
            ///
            /// Args:
            ///     key:     86-character base64 string key (512 bits).  Required if keyless=False.
            ///     keyless: If True, uses the hardcoded key (testing only, NOT SECURE).
            ///
            /// Returns:
            ///     A new codec instance.
            ///
            /// Raises:
            ///     ValueError: If key is invalid or both key and keyless are provided.
            #[new]
            #[pyo3(signature = (key=None, keyless=false))]
            fn new(key: Option<String>, keyless: bool) -> PyResult<Self> {
                let inner = match (key, keyless) {
                    (Some(key), false) => <$rust_type>::new(&key).map_err(|e| {
                        PyValueError::new_err(format!("Failed to create codec: {}", e))
                    })?,
                    (None, true) => <$rust_type>::new_keyless().map_err(|e| {
                        PyValueError::new_err(format!(
                            "Failed to create codec with hardcoded key: {}",
                            e
                        ))
                    })?,
                    (Some(_), true) => {
                        return Err(PyValueError::new_err(
                            "Cannot specify both key and keyless=True",
                        ));
                    }
                    (None, false) => {
                        return Err(PyValueError::new_err(
                            "Must provide either key or set keyless=True",
                        ));
                    }
                };

                Ok(Self { inner })
            }

            /// Encrypt+encode a plaintext string.
            ///
            /// Args:
            ///     plaintext: The plaintext string to encrypt+encode.
            ///
            /// Returns:
            ///     The obtext string.
            ///
            /// Raises:
            ///     ValueError: If the enc operation fails.
            fn enc(&self, plaintext: &str) -> PyResult<String> {
                let result = self.inner.enc(plaintext);
                result.map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
            }

            /// Decode+decrypt an obtext string back to plaintext.
            ///
            /// Args:
            ///     obtext: The encrypted+encoded string to decode+decrypt.
            ///
            /// Returns:
            ///     The decoded+decrypted plaintext string.
            ///
            /// Raises:
            ///     ValueError: If the dec operation fails
            #[pyo3(signature = (obtext))]
            fn dec(&self, obtext: &str) -> PyResult<String> {
                let result = self.inner.dec(obtext);
                result.map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
            }

            /// Get the current format string.
            ///
            /// Returns:
            ///     Format string like "zrbcx.c32", "zrbcx.b32", "aags.b64", etc.
            #[getter]
            fn format(&self) -> String {
                format!("{}", self.inner.format())
            }

            /// The scheme used by this instance.
            #[getter]
            fn scheme(&self) -> String {
                self.inner.scheme().to_string()
            }

            /// The encoding format used by this instance.
            #[getter]
            fn encoding(&self) -> String {
                self.inner.encoding().to_string()
            }

            /// Get the key used by this instance (as base64 string).
            #[getter]
            fn key(&self) -> String {
                self.inner.key()
            }

            /// Get the key as hex used by this instance.
            #[getter]
            fn key_hex(&self) -> String {
                self.inner.key_hex()
            }

            /// Get the key as bytes used by this instance.
            #[getter]
            fn key_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
                Ok(PyBytes::new_bound(py, self.inner.key_bytes()).into())
            }
        }
    };
}

macro_rules! impl_zcodec_class {
    ($py_name:ident, $rust_type:ty, $doc:expr) => {
        #[doc = $doc]
        #[pyclass]
        #[allow(non_camel_case_types)]
        struct $py_name {
            inner: $rust_type,
        }

        #[pymethods]
        impl $py_name {
            /// Create a new codec instance.
            ///
            /// Args:
            ///     key:     43-character base64 string secret (256 bits).  Required if keyless=False.
            ///     keyless: If True, uses the hardcoded secret (testing only, NOT SECURE).
            ///
            /// Returns:
            ///     A new codec instance.
            ///
            /// Raises:
            ///     ValueError: If key is invalid or both key and keyless are provided.
            #[new]
            #[pyo3(signature = (secret=None, keyless=false))]
            fn new(secret: Option<String>, keyless: bool) -> PyResult<Self> {
                let inner = match (secret, keyless) {
                    (Some(secret), false) => <$rust_type>::new(&secret).map_err(|e| {
                        PyValueError::new_err(format!("Failed to create codec: {}", e))
                    })?,
                    (None, true) => <$rust_type>::new_keyless().map_err(|e| {
                        PyValueError::new_err(format!(
                            "Failed to create codec with hardcoded secret: {}",
                            e
                        ))
                    })?,
                    (Some(_), true) => {
                        return Err(PyValueError::new_err(
                            "Cannot specify both secret and keyless=True",
                        ));
                    }
                    (None, false) => {
                        return Err(PyValueError::new_err(
                            "Must provide either secret or set keyless=True",
                        ));
                    }
                };

                Ok(Self { inner })
            }

            /// Encrypt+encode a plaintext string.
            ///
            /// Args:
            ///     plaintext: The plaintext string to encrypt+encode.
            ///
            /// Returns:
            ///     The obtext string.
            ///
            /// Raises:
            ///     ValueError: If the enc operation fails.
            fn enc(&self, plaintext: &str) -> PyResult<String> {
                let result = self.inner.enc(plaintext);
                result.map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
            }

            /// Decode+decrypt an obtext string back to plaintext.
            ///
            /// Args:
            ///     obtext: The encrypted+encoded string to decode+decrypt.
            ///
            /// Returns:
            ///     The decoded+decrypted plaintext string.
            ///
            /// Raises:
            ///     ValueError: If the dec operation fails
            #[pyo3(signature = (obtext))]
            fn dec(&self, obtext: &str) -> PyResult<String> {
                let result = self.inner.dec(obtext);
                result.map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
            }

            /// Get the current format string.
            ///
            /// Returns:
            ///     Format string like "zrbcx.c32", "zrbcx.b32", etc.
            #[getter]
            fn format(&self) -> String {
                format!("{}", self.inner.format())
            }

            /// The scheme used by this instance.
            #[getter]
            fn scheme(&self) -> String {
                self.inner.scheme().to_string()
            }

            /// The encoding format used by this instance.
            #[getter]
            fn encoding(&self) -> String {
                self.inner.encoding().to_string()
            }

            /// Get the secret used by this instance (as base64 string).
            #[getter]
            fn secret(&self) -> String {
                self.inner.secret()
            }

            /// Get the secret as bytes used by this instance.
            #[getter]
            fn secret_hex(&self) -> String {
                self.inner.secret_hex()
            }

            /// Get the secret as bytes used by this instance.
            #[getter]
            fn secret_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
                Ok(PyBytes::new_bound(py, self.inner.secret_bytes()).into())
            }
        }
    };
}

// Aags variants
// -------------
#[cfg(feature = "aags")]
impl_codec_class!(
    AagsB32,
    ::oboron::AagsB32,
    "Aags codec (deterministic AES-GCM-SIV) with B32 encoding "
);
#[cfg(feature = "aags")]
impl_codec_class!(
    AagsB64,
    ::oboron::AagsB64,
    "Aags codec (deterministic AES-GCM-SIV) with B64 encoding"
);
#[cfg(feature = "aags")]
impl_codec_class!(
    AagsC32,
    ::oboron::AagsC32,
    "Aags codec (deterministic AES-GCM-SIV) with C32 encoding"
);
#[cfg(feature = "aags")]
impl_codec_class!(
    AagsHex,
    ::oboron::AagsHex,
    "Aags codec (deterministic AES-GCM-SIV) with Hex encoding"
);

// Aasv variants
// -------------
#[cfg(feature = "aasv")]
impl_codec_class!(
    AasvB32,
    ::oboron::AasvB32,
    "Aasv codec (deterministic AES-SIV, nonce-misuse resistant) with B32 encoding"
);
#[cfg(feature = "aasv")]
impl_codec_class!(
    AasvB64,
    ::oboron::AasvB64,
    "Aasv codec (deterministic AES-SIV, nonce-misuse resistant) with B64 encoding"
);
#[cfg(feature = "aasv")]
impl_codec_class!(
    AasvC32,
    ::oboron::AasvC32,
    "Aasv codec (deterministic AES-SIV, nonce-misuse resistant) with C32 encoding"
);
#[cfg(feature = "aasv")]
impl_codec_class!(
    AasvHex,
    ::oboron::AasvHex,
    "Aasv codec (deterministic AES-SIV, nonce-misuse resistant) with Hex encoding"
);

// Apgs variants
// --------------
#[cfg(feature = "apgs")]
impl_codec_class!(
    ApgsB32,
    ::oboron::ApgsB32,
    "Apgs codec (probabilistic AES-GCM-SIV) with B32 encoding"
);
#[cfg(feature = "apgs")]
impl_codec_class!(
    ApgsB64,
    ::oboron::ApgsB64,
    "Apgs codec (probabilistic AES-GCM-SIV) with B64 encoding"
);
#[cfg(feature = "apgs")]
impl_codec_class!(
    ApgsC32,
    ::oboron::ApgsC32,
    "Apgs codec (probabilistic AES-GCM-SIV) with C32 encoding"
);
#[cfg(feature = "apgs")]
impl_codec_class!(
    ApgsHex,
    ::oboron::ApgsHex,
    "Apgs codec (probabilistic AES-GCM-SIV) with Hex encoding"
);

// Apsv variants
// --------------
#[cfg(feature = "apsv")]
impl_codec_class!(
    ApsvB32,
    ::oboron::ApsvB32,
    "Apsv codec (probabilistic AES-SIV) with B32 encoding"
);
#[cfg(feature = "apsv")]
impl_codec_class!(
    ApsvB64,
    ::oboron::ApsvB64,
    "Apsv codec (probabilistic AES-SIV) with B64 encoding"
);
#[cfg(feature = "apsv")]
impl_codec_class!(
    ApsvC32,
    ::oboron::ApsvC32,
    "Apsv codec (probabilistic AES-SIV) with C32 encoding"
);
#[cfg(feature = "apsv")]
impl_codec_class!(
    ApsvHex,
    ::oboron::ApsvHex,
    "Apsv codec (probabilistic AES-SIV) with Hex encoding"
);

// Upbc variants
// ------------
#[cfg(feature = "upbc")]
impl_codec_class!(
    UpbcB32,
    ::oboron::UpbcB32,
    "Upbc codec (probabilistic AES-CBC) with B32 encoding"
);
#[cfg(feature = "upbc")]
impl_codec_class!(
    UpbcB64,
    ::oboron::UpbcB64,
    "Upbc codec (probabilistic AES-CBC) with B64 encoding"
);
#[cfg(feature = "upbc")]
impl_codec_class!(
    UpbcC32,
    ::oboron::UpbcC32,
    "Upbc codec (probabilistic AES-CBC) with C32 encoding"
);
#[cfg(feature = "upbc")]
impl_codec_class!(
    UpbcHex,
    ::oboron::UpbcHex,
    "Upbc codec (probabilistic AES-CBC) with Hex encoding"
);

// Zrbcx variants
// -------------
#[cfg(feature = "zrbcx")]
impl_zcodec_class!(
    ZrbcxB32,
    ::oboron::ztier::ZrbcxB32,
    "Zrbcx codec (deterministic AES-CBC, constant IV) with B32 encoding "
);
#[cfg(feature = "zrbcx")]
impl_zcodec_class!(
    ZrbcxB64,
    ::oboron::ztier::ZrbcxB64,
    "Zrbcx codec (deterministic AES-CBC, constant IV) with B64 encoding"
);
#[cfg(feature = "zrbcx")]
impl_zcodec_class!(
    ZrbcxC32,
    ::oboron::ztier::ZrbcxC32,
    "Zrbcx codec (deterministic AES-CBC, constant IV) with C32 encoding"
);
#[cfg(feature = "zrbcx")]
impl_zcodec_class!(
    ZrbcxHex,
    ::oboron::ztier::ZrbcxHex,
    "Zrbcx codec (deterministic AES-CBC, constant IV) with Hex encoding"
);

// --- TESTING CLASSES ---

// Mock1 variants
// -------------
impl_codec_class!(
    Mock1B32,
    ::oboron::Mock1B32,
    "Mock1 codec (identity scheme, for testing) with B32 encoding"
);
impl_codec_class!(
    Mock1B64,
    ::oboron::Mock1B64,
    "Mock1 codec (identity scheme, for testing) with B64 encoding"
);
impl_codec_class!(
    Mock1C32,
    ::oboron::Mock1C32,
    "Mock1 codec (identity scheme, for testing) with C32 encoding"
);
impl_codec_class!(
    Mock1Hex,
    ::oboron::Mock1Hex,
    "Mock1 codec (identity scheme, for testing) with Hex encoding"
);

// Mock2 variants
// -------------
impl_codec_class!(
    Mock2B32,
    ::oboron::Mock2B32,
    "Mock2 codec (reverse plaintext scheme, for testing) with B32 encoding"
);
impl_codec_class!(
    Mock2B64,
    ::oboron::Mock2B64,
    "Mock2 codec (reverse plaintext scheme, for testing) with B64 encoding"
);
impl_codec_class!(
    Mock2C32,
    ::oboron::Mock2C32,
    "Mock2 codec (reverse plaintext scheme, for testing) with C32 encoding"
);
impl_codec_class!(
    Mock2Hex,
    ::oboron::Mock2Hex,
    "Mock2 codec (reverse plaintext scheme, for testing) with Hex encoding"
);

// Zmock1 variants
// -------------
impl_zcodec_class!(
    Zmock1B32,
    ::oboron::ztier::Zmock1B32,
    "Zmock1 codec (identity scheme, for testing) with B32 encoding"
);
impl_zcodec_class!(
    Zmock1B64,
    ::oboron::ztier::Zmock1B64,
    "Zmock1 codec (identity scheme, for testing) with B64 encoding"
);
impl_zcodec_class!(
    Zmock1C32,
    ::oboron::ztier::Zmock1C32,
    "Zmock1 codec (identity scheme, for testing) with C32 encoding"
);
impl_zcodec_class!(
    Zmock1Hex,
    ::oboron::ztier::Zmock1Hex,
    "Zmock1 codec (identity scheme, for testing) with Hex encoding"
);

// Legacy - LEGACY variants
// ----------------------
#[cfg(feature = "legacy")]
impl_zcodec_class!(
    LegacyB32,
    ::oboron::ztier::LegacyB32,
    "Legacy codec (deterministic AES-CBC, constant IV, custom padding) with B32 encoding\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zrbcx or more secure schemes like Aags/Aasv."
);
#[cfg(feature = "legacy")]
impl_zcodec_class!(
    LegacyB64,
    ::oboron::ztier::LegacyB64,
    "Legacy codec (deterministic AES-CBC, constant IV, custom padding) with B64 encoding\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zrbcx or more secure schemes like Aags/Aasv."
);
#[cfg(feature = "legacy")]
impl_zcodec_class!(
    LegacyC32,
    ::oboron::ztier::LegacyC32,
    "Legacy codec (deterministic AES-CBC, constant IV, custom padding) with C32 encoding\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zrbcx or more secure schemes like Aags/Aasv."
);
#[cfg(feature = "legacy")]
impl_zcodec_class!(
    LegacyHex,
    ::oboron::ztier::LegacyHex,
    "Legacy codec (deterministic AES-CBC, constant IV, custom padding) with Hex encoding\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zrbcx or more secure schemes like Aags/Aasv."
);

/// Ob - Flexible codec with runtime format selection.   
///
/// This is the main interface for most use cases.  It wraps Rust's Ob
/// and allows changing the format (scheme + encoding) at runtime.
#[pyclass]
struct Ob {
    inner: ::oboron::Ob,
}

#[pymethods]
impl Ob {
    /// Create a new Ob instance.
    ///
    /// Args:
    ///     format: Format string like "aags.b64", "apsv.hex", "zrbcx.c32", "zrbcx.b32", etc.
    ///     key:     86-character base64 string key (512 bits). Required if keyless=False.
    ///     keyless: If True, uses the hardcoded key (testing only, NOT SECURE).
    ///
    /// Returns:
    ///     A new Ob instance.
    ///
    /// Raises:
    ///     ValueError: If key or format is invalid.
    #[new]
    #[pyo3(signature = (format, key=None, keyless=false))]
    fn new(format: &str, key: Option<String>, keyless: bool) -> PyResult<Self> {
        let inner = match (key, keyless) {
            (Some(key), false) => ::oboron::Ob::new(format, &key)
                .map_err(|e| PyValueError::new_err(format!("Failed to create Ob: {}", e)))?,
            (None, true) => ::oboron::Ob::new_keyless(format).map_err(|e| {
                PyValueError::new_err(format!("Failed to create Ob with hardcoded key: {}", e))
            })?,
            (Some(_), true) => {
                return Err(PyValueError::new_err(
                    "Cannot specify both key and keyless=True",
                ));
            }
            (None, false) => {
                return Err(PyValueError::new_err(
                    "Must provide either key or set keyless=True",
                ));
            }
        };

        Ok(Self { inner })
    }

    /// Encrypt+encode a plaintext string.
    ///
    /// Args:  
    ///     plaintext: The plaintext string to encrypt+encode.
    ///
    /// Returns:  
    ///     The obtext string.
    ///
    /// Raises:  
    ///     ValueError: If encoding fails.
    fn enc(&self, plaintext: &str) -> PyResult<String> {
        let result = self.inner.enc(plaintext);
        result.map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
    }

    /// Decode+decrypt an obtext string back to plaintext.  
    ///
    /// Args:  
    ///     obtext: The encrypted+encoded string to decode.  
    ///
    /// Returns:  
    ///     The decoded plaintext string.
    ///
    /// Raises:  
    ///     ValueError: If the dec operation fails
    #[pyo3(signature = (obtext))]
    fn dec(&self, obtext: &str) -> PyResult<String> {
        let result = self.inner.dec(obtext);
        result.map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// This method tries to decode with the instance's encoding, and if that fails
    /// it does full format autodetection (`Omnib.autodec()` functionality as failover)
    ///
    /// Args:  
    ///     obtext: The encrypted+encoded string to decode+decrypt.
    ///
    /// Returns:  
    ///     The decoded+decrypted plaintext string.
    ///
    /// Raises:  
    ///     ValueError: If the dec operation fails or format cannot be detected.
    fn autodec(&self, obtext: &str) -> PyResult<String> {
        let result = self.inner.autodec(obtext);
        result.map_err(|e| PyValueError::new_err(format!("Autodec operation failed: {}", e)))
    }

    /// Get the current format string.
    ///
    /// Returns:
    ///     Format string like "aags.b64", "apgs.c32", "aasv.b32", etc.
    #[getter]
    fn format(&self) -> String {
        format!("{}", self.inner.format())
    }

    /// The scheme used by this instance.
    #[getter]
    fn scheme(&self) -> String {
        self.inner.scheme().to_string()
    }

    /// The encoding format used by this instance.
    #[getter]
    fn encoding(&self) -> String {
        self.inner.encoding().to_string()
    }

    /// Get the key used by this instance (as base64 string).
    #[getter]
    fn key(&self) -> String {
        self.inner.key()
    }

    /// Get the key as hex used by this instance.
    #[getter]
    fn key_hex(&self) -> String {
        self.inner.key_hex()
    }

    /// Get the key as bytes used by this instance.
    #[getter]
    fn key_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        Ok(PyBytes::new_bound(py, self.inner.key_bytes()).into())
    }

    /// Change the format (scheme + encoding).  
    ///
    /// Args:  
    ///     format: Format string like "aags.b64", "apsv.hex", "apgs.c32", "aasv.b32", etc.
    ///
    /// Raises:  
    ///     ValueError: If format is invalid.
    fn set_format(&mut self, format: &str) -> PyResult<()> {
        self.inner
            .set_format(format)
            .map_err(|e| PyValueError::new_err(format!("Failed to set format: {}", e)))
    }

    /// Change the scheme while keeping the current encoding.
    ///
    /// Args:  
    ///     scheme: Scheme name like "aags", "apsv", "apgs", etc.  
    ///
    /// Raises:  
    ///     ValueError: If scheme is invalid.
    fn set_scheme(&mut self, scheme: &str) -> PyResult<()> {
        let scheme_enum = ::oboron::Scheme::from_str(scheme)
            .map_err(|e| PyValueError::new_err(format!("Invalid scheme: {}", e)))?;
        self.inner
            .set_scheme(scheme_enum)
            .map_err(|e| PyValueError::new_err(format!("Failed to set scheme: {}", e)))
    }

    /// Change the encoding while keeping the current scheme.
    ///
    /// Args:  
    ///     encoding: Encoding name: "b32", "b64", "c32", "hex".
    ///               Also accepts long forms: "base32rfc", "base64", "base32crockford", or "hex".
    ///
    /// Raises:  
    ///     ValueError: If encoding is invalid.
    fn set_encoding(&mut self, encoding: &str) -> PyResult<()> {
        let encoding_enum = ::oboron::Encoding::from_str(encoding)
            .map_err(|e| PyValueError::new_err(format!("Invalid encoding: {}", e)))?;
        self.inner
            .set_encoding(encoding_enum)
            .map_err(|e| PyValueError::new_err(format!("Failed to set encoding: {}", e)))
    }
}

/// Omnib - Multi-format codec with full autodetection.
///
/// Unlike other codecs, Omnib doesn't store a format internally.
/// The format must be specified for each enc operation, and it can
/// automatically detect both scheme and encoding on dec operations.
#[pyclass]
struct Omnib {
    inner: ::oboron::Omnib,
}

#[pymethods]
impl Omnib {
    /// Create a new Omnib instance.
    ///
    /// Args:
    ///     key:     86-character base64 string key (512 bits).  Required if keyless=False.
    ///     keyless: If True, uses the hardcoded key (testing only, NOT SECURE).
    ///
    /// Returns:
    ///     A new Omnib instance.
    ///
    /// Raises:
    ///     ValueError: If key is invalid.
    #[new]
    #[pyo3(signature = (key=None, keyless=false))]
    fn new(key: Option<String>, keyless: bool) -> PyResult<Self> {
        let inner = match (key, keyless) {
            (Some(key), false) => ::oboron::Omnib::new(&key)
                .map_err(|e| PyValueError::new_err(format!("Failed to create Omnib: {}", e)))?,
            (None, true) => ::oboron::Omnib::new_keyless().map_err(|e| {
                PyValueError::new_err(format!("Failed to create Omnib with hardcoded key: {}", e))
            })?,
            (Some(_), true) => {
                return Err(PyValueError::new_err(
                    "Cannot specify both key and keyless=True",
                ));
            }
            (None, false) => {
                return Err(PyValueError::new_err(
                    "Must provide either key or set keyless=True",
                ));
            }
        };

        Ok(Self { inner })
    }

    /// Ecrypt+encode a plaintext string with a specific format.
    ///
    /// Args:
    ///     plaintext: The plaintext string to encrypt+encode.
    ///     format: Format string like "aags.b64", "apsv.hex", etc.
    ///
    /// Returns:
    ///     The obtext string.
    ///
    /// Raises:
    ///     ValueError: If the enc operation fails or format is invalid.
    fn enc(&self, plaintext: &str, format: &str) -> PyResult<String> {
        let result = self.inner.enc(plaintext, format);
        result.map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
    }

    /// Decode+decrypt an obtext string with a specific format.
    ///
    /// Args:
    ///     obtext: The encrypted+encoded string to decode+decrypt.  
    ///     format: Format string like "aags.b64", "apsv.hex", etc.
    ///
    /// Returns:
    ///     The decoded+decrypted plaintext string.
    ///
    /// Raises:
    ///     ValueError: If the dec operation fails or format is invalid.
    fn dec(&self, obtext: &str, format: &str) -> PyResult<String> {
        let result = self.inner.dec(obtext, format);
        result.map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// This is the only decoder that can automatically detect both the scheme
    /// (aags, apsv, etc.) AND the encoding (b32, b64, c32, hex).
    ///
    /// Args:
    ///     obtext: The encrypted+encoded string to decode+decrypt.
    ///
    /// Returns:
    ///     The decoded+decrypted plaintext string.
    ///
    /// Raises:
    ///     ValueError: If the dec operation fails or format cannot be detected.
    fn autodec(&self, obtext: &str) -> PyResult<String> {
        let result = self.inner.autodec(obtext);
        result.map_err(|e| PyValueError::new_err(format!("Autodec operation failed: {}", e)))
    }

    /// Get the key used by this instance (as base64 string).
    #[getter]
    fn key(&self) -> String {
        self.inner.key()
    }

    /// Get the key as hex used by this instance.
    #[getter]
    fn key_hex(&self) -> String {
        self.inner.key_hex()
    }

    /// Get the key as bytes used by this instance.
    #[getter]
    fn key_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        Ok(PyBytes::new_bound(py, self.inner.key_bytes()).into())
    }
}

// Z-tier schemes - Obz
#[pyclass]
struct Obz {
    inner: ::oboron::ztier::Obz,
}

#[pymethods]
impl Obz {
    /// Create a new Obz instance.
    ///
    /// Args:
    ///     format: Format string like "aags.b64", "apsv.hex", "zrbcx.c32", "zrbcx.b32", etc.
    ///     key:     86-character base64 string key (512 bits). Required if keyless=False.
    ///     keyless: If True, uses the hardcoded key (testing only, NOT SECURE).
    ///
    /// Returns:
    ///     A new Obz instance.
    ///
    /// Raises:
    ///     ValueError: If key or format is invalid.
    #[new]
    #[pyo3(signature = (format, key=None, keyless=false))]
    fn new(format: &str, key: Option<String>, keyless: bool) -> PyResult<Self> {
        let inner = match (key, keyless) {
            (Some(key), false) => ::oboron::ztier::Obz::new(format, &key)
                .map_err(|e| PyValueError::new_err(format!("Failed to create Obz: {}", e)))?,
            (None, true) => ::oboron::ztier::Obz::new_keyless(format).map_err(|e| {
                PyValueError::new_err(format!("Failed to create Obz with hardcoded key: {}", e))
            })?,
            (Some(_), true) => {
                return Err(PyValueError::new_err(
                    "Cannot specify both key and keyless=True",
                ));
            }
            (None, false) => {
                return Err(PyValueError::new_err(
                    "Must provide either key or set keyless=True",
                ));
            }
        };

        Ok(Self { inner })
    }

    /// Encrypt+encode a plaintext string.
    ///
    /// Args:  
    ///     plaintext: The plaintext string to encrypt+encode.
    ///
    /// Returns:  
    ///     The obtext string.
    ///
    /// Raises:  
    ///     ValueError: If encoding fails.
    fn enc(&self, plaintext: &str) -> PyResult<String> {
        let result = self.inner.enc(plaintext);
        result.map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
    }

    /// Decode+decrypt an obtext string back to plaintext.  
    ///
    /// Args:  
    ///     obtext: The encrypted+encoded string to decode.  
    ///
    /// Returns:  
    ///     The decoded plaintext string.
    ///
    /// Raises:  
    ///     ValueError: If the dec operation fails
    #[pyo3(signature = (obtext))]
    fn dec(&self, obtext: &str) -> PyResult<String> {
        let result = self.inner.dec(obtext);
        result.map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// This method tries to decode with the instance's encoding, and if that fails
    /// it does full format autodetection (`Omnib.autodec()` functionality as failover)
    ///
    /// Args:  
    ///     obtext: The encrypted+encoded string to decode+decrypt.
    ///
    /// Returns:  
    ///     The decoded+decrypted plaintext string.
    ///
    /// Raises:  
    ///     ValueError: If the dec operation fails or format cannot be detected.
    fn autodec(&self, obtext: &str) -> PyResult<String> {
        let result = self.inner.autodec(obtext);
        result.map_err(|e| PyValueError::new_err(format!("Autodec operation failed: {}", e)))
    }

    /// Get the current format string.
    ///
    /// Returns:
    ///     Format string like "zrbcx.hex", "zrbcx.c32", "zrbcx.b32", etc.
    #[getter]
    fn format(&self) -> String {
        format!("{}", self.inner.format())
    }

    /// The scheme used by this instance.
    #[getter]
    fn scheme(&self) -> String {
        self.inner.scheme().to_string()
    }

    /// The encoding format used by this instance.
    #[getter]
    fn encoding(&self) -> String {
        self.inner.encoding().to_string()
    }

    /// Get the secret used by this instance (as base64 string).
    #[getter]
    fn secret(&self) -> String {
        self.inner.secret()
    }

    /// Get the secret as hex used by this instance.
    #[getter]
    fn secret_hex(&self) -> String {
        self.inner.secret_hex()
    }

    /// Get the secret as bytes used by this instance.
    #[getter]
    fn secret_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        Ok(PyBytes::new_bound(py, self.inner.secret_bytes()).into())
    }

    /// Change the format (scheme + encoding).  
    ///
    /// Args:  
    ///     format: Format string like "zrbcx.b64", "zrbcx.hex", "zrbcx.c32", "zrbcx.b32", etc.
    ///
    /// Raises:  
    ///     ValueError: If format is invalid.
    fn set_format(&mut self, format: &str) -> PyResult<()> {
        self.inner
            .set_format(format)
            .map_err(|e| PyValueError::new_err(format!("Failed to set format: {}", e)))
    }

    /// Change the scheme while keeping the current encoding.
    ///
    /// Args:  
    ///     scheme: Scheme name like "zrbcx", "zmock1", etc.  
    ///
    /// Raises:  
    ///     ValueError: If scheme is invalid.
    fn set_scheme(&mut self, scheme: &str) -> PyResult<()> {
        let scheme_enum = ::oboron::Scheme::from_str(scheme)
            .map_err(|e| PyValueError::new_err(format!("Invalid scheme: {}", e)))?;
        self.inner
            .set_scheme(scheme_enum)
            .map_err(|e| PyValueError::new_err(format!("Failed to set scheme: {}", e)))
    }

    /// Change the encoding while keeping the current scheme.
    ///
    /// Args:  
    ///     encoding: Encoding name: "b32", "b64", "c32", "hex".
    ///               Also accepts long forms: "base32rfc", "base64", "base32crockford", or "hex".
    ///
    /// Raises:  
    ///     ValueError: If encoding is invalid.
    fn set_encoding(&mut self, encoding: &str) -> PyResult<()> {
        let encoding_enum = ::oboron::Encoding::from_str(encoding)
            .map_err(|e| PyValueError::new_err(format!("Invalid encoding: {}", e)))?;
        self.inner
            .set_encoding(encoding_enum)
            .map_err(|e| PyValueError::new_err(format!("Failed to set encoding: {}", e)))
    }
}

// Z-tier schemes - Omnibz
#[pyclass]
struct Omnibz {
    inner: ::oboron::ztier::Omnibz,
}

#[pymethods]
impl Omnibz {
    /// Create a new Omnibz instance.
    ///
    /// Args:
    ///     secret:     43-character base64 string key (256 bits).  Required if keyless=False.
    ///     keyless: If True, uses the hardcoded secret (testing only, NOT SECURE).
    ///
    /// Returns:
    ///     A new Omnibz instance.
    ///
    /// Raises:
    ///     ValueError: If secret is invalid.
    #[new]
    #[pyo3(signature = (secret=None, keyless=false))]
    fn new(secret: Option<String>, keyless: bool) -> PyResult<Self> {
        let inner = match (secret, keyless) {
            (Some(secret), false) => ::oboron::ztier::Omnibz::new(&secret)
                .map_err(|e| PyValueError::new_err(format!("Failed to create Omnibz: {}", e)))?,
            (None, true) => ::oboron::ztier::Omnibz::new_keyless().map_err(|e| {
                PyValueError::new_err(format!(
                    "Failed to create Omnibz with hardcoded secret: {}",
                    e
                ))
            })?,
            (Some(_), true) => {
                return Err(PyValueError::new_err(
                    "Cannot specify both secret and keyless=True",
                ));
            }
            (None, false) => {
                return Err(PyValueError::new_err(
                    "Must provide either secret or set keyless=True",
                ));
            }
        };

        Ok(Self { inner })
    }

    /// Ecrypt+encode a plaintext string with a specific format.
    ///
    /// Args:
    ///     plaintext: The plaintext string to encrypt+encode.
    ///     format: Format string like "zrbcx.c32", "zrbcx.b32", etc.
    ///
    /// Returns:
    ///     The obtext string.
    ///
    /// Raises:
    ///     ValueError: If the enc operation fails or format is invalid.
    fn enc(&self, plaintext: &str, format: &str) -> PyResult<String> {
        let result = self.inner.enc(plaintext, format);
        result.map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
    }

    /// Decode+decrypt an obtext string with a specific format.
    ///
    /// Args:
    ///     obtext: The encrypted+encoded string to decode+decrypt.  
    ///     format: Format string like "zrbcx.c32", "zrbcx.b32", etc.
    ///
    /// Returns:
    ///     The decoded+decrypted plaintext string.
    ///
    /// Raises:
    ///     ValueError: If the dec operation fails or format is invalid.
    fn dec(&self, obtext: &str, format: &str) -> PyResult<String> {
        let result = self.inner.dec(obtext, format);
        result.map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// This is the only decoder that can automatically detect both the scheme
    /// (zrbcx, zmock1, etc.) AND the encoding (b32, b64, c32, hex).
    ///
    /// Args:
    ///     obtext: The encrypted+encoded string to decode+decrypt.
    ///
    /// Returns:
    ///     The decoded+decrypted plaintext string.
    ///
    /// Raises:
    ///     ValueError: If the dec operation fails or format cannot be detected.
    fn autodec(&self, obtext: &str) -> PyResult<String> {
        let result = self.inner.autodec(obtext);
        result.map_err(|e| PyValueError::new_err(format!("Autodec operation failed: {}", e)))
    }

    /// Get the secret used by this instance (as base64 string).
    fn secret(&self) -> String {
        self.inner.secret()
    }

    /// Get the secret as hex used by this instance.
    fn secret_hex(&self) -> String {
        self.inner.secret_hex()
    }

    /// Get the key as bytes used by this instance.
    fn secret_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        Ok(PyBytes::new_bound(py, self.inner.secret_bytes()).into())
    }
}

/// Generate a random 64-byte key as a base64 string.
///
/// Returns:
///     A random 64-byte key as a 86-character base64 string.
#[pyfunction]
fn generate_key() -> PyResult<String> {
    Ok(::oboron::generate_key())
}

/// Generate a random 64-byte key as a hex string.
///
/// Returns:
///     A random 64-byte key as a 128-character hex string.
#[pyfunction]
fn generate_key_hex() -> PyResult<String> {
    Ok(::oboron::generate_key_hex())
}

/// Generate a random 64-byte key as bytes.
///
/// Returns:
///     A random 64-byte key as bytes.
#[pyfunction]
fn generate_key_bytes(py: Python) -> PyResult<Py<PyBytes>> {
    let key = ::oboron::generate_key_bytes();
    Ok(PyBytes::new_bound(py, &key).into())
}

/// Generate a random 32-byte secret as a base64 string.
///
/// Returns:
///     A random 64-byte key as a 43-character base64 string.
#[pyfunction]
fn generate_secret() -> PyResult<String> {
    Ok(::oboron::generate_secret())
}

/// Generate a random 32-byte secret as a hex string.
///
/// Returns:
///     A random 32-byte key as a 64-character hex string.
#[pyfunction]
fn generate_secret_hex() -> PyResult<String> {
    Ok(::oboron::generate_secret_hex())
}

/// Generate a random 32-byte secret as bytes.
///
/// Returns:
///     A random 32-byte secret as bytes.
#[pyfunction]
fn generate_secret_bytes(py: Python) -> PyResult<Py<PyBytes>> {
    let secret = ::oboron::generate_secret_bytes();
    Ok(PyBytes::new_bound(py, &secret).into())
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Encrypt+encode plaintext with a specified format.
///
/// Args:
///     plaintext: The plaintext string to encode.
///     format: Format string like "aags.b64", "apsv.hex", "zrbcx.b32", etc.
///     key:     86-character base64 string key (512 bits).
///
/// Returns:
///     The obtext string.
///
/// Raises:
///     ValueError: If the enc operation fails.
#[pyfunction]
fn enc(plaintext: &str, format: &str, key: &str) -> PyResult<String> {
    ::oboron::enc(plaintext, format, key)
        .map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
}

/// Encrypt+encode plaintext with a specified format using the hardcoded key (testing only).
///
/// Args:
///     plaintext: The plaintext string to encrypt+encode.
///     format: Format string like "aags.b64", "apsv.hex", "zrbcx.b32", etc.
///
/// Returns:
///     The obtext string.
///
/// Raises:
///     ValueError: If the enc operation fails.
#[pyfunction]
#[cfg(feature = "keyless")]
fn enc_keyless(plaintext: &str, format: &str) -> PyResult<String> {
    ::oboron::enc_keyless(plaintext, format)
        .map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
}

/// Decode+decrypt obtext with a specified format.
///
/// Args:
///     obtext: The encrypted+encoded string to decode+decrypt  
///     format: Format string like "zrbcx.b32", "aags.b64", "apsv.hex", etc.  
///     key:    86-character base64 string key (512 bits).
///
/// Returns:
///     The decoded+decrypted plaintext string.
///
/// Raises:
///     ValueError: If the dec operation fails.
#[pyfunction]
fn dec(obtext: &str, format: &str, key: &str) -> PyResult<String> {
    ::oboron::dec(obtext, format, key)
        .map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
}

/// Decode+decrypt obtext with a specified format using the hardcoded key (testing only).
///
/// Args:
///     obtext: The encrypted+encoded string to decode+decrypt.  
///     format: Format string like "aags.b64", "apsv.hex", "zrbcx.b32", etc.
///
/// Returns:
///     The decoded+decrypted plaintext string.
///
/// Raises:
///     ValueError: If the dec operation fails.
#[pyfunction]
#[cfg(feature = "keyless")]
fn dec_keyless(obtext: &str, format: &str) -> PyResult<String> {
    ::oboron::dec_keyless(obtext, format)
        .map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
}

/// Decode+decrypt obtext with automatic format detection.
///
/// Args:
///     obtext: The encrypted+encoded string to decode+decrypt.
///     key:    86-character base64 string key (512 bits).
///
/// Returns:
///     The decoded+decrypted plaintext string.
///
/// Raises:
///     ValueError: If the dec operation fails.
#[pyfunction]
fn autodec(obtext: &str, key: &str) -> PyResult<String> {
    ::oboron::autodec(obtext, key)
        .map_err(|e| PyValueError::new_err(format!("Autodec operation failed: {}", e)))
}

/// Decode+decrypt obtext with automatic format detection using the hardcoded key (testing only).
///
/// Args:
///     obtext: The encrypted+encoded string to decode+decrypt.
///
/// Returns:
///     The decoded+decrypted plaintext string.
///
/// Raises:
///     ValueError: If the autodec operation fails.
#[pyfunction]
#[cfg(feature = "keyless")]
fn autodec_keyless(obtext: &str) -> PyResult<String> {
    ::oboron::autodec_keyless(obtext)
        .map_err(|e| PyValueError::new_err(format!("Autodec operation failed: {}", e)))
}

/// Python module for Oboron (internal Rust extension)
#[pymodule]
fn _oboron(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Add version from Cargo.toml
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Main flexible interface
    m.add_class::<Ob>()?;

    // Multi-format interface
    m.add_class::<Omnib>()?;

    // Aags variants
    #[cfg(feature = "aags")]
    {
        m.add_class::<AagsC32>()?;
        m.add_class::<AagsB32>()?;
        m.add_class::<AagsB64>()?;
        m.add_class::<AagsHex>()?;
    }

    // Apgs variants
    #[cfg(feature = "apgs")]
    {
        m.add_class::<ApgsC32>()?;
        m.add_class::<ApgsB32>()?;
        m.add_class::<ApgsB64>()?;
        m.add_class::<ApgsHex>()?;
    }

    // Aasv variants
    #[cfg(feature = "aasv")]
    {
        m.add_class::<AasvC32>()?;
        m.add_class::<AasvB32>()?;
        m.add_class::<AasvB64>()?;
        m.add_class::<AasvHex>()?;
    }

    // Apsv variants
    #[cfg(feature = "apsv")]
    {
        m.add_class::<ApsvC32>()?;
        m.add_class::<ApsvB32>()?;
        m.add_class::<ApsvB64>()?;
        m.add_class::<ApsvHex>()?;
    }

    // Upbc variants
    #[cfg(feature = "upbc")]
    {
        m.add_class::<UpbcC32>()?;
        m.add_class::<UpbcB32>()?;
        m.add_class::<UpbcB64>()?;
        m.add_class::<UpbcHex>()?;
    }

    // TESTING =======================

    // Mock variants
    #[cfg(feature = "mock")]
    {
        // Mock1 variants
        m.add_class::<Mock1C32>()?;
        m.add_class::<Mock1B32>()?;
        m.add_class::<Mock1B64>()?;
        m.add_class::<Mock1Hex>()?;
        // Mock2 variants
        m.add_class::<Mock2C32>()?;
        m.add_class::<Mock2B32>()?;
        m.add_class::<Mock2B64>()?;
        m.add_class::<Mock2Hex>()?;
    }

    // Z-TIER =========================
    //
    // Main flexible interface
    m.add_class::<Obz>()?;

    // Multi-format interface
    m.add_class::<Omnibz>()?;

    // Zrbcx variants
    #[cfg(feature = "zrbcx")]
    {
        m.add_class::<ZrbcxC32>()?;
        m.add_class::<ZrbcxB32>()?;
        m.add_class::<ZrbcxB64>()?;
        m.add_class::<ZrbcxHex>()?;
    }

    // Zmock variants
    #[cfg(feature = "zmock")]
    {
        // Zmock1 variants
        m.add_class::<Zmock1C32>()?;
        m.add_class::<Zmock1B32>()?;
        m.add_class::<Zmock1B64>()?;
        m.add_class::<Zmock1Hex>()?;
    }

    // Legacy variants
    #[cfg(feature = "legacy")]
    {
        m.add_class::<LegacyC32>()?;
        m.add_class::<LegacyB32>()?;
        m.add_class::<LegacyB64>()?;
        m.add_class::<LegacyHex>()?;
    }

    // Functions =====================

    // Utility functions
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_hex, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(generate_secret, m)?)?;
    m.add_function(wrap_pyfunction!(generate_secret_hex, m)?)?;
    m.add_function(wrap_pyfunction!(generate_secret_bytes, m)?)?;

    // Convenience functions
    m.add_function(wrap_pyfunction!(enc, m)?)?;
    #[cfg(feature = "keyless")]
    m.add_function(wrap_pyfunction!(enc_keyless, m)?)?;
    m.add_function(wrap_pyfunction!(dec, m)?)?;
    #[cfg(feature = "keyless")]
    m.add_function(wrap_pyfunction!(dec_keyless, m)?)?;
    m.add_function(wrap_pyfunction!(autodec, m)?)?;
    #[cfg(feature = "keyless")]
    m.add_function(wrap_pyfunction!(autodec_keyless, m)?)?;

    Ok(())
}
