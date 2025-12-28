use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Macro to generate Python wrapper classes for fixed-format ObtextCodec ciphers
macro_rules! impl_cipher_class {
    ($py_name:ident, $rust_type:ty, $doc:expr) => {
        #[doc = $doc]
        #[pyclass]
        #[allow(non_camel_case_types)]
        struct $py_name {
            inner: $rust_type,
        }

        #[pymethods]
        impl $py_name {
            /// Create a new cipher instance.
            ///
            /// Args:
            ///     key:     86-character base64 string key (512 bits).  Required if keyless=False.
            ///     keyless: If True, uses the hardcoded key (testing only, NOT SECURE).
            ///
            /// Returns:
            ///     A new cipher instance.
            ///
            /// Raises:
            ///     ValueError: If key is invalid or both key and keyless are provided.
            #[new]
            #[pyo3(signature = (key=None, keyless=false))]
            fn new(key: Option<String>, keyless: bool) -> PyResult<Self> {
                let inner = match (key, keyless) {
                    (Some(key), false) => <$rust_type>::new(&key).map_err(|e| {
                        PyValueError::new_err(format!("Failed to create cipher: {}", e))
                    })?,
                    (None, true) => <$rust_type>::new_keyless().map_err(|e| {
                        PyValueError::new_err(format!(
                            "Failed to create cipher with hardcoded key: {}",
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
                self.inner
                    .enc(plaintext)
                    .map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
            }

            /// Decode+decrypt an obtext string back to plaintext.
            ///
            /// Args:
            ///     obtext: The encrypted+encoded string to decode+decrypt.
            ///     strict: If True, only decrypt using this instance's scheme (no scheme autodetection).
            ///             If False (default), automatically detects the scheme used for
            ///             encryption.
            ///
            /// Returns:
            ///     The decoded+decrypted plaintext string.
            ///
            /// Raises:
            ///     ValueError: If the dec operation fails, or if strict=True and the ciphertext
            ///                 was created with a different scheme.
            #[pyo3(signature = (obtext, strict=false))]
            fn dec(&self, obtext: &str, strict: bool) -> PyResult<String> {
                let result = if strict {
                    self.inner.dec_strict(obtext)
                } else {
                    self.inner.dec(obtext)
                };
                result.map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
            }

            /// Get the key used by this instance (as base64 string).
            #[getter]
            fn key(&self) -> String {
                self.inner.key()
            }

            /// Get the key as bytes used by this instance.
            #[getter]
            fn key_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
                Ok(PyBytes::new_bound(py, self.inner.key_bytes()).into())
            }

            /// The scheme used by this instance.
            #[getter]
            fn scheme(&self) -> String {
                self.inner.scheme().as_str().to_string()
            }

            /// The encoding format used by this instance.
            #[getter]
            fn encoding(&self) -> String {
                self.inner.encoding().as_str().to_string()
            }

            /// Get the current format string.
            ///
            /// Returns:
            ///     Format string like "zrbcx.c32", "zrbcx.b32", "aags.b64", etc.
            #[getter]
            fn format(&self) -> String {
                format!("{}", self.inner.format())
            }
        }
    };
}

// Aags variants
// -------------
#[cfg(feature = "aags")]
impl_cipher_class!(
    AagsB32,
    ::oboron::AagsB32,
    "Aags cipher (deterministic AES-GCM-SIV) with B32 encoding "
);
#[cfg(feature = "aags")]
impl_cipher_class!(
    AagsB64,
    ::oboron::AagsB64,
    "Aags cipher (deterministic AES-GCM-SIV) with B64 encoding"
);
#[cfg(feature = "aags")]
impl_cipher_class!(
    AagsC32,
    ::oboron::AagsC32,
    "Aags cipher (deterministic AES-GCM-SIV) with C32 encoding"
);
#[cfg(feature = "aags")]
impl_cipher_class!(
    AagsHex,
    ::oboron::AagsHex,
    "Aags cipher (deterministic AES-GCM-SIV) with Hex encoding"
);

// Aasv variants
// -------------
#[cfg(feature = "aasv")]
impl_cipher_class!(
    AasvB32,
    ::oboron::AasvB32,
    "Aasv cipher (deterministic AES-SIV, nonce-misuse resistant) with B32 encoding"
);
#[cfg(feature = "aasv")]
impl_cipher_class!(
    AasvB64,
    ::oboron::AasvB64,
    "Aasv cipher (deterministic AES-SIV, nonce-misuse resistant) with B64 encoding"
);
#[cfg(feature = "aasv")]
impl_cipher_class!(
    AasvC32,
    ::oboron::AasvC32,
    "Aasv cipher (deterministic AES-SIV, nonce-misuse resistant) with C32 encoding"
);
#[cfg(feature = "aasv")]
impl_cipher_class!(
    AasvHex,
    ::oboron::AasvHex,
    "Aasv cipher (deterministic AES-SIV, nonce-misuse resistant) with Hex encoding"
);

// Apgs variants
// --------------
#[cfg(feature = "apgs")]
impl_cipher_class!(
    ApgsB32,
    ::oboron::ApgsB32,
    "Apgs cipher (probabilistic AES-GCM-SIV) with B32 encoding"
);
#[cfg(feature = "apgs")]
impl_cipher_class!(
    ApgsB64,
    ::oboron::ApgsB64,
    "Apgs cipher (probabilistic AES-GCM-SIV) with B64 encoding"
);
#[cfg(feature = "apgs")]
impl_cipher_class!(
    ApgsC32,
    ::oboron::ApgsC32,
    "Apgs cipher (probabilistic AES-GCM-SIV) with C32 encoding"
);
#[cfg(feature = "apgs")]
impl_cipher_class!(
    ApgsHex,
    ::oboron::ApgsHex,
    "Apgs cipher (probabilistic AES-GCM-SIV) with Hex encoding"
);

// Apsv variants
// --------------
#[cfg(feature = "apsv")]
impl_cipher_class!(
    ApsvB32,
    ::oboron::ApsvB32,
    "Apsv cipher (probabilistic AES-SIV) with B32 encoding"
);
#[cfg(feature = "apsv")]
impl_cipher_class!(
    ApsvB64,
    ::oboron::ApsvB64,
    "Apsv cipher (probabilistic AES-SIV) with B64 encoding"
);
#[cfg(feature = "apsv")]
impl_cipher_class!(
    ApsvC32,
    ::oboron::ApsvC32,
    "Apsv cipher (probabilistic AES-SIV) with C32 encoding"
);
#[cfg(feature = "apsv")]
impl_cipher_class!(
    ApsvHex,
    ::oboron::ApsvHex,
    "Apsv cipher (probabilistic AES-SIV) with Hex encoding"
);

// Upbc variants
// ------------
#[cfg(feature = "upbc")]
impl_cipher_class!(
    UpbcB32,
    ::oboron::UpbcB32,
    "Upbc cipher (probabilistic AES-CBC) with B32 encoding"
);
#[cfg(feature = "upbc")]
impl_cipher_class!(
    UpbcB64,
    ::oboron::UpbcB64,
    "Upbc cipher (probabilistic AES-CBC) with B64 encoding"
);
#[cfg(feature = "upbc")]
impl_cipher_class!(
    UpbcC32,
    ::oboron::UpbcC32,
    "Upbc cipher (probabilistic AES-CBC) with C32 encoding"
);
#[cfg(feature = "upbc")]
impl_cipher_class!(
    UpbcHex,
    ::oboron::UpbcHex,
    "Upbc cipher (probabilistic AES-CBC) with Hex encoding"
);

// Zrbcx variants
// -------------
#[cfg(feature = "zrbcx")]
impl_cipher_class!(
    ZrbcxB32,
    ::oboron::ZrbcxB32,
    "Zrbcx cipher (deterministic AES-CBC, constant IV) with B32 encoding "
);
#[cfg(feature = "zrbcx")]
impl_cipher_class!(
    ZrbcxB64,
    ::oboron::ZrbcxB64,
    "Zrbcx cipher (deterministic AES-CBC, constant IV) with B64 encoding"
);
#[cfg(feature = "zrbcx")]
impl_cipher_class!(
    ZrbcxC32,
    ::oboron::ZrbcxC32,
    "Zrbcx cipher (deterministic AES-CBC, constant IV) with C32 encoding"
);
#[cfg(feature = "zrbcx")]
impl_cipher_class!(
    ZrbcxHex,
    ::oboron::ZrbcxHex,
    "Zrbcx cipher (deterministic AES-CBC, constant IV) with Hex encoding"
);

// --- TESTING CLASSES ---

// Mock1 variants
// -------------
impl_cipher_class!(
    Mock1B32,
    ::oboron::Mock1B32,
    "Mock1 cipher (identity scheme, for testing) with B32 encoding"
);
impl_cipher_class!(
    Mock1B64,
    ::oboron::Mock1B64,
    "Mock1 cipher (identity scheme, for testing) with B64 encoding"
);
impl_cipher_class!(
    Mock1C32,
    ::oboron::Mock1C32,
    "Mock1 cipher (identity scheme, for testing) with C32 encoding"
);
impl_cipher_class!(
    Mock1Hex,
    ::oboron::Mock1Hex,
    "Mock1 cipher (identity scheme, for testing) with Hex encoding"
);

// Mock2 variants
// -------------
impl_cipher_class!(
    Mock2B32,
    ::oboron::Mock2B32,
    "Mock2 cipher (reverse plaintext scheme, for testing) with B32 encoding"
);
impl_cipher_class!(
    Mock2B64,
    ::oboron::Mock2B64,
    "Mock2 cipher (reverse plaintext scheme, for testing) with B64 encoding"
);
impl_cipher_class!(
    Mock2C32,
    ::oboron::Mock2C32,
    "Mock2 cipher (reverse plaintext scheme, for testing) with C32 encoding"
);
impl_cipher_class!(
    Mock2Hex,
    ::oboron::Mock2Hex,
    "Mock2 cipher (reverse plaintext scheme, for testing) with Hex encoding"
);

// Legacy - LEGACY variants
// ----------------------
#[cfg(feature = "legacy")]
impl_cipher_class!(
    LegacyB32,
    ::oboron::LegacyB32,
    "Legacy cipher (deterministic AES-CBC, constant IV, custom padding) with B32 encoding\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zrbcx or more secure schemes like Aags/Aasv."
);
#[cfg(feature = "legacy")]
impl_cipher_class!(
    LegacyB64,
    ::oboron::LegacyB64,
    "Legacy cipher (deterministic AES-CBC, constant IV, custom padding) with B64 encoding\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zrbcx or more secure schemes like Aags/Aasv."
);
#[cfg(feature = "legacy")]
impl_cipher_class!(
    LegacyC32,
    ::oboron::LegacyC32,
    "Legacy cipher (deterministic AES-CBC, constant IV, custom padding) with C32 encoding\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zrbcx or more secure schemes like Aags/Aasv."
);
#[cfg(feature = "legacy")]
impl_cipher_class!(
    LegacyHex,
    ::oboron::LegacyHex,
    "Legacy cipher (deterministic AES-CBC, constant IV, custom padding) with Hex encoding\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zrbcx or more secure schemes like Aags/Aasv."
);

/// Ob - Flexible cipher with runtime format selection.   
///
/// This is the main interface for most use cases.  It wraps Rust's ObFlex
/// and allows changing the format (scheme + encoding) at runtime.
///
/// Note: In Rust, there's both Ob (immutable) and ObFlex (mutable), but since
/// Python doesn't have immutability, we expose ObFlex as "Ob" in Python.
#[pyclass]
struct Ob {
    inner: ::oboron::ObFlex,
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
            (Some(key), false) => ::oboron::ObFlex::new(format, &key)
                .map_err(|e| PyValueError::new_err(format!("Failed to create Ob: {}", e)))?,
            (None, true) => ::oboron::ObFlex::new_keyless(format).map_err(|e| {
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
        self.inner
            .enc(plaintext)
            .map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
    }

    /// Decode+decrypt an obtext string back to plaintext.  
    ///
    /// Args:
    ///     obtext: The encrypted+encoded string to decode.
    ///     strict: If True, only decrypt using this instance's scheme (no scheme autodetection).  
    ///             If False (default), automatically detects the scheme used for encryption.  
    ///
    /// Returns:
    ///     The decoded plaintext string.
    ///
    /// Raises:
    ///     ValueError: If the dec operation fails, or if strict=True and the obtext
    ///                 was created with a different scheme.  
    #[pyo3(signature = (obtext, strict=false))]
    fn dec(&self, obtext: &str, strict: bool) -> PyResult<String> {
        let result = if strict {
            self.inner.dec_strict(obtext)
        } else {
            self.inner.dec(obtext)
        };
        result.map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
    }

    /// Change the format (scheme + encoding).   
    ///
    /// Args:
    ///     format: Format string like "aags.b64", "apsv.hex", "zrbcx.c32", "zrbcx.b32", etc.
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
    ///     scheme: Scheme name like "aags", "apsv", "zrbcx", etc.  
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

    /// Get the current format string.
    ///
    /// Returns:
    ///     Format string like "aags.b64", "zrbcx.c32", "zrbcx.b32", etc.
    #[getter]
    fn format(&self) -> String {
        format!("{}", self.inner.format())
    }

    /// Get the key used by this instance (as base64 string).
    #[getter]
    fn key(&self) -> String {
        self.inner.key()
    }

    /// Get the key as bytes used by this instance.
    #[getter]
    fn key_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        Ok(PyBytes::new_bound(py, self.inner.key_bytes()).into())
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
}

/// ObMulti - Multi-format cipher with full autodetection.
///
/// Unlike other ciphers, ObMulti doesn't store a format internally.
/// The format must be specified for each enc operation, and it can
/// automatically detect both scheme and encoding on dec operations.
#[pyclass]
struct ObMulti {
    inner: ::oboron::ObMulti,
}

#[pymethods]
impl ObMulti {
    /// Create a new ObMulti instance.
    ///
    /// Args:
    ///     key:     86-character base64 string key (512 bits).  Required if keyless=False.
    ///     keyless: If True, uses the hardcoded key (testing only, NOT SECURE).
    ///
    /// Returns:
    ///     A new ObMulti instance.
    ///
    /// Raises:
    ///     ValueError: If key is invalid.
    #[new]
    #[pyo3(signature = (key=None, keyless=false))]
    fn new(key: Option<String>, keyless: bool) -> PyResult<Self> {
        let inner = match (key, keyless) {
            (Some(key), false) => ::oboron::ObMulti::new(&key)
                .map_err(|e| PyValueError::new_err(format!("Failed to create ObMulti: {}", e)))?,
            (None, true) => ::oboron::ObMulti::new_keyless().map_err(|e| {
                PyValueError::new_err(format!(
                    "Failed to create ObMulti with hardcoded key: {}",
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

    /// Ecrypt+encode a plaintext string with a specific format.
    ///
    /// Args:
    ///     plaintext: The plaintext string to encrypt+encode.
    ///     format: Format string like "aags.b64", "apsv.hex", "zrbcx.c32", "zrbcx.b32", etc.
    ///
    /// Returns:
    ///     The obtext string.
    ///
    /// Raises:
    ///     ValueError: If the enc operation fails or format is invalid.
    fn enc(&self, plaintext: &str, format: &str) -> PyResult<String> {
        self.inner
            .enc_with_format_str(plaintext, format)
            .map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
    }

    /// Decode+decrypt an obtext string with a specific format.
    ///
    /// Args:
    ///     obtext: The encrypted+encoded string to decode+decrypt.  
    ///     format: Format string like "aags.b64", "apsv.hex", "zrbcx.c32", "zrbcx.b32", etc.
    ///
    /// Returns:
    ///     The decoded+decrypted plaintext string.
    ///
    /// Raises:
    ///     ValueError: If the dec operation fails or format is invalid.
    fn dec(&self, obtext: &str, format: &str) -> PyResult<String> {
        self.inner
            .dec_with_format_str(obtext, format)
            .map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// This is the only decoder that can automatically detect both the scheme
    /// (aags, zrbcx, etc.) AND the encoding (b32, b64, c32, hex).
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
        self.inner
            .autodec(obtext)
            .map_err(|e| PyValueError::new_err(format!("Autodec operation failed: {}", e)))
    }

    /// Get the key used by this instance (as base64 string).
    #[getter]
    fn key(&self) -> String {
        self.inner.key()
    }

    /// Get the key as bytes used by this instance.
    #[getter]
    fn key_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        Ok(PyBytes::new_bound(py, self.inner.key_bytes()).into())
    }
}

/// Generate a random 64-byte key as a hex string.
///
/// Returns:
///     A random 64-byte key as a 128-character hex string.
#[pyfunction]
fn generate_key() -> PyResult<String> {
    Ok(::oboron::generate_key())
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
    m.add_class::<ObMulti>()?;

    // Legacy variants (LEGACY)
    #[cfg(feature = "legacy")]
    {
        m.add_class::<LegacyC32>()?;
        m.add_class::<LegacyB32>()?;
        m.add_class::<LegacyB64>()?;
        m.add_class::<LegacyHex>()?;
    }

    // Zrbcx variants
    #[cfg(feature = "zrbcx")]
    {
        m.add_class::<ZrbcxC32>()?;
        m.add_class::<ZrbcxB32>()?;
        m.add_class::<ZrbcxB64>()?;
        m.add_class::<ZrbcxHex>()?;
    }

    // Upbc variants
    #[cfg(feature = "upbc")]
    {
        m.add_class::<UpbcC32>()?;
        m.add_class::<UpbcB32>()?;
        m.add_class::<UpbcB64>()?;
        m.add_class::<UpbcHex>()?;
    }

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

    // Mock variants
    #[cfg(feature = "mock")]
    {
        // Mock2 variants
        m.add_class::<Mock2C32>()?;
        m.add_class::<Mock2B32>()?;
        m.add_class::<Mock2B64>()?;
        m.add_class::<Mock2Hex>()?;

        // Mock1 variants
        m.add_class::<Mock1C32>()?;
        m.add_class::<Mock1B32>()?;
        m.add_class::<Mock1B64>()?;
        m.add_class::<Mock1Hex>()?;
    }

    // Utility functions
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_bytes, m)?)?;

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
