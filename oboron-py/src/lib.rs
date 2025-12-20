use ::oboron::Oboron;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Macro to generate Python wrapper classes for Oboron schemes with specific encoding
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
            ///     key:     86-character base64 string key (512 bits).  Optional if keyless=True.
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
                self.inner.encoding().as_short_str().to_string()
            }

            /// Get the current format string.
            ///
            /// Returns:
            ///     Format string like "zdc:c32", "zdc:b32", "adgs:b64", etc.
            #[getter]
            fn format(&self) -> String {
                format!("{}", self.inner.format())
            }
        }
    };
}

// Zdc variants
// -------------
#[cfg(feature = "zdc")]
impl_cipher_class!(
    ZdcC32,
    ::oboron::ZdcC32,
    "Zdc cipher with Base32Crockford encoding (AES-CBC, deterministic)"
);
#[cfg(feature = "zdc")]
impl_cipher_class!(
    ZdcB32,
    ::oboron::ZdcB32,
    "Zdc cipher with Base32Rfc encoding (AES-CBC, deterministic)"
);
#[cfg(feature = "zdc")]
impl_cipher_class!(
    ZdcB64,
    ::oboron::ZdcB64,
    "Zdc cipher with Base64 encoding (AES-CBC, deterministic)"
);
#[cfg(feature = "zdc")]
impl_cipher_class!(
    ZdcHex,
    ::oboron::ZdcHex,
    "Zdc cipher with Hex encoding (AES-CBC, deterministic)"
);

// Upc variants
// --------------
#[cfg(feature = "upc")]
impl_cipher_class!(
    UpcC32,
    ::oboron::UpcC32,
    "Upc cipher with Base32Crockford encoding (Probabilistic AES-CBC)"
);
#[cfg(feature = "upc")]
impl_cipher_class!(
    UpcB32,
    ::oboron::UpcB32,
    "Upc cipher with Base32Rfc encoding (Probabilistic AES-CBC)"
);
#[cfg(feature = "upc")]
impl_cipher_class!(
    UpcB64,
    ::oboron::UpcB64,
    "Upc cipher with Base64 encoding (Probabilistic AES-CBC)"
);
#[cfg(feature = "upc")]
impl_cipher_class!(
    UpcHex,
    ::oboron::UpcHex,
    "Upc cipher with Hex encoding (Probabilistic AES-CBC)"
);

// Adgs variants
// -------------
#[cfg(feature = "adgs")]
impl_cipher_class!(
    AdgsC32,
    ::oboron::AdgsC32,
    "Adgs cipher with Base32Crockford encoding (AES-GCM-SIV, deterministic)"
);
#[cfg(feature = "adgs")]
impl_cipher_class!(
    AdgsB32,
    ::oboron::AdgsB32,
    "Adgs cipher with Base32Rfc encoding (AES-GCM-SIV, deterministic)"
);
#[cfg(feature = "adgs")]
impl_cipher_class!(
    AdgsB64,
    ::oboron::AdgsB64,
    "Adgs cipher with Base64 encoding (AES-GCM-SIV, deterministic)"
);
#[cfg(feature = "adgs")]
impl_cipher_class!(
    AdgsHex,
    ::oboron::AdgsHex,
    "Adgs cipher with Hex encoding (AES-GCM-SIV, deterministic)"
);

// Apgs variants
// --------------
#[cfg(feature = "apgs")]
impl_cipher_class!(
    ApgsC32,
    ::oboron::ApgsC32,
    "Apgs cipher with Base32Crockford encoding (Probabilistic AES-GCM-SIV)"
);
#[cfg(feature = "apgs")]
impl_cipher_class!(
    ApgsB32,
    ::oboron::ApgsB32,
    "Apgs cipher with Base32Rfc encoding (Probabilistic AES-GCM-SIV)"
);
#[cfg(feature = "apgs")]
impl_cipher_class!(
    ApgsB64,
    ::oboron::ApgsB64,
    "Apgs cipher with Base64 encoding (Probabilistic AES-GCM-SIV)"
);
#[cfg(feature = "apgs")]
impl_cipher_class!(
    ApgsHex,
    ::oboron::ApgsHex,
    "Apgs cipher with Hex encoding (Probabilistic AES-GCM-SIV)"
);

// Adsv variants
// -------------
#[cfg(feature = "adsv")]
impl_cipher_class!(
    AdsvC32,
    ::oboron::AdsvC32,
    "Adsv cipher with Base32Crockford encoding (AES-SIV, deterministic, nonce-misuse resistant)"
);
#[cfg(feature = "adsv")]
impl_cipher_class!(
    AdsvB32,
    ::oboron::AdsvB32,
    "Adsv cipher with Base32Rfc encoding (AES-SIV, deterministic, nonce-misuse resistant)"
);
#[cfg(feature = "adsv")]
impl_cipher_class!(
    AdsvB64,
    ::oboron::AdsvB64,
    "Adsv cipher with Base64 encoding (AES-SIV, deterministic, nonce-misuse resistant)"
);
#[cfg(feature = "adsv")]
impl_cipher_class!(
    AdsvHex,
    ::oboron::AdsvHex,
    "Adsv cipher with Hex encoding (AES-SIV, deterministic, nonce-misuse resistant)"
);

// Apsv variants
// --------------
#[cfg(feature = "apsv")]
impl_cipher_class!(
    ApsvC32,
    ::oboron::ApsvC32,
    "Apsv cipher with Base32Crockford encoding (Probabilistic AES-SIV)"
);
#[cfg(feature = "apsv")]
impl_cipher_class!(
    ApsvB32,
    ::oboron::ApsvB32,
    "Apsv cipher with Base32Rfc encoding (Probabilistic AES-SIV)"
);
#[cfg(feature = "apsv")]
impl_cipher_class!(
    ApsvB64,
    ::oboron::ApsvB64,
    "Apsv cipher with Base64 encoding (Probabilistic AES-SIV)"
);
#[cfg(feature = "apsv")]
impl_cipher_class!(
    ApsvHex,
    ::oboron::ApsvHex,
    "Apsv cipher with Hex encoding (Probabilistic AES-SIV)"
);

// --- TESTING CLASSES ---

// Tdi variants
// -------------
impl_cipher_class!(
    TdiC32,
    ::oboron::TdiC32,
    "Tdi cipher with Base32Crockford encoding (Identity scheme, for testing)"
);
impl_cipher_class!(
    TdiB32,
    ::oboron::TdiB32,
    "Tdi cipher with Base32Rfc encoding (Identity scheme, for testing)"
);
impl_cipher_class!(
    TdiB64,
    ::oboron::TdiB64,
    "Tdi cipher with Base64 encoding (Identity scheme, for testing)"
);
impl_cipher_class!(
    TdiHex,
    ::oboron::TdiHex,
    "Tdi cipher with Hex encoding (Identity scheme, for testing)"
);

// Ob71 variants
// -------------
impl_cipher_class!(
    Ob71Base32Crockford,
    ::oboron::Ob71Base32Crockford,
    "Ob71 cipher with Base32Crockford encoding (Reverse scheme, for testing)"
);
impl_cipher_class!(
    Ob71Base32Rfc,
    ::oboron::Ob71Base32Rfc,
    "Ob71 cipher with Base32Rfc encoding (Reverse scheme, for testing)"
);
impl_cipher_class!(
    Ob71Base64,
    ::oboron::Ob71Base64,
    "Ob71 cipher with Base64 encoding (Reverse scheme, for testing)"
);
impl_cipher_class!(
    Ob71Hex,
    ::oboron::Ob71Hex,
    "Ob71 cipher with Hex encoding (Reverse scheme, for testing)"
);

// Ob00 - LEGACY variants
// ----------------------
#[cfg(feature = "ob00")]
impl_cipher_class!(
    Ob00Base32Crockford,
    ::oboron::Ob00Base32Crockford,
    "Ob00 cipher with Base32Crockford encoding (LEGACY AES-CBC with custom padding)\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zdc or more secure schemes like Adgs/Adsv."
);
#[cfg(feature = "ob00")]
impl_cipher_class!(
    Ob00Base32Rfc,
    ::oboron::Ob00Base32Rfc,
    "Ob00 cipher with Base32Rfc encoding (LEGACY AES-CBC with custom padding)\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zdc or more secure schemes like Adgs/Adsv."
);
#[cfg(feature = "ob00")]
impl_cipher_class!(
    Ob00Base64,
    ::oboron::Ob00Base64,
    "Ob00 cipher with Base64 encoding (LEGACY AES-CBC with custom padding)\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zdc or more secure schemes like Adgs/Adsv."
);
#[cfg(feature = "ob00")]
impl_cipher_class!(
    Ob00Hex,
    ::oboron::Ob00Hex,
    "Ob00 cipher with Hex encoding (LEGACY AES-CBC with custom padding)\n\n\
     **LEGACY**: This scheme is maintained for backward compatibility only.\n\
     For new projects, use Zdc or more secure schemes like Adgs/Adsv."
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
    ///     format: Format string like "zdc:c32", "zdc:b32", "adgs:b64", "apsv:hex", etc.
    ///     key:     86-character base64 string key (512 bits). Optional if keyless=True.
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
    ///     format: Format string like "zdc:c32", "zdc:b32", "adgs:b64", "apsv:hex", etc.
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
    ///     scheme: Scheme name like "Zdc", "Adgs", "Apsv", etc.  
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
    ///     encoding: Encoding name: "base32crockford", "base32rfc", "base64", or "hex".
    ///               Also accepts short forms: "c32", "b32", "b64", "hex".
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
    ///     Format string like "zdc:c32", "zdc:b32", "adgs:b64", etc.
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
        self.inner.scheme().as_str().to_string()
    }

    /// The encoding format used by this instance.
    #[getter]
    fn encoding(&self) -> String {
        self.inner.encoding().as_short_str().to_string()
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
    ///     key:     86-character base64 string key (512 bits).  Optional if keyless=True.
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
    ///     format: Format string like "zdc:c32", "zdc:b32", "adgs:b64", "apsv:hex", etc.
    ///
    /// Returns:
    ///     The obtext string.
    ///
    /// Raises:
    ///     ValueError: If the enc operation fails or format is invalid.
    fn enc(&self, plaintext: &str, format: &str) -> PyResult<String> {
        self.inner
            .enc(plaintext, format)
            .map_err(|e| PyValueError::new_err(format!("Enc operation failed: {}", e)))
    }

    /// Decode+decrypt an obtext string with a specific format.
    ///
    /// Args:
    ///     obtext: The encrypted+encoded string to decode+decrypt.  
    ///     format: Format string like "zdc:c32", "zdc:b32", "adgs:b64", "apsv:hex", etc.
    ///
    /// Returns:
    ///     The decoded+decrypted plaintext string.
    ///
    /// Raises:
    ///     ValueError: If the dec operation fails or format is invalid.  
    fn dec(&self, obtext: &str, format: &str) -> PyResult<String> {
        self.inner
            .dec(obtext, format)
            .map_err(|e| PyValueError::new_err(format!("Dec operation failed: {}", e)))
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// This is the only decoder that can automatically detect both the scheme
    /// (zdc, adgs, etc.) AND the encoding (base32, base64, hex).   
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
///     format: Format string like "zdc:b32", "adgs:b64", "apsv:hex", etc.
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
///     format: Format string like "zdc:b32", "adgs:b64", "apsv:hex", etc.
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
///     format: Format string like "zdc:b32", "adgs:b64", "apsv:hex", etc.
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
///     format: Format string like "zdc:b32", "adgs:b64", "apsv:hex", etc.
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

    // Ob00 variants (LEGACY)
    #[cfg(feature = "ob00")]
    {
        m.add_class::<Ob00Base32Crockford>()?;
        m.add_class::<Ob00Base32Rfc>()?;
        m.add_class::<Ob00Base64>()?;
        m.add_class::<Ob00Hex>()?;
    }

    // Zdc variants
    #[cfg(feature = "zdc")]
    {
        m.add_class::<ZdcC32>()?;
        m.add_class::<ZdcB32>()?;
        m.add_class::<ZdcB64>()?;
        m.add_class::<ZdcHex>()?;
    }

    // Upc variants
    #[cfg(feature = "upc")]
    {
        m.add_class::<UpcC32>()?;
        m.add_class::<UpcB32>()?;
        m.add_class::<UpcB64>()?;
        m.add_class::<UpcHex>()?;
    }

    // Adgs variants
    #[cfg(feature = "adgs")]
    {
        m.add_class::<AdgsC32>()?;
        m.add_class::<AdgsB32>()?;
        m.add_class::<AdgsB64>()?;
        m.add_class::<AdgsHex>()?;
    }

    // Apgs variants
    #[cfg(feature = "apgs")]
    {
        m.add_class::<ApgsC32>()?;
        m.add_class::<ApgsB32>()?;
        m.add_class::<ApgsB64>()?;
        m.add_class::<ApgsHex>()?;
    }

    // Adsv variants
    #[cfg(feature = "adsv")]
    {
        m.add_class::<AdsvC32>()?;
        m.add_class::<AdsvB32>()?;
        m.add_class::<AdsvB64>()?;
        m.add_class::<AdsvHex>()?;
    }

    // Apsv variants
    #[cfg(feature = "apsv")]
    {
        m.add_class::<ApsvC32>()?;
        m.add_class::<ApsvB32>()?;
        m.add_class::<ApsvB64>()?;
        m.add_class::<ApsvHex>()?;
    }

    // Ob71 variants
    m.add_class::<Ob71Base32Crockford>()?;
    m.add_class::<Ob71Base32Rfc>()?;
    m.add_class::<Ob71Base64>()?;
    m.add_class::<Ob71Hex>()?;

    // Tdi variants
    m.add_class::<TdiC32>()?;
    m.add_class::<TdiB32>()?;
    m.add_class::<TdiB64>()?;
    m.add_class::<TdiHex>()?;

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
