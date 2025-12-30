//! Z-tier obfuscation schemes (NOT cryptographically secure)
//!
//! ⚠️ **WARNING**:  Everything in this module is for OBFUSCATION ONLY.   
//! Do NOT use z-tier schemes for actual encryption or security.
//!
//! Z-tier schemes use 32-byte secrets instead of 64-byte keys.

#![cfg(feature = "ztier")]

// Z-tier scheme implementations
mod zkeychain;

#[cfg(feature = "legacy")]
mod legacy;
#[cfg(feature = "zrbcx")]
mod zrbcx;

// Re-export public types
#[cfg(feature = "zrbcx")]
pub use zcodec::{ZrbcxB32, ZrbcxB64, ZrbcxC32, ZrbcxHex};

#[cfg(feature = "zrbcx")]
pub(crate) use zrbcx::{decrypt_zrbcx, encrypt_zrbcx};

#[cfg(feature = "legacy")]
pub use legacy::{LegacyB32, LegacyB64, LegacyC32, LegacyHex};
