//! Z-tier obfuscation schemes (NOT cryptographically secure)
//!
//! ⚠️ **WARNING**:  Everything in this module is for OBFUSCATION ONLY.   
//! Do NOT use z-tier schemes for actual encryption or security.
//!
//! Z-tier schemes use 32-byte secrets instead of 64-byte keys.

#![cfg(feature = "ztier")]

mod constants;
#[cfg(feature = "legacy")]
mod legacy;
mod oz;
mod zcodec;
mod zdec_auto;
mod zkeychain;
#[cfg(feature = "zmock")]
mod zmock1;
#[cfg(feature = "zrbcx")]
mod zrbcx;

// Re-export public types
#[cfg(feature = "zmock")]
pub use zcodec::{Zmock1B32, Zmock1B64, Zmock1C32, Zmock1Hex};
#[cfg(feature = "zrbcx")]
pub use zcodec::{ZrbcxB32, ZrbcxB64, ZrbcxC32, ZrbcxHex};

pub use oz::Oz;

#[cfg(feature = "zmock")]
pub(crate) use zmock1::{decrypt_zmock1, encrypt_zmock1};
#[cfg(feature = "zrbcx")]
pub(crate) use zrbcx::{decrypt_zrbcx, encrypt_zrbcx};

#[cfg(feature = "legacy")]
pub use legacy::{LegacyB32, LegacyB64, LegacyC32, LegacyHex};
