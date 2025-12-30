//! This library provides cryptographic library wrappings for oboron

mod constants;

#[cfg(feature = "aags")]
mod aags; //  AES-GCM-SIV (deterministic)
#[cfg(feature = "aasv")]
mod aasv; //  AES-SIV (deterministic)
#[cfg(feature = "apgs")]
mod apgs; // AES-GCM-SIV (probabilistic)
#[cfg(feature = "apsv")]
mod apsv;
#[cfg(feature = "upbc")]
mod upbc; // AES-CBC (probabilistic)

// Testing schemes (no encryption - no dependencies)
#[cfg(feature = "mock")]
mod mock1;
#[cfg(feature = "mock")]
mod mock2; // Identity // String reversal

#[cfg(feature = "aags")]
pub use aags::{decrypt as decrypt_aags, encrypt as encrypt_aags};
#[cfg(feature = "aasv")]
pub use aasv::{decrypt as decrypt_aasv, encrypt as encrypt_aasv};
#[cfg(feature = "apgs")]
pub use apgs::{decrypt as decrypt_apgs, encrypt as encrypt_apgs};
#[cfg(feature = "apsv")]
pub use apsv::{decrypt as decrypt_apsv, encrypt as encrypt_apsv};
#[cfg(feature = "upbc")]
pub use upbc::{decrypt as decrypt_upbc, encrypt as encrypt_upbc};

// Testing
#[cfg(feature = "mock")]
pub use mock1::{decrypt as decrypt_mock1, encrypt as encrypt_mock1};
#[cfg(feature = "mock")]
pub use mock2::{decrypt as decrypt_mock2, encrypt as encrypt_mock2};
