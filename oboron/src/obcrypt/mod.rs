//! This library provides cryptographic library wrappings for oboron

mod constants;
mod keychain;

#[cfg(feature = "adgs")]
mod adgs; //  AES-GCM-SIV (deterministic)
#[cfg(feature = "adsv")]
mod adsv; //  AES-SIV (deterministic)
#[cfg(feature = "apgs")]
mod apgs; // AES-GCM-SIV (probabilistic)
#[cfg(feature = "apsv")]
mod apsv;
#[cfg(feature = "upc")]
mod upc; // AES-CBC (probabilistic)
#[cfg(feature = "zdc")]
mod zdc; //  AES-CBC (deterministic, not cryptographically secure - obfuscation only!) // AES-SIV (probabilistic)

// Testing schemes (no encryption - no dependencies)
#[cfg(feature = "mock1")]
mod mock1;
#[cfg(feature = "mock2")]
mod mock2; // Identity // String reversal

// Legacy
#[cfg(feature = "ob00")]
mod ob00; //  Legacy AES-CBC

pub use keychain::Keychain;

#[cfg(feature = "adgs")]
pub use adgs::{decrypt as decrypt_adgs, encrypt as encrypt_adgs};
#[cfg(feature = "adsv")]
pub use adsv::{decrypt as decrypt_adsv, encrypt as encrypt_adsv};
#[cfg(feature = "apgs")]
pub use apgs::{decrypt as decrypt_apgs, encrypt as encrypt_apgs};
#[cfg(feature = "apsv")]
pub use apsv::{decrypt as decrypt_apsv, encrypt as encrypt_apsv};
#[cfg(feature = "upc")]
pub use upc::{decrypt as decrypt_upc, encrypt as encrypt_upc};
#[cfg(feature = "zdc")]
pub use zdc::{decrypt as decrypt_zdc, encrypt as encrypt_zdc};

// Testing
#[cfg(feature = "mock1")]
pub use mock1::{decrypt as decrypt_mock1, encrypt as encrypt_mock1};
#[cfg(feature = "mock2")]
pub use mock2::{decrypt as decrypt_mock2, encrypt as encrypt_mock2};

// Legacy
#[cfg(feature = "ob00")]
pub use ob00::{decrypt as decrypt_ob00, encrypt as encrypt_ob00};
