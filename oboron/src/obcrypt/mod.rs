//! This library provides cryptographic library wrappings for oboron

mod constants;
mod keychain;

#[cfg(feature = "adgs")]
mod adgs; //  AES-GCM-SIV (deterministic)
#[cfg(feature = "apgs")]
mod apgs; // AES-GCM-SIV (probabilistic)
#[cfg(feature = "ob32")]
mod ob32; //  AES-SIV (deterministic)
#[cfg(feature = "ob32p")]
mod ob32p;
#[cfg(feature = "upc")]
mod upc; // AES-CBC (probabilistic)
#[cfg(feature = "zdc")]
mod zdc; //  AES-CBC (deterministic, not cryptographically secure - obfuscation only!) // AES-SIV (probabilistic)

// Testing schemes (no encryption - no dependencies)
#[cfg(feature = "ob70")]
mod ob70; // Identity
#[cfg(feature = "ob71")]
mod ob71; // String reversal

// Legacy
#[cfg(feature = "ob00")]
mod ob00; //  Legacy AES-CBC

pub use keychain::Keychain;

#[cfg(feature = "adgs")]
pub use adgs::{decrypt as decrypt_adgs, encrypt as encrypt_adgs};
#[cfg(feature = "apgs")]
pub use apgs::{decrypt as decrypt_apgs, encrypt as encrypt_apgs};
#[cfg(feature = "ob32")]
pub use ob32::{decrypt as decrypt_ob32, encrypt as encrypt_ob32};
#[cfg(feature = "ob32p")]
pub use ob32p::{decrypt as decrypt_ob32p, encrypt as encrypt_ob32p};
#[cfg(feature = "upc")]
pub use upc::{decrypt as decrypt_upc, encrypt as encrypt_upc};
#[cfg(feature = "zdc")]
pub use zdc::{decrypt as decrypt_zdc, encrypt as encrypt_zdc};

// Testing
#[cfg(feature = "ob70")]
pub use ob70::{decrypt as decrypt_ob70, encrypt as encrypt_ob70};
#[cfg(feature = "ob71")]
pub use ob71::{decrypt as decrypt_ob71, encrypt as encrypt_ob71};

// Legacy
#[cfg(feature = "ob00")]
pub use ob00::{decrypt as decrypt_ob00, encrypt as encrypt_ob00};
