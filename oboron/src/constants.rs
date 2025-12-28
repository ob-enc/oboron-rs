// Fixed key for oboron (testing only - NOT SECURE)
// Master value
#[allow(dead_code)]
pub const HARDCODED_KEY_BASE64: &str =
    "OBKEYz0C6l8134WWtcxCGDEAYEaOi0ZUVaQVF06m6Wap9I7sS6RG3fyLeFh4lTVvRadaGrdBlFTdn3qoqV291Q";
pub const HARDCODED_KEY_BYTES: [u8; 64] = [
    0x38, 0x12, 0x84, 0x63, 0x3d, 0x02, 0xea, 0x5f, 0x35, 0xdf, 0x85, 0x96, 0xb5, 0xcc, 0x42, 0x18,
    0x31, 0x00, 0x60, 0x46, 0x8e, 0x8b, 0x46, 0x54, 0x55, 0xa4, 0x15, 0x17, 0x4e, 0xa6, 0xe9, 0x66,
    0xa9, 0xf4, 0x8e, 0xec, 0x4b, 0xa4, 0x46, 0xdd, 0xfc, 0x8b, 0x78, 0x58, 0x78, 0x95, 0x35, 0x6f,
    0x45, 0xa7, 0x5a, 0x1a, 0xb7, 0x41, 0x94, 0x54, 0xdd, 0x9f, 0x7a, 0xa8, 0xa9, 0x5d, 0xbd, 0xd5,
];
// Scheme byte (scheme identifier)
// ===============================
// (tail byte appended to ciphertext payload before encoding)
//
// Tail byte structure: [tier:3 bits][scheme:4 bits][probabilistic:1 bit]

// Tier ob0x - Insecure, non-authenticated
// ---------------------------------------
// zrbcx:  tier=0 (000), scheme=1 (0001), probabilistic=0 -> 00000010 = 0x02 (decimal: 2)
#[cfg(feature = "zrbcx")]
pub const ZRBCX_BYTE: u8 = 0x02;

// Tier ob2x - Secure, non-authenticated
// -------------------------------------
// upbc: tier=2 (010), scheme=2 (0001), probabilistic=1 -> 01000011 = 0x23 (decimal: 35)
#[cfg(feature = "upbc")]
pub const UPBC_BYTE: u8 = 0x23;

// Tier ob3x - Secure, authenticated
// ---------------------------------
// aags: tier=3 (011), scheme=1 (0001), probabilistic=0 -> 01100010 = 0x62 (decimal: 98)
#[cfg(feature = "aags")]
pub const AAGS_BYTE: u8 = 0x62;

// apgs: tier=3 (011), scheme=1 (0001), probabilistic=1 -> 01100011 = 0x63 (decimal: 99)
#[cfg(feature = "apgs")]
pub const APGS_BYTE: u8 = 0x63;

// aasv: tier=3 (011), scheme=2 (0010), probabilistic=0 -> 01100100 = 0x64 (decimal: 100)
#[cfg(feature = "aasv")]
pub const AASV_BYTE: u8 = 0x64;

// apsv: tier=3 (011), scheme=2 (0010), probabilistic=1 -> 01100101 = 0x65 (decimal: 101)
#[cfg(feature = "apsv")]
pub const APSV_BYTE: u8 = 0x65;

// Tier ob7x - Testing
// -------------------
// Identity scheme (no encryption)
// mock1: tier=7 (111), scheme=0 (0000), probabilistic=0 -> 11100000 = 0xE0 (decimal: 224)
#[cfg(feature = "mock")]
pub const MOCK1_BYTE: u8 = 0xE0;
// String-reversal (no encryption)
// mock2: tier=7 (111), scheme=1 (0001), probabilistic=0 -> 11100010 = 0xE2 (decimal: 226)
#[cfg(feature = "mock")]
pub const MOCK2_BYTE: u8 = 0xE2;

// For efficient resolution in decode logic, list all scheme bytes of reversed schemes
const fn get_reversed_schemes() -> &'static [u8] {
    #[cfg(all(feature = "zrbcx", feature = "upbc"))]
    return &[ZRBCX_BYTE, UPBC_BYTE];
    #[cfg(all(feature = "zrbcx", not(feature = "upbc")))]
    return &[ZRBCX_BYTE];
    #[cfg(all(not(feature = "zrbcx"), feature = "upbc"))]
    return &[UPBC_BYTE];
    #[cfg(all(not(feature = "zrbcx"), not(feature = "upbc")))]
    return &[];
}
pub const REVERSED_SCHEME_BYTES: &[u8] = get_reversed_schemes();

// Format identifiers
//
#[cfg(feature = "aags")]
pub(crate) mod aags_constants {
    pub const AAGS_C32_STR: &str = "aags.c32";
    pub const AAGS_B32_STR: &str = "aags.b32";
    pub const AAGS_B64_STR: &str = "aags.b64";
    pub const AAGS_HEX_STR: &str = "aags.hex";
}

#[cfg(feature = "apgs")]
pub(crate) mod apgs_constants {
    pub const APGS_C32_STR: &str = "apgs.c32";
    pub const APGS_B32_STR: &str = "apgs.b32";
    pub const APGS_B64_STR: &str = "apgs.b64";
    pub const APGS_HEX_STR: &str = "apgs.hex";
}

#[cfg(feature = "aasv")]
pub(crate) mod aasv_constants {
    pub const AASV_C32_STR: &str = "aasv.c32";
    pub const AASV_B32_STR: &str = "aasv.b32";
    pub const AASV_B64_STR: &str = "aasv.b64";
    pub const AASV_HEX_STR: &str = "aasv.hex";
}

#[cfg(feature = "apsv")]
pub(crate) mod apsv_constants {
    pub const APSV_C32_STR: &str = "apsv.c32";
    pub const APSV_B32_STR: &str = "apsv.b32";
    pub const APSV_B64_STR: &str = "apsv.b64";
    pub const APSV_HEX_STR: &str = "apsv.hex";
}

#[cfg(feature = "upbc")]
pub(crate) mod upbc_constants {
    pub const UPBC_C32_STR: &str = "upbc.c32";
    pub const UPBC_B32_STR: &str = "upbc.b32";
    pub const UPBC_B64_STR: &str = "upbc.b64";
    pub const UPBC_HEX_STR: &str = "upbc.hex";
}

#[cfg(feature = "zrbcx")]
pub(crate) mod zrbcx_constants {
    pub const ZRBCX_C32_STR: &str = "zrbcx.c32";
    pub const ZRBCX_B32_STR: &str = "zrbcx.b32";
    pub const ZRBCX_B64_STR: &str = "zrbcx.b64";
    pub const ZRBCX_HEX_STR: &str = "zrbcx.hex";
}

#[cfg(feature = "mock")]
pub(crate) mod mock_constants {
    pub const MOCK1_B32_STR: &str = "mock1.b32";
    pub const MOCK1_B64_STR: &str = "mock1.b64";
    pub const MOCK1_C32_STR: &str = "mock1.c32";
    pub const MOCK1_HEX_STR: &str = "mock1.hex";
    pub const MOCK2_B32_STR: &str = "mock2.b32";
    pub const MOCK2_B64_STR: &str = "mock2.b64";
    pub const MOCK2_C32_STR: &str = "mock2.c32";
    pub const MOCK2_HEX_STR: &str = "mock2.hex";
}

#[cfg(feature = "legacy")]
pub(crate) mod legacy_constants {
    pub const LEGACY_C32_STR: &str = "legacy.c32";
    pub const LEGACY_B32_STR: &str = "legacy.b32";
    pub const LEGACY_HEX_STR: &str = "legacy.hex";
    pub const LEGACY_B64_STR: &str = "legacy.b64";
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64URL_NOPAD;

    #[test]
    fn test_hardcoded_key_consistency() {
        // Decode base64 to bytes
        let decoded = BASE64URL_NOPAD
            .decode(HARDCODED_KEY_BASE64.as_bytes())
            .expect("Failed to decode base64");

        // Verify length
        assert_eq!(decoded.len(), 64, "Decoded key should be 64 bytes");

        // Verify the bytes match
        assert_eq!(
            decoded.as_slice(),
            &HARDCODED_KEY_BYTES,
            "Base64 and bytes constants must match"
        );

        // Also verify encoding back
        let encoded = BASE64URL_NOPAD.encode(&HARDCODED_KEY_BYTES);
        assert_eq!(
            encoded, HARDCODED_KEY_BASE64,
            "Bytes encoded back to base64 must match original"
        );
    }
}
