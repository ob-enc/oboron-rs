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
// zdc:  tier=0 (000), scheme=1 (0001), probabilistic=0 -> 00000010 = 0x02 (decimal: 2)
#[cfg(feature = "zdc")]
pub const ZDC_BYTE: u8 = 0x02;

// Tier ob2x - Secure, non-authenticated
// -------------------------------------
// upc: tier=2 (010), scheme=2 (0001), probabilistic=1 -> 01000011 = 0x23 (decimal: 35)
#[cfg(feature = "upc")]
pub const UPC_BYTE: u8 = 0x23;

// Tier ob3x - Secure, authenticated
// ---------------------------------
// adgs: tier=3 (011), scheme=1 (0001), probabilistic=0 -> 01100010 = 0x62 (decimal: 98)
#[cfg(feature = "adgs")]
pub const ADGS_BYTE: u8 = 0x62;

// apgs: tier=3 (011), scheme=1 (0001), probabilistic=1 -> 01100011 = 0x63 (decimal: 99)
#[cfg(feature = "apgs")]
pub const APGS_BYTE: u8 = 0x63;

// adsv: tier=3 (011), scheme=2 (0010), probabilistic=0 -> 01100100 = 0x64 (decimal: 100)
#[cfg(feature = "adsv")]
pub const ADSV_BYTE: u8 = 0x64;

// apsv: tier=3 (011), scheme=2 (0010), probabilistic=1 -> 01100101 = 0x65 (decimal: 101)
#[cfg(feature = "apsv")]
pub const APSV_BYTE: u8 = 0x65;

// Tier ob7x - Testing
// -------------------
// Identity scheme (no encryption)
// tdi: tier=7 (111), scheme=0 (0000), probabilistic=0 -> 11100000 = 0xE0 (decimal: 224)
#[cfg(feature = "tdi")]
pub const TDI_BYTE: u8 = 0xE0;
// String-reversal (no encryption)
// tdr: tier=7 (111), scheme=1 (0001), probabilistic=0 -> 11100010 = 0xE2 (decimal: 226)
#[cfg(feature = "tdr")]
pub const TDR_BYTE: u8 = 0xE2;

// For efficient resolution in decode logic, list all scheme bytes of reversed schemes
const fn get_reversed_schemes() -> &'static [u8] {
    #[cfg(all(feature = "zdc", feature = "upc"))]
    return &[ZDC_BYTE, UPC_BYTE];
    #[cfg(all(feature = "zdc", not(feature = "upc")))]
    return &[ZDC_BYTE];
    #[cfg(all(not(feature = "zdc"), feature = "upc"))]
    return &[UPC_BYTE];
    #[cfg(all(not(feature = "zdc"), not(feature = "upc")))]
    return &[];
}
pub const REVERSED_SCHEME_BYTES: &[u8] = get_reversed_schemes();

// Format identifiers
//
// c32 - Base32Crockford encoding
#[cfg(feature = "zdc")]
pub const ZDC_C32: &str = "zdc:c32";
#[cfg(feature = "upc")]
pub const UPC_C32: &str = "upc:c32";
#[cfg(feature = "adgs")]
pub const ADGS_C32: &str = "adgs:c32";
#[cfg(feature = "apgs")]
pub const APGS_C32: &str = "apgs:c32";
#[cfg(feature = "adsv")]
pub const ADSV_C32: &str = "adsv:c32";
#[cfg(feature = "apsv")]
pub const APSV_C32: &str = "apsv:c32";
// Tier ob7x - Testing
#[cfg(feature = "tdi")]
pub const TDI_C32: &str = "tdi:c32";
#[cfg(feature = "tdr")]
pub const TDR_C32: &str = "tdr:c32";
// Legacy
#[cfg(feature = "ob00")]
pub const OB00_C32: &str = "ob00:c32";

// b32 - Base32Rfc encoding
#[cfg(feature = "zdc")]
pub const ZDC_B32: &str = "zdc:b32";
#[cfg(feature = "upc")]
pub const UPC_B32: &str = "upc:b32";
#[cfg(feature = "adgs")]
pub const ADGS_B32: &str = "adgs:b32";
#[cfg(feature = "apgs")]
pub const APGS_B32: &str = "apgs:b32";
#[cfg(feature = "adsv")]
pub const ADSV_B32: &str = "adsv:b32";
#[cfg(feature = "apsv")]
pub const APSV_B32: &str = "apsv:b32";
// Tier ob7x - Testing
#[cfg(feature = "tdi")]
pub const TDI_B32: &str = "tdi:b32";
#[cfg(feature = "tdr")]
pub const TDR_B32: &str = "tdr:b32";
// Legacy
#[cfg(feature = "ob00")]
pub const OB00_B32: &str = "ob00:b32";

// b64 - Base64 encoding
#[cfg(feature = "zdc")]
pub const ZDC_B64: &str = "zdc:b64";
#[cfg(feature = "upc")]
pub const UPC_B64: &str = "upc:b64";
#[cfg(feature = "adgs")]
pub const ADGS_B64: &str = "adgs:b64";
#[cfg(feature = "apgs")]
pub const APGS_B64: &str = "apgs:b64";
#[cfg(feature = "adsv")]
pub const ADSV_B64: &str = "adsv:b64";
#[cfg(feature = "apsv")]
pub const APSV_B64: &str = "apsv:b64";
// Tier ob7x - Testing
#[cfg(feature = "tdi")]
pub const TDI_B64: &str = "tdi:b64";
#[cfg(feature = "tdr")]
pub const TDR_B64: &str = "tdr:b64";
// Legacy
#[cfg(feature = "ob00")]
pub const OB00_B64: &str = "ob00:b64";

// hex - Hex encoding
#[cfg(feature = "zdc")]
pub const ZDC_HEX: &str = "zdc:hex";
#[cfg(feature = "upc")]
pub const UPC_HEX: &str = "upc:hex";
#[cfg(feature = "adgs")]
pub const ADGS_HEX: &str = "adgs:hex";
#[cfg(feature = "apgs")]
pub const APGS_HEX: &str = "apgs:hex";
#[cfg(feature = "adsv")]
pub const ADSV_HEX: &str = "adsv:hex";
#[cfg(feature = "apsv")]
pub const APSV_HEX: &str = "apsv:hex";
// Tier ob7x - Testing
#[cfg(feature = "tdi")]
pub const TDI_HEX: &str = "tdi:hex";
#[cfg(feature = "tdr")]
pub const TDR_HEX: &str = "tdr:hex";
// Legacy
#[cfg(feature = "ob00")]
pub const OB00_HEX: &str = "ob00:hex";

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
