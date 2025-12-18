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
// ob01:  tier=0 (000), scheme=1 (0001), probabilistic=0 -> 00000010 = 0x02 (decimal: 2)
#[cfg(feature = "ob01")]
pub const OB01_BYTE: u8 = 0x02;

// Tier ob2x - Secure, non-authenticated
// -------------------------------------
// ob21p: tier=2 (010), scheme=2 (0001), probabilistic=1 -> 01000011 = 0x23 (decimal: 35)
#[cfg(feature = "ob21p")]
pub const OB21P_BYTE: u8 = 0x23;

// Tier ob3x - Secure, authenticated
// ---------------------------------
// ob31: tier=3 (011), scheme=1 (0001), probabilistic=0 -> 01100010 = 0x62 (decimal: 98)
#[cfg(feature = "ob31")]
pub const OB31_BYTE: u8 = 0x62;

// ob31p: tier=3 (011), scheme=1 (0001), probabilistic=1 -> 01100011 = 0x63 (decimal: 99)
#[cfg(feature = "ob31p")]
pub const OB31P_BYTE: u8 = 0x63;

// ob32: tier=3 (011), scheme=2 (0010), probabilistic=0 -> 01100100 = 0x64 (decimal: 100)
#[cfg(feature = "ob32")]
pub const OB32_BYTE: u8 = 0x64;

// ob32p: tier=3 (011), scheme=2 (0010), probabilistic=1 -> 01100101 = 0x65 (decimal: 101)
#[cfg(feature = "ob32p")]
pub const OB32P_BYTE: u8 = 0x65;

// Tier ob7x - Testing
// -------------------
// Identity scheme (no encryption)
// ob70: tier=7 (111), scheme=0 (0000), probabilistic=0 -> 11100000 = 0xE0 (decimal: 224)
#[cfg(feature = "ob70")]
pub const OB70_BYTE: u8 = 0xE0;
// String-reversal (no encryption)
// ob71: tier=7 (111), scheme=1 (0001), probabilistic=0 -> 11100010 = 0xE2 (decimal: 226)
#[cfg(feature = "ob71")]
pub const OB71_BYTE: u8 = 0xE2;

// For efficient resolution in decode logic, list all scheme bytes of reversed schemes
const fn get_reversed_schemes() -> &'static [u8] {
    #[cfg(all(feature = "ob01", feature = "ob21p"))]
    return &[OB01_BYTE, OB21P_BYTE];
    #[cfg(all(feature = "ob01", not(feature = "ob21p")))]
    return &[OB01_BYTE];
    #[cfg(all(not(feature = "ob01"), feature = "ob21p"))]
    return &[OB21P_BYTE];
    #[cfg(all(not(feature = "ob01"), not(feature = "ob21p")))]
    return &[];
}
pub const REVERSED_SCHEME_BYTES: &[u8] = get_reversed_schemes();

// Format identifiers
//
// c32 - Base32Crockford encoding
#[cfg(feature = "ob01")]
pub const OB01_C32: &str = "ob01:c32";
#[cfg(feature = "ob21p")]
pub const OB21P_C32: &str = "ob21p:c32";
#[cfg(feature = "ob31")]
pub const OB31_C32: &str = "ob31:c32";
#[cfg(feature = "ob31p")]
pub const OB31P_C32: &str = "ob31p:c32";
#[cfg(feature = "ob32")]
pub const OB32_C32: &str = "ob32:c32";
#[cfg(feature = "ob32p")]
pub const OB32P_C32: &str = "ob32p:c32";
// Tier ob7x - Testing
#[cfg(feature = "ob70")]
pub const OB70_C32: &str = "ob70:c32";
#[cfg(feature = "ob71")]
pub const OB71_C32: &str = "ob71:c32";
// Legacy
#[cfg(feature = "ob00")]
pub const OB00_C32: &str = "ob00:c32";

// b32 - Base32Rfc encoding
#[cfg(feature = "ob01")]
pub const OB01_B32: &str = "ob01:b32";
#[cfg(feature = "ob21p")]
pub const OB21P_B32: &str = "ob21p:b32";
#[cfg(feature = "ob31")]
pub const OB31_B32: &str = "ob31:b32";
#[cfg(feature = "ob31p")]
pub const OB31P_B32: &str = "ob31p:b32";
#[cfg(feature = "ob32")]
pub const OB32_B32: &str = "ob32:b32";
#[cfg(feature = "ob32p")]
pub const OB32P_B32: &str = "ob32p:b32";
// Tier ob7x - Testing
#[cfg(feature = "ob70")]
pub const OB70_B32: &str = "ob70:b32";
#[cfg(feature = "ob71")]
pub const OB71_B32: &str = "ob71:b32";
// Legacy
#[cfg(feature = "ob00")]
pub const OB00_B32: &str = "ob00:b32";

// b64 - Base64 encoding
#[cfg(feature = "ob01")]
pub const OB01_B64: &str = "ob01:b64";
#[cfg(feature = "ob21p")]
pub const OB21P_B64: &str = "ob21p:b64";
#[cfg(feature = "ob31")]
pub const OB31_B64: &str = "ob31:b64";
#[cfg(feature = "ob31p")]
pub const OB31P_B64: &str = "ob31p:b64";
#[cfg(feature = "ob32")]
pub const OB32_B64: &str = "ob32:b64";
#[cfg(feature = "ob32p")]
pub const OB32P_B64: &str = "ob32p:b64";
// Tier ob7x - Testing
#[cfg(feature = "ob70")]
pub const OB70_B64: &str = "ob70:b64";
#[cfg(feature = "ob71")]
pub const OB71_B64: &str = "ob71:b64";
// Legacy
#[cfg(feature = "ob00")]
pub const OB00_B64: &str = "ob00:b64";

// hex - Hex encoding
#[cfg(feature = "ob01")]
pub const OB01_HEX: &str = "ob01:hex";
#[cfg(feature = "ob21p")]
pub const OB21P_HEX: &str = "ob21p:hex";
#[cfg(feature = "ob31")]
pub const OB31_HEX: &str = "ob31:hex";
#[cfg(feature = "ob31p")]
pub const OB31P_HEX: &str = "ob31p:hex";
#[cfg(feature = "ob32")]
pub const OB32_HEX: &str = "ob32:hex";
#[cfg(feature = "ob32p")]
pub const OB32P_HEX: &str = "ob32p:hex";
// Tier ob7x - Testing
#[cfg(feature = "ob70")]
pub const OB70_HEX: &str = "ob70:hex";
#[cfg(feature = "ob71")]
pub const OB71_HEX: &str = "ob71:hex";
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
