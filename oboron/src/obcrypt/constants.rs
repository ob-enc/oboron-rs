// AES-CBC padding byte
#[cfg(any(feature = "zfbcx", feature = "upc"))]
pub const CBC_PADDING_BYTE: u8 = 0x01;
#[cfg(any(feature = "legacy", feature = "zfbcx", feature = "upc"))]
pub const AES_BLOCK_SIZE: usize = 16;
