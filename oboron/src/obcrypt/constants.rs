// AES-CBC padding byte
#[cfg(any(feature = "zfbcx", feature = "upbc"))]
pub const CBC_PADDING_BYTE: u8 = 0x01;
#[cfg(any(feature = "legacy", feature = "zfbcx", feature = "upbc"))]
pub const AES_BLOCK_SIZE: usize = 16;
