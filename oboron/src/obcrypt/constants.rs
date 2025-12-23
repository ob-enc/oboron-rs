// AES-CBC padding byte
#[cfg(any(feature = "zrbcx", feature = "upbc"))]
pub const CBC_PADDING_BYTE: u8 = 0x01;
#[cfg(any(feature = "legacy", feature = "zrbcx", feature = "upbc"))]
pub const AES_BLOCK_SIZE: usize = 16;
