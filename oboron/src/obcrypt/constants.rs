// AES-CBC padding byte
#[cfg(any(feature = "zdc", feature = "upc"))]
pub const CBC_PADDING_BYTE: u8 = 0x01;
#[cfg(any(feature = "ob00", feature = "zdc", feature = "upc"))]
pub const AES_BLOCK_SIZE: usize = 16;
