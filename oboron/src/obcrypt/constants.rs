// AES-CBC padding byte
#[cfg(any(feature = "ob01", feature = "ob21p"))]
pub const CBC_PADDING_BYTE: u8 = 0x01;
#[cfg(any(feature = "ob00", feature = "ob01", feature = "ob21p"))]
pub const AES_BLOCK_SIZE: usize = 16;
