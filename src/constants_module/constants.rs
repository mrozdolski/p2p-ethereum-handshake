// The version of the protocol being used
pub const PROTOCOL_VERSION: usize = 5;

// The header used to indicate a zero-length payload
pub const ZERO_HEADER: &[u8; 3] = &[194, 128, 128]; 