#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AesError {
    InvalidBlockSize(usize),
    InvalidKeySize(usize),
    InvalidInitializationVectorSize {
        explanation: &'static str,
        was: usize,
    },
    InvalidOffset {
        length: usize,
        offset: usize,
    },
}

impl std::error::Error for AesError {
    #[must_use]
    fn description(&self) -> &str {
        match *self {
            Self::InvalidBlockSize(_) => "invalid block size",
            Self::InvalidKeySize(_) => "invalid key size",
            Self::InvalidInitializationVectorSize { .. } => "invalid initialization vector size",
            Self::InvalidOffset { .. } => "invalid offset for length of input",
        }
    }
}

impl ::core::fmt::Display for AesError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match *self {
            Self::InvalidBlockSize(size) => write!(
                f,
                "Invalid block size of '{}' must be divisible by 16",
                size
            ),
            Self::InvalidKeySize(size) => {
                write!(f, "Invalid key size of '{}' must be 16, 24, or 32", size)
            }
            Self::InvalidInitializationVectorSize { was, explanation } => write!(
                f,
                "Invalid initialization vector size of '{}' {}",
                was, explanation
            ),
            Self::InvalidOffset { length, offset } => write!(
                f,
                "Invalid offset of '{}' for input length of {}",
                offset, length
            ),
        }
    }
}
