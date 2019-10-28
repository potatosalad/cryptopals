#[derive(Debug, Clone)]
pub enum Pkcs7PadError {
    ZeroBlockSize,
}

// This is important for other errors to wrap this one.
impl std::error::Error for Pkcs7PadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl std::fmt::Display for Pkcs7PadError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Pkcs7PadError::ZeroBlockSize => {
                write!(f, "block_size must be a non-zero u8 (between 1 and 255)")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Pkcs7UnpadError {
    ZeroBlockSize,
    InvalidBlockLength {
        was: usize,
        expected: u8,
    },
    InvalidPaddingLength {
        was: u8,
        offset: usize,
    },
    InvalidPaddingByte {
        was: u8,
        offset: usize,
        expected: u8,
    },
}

// This is important for other errors to wrap this one.
impl std::error::Error for Pkcs7UnpadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl std::fmt::Display for Pkcs7UnpadError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Pkcs7UnpadError::ZeroBlockSize => {
                write!(f, "block_size must be a non-zero u8 (between 1 and 255)")
            }
            Pkcs7UnpadError::InvalidBlockLength { was, expected } => write!(
                f,
                "invalid block length '{}' (expected multiple of '{}')",
                was, expected
            ),
            Pkcs7UnpadError::InvalidPaddingLength { was, offset } => {
                write!(f, "invalid padding length '{}' at offset {}", was, offset)
            }
            Pkcs7UnpadError::InvalidPaddingByte {
                was,
                offset,
                expected,
            } => write!(
                f,
                "invalid padding nyte '{}' at offset {} (expected '{}')",
                was, offset, expected
            ),
        }
    }
}
