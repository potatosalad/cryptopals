pub trait Base16Decoder {
    fn base16_decode_lowercase<I: std::iter::FromIterator<Result<u8, Base16DecoderError>>>(
        &self,
    ) -> I;
    fn base16_decode_mixedcase<I: std::iter::FromIterator<Result<u8, Base16DecoderError>>>(
        &self,
    ) -> I;
    fn base16_decode_uppercase<I: std::iter::FromIterator<Result<u8, Base16DecoderError>>>(
        &self,
    ) -> I;
}

pub struct Base16DecoderConfig {
    pub case: Base16DecoderCase,
}

pub enum Base16DecoderCase {
    Mixedcase,
    Lowercase,
    Uppercase,
}

impl Base16DecoderConfig {
    #[must_use]
    pub fn default() -> Self {
        Self {
            case: Base16DecoderCase::Mixedcase,
        }
    }

    #[must_use]
    pub fn lowercase(mut self) -> Self {
        self.case = Base16DecoderCase::Lowercase;
        self
    }

    #[must_use]
    pub fn mixedcase(mut self) -> Self {
        self.case = Base16DecoderCase::Mixedcase;
        self
    }

    #[must_use]
    pub fn uppercase(mut self) -> Self {
        self.case = Base16DecoderCase::Uppercase;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Base16DecoderError {
    /// An invalid character was found. Valid ones are: `0...9`, `a...f`
    /// or `A...F`.
    InvalidCharacter { value: char, index: usize },

    /// A hex string's length needs to be even, as two digits correspond to
    /// one byte.
    OddLength,
}

impl std::error::Error for Base16DecoderError {
    #[must_use]
    fn description(&self) -> &str {
        match *self {
            Self::InvalidCharacter { .. } => "invalid character",
            Self::OddLength => "odd number of digits",
        }
    }
}

impl ::core::fmt::Display for Base16DecoderError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match *self {
            Self::InvalidCharacter { value, index } => {
                write!(f, "Invalid character '{}' at position {}", value, index)
            }
            Self::OddLength => write!(f, "Odd number of digits"),
        }
    }
}

trait Base16CaseDecoder {
    fn base16_decode_value(&self, value: u8, index: usize) -> Result<u8, Base16DecoderError>;
}

struct Base16DecoderCaseLowercase;
struct Base16DecoderCaseMixedcase;
struct Base16DecoderCaseUppercase;

impl Base16CaseDecoder for Base16DecoderCaseLowercase {
    fn base16_decode_value(&self, value: u8, index: usize) -> Result<u8, Base16DecoderError> {
        match value {
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'0'..=b'9' => Ok(value - b'0'),
            _ => Err(Base16DecoderError::InvalidCharacter {
                value: value as char,
                index,
            }),
        }
    }
}

impl Base16CaseDecoder for Base16DecoderCaseMixedcase {
    fn base16_decode_value(&self, value: u8, index: usize) -> Result<u8, Base16DecoderError> {
        match value {
            b'A'..=b'F' => Ok(value - b'A' + 10),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'0'..=b'9' => Ok(value - b'0'),
            _ => Err(Base16DecoderError::InvalidCharacter {
                value: value as char,
                index,
            }),
        }
    }
}

impl Base16CaseDecoder for Base16DecoderCaseUppercase {
    fn base16_decode_value(&self, value: u8, index: usize) -> Result<u8, Base16DecoderError> {
        match value {
            b'A'..=b'F' => Ok(value - b'A' + 10),
            b'0'..=b'9' => Ok(value - b'0'),
            _ => Err(Base16DecoderError::InvalidCharacter {
                value: value as char,
                index,
            }),
        }
    }
}

struct Base16CharsToBytes<'a, D: Base16CaseDecoder> {
    inner: ::core::slice::Iter<'a, u8>,
    decoder: D,
    index: usize,
    failed: bool,
}

impl<'a, D: Base16CaseDecoder> Base16CharsToBytes<'a, D> {
    fn new(inner: &'a [u8], decoder: D) -> Base16CharsToBytes<'a, D> {
        Base16CharsToBytes {
            inner: inner.iter(),
            decoder,
            index: 0,
            failed: false,
        }
    }
}

impl<'a, D: Base16CaseDecoder> Iterator for Base16CharsToBytes<'a, D> {
    type Item = Result<u8, Base16DecoderError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            None
        } else {
            match (self.inner.next(), self.inner.next()) {
                (Some(a), Some(b)) => Some(
                    self.decoder
                        .base16_decode_value(*a, self.index)
                        .and_then(|lhs| {
                            self.index += 1;
                            self.decoder
                                .base16_decode_value(*b, self.index)
                                .and_then(|rhs| {
                                    self.index += 1;
                                    Ok((lhs << 4) | (rhs & 0xf))
                                })
                        })
                        .or_else(|err| {
                            self.failed = true;
                            Err(err)
                        }),
                ),
                (Some(_), None) => {
                    self.failed = true;
                    Some(Err(Base16DecoderError::OddLength))
                }
                _ => None,
            }
        }
    }
}

impl<T: ?Sized + AsRef<[u8]>> Base16Decoder for T {
    fn base16_decode_lowercase<I: std::iter::FromIterator<Result<u8, Base16DecoderError>>>(
        &self,
    ) -> I {
        Base16CharsToBytes::new(self.as_ref(), Base16DecoderCaseLowercase).collect()
    }

    fn base16_decode_mixedcase<I: std::iter::FromIterator<Result<u8, Base16DecoderError>>>(
        &self,
    ) -> I {
        Base16CharsToBytes::new(self.as_ref(), Base16DecoderCaseMixedcase).collect()
    }

    fn base16_decode_uppercase<I: std::iter::FromIterator<Result<u8, Base16DecoderError>>>(
        &self,
    ) -> I {
        Base16CharsToBytes::new(self.as_ref(), Base16DecoderCaseUppercase).collect()
    }
}

pub fn decode_config<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    config: &Base16DecoderConfig,
) -> Result<Vec<u8>, Base16DecoderError> {
    match config.case {
        Base16DecoderCase::Lowercase => input.base16_decode_lowercase(),
        Base16DecoderCase::Mixedcase => input.base16_decode_mixedcase(),
        Base16DecoderCase::Uppercase => input.base16_decode_uppercase(),
    }
}

pub fn decode<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, Base16DecoderError> {
    input.base16_decode_mixedcase()
}

pub fn decode_lowercase<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, Base16DecoderError> {
    input.base16_decode_lowercase()
}

pub fn decode_uppercase<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, Base16DecoderError> {
    input.base16_decode_uppercase()
}
