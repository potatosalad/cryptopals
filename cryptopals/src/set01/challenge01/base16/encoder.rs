pub trait Base16Encoder {
    fn base16_encode_lowercase<I: std::iter::FromIterator<char>>(&self) -> I;
    fn base16_encode_uppercase<I: std::iter::FromIterator<char>>(&self) -> I;
}

pub struct Base16EncoderConfig {
    pub case: Base16EncoderCase,
}

pub enum Base16EncoderCase {
    Lowercase,
    Uppercase,
}

impl Base16EncoderConfig {
    #[must_use]
    pub fn default() -> Self {
        Self {
            case: Base16EncoderCase::Lowercase,
        }
    }

    #[must_use]
    pub fn lowercase(mut self) -> Self {
        self.case = Base16EncoderCase::Lowercase;
        self
    }

    #[must_use]
    pub fn uppercase(mut self) -> Self {
        self.case = Base16EncoderCase::Uppercase;
        self
    }
}

const BASE16_CHARS_LOWERCASE: &[u8; 16] = b"0123456789abcdef";
const BASE16_CHARS_UPPERCASE: &[u8; 16] = b"0123456789ABCDEF";

struct BytesToBase16Chars<'a> {
    inner: ::core::slice::Iter<'a, u8>,
    table: &'static [u8; 16],
    next: Option<char>,
}

impl<'a> BytesToBase16Chars<'a> {
    fn new(inner: &'a [u8], table: &'static [u8; 16]) -> BytesToBase16Chars<'a> {
        BytesToBase16Chars {
            inner: inner.iter(),
            table,
            next: None,
        }
    }
}

impl<'a> Iterator for BytesToBase16Chars<'a> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current) = self.next.take() {
            Some(current)
        } else {
            self.inner.next().map(|byte| {
                let current = self.table[(byte >> 4) as usize] as char;
                self.next = Some(self.table[(byte & 0xf) as usize] as char);
                current
            })
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.len();
        (length, Some(length))
    }
}

impl<'a> std::iter::ExactSizeIterator for BytesToBase16Chars<'a> {
    fn len(&self) -> usize {
        let mut length = self.inner.len() * 2;
        if self.next.is_some() {
            length += 1;
        }
        length
    }
}

impl<T: ?Sized + AsRef<[u8]>> Base16Encoder for T {
    fn base16_encode_lowercase<I: std::iter::FromIterator<char>>(&self) -> I {
        BytesToBase16Chars::new(self.as_ref(), BASE16_CHARS_LOWERCASE).collect()
    }

    fn base16_encode_uppercase<I: std::iter::FromIterator<char>>(&self) -> I {
        BytesToBase16Chars::new(self.as_ref(), BASE16_CHARS_UPPERCASE).collect()
    }
}

pub fn encode_config<T: ?Sized + AsRef<[u8]>>(input: &T, config: &Base16EncoderConfig) -> String {
    match config.case {
        Base16EncoderCase::Lowercase => input.base16_encode_lowercase(),
        Base16EncoderCase::Uppercase => input.base16_encode_uppercase(),
    }
}

pub fn encode<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    input.base16_encode_lowercase()
}

pub fn encode_uppercase<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    input.base16_encode_uppercase()
}
