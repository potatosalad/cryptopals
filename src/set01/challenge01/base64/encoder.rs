use std::collections::VecDeque;

pub trait Base64Encoder {
    fn base64_encode_padding<I: std::iter::FromIterator<char>>(&self) -> I;
    fn base64_encode_no_padding<I: std::iter::FromIterator<char>>(&self) -> I;
}

pub struct Base64EncoderConfig {
    pub padding: bool,
}

impl Base64EncoderConfig {
    #[must_use]
    pub fn default() -> Self {
        Self { padding: true }
    }

    #[must_use]
    pub fn no_padding(mut self) -> Self {
        self.padding = false;
        self
    }

    #[must_use]
    pub fn padding(mut self) -> Self {
        self.padding = true;
        self
    }
}

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const LOWER_6_BITS: u8 = 0x3f_u8;

struct BytesToBase64Chars<'a> {
    inner: ::core::slice::Iter<'a, u8>,
    offset: usize,
    padding: bool,
    buffer: VecDeque<char>,
}

impl<'a> BytesToBase64Chars<'a> {
    fn new(inner: &'a [u8], padding: bool) -> BytesToBase64Chars<'a> {
        BytesToBase64Chars {
            inner: inner.iter(),
            offset: 6 * (inner.len() / 6),
            padding,
            buffer: VecDeque::with_capacity(7),
        }
    }
}

impl<'a> Iterator for BytesToBase64Chars<'a> {
    type Item = char;

    #[allow(clippy::many_single_char_names)]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current) = self.buffer.pop_front() {
            Some(current)
        } else if self.offset > 0 {
            match (
                self.inner.next(),
                self.inner.next(),
                self.inner.next(),
                self.inner.next(),
                self.inner.next(),
                self.inner.next(),
            ) {
                (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => {
                    let current = BASE64_CHARS[((a >> 2) & LOWER_6_BITS) as usize] as char;
                    self.buffer.push_back(
                        BASE64_CHARS[(((a << 4) | (b >> 4)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer.push_back(
                        BASE64_CHARS[(((b << 2) | (c >> 6)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer
                        .push_back(BASE64_CHARS[(c & LOWER_6_BITS) as usize] as char);
                    self.buffer
                        .push_back(BASE64_CHARS[(d >> 2) as usize] as char);
                    self.buffer.push_back(
                        BASE64_CHARS[(((d << 4) | (e >> 4)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer.push_back(
                        BASE64_CHARS[(((e << 2) | (f >> 6)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer
                        .push_back(BASE64_CHARS[(f & LOWER_6_BITS) as usize] as char);
                    self.offset -= 6;
                    Some(current)
                }
                _ => unreachable!(),
            }
        } else if self.inner.len() == 0 {
            None
        } else {
            match (
                self.inner.next(),
                self.inner.next(),
                self.inner.next(),
                self.inner.next(),
                self.inner.next(),
            ) {
                (Some(a), Some(b), Some(c), Some(d), Some(e)) => {
                    let current = BASE64_CHARS[((a >> 2) & LOWER_6_BITS) as usize] as char;
                    self.buffer.push_back(
                        BASE64_CHARS[(((a << 4) | (b >> 4)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer.push_back(
                        BASE64_CHARS[(((b << 2) | (c >> 6)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer
                        .push_back(BASE64_CHARS[(c & LOWER_6_BITS) as usize] as char);
                    self.buffer
                        .push_back(BASE64_CHARS[((d >> 2) & LOWER_6_BITS) as usize] as char);
                    self.buffer.push_back(
                        BASE64_CHARS[(((d << 4) | (e >> 4)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer
                        .push_back(BASE64_CHARS[((e << 2) & LOWER_6_BITS) as usize] as char);
                    if self.padding {
                        self.buffer.push_back('=');
                    }
                    Some(current)
                }
                (Some(a), Some(b), Some(c), Some(d), None) => {
                    let current = BASE64_CHARS[((a >> 2) & LOWER_6_BITS) as usize] as char;
                    self.buffer.push_back(
                        BASE64_CHARS[(((a << 4) | (b >> 4)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer.push_back(
                        BASE64_CHARS[(((b << 2) | (c >> 6)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer
                        .push_back(BASE64_CHARS[(c & LOWER_6_BITS) as usize] as char);
                    self.buffer
                        .push_back(BASE64_CHARS[((d >> 2) & LOWER_6_BITS) as usize] as char);
                    self.buffer
                        .push_back(BASE64_CHARS[((d << 4) & LOWER_6_BITS) as usize] as char);
                    if self.padding {
                        self.buffer.push_back('=');
                        self.buffer.push_back('=');
                    }
                    Some(current)
                }
                (Some(a), Some(b), Some(c), None, None) => {
                    let current = BASE64_CHARS[((a >> 2) & LOWER_6_BITS) as usize] as char;
                    self.buffer.push_back(
                        BASE64_CHARS[(((a << 4) | (b >> 4)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer.push_back(
                        BASE64_CHARS[(((b << 2) | (c >> 6)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer
                        .push_back(BASE64_CHARS[(c & LOWER_6_BITS) as usize] as char);
                    Some(current)
                }
                (Some(a), Some(b), None, None, None) => {
                    let current = BASE64_CHARS[((a >> 2) & LOWER_6_BITS) as usize] as char;
                    self.buffer.push_back(
                        BASE64_CHARS[(((a << 4) | (b >> 4)) & LOWER_6_BITS) as usize] as char,
                    );
                    self.buffer
                        .push_back(BASE64_CHARS[((b << 2) & LOWER_6_BITS) as usize] as char);
                    if self.padding {
                        self.buffer.push_back('=');
                    }
                    Some(current)
                }
                (Some(a), None, None, None, None) => {
                    let current = BASE64_CHARS[((a >> 2) & LOWER_6_BITS) as usize] as char;
                    self.buffer
                        .push_back(BASE64_CHARS[((a << 4) & LOWER_6_BITS) as usize] as char);
                    if self.padding {
                        self.buffer.push_back('=');
                        self.buffer.push_back('=');
                    }
                    Some(current)
                }
                _ => unreachable!(),
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.len();
        (length, Some(length))
    }
}

impl<'a> std::iter::ExactSizeIterator for BytesToBase64Chars<'a> {
    fn len(&self) -> usize {
        if self.padding {
            ((self.inner.len() + 3 - 1) / 3) * 4
        } else {
            (self.inner.len() * 4 + 3 - 1) / 3
        }
    }
}

impl<T: ?Sized + AsRef<[u8]>> Base64Encoder for T {
    fn base64_encode_padding<I: std::iter::FromIterator<char>>(&self) -> I {
        BytesToBase64Chars::new(self.as_ref(), true).collect()
    }

    fn base64_encode_no_padding<I: std::iter::FromIterator<char>>(&self) -> I {
        BytesToBase64Chars::new(self.as_ref(), false).collect()
    }
}

pub fn encode_config<T: ?Sized + AsRef<[u8]>>(input: &T, config: &Base64EncoderConfig) -> String {
    if config.padding {
        input.base64_encode_padding()
    } else {
        input.base64_encode_no_padding()
    }
}

pub fn encode<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    input.base64_encode_padding()
}

pub fn encode_no_padding<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    input.base64_encode_no_padding()
}
