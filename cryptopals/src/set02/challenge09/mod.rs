#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Pkcs7Error {
    InvalidBlockSize,
    InvalidPadding,
}

impl std::error::Error for Pkcs7Error {
    #[must_use]
    fn description(&self) -> &str {
        match *self {
            Self::InvalidBlockSize => "invalid block size",
            Self::InvalidPadding => "invalid padding",
        }
    }
}

impl ::core::fmt::Display for Pkcs7Error {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match *self {
            Self::InvalidBlockSize => write!(f, "Invalid block size"),
            Self::InvalidPadding => write!(f, "Invalid padding"),
        }
    }
}

pub fn pkcs7_pad<T: ?Sized + AsRef<[u8]>>(input: &T, block_size: u8) -> Vec<u8> {
    let mut bytes = input.as_ref().to_vec();
    let pad = block_size - (bytes.len() as u8 % block_size);
    let mut padding = vec![pad; pad as usize];
    bytes.append(&mut padding);
    bytes
}

pub fn pkcs7_unpad<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    block_size: u8,
) -> Result<Vec<u8>, Pkcs7Error> {
    let input = input.as_ref();
    if input.is_empty() {
        Ok(vec![])
    } else if input.len() % block_size as usize == 0 {
        let mut bytes = input.to_vec();
        if let Some(&pad) = bytes.last() {
            let mut count = pad as usize;
            if count >= 1 && count <= block_size as usize && bytes.len() > count {
                while count > 0 {
                    if bytes.pop().unwrap() == pad {
                        count -= 1;
                    } else {
                        return Err(Pkcs7Error::InvalidPadding);
                    }
                }
                return Ok(bytes);
            }
        }
        Err(Pkcs7Error::InvalidPadding)
    } else {
        Err(Pkcs7Error::InvalidBlockSize)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn implement_pkcs7_padding() {
        let plaintext = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        let challenge = super::pkcs7_pad(&plaintext, 20);
        assert_eq!(&expected[..], &challenge[..]);
        let challenge = super::pkcs7_unpad(&expected, 20).unwrap();
        assert_eq!(&plaintext[..], &challenge[..]);
    }
}
