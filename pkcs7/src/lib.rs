#![warn(
    clippy::all,
    // clippy::restriction,
    // clippy::pedantic,
    // clippy::nursery,
    // clippy::cargo,
)]

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

pub mod errors;

use errors::{Pkcs7PadError, Pkcs7UnpadError};

pub type PadResult<T> = std::result::Result<T, Pkcs7PadError>;
pub type UnpadResult<T> = std::result::Result<T, Pkcs7UnpadError>;

pub trait Pkcs7 {
    fn pkcs7_pad<I: std::iter::FromIterator<u8>>(&self, block_size: u8) -> PadResult<I>;
    fn pkcs7_unpad<I: std::iter::FromIterator<u8>>(&self, block_size: u8) -> UnpadResult<I>;
}

pub trait Pkcs7Mut {
    fn pkcs7_pad_mut(&mut self, block_size: u8) -> PadResult<()>;
    fn pkcs7_unpad_mut(&mut self, block_size: u8) -> UnpadResult<()>;
}

impl<U: ?Sized + AsRef<[u8]>> Pkcs7 for U {
    fn pkcs7_pad<I: std::iter::FromIterator<u8>>(&self, block_size: u8) -> PadResult<I> {
        if block_size == 0 {
            return Err(Pkcs7PadError::ZeroBlockSize);
        }
        let head = self.as_ref();
        if head.is_empty() {
            return Ok(head.iter().copied().collect());
        }
        let pad = block_size - (head.len() as u8 % block_size);
        let tail = std::iter::repeat(pad).take(pad as usize);
        Ok(head.iter().copied().chain(tail).collect())
    }

    fn pkcs7_unpad<I: std::iter::FromIterator<u8>>(&self, block_size: u8) -> UnpadResult<I> {
        if block_size == 0 {
            return Err(Pkcs7UnpadError::ZeroBlockSize);
        }
        let head = self.as_ref();
        if head.is_empty() {
            Ok(head.iter().copied().collect())
        } else if head.len() % block_size as usize == 0 {
            if let Some(&pad) = head.last() {
                let hlen = head.len();
                let plen = pad as usize;
                if plen >= 1 && plen <= block_size as usize && hlen > plen {
                    if let Some(position) = head[(hlen - plen)..].iter().position(|&c| c != pad) {
                        let offset = position + hlen - plen;
                        let challenge = head.get(offset).unwrap();
                        Err(Pkcs7UnpadError::InvalidPaddingByte {
                            was: *challenge,
                            offset,
                            expected: pad,
                        })
                    } else {
                        Ok(head[..(hlen - plen)].iter().copied().collect())
                    }
                } else {
                    Err(Pkcs7UnpadError::InvalidPaddingLength {
                        was: pad,
                        offset: hlen - 1,
                    })
                }
            } else {
                unreachable!()
            }
        } else {
            Err(Pkcs7UnpadError::InvalidBlockLength {
                was: head.len(),
                expected: block_size,
            })
        }
    }
}

impl<U: ?Sized + AsMut<Vec<u8>>> Pkcs7Mut for U {
    fn pkcs7_pad_mut(&mut self, block_size: u8) -> PadResult<()> {
        if block_size == 0 {
            return Err(Pkcs7PadError::ZeroBlockSize);
        }
        let head = self.as_mut();
        if head.is_empty() {
            return Ok(());
        }
        let pad = block_size - (head.len() as u8 % block_size);
        let tail = std::iter::repeat(pad).take(pad as usize);
        head.extend(tail);
        Ok(())
    }

    fn pkcs7_unpad_mut(&mut self, block_size: u8) -> UnpadResult<()> {
        if block_size == 0 {
            return Err(Pkcs7UnpadError::ZeroBlockSize);
        }
        let head = self.as_mut();
        if head.is_empty() {
            Ok(())
        } else if head.len() % block_size as usize == 0 {
            if let Some(&pad) = head.last() {
                let hlen = head.len();
                let plen = pad as usize;
                if plen >= 1 && plen <= block_size as usize && hlen > plen {
                    if let Some(position) = head[(hlen - plen)..].iter().position(|&c| c != pad) {
                        let offset = position + hlen - plen;
                        let challenge = head.get(offset).unwrap();
                        Err(Pkcs7UnpadError::InvalidPaddingByte {
                            was: *challenge,
                            offset,
                            expected: pad,
                        })
                    } else {
                        head.truncate(hlen - plen);
                        Ok(())
                    }
                } else {
                    Err(Pkcs7UnpadError::InvalidPaddingLength {
                        was: pad,
                        offset: hlen - 1,
                    })
                }
            } else {
                unreachable!()
            }
        } else {
            Err(Pkcs7UnpadError::InvalidBlockLength {
                was: head.len(),
                expected: block_size,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Pkcs7, Pkcs7Mut};
    use quickcheck::TestResult;

    #[test]
    fn pkcs7_pad_sanity_check() -> crate::PadResult<()> {
        let unpadded = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        let challenge: Vec<u8> = unpadded.pkcs7_pad(20)?;
        assert_eq!(&expected[..], &challenge[..]);
        Ok(())
    }

    #[test]
    fn pkcs7_pad_mut_sanity_check() -> crate::PadResult<()> {
        let mut unpadded = b"YELLOW SUBMARINE".to_vec();
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        unpadded.pkcs7_pad_mut(20)?;
        assert_eq!(&expected[..], &unpadded[..]);
        Ok(())
    }

    #[test]
    fn pkcs7_unpad_sanity_check() -> crate::UnpadResult<()> {
        let padded = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        let expected = b"YELLOW SUBMARINE";
        let challenge: Vec<u8> = padded.pkcs7_unpad(20)?;
        assert_eq!(&expected[..], &challenge[..]);
        Ok(())
    }

    #[test]
    fn pkcs7_unpad_mut_sanity_check() -> crate::UnpadResult<()> {
        let mut padded = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();
        let expected = b"YELLOW SUBMARINE";
        padded.pkcs7_unpad_mut(20)?;
        assert_eq!(&expected[..], &padded[..]);
        Ok(())
    }

    #[quickcheck]
    fn prop_pad_and_unpad_is_identity(xs: Vec<u8>, block_size: u8) -> TestResult {
        let test = test_pad_and_unpad_is_identity(xs, block_size);
        if block_size == 0 {
            TestResult::must_fail(move || test.unwrap())
        } else {
            TestResult::from_bool(test.unwrap())
        }
    }

    fn test_pad_and_unpad_is_identity(
        xs: Vec<u8>,
        block_size: u8,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut ys: Vec<u8> = xs.pkcs7_pad(block_size)?;
        ys.pkcs7_unpad_mut(block_size)?;
        Ok(ys == xs)
    }
}
