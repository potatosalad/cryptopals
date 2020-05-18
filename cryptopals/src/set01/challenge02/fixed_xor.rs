use crate::set01::challenge01::base16::{self, decoder::Base16DecoderError};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FixedXorError {
    MustBeEqualLength,
    Base16(Base16DecoderError),
}

impl ::core::fmt::Display for FixedXorError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match *self {
            Self::MustBeEqualLength => write!(f, "Inputs must be of equal length"),
            Self::Base16(ref err) => err.fmt(f),
        }
    }
}

impl From<Base16DecoderError> for FixedXorError {
    #[must_use]
    fn from(value: Base16DecoderError) -> Self {
        Self::Base16(value)
    }
}

pub fn fixed_xor<T: ?Sized + AsRef<[u8]>, U: ?Sized + AsRef<[u8]>>(
    xs: &T,
    ys: &U,
) -> Result<Vec<u8>, FixedXorError> {
    let xs = xs.as_ref();
    let ys = ys.as_ref();
    if xs.len() != ys.len() {
        return Err(FixedXorError::MustBeEqualLength);
    }
    Ok(xs.iter().zip(ys.iter()).map(|(x, y)| x ^ y).collect())
}

pub fn fixed_xor_base16<T: ?Sized + AsRef<[u8]>, U: ?Sized + AsRef<[u8]>>(
    xs: &T,
    ys: &U,
) -> Result<String, FixedXorError> {
    let xs = base16::decode(xs).map_err(FixedXorError::from)?;
    let ys = base16::decode(ys).map_err(FixedXorError::from)?;
    fixed_xor(&xs, &ys).map(|zs| base16::encode(&zs))
}
