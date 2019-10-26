use crate::set1::challenge1::base16::{self, decoder::Base16DecoderError};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FixedXorError {
    MustBeEqualLength,
    Base16(Base16DecoderError),
}

impl std::error::Error for FixedXorError {
    #[must_use]
    fn description(&self) -> &str {
        match *self {
            Self::MustBeEqualLength => "inputs must be of equal length",
            Self::Base16(ref err) => err.description(),
        }
    }
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

#[cfg(test)]
mod tests {
    #[test]
    fn fixed_xor_should_produce() {
        let xs = "1c0111001f010100061a024b53535009181c";
        let ys = "686974207468652062756c6c277320657965";
        let zs = "746865206b696420646f6e277420706c6179";
        assert_eq!(zs, super::fixed_xor_base16(&xs, &ys).unwrap());
    }
}
