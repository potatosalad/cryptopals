use super::english_distribution;
use super::single_byte_xor;
use crate::set1::challenge1::base16::{self, decoder::Base16DecoderError};

#[derive(Clone, Debug, PartialEq)]
pub struct Match {
    pub score: f64,
    pub byte: u8,
    pub output: String,
}

pub fn decrypt_as_vec<T: ?Sized + AsRef<[u8]>>(input: &T) -> Vec<Match> {
    let mut matches: Vec<Match> = (0x00_u8..=0xff_u8)
        .filter_map(|byte| {
            let output = single_byte_xor(&input, byte);
            english_distribution::ascii_histogram(&output).map(|hst| Match {
                score: hst.score(),
                byte,
                output: String::from_utf8(output).unwrap(),
            })
        })
        .filter(|m| m.score > 0.0_f64)
        .collect();
    matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    matches
}

pub fn decrypt_as_vec_base16<T: ?Sized + AsRef<[u8]>>(
    input: &T,
) -> Result<Vec<Match>, Base16DecoderError> {
    Ok(decrypt_as_vec(&base16::decode(input)?))
}

pub fn decrypt<T: ?Sized + AsRef<[u8]>>(input: &T) -> Option<Match> {
    decrypt_as_vec(input).first().cloned()
}

pub fn decrypt_base16<T: ?Sized + AsRef<[u8]>>(
    input: &T,
) -> Result<Option<Match>, Base16DecoderError> {
    Ok(decrypt(&base16::decode(input)?))
}
