use super::english_distribution;
use super::single_byte_xor;
use crate::set1::challenge1::base16::{self, decoder::Base16DecoderError};

pub fn decrypt_as_vec<T: ?Sized + AsRef<[u8]>>(input: &T) -> Vec<(f64, String, u8)> {
    let mut matches: Vec<(f64, String, u8)> = (0x00_u8..=0xff_u8)
        .filter_map(|byte| {
            let output = single_byte_xor(&input, byte);
            english_distribution::ascii_histogram(&output)
                .map(|hst| (hst.score(), String::from_utf8(output).unwrap(), byte))
        })
        .filter(|(score, _, _)| *score > 0.0_f64)
        .collect();
    matches.sort_by(|(a, _, _), (b, _, _)| b.partial_cmp(a).unwrap());
    matches
}

pub fn decrypt_as_vec_base16<T: ?Sized + AsRef<[u8]>>(
    input: &T,
) -> Result<Vec<(f64, String, u8)>, Base16DecoderError> {
    Ok(decrypt_as_vec(&base16::decode(input)?))
}

pub fn decrypt<T: ?Sized + AsRef<[u8]>>(input: &T) -> Option<(String, u8)> {
    decrypt_as_vec(input)
        .first()
        .map(|(_, output, byte)| (output.clone(), *byte))
}

pub fn decrypt_base16<T: ?Sized + AsRef<[u8]>>(
    input: &T,
) -> Result<Option<(String, u8)>, Base16DecoderError> {
    Ok(decrypt(&base16::decode(input)?))
}
