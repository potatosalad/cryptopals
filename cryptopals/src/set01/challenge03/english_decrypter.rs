use super::english_distribution;
use super::single_byte_xor;

#[derive(Clone, Debug, PartialEq)]
pub struct RankedByte {
    pub score: f64,
    pub byte: u8,
    pub index: usize,
    pub input: Vec<u8>,
    pub output: String,
}

pub fn decrypt_as_vec<T: ?Sized + AsRef<[u8]>>(input: &T, index: usize) -> Vec<RankedByte> {
    let mut matches: Vec<RankedByte> = (0x00_u8..=0xff_u8)
        .filter_map(|byte| {
            let output = single_byte_xor(&input, byte);
            english_distribution::ascii_histogram(&output).map(|hst| RankedByte {
                score: hst.score(),
                byte,
                index,
                input: input.as_ref().to_vec(),
                output: String::from_utf8(output).unwrap(),
            })
        })
        .filter(|m| m.score > 0.0_f64)
        .collect();
    matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    matches
}

pub fn decrypt<T: ?Sized + AsRef<[u8]>>(input: &T, index: usize) -> Option<RankedByte> {
    decrypt_as_vec(input, index).first().cloned()
}
