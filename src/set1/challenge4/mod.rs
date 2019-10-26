pub use crate::set1::challenge3::english_decrypter::{self, RankedByte};

pub fn from_base16_lines_to_match_vec(input: &str) -> Vec<RankedByte> {
    let blocks: Vec<Block> = input
        .split('\n')
        .filter_map(|line| hex::decode(&line).ok())
        .collect();
    SingleByteXorSolver::new(&blocks).decrypt_and_rank_bytes()
}

pub fn from_base16_lines_to_match(input: &str) -> Option<RankedByte> {
    from_base16_lines_to_match_vec(input).first().cloned()
}

pub type Block = Vec<u8>;

#[derive(Clone, Debug, PartialEq)]
pub struct SingleByteXorSolver<'a> {
    blocks: &'a [Block],
}

impl<'a> SingleByteXorSolver<'a> {
    pub fn new<T: ?Sized + AsRef<[Block]>>(blocks: &'a T) -> SingleByteXorSolver {
        SingleByteXorSolver {
            blocks: blocks.as_ref(),
        }
    }

    pub fn decrypt_all_blocks(&self) -> Option<Vec<RankedByte>> {
        let ranked_bytes = self.decrypt_and_rank_bytes();
        if self.blocks.len() > ranked_bytes.len() {
            None
        } else {
            use std::collections::BTreeMap;
            let mut map: BTreeMap<usize, RankedByte> = BTreeMap::new();
            for ranked_byte in ranked_bytes {
                if let Some(value) = map.get(&ranked_byte.index) {
                    if ranked_byte.score > value.score {
                        map.insert(ranked_byte.index, ranked_byte);
                    }
                } else {
                    map.insert(ranked_byte.index, ranked_byte);
                }
            }
            Some(map.into_iter().map(|(_, value)| value).collect())
        }
    }

    pub fn decrypt_and_rank_bytes(&self) -> Vec<RankedByte> {
        let mut matches: Vec<RankedByte> = self
            .blocks
            .iter()
            .enumerate()
            .filter_map(|(index, block)| english_decrypter::decrypt(&block, index))
            .collect();
        matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        matches
    }

    pub fn decrypt_and_guess_byte(&self) -> Option<RankedByte> {
        self.decrypt_and_rank_bytes().first().cloned()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn detect_single_character_xor() {
        let contents = include_str!("4.txt");
        let expected = "Now that the party is jumping\n";
        let challenge = super::from_base16_lines_to_match(contents).unwrap();
        assert_eq!(expected, challenge.output);
    }
}
