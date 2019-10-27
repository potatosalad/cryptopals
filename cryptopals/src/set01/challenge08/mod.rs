#[derive(Clone, Debug, PartialEq)]
pub struct MaybeAesEcb<'a> {
    pub duplicates: usize,
    pub index: usize,
    pub input: &'a str,
}

fn count_duplicate_blocks(line: &[u8]) -> usize {
    let expected = (line.len() + 16 - 1) / 16;
    let mut blocks: Vec<Vec<u8>> = line.chunks_exact(16).map(|chunk| chunk.to_vec()).collect();
    blocks.sort();
    blocks.dedup();
    expected - blocks.len()
}

pub fn find_duplicate_blocks_in_lines(input: &str) -> Vec<MaybeAesEcb> {
    let mut blocks: Vec<MaybeAesEcb> = input
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            if let Ok(decoded) = hex::decode(&line.trim()) {
                if !decoded.is_empty() && decoded.len() % 16 == 0 {
                    let duplicates = count_duplicate_blocks(decoded.as_slice());
                    if duplicates > 0 {
                        return Some(MaybeAesEcb {
                            duplicates,
                            index,
                            input: line,
                        });
                    }
                }
            }
            None
        })
        .collect();
    blocks.sort_by(|a, b| b.duplicates.partial_cmp(&a.duplicates).unwrap());
    blocks
}

#[cfg(test)]
mod tests {
    const TEST_VECTOR: &str = include_str!("8.txt");

    #[test]
    fn detect_aes_in_ebc_mode() {
        let maybe_aes_ecb = super::find_duplicate_blocks_in_lines(&TEST_VECTOR);
        let challenge = maybe_aes_ecb.first().cloned().unwrap();
        let expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        assert_eq!(132, challenge.index);
        assert_eq!(3, challenge.duplicates);
        assert_eq!(expected, challenge.input);
    }
}
