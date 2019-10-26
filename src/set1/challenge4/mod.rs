use crate::set1::challenge3::english_decrypter;

pub fn from_base16_lines_to_match_vec(input: &str) -> Vec<english_decrypter::Match> {
    let mut matches: Vec<english_decrypter::Match> = input
        .split('\n')
        .filter_map(|line| {
            english_decrypter::decrypt_base16(&line)
                .ok()
                .and_then(|mut option| option.take())
        })
        .collect();
    matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    matches
}

pub fn from_base16_lines_to_match(input: &str) -> Option<english_decrypter::Match> {
    from_base16_lines_to_match_vec(input).first().cloned()
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
