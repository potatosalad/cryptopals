use crate::set01::challenge04::{Block, SingleByteXorSolver};
pub use crate::set01::challenge05::RepeatingKeyXor;

pub fn hamming_distance<X: ?Sized + AsRef<[u8]>, Y: ?Sized + AsRef<[u8]>>(xs: &X, ys: &Y) -> u32 {
    xs.as_ref()
        .iter()
        .zip(ys.as_ref().iter())
        .fold(0_u32, |sum, (x, y)| sum + (*x ^ *y).count_ones())
}

pub fn rank_key_sizes<T: ?Sized + AsRef<[u8]>>(
    ciphertext: &T,
    max_key_size: u32,
) -> Vec<(f64, u32)> {
    let ciphertext = ciphertext.as_ref();
    let mut key_size: u32 = 2;
    match ciphertext.len() {
        0 => vec![],
        1 => vec![(1.0, 1)],
        clen => {
            let mut distances: Vec<(f64, u32)> = Vec::new();
            while clen > (2 * key_size as usize) && key_size <= max_key_size {
                let idx = key_size as usize;
                let lhs = &ciphertext[..idx];
                let rhs = &ciphertext[idx..];
                distances.push((
                    f64::from(hamming_distance(lhs, rhs)) / f64::from(key_size),
                    key_size,
                ));
                key_size += 1;
            }
            distances.sort_by(|(a, _), (b, _)| a.partial_cmp(b).unwrap());
            distances
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RankedKey {
    pub key: Vec<u8>,
    pub score: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RepeatingKeyXorSolver<'a> {
    ciphertext: &'a [u8],
    key_sizes: Vec<(f64, u32)>,
}

impl<'a> RepeatingKeyXorSolver<'a> {
    pub fn new<T: ?Sized + AsRef<[u8]>>(
        ciphertext: &'a T,
        max_key_size: u32,
    ) -> RepeatingKeyXorSolver {
        RepeatingKeyXorSolver {
            ciphertext: ciphertext.as_ref(),
            key_sizes: rank_key_sizes(&ciphertext, max_key_size),
        }
    }

    pub fn get_key_size_by_index(&self, index: usize) -> Option<usize> {
        let (_, key_size) = self.key_sizes.get(index)?;
        Some(*key_size as usize)
    }

    pub fn get_blocks_by_index(&self, index: usize) -> Option<Vec<Block>> {
        self.get_key_size_by_index(index)
            .and_then(|key_size| self.get_blocks_by_key_size(key_size))
    }

    pub fn decrypt_and_rank_keys(&self) -> Vec<RankedKey> {
        let mut keys: Vec<RankedKey> = Vec::new();
        for index in 0_usize..self.key_sizes.len() {
            let key_size = self.get_key_size_by_index(index).unwrap();
            let blocks = self.get_blocks_by_key_size(key_size).unwrap();
            if let Some(ranked_bytes) = SingleByteXorSolver::new(&blocks).decrypt_all_blocks() {
                let key: Vec<u8> = ranked_bytes
                    .iter()
                    .take(key_size)
                    .map(|ranked_byte| ranked_byte.byte)
                    .collect();
                let score: f64 = ranked_bytes
                    .iter()
                    .take(key_size)
                    .map(|ranked_byte| ranked_byte.score)
                    .sum::<f64>()
                    / f64::from(key_size as u32);
                keys.push(RankedKey { key, score });
            }
        }
        keys.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        keys
    }

    pub fn guess_key(&self) -> Option<RankedKey> {
        self.decrypt_and_rank_keys().first().cloned()
    }

    pub fn guess_key_and_decrypt(&self) -> Option<String> {
        let ranked_key = self.guess_key()?;
        let mut cipher = RepeatingKeyXor::new(&ranked_key.key);
        String::from_utf8(cipher.encrypt(&self.ciphertext)).ok()
    }

    fn get_blocks_by_key_size(&self, key_size: usize) -> Option<Vec<Block>> {
        let capacity = (self.ciphertext.len() + key_size - 1) / key_size;
        let mut blocks: Vec<Block> = Vec::with_capacity(capacity);
        for chunk in self.ciphertext.chunks(key_size) {
            for k in 0..key_size {
                if let Some(c) = chunk.get(k) {
                    if let Some(block) = blocks.get_mut(k) {
                        block
                    } else {
                        blocks.insert(k, Vec::new());
                        unsafe { blocks.get_unchecked_mut(k) }
                    }
                    .push(*c);
                }
            }
        }
        Some(blocks)
    }
}

#[cfg(test)]
mod tests {
    lazy_static! {
        #[derive(Clone, Copy, Debug, PartialEq)]
        static ref TEST_VECTOR: String = {
            let contents = include_str!("6.txt");
            contents.chars().filter(|c| !c.is_whitespace()).collect::<String>()
        };
    }

    #[test]
    fn hamming_distance_sanity_check() {
        assert_eq!(3_u32, super::hamming_distance("hello", "help"));
        assert_eq!(
            37_u32,
            super::hamming_distance("this is a test", "wokka wokka!!!")
        );
    }

    #[test]
    fn rank_key_sizes_sanity_check() {
        let ciphertext = base64::decode(&*TEST_VECTOR).unwrap();
        let key_sizes = super::rank_key_sizes(&ciphertext, 40);
        assert_eq!(vec![(1.2, 5), (2.0, 3), (2.5, 2)], &key_sizes[..3]);
    }

    #[ignore]
    #[test]
    fn repeating_key_xor_solver() {
        use super::RepeatingKeyXorSolver;
        let ciphertext = base64::decode(&*TEST_VECTOR).unwrap();
        let solver = RepeatingKeyXorSolver::new(&ciphertext, 40);
        let plaintext = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
        assert_eq!(plaintext, solver.guess_key_and_decrypt().unwrap());
    }
}
