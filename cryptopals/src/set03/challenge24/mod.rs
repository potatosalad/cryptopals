pub use std::time::{Duration, SystemTime};

pub use crate::set03::challenge21::*;

#[derive(Clone, Debug)]
pub struct MersenneTwister19937Keystream {
    mt: MersenneTwister19937,
    data: [u8; 4],
    offset: usize,
}

impl MersenneTwister19937Keystream {
    pub fn new(seed: u32) -> Self {
        Self::from(MersenneTwister19937::new(seed))
    }

    pub fn encrypt<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &self,
        plaintext: &T,
    ) -> I {
        self.clone().encrypt_mut(plaintext)
    }

    pub fn decrypt<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &self,
        ciphertext: &T,
    ) -> I {
        self.clone().decrypt_mut(ciphertext)
    }

    fn crypt_mut<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &mut self,
        input: &T,
    ) -> I {
        input
            .as_ref()
            .iter()
            .zip(self)
            .map(|(a, b)| a ^ b)
            .collect()
    }

    pub fn encrypt_mut<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &mut self,
        plaintext: &T,
    ) -> I {
        self.crypt_mut(plaintext)
    }

    pub fn decrypt_mut<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &mut self,
        ciphertext: &T,
    ) -> I {
        self.crypt_mut(ciphertext)
    }
}

impl Default for MersenneTwister19937Keystream {
    fn default() -> Self {
        Self::from(MersenneTwister19937::default())
    }
}

impl From<u16> for MersenneTwister19937Keystream {
    fn from(seed: u16) -> Self {
        Self::new(seed as u32)
    }
}

impl From<MersenneTwister19937> for MersenneTwister19937Keystream {
    fn from(mt: MersenneTwister19937) -> Self {
        Self {
            mt,
            data: [0_u8; 4],
            offset: 4,
        }
    }
}

impl Iterator for MersenneTwister19937Keystream {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            self.data = self.mt.generate().to_be_bytes();
            self.offset = 0;
        }
        let output = self.data[self.offset];
        self.offset += 1;
        Some(output)
    }
}

#[derive(Clone, Debug)]
pub struct MersenneTwister19937_64Keystream {
    mt: MersenneTwister19937_64,
    data: [u8; 8],
    offset: usize,
}

impl MersenneTwister19937_64Keystream {
    pub fn new(seed: u64) -> Self {
        Self::from(MersenneTwister19937_64::new(seed))
    }

    pub fn encrypt<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &self,
        plaintext: &T,
    ) -> I {
        self.clone().encrypt_mut(plaintext)
    }

    pub fn decrypt<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &self,
        ciphertext: &T,
    ) -> I {
        self.clone().decrypt_mut(ciphertext)
    }

    fn crypt_mut<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &mut self,
        input: &T,
    ) -> I {
        input
            .as_ref()
            .iter()
            .zip(self)
            .map(|(a, b)| a ^ b)
            .collect()
    }

    pub fn encrypt_mut<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &mut self,
        plaintext: &T,
    ) -> I {
        self.crypt_mut(plaintext)
    }

    pub fn decrypt_mut<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &mut self,
        ciphertext: &T,
    ) -> I {
        self.crypt_mut(ciphertext)
    }
}

impl Default for MersenneTwister19937_64Keystream {
    fn default() -> Self {
        Self::from(MersenneTwister19937_64::default())
    }
}

impl From<u16> for MersenneTwister19937_64Keystream {
    fn from(seed: u16) -> Self {
        Self::new(seed as u64)
    }
}

impl From<MersenneTwister19937_64> for MersenneTwister19937_64Keystream {
    fn from(mt: MersenneTwister19937_64) -> Self {
        Self {
            mt,
            data: [0_u8; 8],
            offset: 8,
        }
    }
}

impl Iterator for MersenneTwister19937_64Keystream {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            self.data = self.mt.generate().to_be_bytes();
            self.offset = 0;
        }
        let output = self.data[self.offset];
        self.offset += 1;
        Some(output)
    }
}

pub fn brute_force_an_mt19937_seed_from_nth(
    output: u32,
    nth: usize,
    candidates: impl Iterator<Item = u32>,
) -> Option<u32> {
    let mut mt = mt19937_init(0);
    for candidate in candidates {
        mt.reseed(candidate);
        if output == mt.nth(nth).unwrap() {
            return Some(candidate);
        }
    }
    None
}

pub fn brute_force_an_mt19937_64_seed_from_nth(
    output: u64,
    nth: usize,
    candidates: impl Iterator<Item = u64>,
) -> Option<u64> {
    let mut mt = mt19937_64_init(0);
    for candidate in candidates {
        mt.reseed(candidate);
        if output == mt.nth(nth).unwrap() {
            return Some(candidate);
        }
    }
    None
}

pub fn mt19937_password_reset_token(seed: u32) -> String {
    let output: u32 = mt19937_init(seed).generate() % 999_999;
    format!("{:06}", output)
}

pub fn mt19937_64_password_reset_token(seed: u64) -> String {
    let output: u64 = mt19937_64_init(seed).generate() % 999_999;
    format!("{:06}", output)
}

pub fn brute_force_an_mt19937_seed_from_password_reset_token(
    token: &str,
    candidates: impl Iterator<Item = u32>,
) -> Option<u32> {
    for candidate in candidates {
        if token == mt19937_password_reset_token(candidate) {
            return Some(candidate);
        }
    }
    None
}

pub fn brute_force_an_mt19937_64_seed_from_password_reset_token(
    token: &str,
    candidates: impl Iterator<Item = u64>,
) -> Option<u64> {
    for candidate in candidates {
        if token == mt19937_64_password_reset_token(candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[ignore]
    #[test]
    fn mt19937_recover_password_reset_token() {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let token = mt19937_password_reset_token(seed);
        let now = SystemTime::now();
        let start_time = now.checked_sub(Duration::from_secs(60 * 60)).unwrap();
        let stop_time = now.checked_add(Duration::from_secs(60 * 60)).unwrap();
        let start_seed = start_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let stop_seed = stop_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let challenge_seed = brute_force_an_mt19937_seed_from_password_reset_token(
            token.as_str(),
            start_seed..stop_seed,
        )
        .unwrap();
        let challenge_token = mt19937_password_reset_token(challenge_seed);
        assert_eq!(seed, challenge_seed);
        assert_eq!(token, challenge_token);
    }

    #[ignore]
    #[test]
    fn mt19937_64_recover_password_reset_token() {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = mt19937_64_password_reset_token(seed);
        let now = SystemTime::now();
        let start_time = now.checked_sub(Duration::from_secs(60 * 60)).unwrap();
        let stop_time = now.checked_add(Duration::from_secs(60 * 60)).unwrap();
        let start_seed = start_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let stop_seed = stop_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let challenge_seed = brute_force_an_mt19937_64_seed_from_password_reset_token(
            token.as_str(),
            start_seed..stop_seed,
        )
        .unwrap();
        let challenge_token = mt19937_64_password_reset_token(challenge_seed);
        assert_eq!(seed, challenge_seed);
        assert_eq!(token, challenge_token);
    }

    #[ignore]
    #[test]
    fn mt19937_recover_16_bit_key() {
        let mut csprng = thread_rng();
        let seed: u16 = csprng.gen();
        let keystream = MersenneTwister19937Keystream::from(seed);
        let prefix_len: usize = csprng.gen_range(1..=255);
        let plaintext = {
            let mut v: Vec<u8> = std::iter::repeat_with(|| csprng.gen())
                .take(prefix_len)
                .collect();
            v.extend_from_slice(&[b'A'; 14]);
            v
        };
        let ciphertext: Vec<u8> = keystream.encrypt(&plaintext);
        let last_block_index: usize = ciphertext.len() / 4 - 1;
        let mut last_block: [u8; 4] = [0_u8; 4];
        let last_block_vec: Vec<u8> = xor::exor::exor(
            &ciphertext[4 * last_block_index..4 * (last_block_index + 1)],
            &[b'A'; 4],
        )
        .unwrap();
        last_block.copy_from_slice(&last_block_vec[..]);
        let output: u32 = u32::from_be_bytes(last_block);
        let challenge_seed: u32 = brute_force_an_mt19937_seed_from_nth(
            output,
            last_block_index,
            0..(u32::from(std::u16::MAX)),
        )
        .unwrap();
        let challenge_keystream = MersenneTwister19937Keystream::new(challenge_seed);
        let challenge_plaintext: Vec<u8> = challenge_keystream.decrypt(&ciphertext);
        assert_eq!(seed as u32, challenge_seed);
        assert_eq!(plaintext, challenge_plaintext);
    }

    #[ignore]
    #[test]
    fn mt19937_64_recover_16_bit_key() {
        let mut csprng = thread_rng();
        let seed: u16 = csprng.gen();
        let keystream = MersenneTwister19937_64Keystream::from(seed);
        let prefix_len: usize = csprng.gen_range(1..=255);
        let plaintext = {
            let mut v: Vec<u8> = std::iter::repeat_with(|| csprng.gen())
                .take(prefix_len)
                .collect();
            v.extend_from_slice(&[b'A'; 14]);
            v
        };
        let ciphertext: Vec<u8> = keystream.encrypt(&plaintext);
        let last_block_index: usize = ciphertext.len() / 8 - 1;
        let mut last_block: [u8; 8] = [0_u8; 8];
        let last_block_vec: Vec<u8> = xor::exor::exor(
            &ciphertext[8 * last_block_index..8 * (last_block_index + 1)],
            &[b'A'; 8],
        )
        .unwrap();
        last_block.copy_from_slice(&last_block_vec[..]);
        let output: u64 = u64::from_be_bytes(last_block);
        let challenge_seed: u64 = brute_force_an_mt19937_64_seed_from_nth(
            output,
            last_block_index,
            0..(u64::from(std::u16::MAX)),
        )
        .unwrap();
        let challenge_keystream = MersenneTwister19937_64Keystream::new(challenge_seed);
        let challenge_plaintext: Vec<u8> = challenge_keystream.decrypt(&ciphertext);
        assert_eq!(seed as u64, challenge_seed);
        assert_eq!(plaintext, challenge_plaintext);
    }

    #[quickcheck]
    fn mt19937_encrypt_and_decrypt_is_identity_with_16_bit_seed(
        seed: u16,
        plaintext: Vec<u8>,
    ) -> bool {
        let keystream = MersenneTwister19937Keystream::from(seed);
        let ciphertext: Vec<u8> = keystream.encrypt(&plaintext);
        let challenge: Vec<u8> = keystream.decrypt(&ciphertext);
        plaintext == challenge
    }

    #[quickcheck]
    fn mt19937_encrypt_and_decrypt_is_identity(seed: u32, plaintext: Vec<u8>) -> bool {
        let keystream = MersenneTwister19937Keystream::new(seed);
        let ciphertext: Vec<u8> = keystream.encrypt(&plaintext);
        let challenge: Vec<u8> = keystream.decrypt(&ciphertext);
        plaintext == challenge
    }

    #[quickcheck]
    fn mt19937_64_encrypt_and_decrypt_is_identity_with_16_bit_seed(
        seed: u16,
        plaintext: Vec<u8>,
    ) -> bool {
        let keystream = MersenneTwister19937_64Keystream::from(seed);
        let ciphertext: Vec<u8> = keystream.encrypt(&plaintext);
        let challenge: Vec<u8> = keystream.decrypt(&ciphertext);
        plaintext == challenge
    }

    #[quickcheck]
    fn mt19937_64_encrypt_and_decrypt_is_identity(seed: u64, plaintext: Vec<u8>) -> bool {
        let keystream = MersenneTwister19937_64Keystream::new(seed);
        let ciphertext: Vec<u8> = keystream.encrypt(&plaintext);
        let challenge: Vec<u8> = keystream.decrypt(&ciphertext);
        plaintext == challenge
    }
}
