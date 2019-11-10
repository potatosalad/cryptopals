// pub use aes::ctr::{decrypt_nist_sp800_38a as aes_ctr_decrypt, encrypt_nist_sp800_38a as aes_ctr_encrypt};
pub use aes::ctr::{decrypt as aes_ctr_decrypt, encrypt as aes_ctr_encrypt};
pub use aes::ctr::{AesCtrCipher, AesCtrIv, AesCtrMode};
pub use aes::error::AesError;
pub use aes::key::AesKey;

pub use crate::set01::challenge06::RepeatingKeyXorSolver;

#[derive(Clone, Debug)]
pub struct FixedNonceCtrSolver {
    pub key: AesKey,
    pub iv: AesCtrIv,
    pub mode: AesCtrMode,
    pub extra: usize,
    pub plaintexts: Vec<Vec<u8>>,
    pub ciphertexts: Vec<Vec<u8>>,
}

impl FixedNonceCtrSolver {
    pub fn new<K: ?Sized + AsRef<[u8]>, IV: ?Sized + AsRef<[u8]>>(
        key: &K,
        iv: &IV,
        mode: AesCtrMode,
    ) -> Result<FixedNonceCtrSolver, AesError> {
        Ok(FixedNonceCtrSolver {
            key: AesKey::try_copy_from_slice(key)?,
            iv: AesCtrIv::try_copy_from_slice(iv)?,
            mode,
            extra: 0,
            plaintexts: Vec::new(),
            ciphertexts: Vec::new(),
        })
    }

    pub fn push<T: ?Sized + AsRef<[u8]>>(&mut self, plaintext: &T) {
        let cipher = AesCtrCipher::new(&self.key, &self.iv, self.mode);
        let plaintext: Vec<u8> = plaintext.as_ref().to_vec();
        let ciphertext: Vec<u8> = cipher.encrypt(&plaintext).unwrap();
        self.plaintexts.push(plaintext);
        self.ciphertexts.push(ciphertext);
    }

    pub fn push_extra<T: ?Sized + AsRef<[u8]>>(&mut self, plaintext: &T) {
        self.extra += 1;
        self.push(plaintext);
    }

    pub fn keysize(&self) -> usize {
        self.ciphertexts.iter().map(|c| c.len()).max().unwrap_or(0)
    }

    pub fn generate_extra(&mut self) {
        let keysize = self.keysize();
        let plaintexts: Vec<Vec<u8>> = (b'a'..=b'z')
            .chain(b'A'..=b'Z')
            .chain(b'0'..=b'9')
            .map(|byte| vec![byte; keysize])
            .collect();
        self.extra += plaintexts.len();
        self.extend(plaintexts);
    }

    pub fn keystream(&self) -> Option<Vec<u8>> {
        let keysize: usize = self.keysize();
        let mut offsets: Vec<usize> = Vec::new();
        let mut transposed: Vec<Vec<u8>> = Vec::new();
        for ciphertext in self.ciphertexts.iter() {
            for (i, c) in ciphertext.iter().enumerate() {
                if let Some(v) = transposed.get_mut(i) {
                    v.push(*c);
                } else {
                    offsets.insert(i, 0_usize);
                    transposed.insert(i, vec![*c]);
                }
            }
        }
        let padded_ciphertexts: Vec<Vec<u8>> = self
            .ciphertexts
            .iter()
            .map(|ciphertext| {
                let mut ciphertext = ciphertext.to_vec();
                while ciphertext.len() < keysize {
                    let idx = ciphertext.len();
                    let values = &transposed[idx];
                    let offset = offsets.get_mut(idx).unwrap();
                    let byte = values[*offset % values.len()];
                    *offset += 1;
                    ciphertext.push(byte);
                }
                ciphertext
            })
            .collect();
        let ciphertext: Vec<u8> = padded_ciphertexts.concat();
        let solver = RepeatingKeyXorSolver::new(&ciphertext, keysize as u32);
        solver.guess_key().map(|ranked_key| ranked_key.key)
    }

    pub fn decrypt<T: ?Sized + AsRef<[u8]>>(&self, keystream: &T) -> Vec<Vec<u8>> {
        self.ciphertexts
            .iter()
            .map(|ciphertext| {
                let plaintext: Vec<u8> = xor::rxor::rxor(&ciphertext, &keystream);
                plaintext
            })
            .collect()
    }
}

impl Extend<Vec<u8>> for FixedNonceCtrSolver {
    #[inline]
    fn extend<I: IntoIterator<Item = Vec<u8>>>(&mut self, iter: I) {
        let cipher = AesCtrCipher::new(&self.key, &self.iv, self.mode);
        for plaintext in iter.into_iter() {
            let ciphertext: Vec<u8> = cipher.encrypt(&plaintext).unwrap();
            self.plaintexts.push(plaintext);
            self.ciphertexts.push(ciphertext);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    lazy_static! {
        #[derive(Clone, Copy, Debug, PartialEq)]
        static ref TEST_VECTORS: Vec<Vec<u8>> = {
            let contents = include_str!("19.txt");
            contents.split('\n').filter_map(|line| base64::decode(&line).ok()).collect::<Vec<Vec<u8>>>()
        };
    }

    #[test]
    fn break_fixed_nonce_ctr_mode_using_substitutions() {
        use rand::prelude::*;
        let mut csprng = thread_rng();
        let mut key: [u8; 16] = [0_u8; 16];
        let mut iv: [u8; 16] = [0_u8; 16];
        csprng.fill_bytes(&mut key);
        csprng.fill_bytes(&mut iv);
        let mut solver = FixedNonceCtrSolver::new(&key, &iv, AesCtrMode::CRYPTOPALS).unwrap();
        solver.extend(TEST_VECTORS.iter().cloned());
        solver.generate_extra();
        let keystream = solver.keystream().unwrap();
        let decrypted = solver.decrypt(&keystream);
        assert_eq!(solver.plaintexts, decrypted);
    }

    #[test]
    fn break_fixed_nonce_ctr_mode_using_substitutions_nist_sp800_38a() {
        use rand::prelude::*;
        let mut csprng = thread_rng();
        let mut key: [u8; 16] = [0_u8; 16];
        let mut iv: [u8; 16] = [0_u8; 16];
        csprng.fill_bytes(&mut key);
        csprng.fill_bytes(&mut iv);
        let mut solver = FixedNonceCtrSolver::new(&key, &iv, AesCtrMode::NIST_SP800_38A).unwrap();
        solver.extend(TEST_VECTORS.iter().cloned());
        solver.generate_extra();
        let keystream = solver.keystream().unwrap();
        let decrypted = solver.decrypt(&keystream);
        assert_eq!(solver.plaintexts, decrypted);
    }
}
