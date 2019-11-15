pub use aes::ctr::{
    encrypt as aes_ctr_encrypt, encrypt_at_offset as aes_ctr_encrypt_at_offset, AesCtrIv,
};
pub use aes::error::AesError;
pub use aes::key::AesKey;

use rand::prelude::*;

#[derive(Clone, Debug)]
pub struct RandomReadWriteAesCtrOracle {
    key: AesKey,
    iv: AesCtrIv,
}

impl RandomReadWriteAesCtrOracle {
    pub fn random() -> Self {
        let mut csprng = thread_rng();
        let key: AesKey = csprng.gen();
        let iv: AesCtrIv = csprng.gen();
        Self { key, iv }
    }

    pub fn encrypt<T: ?Sized + AsRef<[u8]>>(&self, plaintext: &T) -> Result<Vec<u8>, AesError> {
        aes_ctr_encrypt(self.key.as_slice(), self.iv.as_slice(), plaintext)
    }

    pub fn edit<CT: ?Sized + AsRef<[u8]>, PT: ?Sized + AsRef<[u8]>>(
        &self,
        ciphertext: &CT,
        offset: usize,
        plaintext: &PT,
    ) -> Result<Vec<u8>, AesError> {
        let ciphertext = ciphertext.as_ref();
        if offset > ciphertext.len() {
            return Err(AesError::InvalidOffset {
                length: ciphertext.len(),
                offset,
            });
        }
        let mut ciphertext: Vec<u8> = ciphertext.to_vec();
        let tail: Vec<u8> =
            aes_ctr_encrypt_at_offset(self.key.as_slice(), self.iv.as_slice(), plaintext, offset)?;
        if offset + tail.len() > ciphertext.len() {
            let extra_size: usize = ciphertext.len() - (offset + tail.len());
            ciphertext.extend(vec![0_u8; extra_size]);
        }
        ciphertext
            .splice(offset..(offset + tail.len()), tail)
            .for_each(drop);
        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    lazy_static! {
        #[derive(Clone, Copy, Debug, PartialEq)]
        static ref TEST_VECTOR: Vec<u8> = {
            let contents = include_str!("25.txt");
            base64::decode(&contents.chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap()
        };
    }

    #[test]
    fn break_random_access_read_write_aes_ctr() {
        let plaintext: Vec<u8> = TEST_VECTOR.to_vec();
        let oracle = RandomReadWriteAesCtrOracle::random();
        let ciphertext: Vec<u8> = oracle.encrypt(&plaintext).unwrap();
        let attack_plaintext: Vec<u8> = vec![0; ciphertext.len()];
        let keystream: Vec<u8> = oracle.edit(&ciphertext, 0, &attack_plaintext).unwrap();
        let challenge: Vec<u8> = xor::exor::exor(&ciphertext, &keystream).unwrap();
        assert_eq!(plaintext, challenge);
    }
}
