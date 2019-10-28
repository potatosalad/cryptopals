use rand::prelude::*;

pub use aes::cbc::{AesCbcCipher, AesCbcIv};
pub use aes::ecb::{AesEcbBlockCipher, AesEcbCipher};
pub use aes::error::AesError;
pub use aes::key::AesKey;
pub use pkcs7;

pub fn random_aes_128_key() -> AesKey {
    let mut csprng = thread_rng();
    let mut key: [u8; 16] = [0u8; 16];
    csprng.fill_bytes(&mut key);
    AesKey::aes_128_key(key)
}

pub fn random_aes_192_key() -> AesKey {
    let mut csprng = thread_rng();
    let mut key: [u8; 24] = [0u8; 24];
    csprng.fill_bytes(&mut key);
    AesKey::aes_192_key(key)
}

pub fn random_aes_256_key() -> AesKey {
    let mut csprng = thread_rng();
    let mut key: [u8; 32] = [0u8; 32];
    csprng.fill_bytes(&mut key);
    AesKey::aes_256_key(key)
}

pub fn random_aes_cbc_iv() -> AesCbcIv {
    let mut csprng = thread_rng();
    let mut iv: [u8; 16] = [0u8; 16];
    csprng.fill_bytes(&mut iv);
    AesCbcIv::aes_cbc_iv(iv)
}

pub fn aes_128_ecb_encrypt_random<T: ?Sized + AsRef<[u8]>>(
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = random_aes_128_key();
    let cipher = AesEcbCipher::new(&key);
    cipher.encrypt(plaintext)
}

pub fn aes_192_ecb_encrypt_random<T: ?Sized + AsRef<[u8]>>(
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = random_aes_192_key();
    let cipher = AesEcbCipher::new(&key);
    cipher.encrypt(plaintext)
}

pub fn aes_256_ecb_encrypt_random<T: ?Sized + AsRef<[u8]>>(
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = random_aes_256_key();
    let cipher = AesEcbCipher::new(&key);
    cipher.encrypt(plaintext)
}

pub fn aes_128_cbc_encrypt_random<T: ?Sized + AsRef<[u8]>>(
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = random_aes_128_key();
    let iv = random_aes_cbc_iv();
    let cipher = AesCbcCipher::new(&key, &iv);
    cipher.encrypt(plaintext)
}

pub fn aes_192_cbc_encrypt_random<T: ?Sized + AsRef<[u8]>>(
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = random_aes_192_key();
    let iv = random_aes_cbc_iv();
    let cipher = AesCbcCipher::new(&key, &iv);
    cipher.encrypt(plaintext)
}

pub fn aes_256_cbc_encrypt_random<T: ?Sized + AsRef<[u8]>>(
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = random_aes_256_key();
    let iv = random_aes_cbc_iv();
    let cipher = AesCbcCipher::new(&key, &iv);
    cipher.encrypt(plaintext)
}

#[derive(Clone, Debug, PartialEq)]
pub struct OracleHint {
    pub aes_ecb_mode: bool,
    pub ciphertext: Vec<u8>,
}

impl OracleHint {
    pub fn detect_aes_ecb_mode(&self, skip_blocks: usize) -> bool {
        let blocks: Vec<&[u8]> = self
            .ciphertext
            .chunks(16)
            .skip(skip_blocks)
            .take(2)
            .collect();
        blocks[0] == blocks[1]
    }
}

pub fn encryption_oracle<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<OracleHint, AesError> {
    let mut csprng = thread_rng();
    let head_size: usize = csprng.gen_range(5, 10);
    let tail_size: usize = csprng.gen_range(5, 10);
    let mut head: Vec<u8> = vec![0u8; head_size];
    let mut tail: Vec<u8> = vec![0u8; tail_size];
    csprng.fill_bytes(&mut head);
    csprng.fill_bytes(&mut tail);
    let mut body: Vec<u8> = input.as_ref().to_vec();
    head.append(&mut body);
    head.append(&mut tail);
    pkcs7::pad_mut(&mut head, 16).unwrap();
    if csprng.gen() {
        aes_128_ecb_encrypt_random(&head).map(|ciphertext| OracleHint {
            aes_ecb_mode: true,
            ciphertext,
        })
    } else {
        aes_128_cbc_encrypt_random(&head).map(|ciphertext| OracleHint {
            aes_ecb_mode: false,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn encryption_oracle_sanity_check() {
        let plaintext = vec![0u8; 16 * 3];
        let oracle = super::encryption_oracle(&plaintext).unwrap();
        assert_eq!(oracle.aes_ecb_mode, oracle.detect_aes_ecb_mode(1));
    }

    #[quickcheck]
    fn encryption_oracle_detects_aes_ecb_mode(x: usize) -> bool {
        let plaintext = vec![0u8; 16 * (3 + x)];
        let oracle = super::encryption_oracle(&plaintext).unwrap();
        oracle.aes_ecb_mode == oracle.detect_aes_ecb_mode(1)
    }
}
