use rand::prelude::*;
use xor::exor::{exor, exor_mut};

use crate::ecb::AesEcbBlockCipher;
use crate::error::AesError;
use crate::key::AesKey;

pub struct AesCbcIv([u8; 16]);

impl AesCbcIv {
    pub fn aes_cbc_iv(value: [u8; 16]) -> AesCbcIv {
        AesCbcIv(value)
    }

    pub fn try_copy_from_slice<IV: ?Sized + AsRef<[u8]>>(bytes: &IV) -> Result<AesCbcIv, AesError> {
        let bytes = bytes.as_ref();
        match bytes.len() {
            16 => {
                let mut iv: [u8; 16] = [0u8; 16];
                iv.copy_from_slice(&bytes);
                Ok(Self::aes_cbc_iv(iv))
            }
            x => Err(AesError::InvalidInitializationVectorSize {
                was: x,
                explanation: "must be 16 bytes",
            }),
        }
    }
}

impl Distribution<AesCbcIv> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> AesCbcIv {
        AesCbcIv(rng.gen())
    }
}

pub struct AesCbcCipher<'k, 'iv> {
    key: &'k AesKey,
    iv: &'iv AesCbcIv,
}

impl<'k, 'iv> AesCbcCipher<'k, 'iv> {
    pub fn new(key: &'k AesKey, iv: &'iv AesCbcIv) -> AesCbcCipher<'k, 'iv> {
        AesCbcCipher { key, iv }
    }

    pub fn decrypt<T: ?Sized + AsRef<[u8]>>(&self, ciphertext: &T) -> Result<Vec<u8>, AesError> {
        let ciphertext = ciphertext.as_ref();
        match ciphertext.len() {
            0 => Ok(vec![]),
            x => {
                if x % 16 == 0 {
                    let block_cipher = AesEcbBlockCipher::new(&self.key);
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(&self.iv.0[..]);
                    Ok(ciphertext
                        .chunks(16_usize)
                        .flat_map(|encrypted_block| {
                            let mut decrypted_block =
                                block_cipher.decrypt_block(&encrypted_block).unwrap();
                            exor_mut(&mut decrypted_block, &iv).unwrap();
                            iv.copy_from_slice(&encrypted_block[..]);
                            decrypted_block.into_iter()
                        })
                        .collect())
                } else {
                    Err(AesError::InvalidBlockSize(x))
                }
            }
        }
    }

    pub fn encrypt<T: ?Sized + AsRef<[u8]>>(&self, plaintext: &T) -> Result<Vec<u8>, AesError> {
        let plaintext = plaintext.as_ref();
        match plaintext.len() {
            0 => Ok(vec![]),
            x => {
                if x % 16 == 0 {
                    let block_cipher = AesEcbBlockCipher::new(&self.key);
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(&self.iv.0[..]);
                    Ok(plaintext
                        .chunks(16_usize)
                        .flat_map(|decrypted_block| {
                            let decrypted_block: Vec<u8> = exor(&decrypted_block, &iv).unwrap();
                            let encrypted_block =
                                block_cipher.encrypt_block(&decrypted_block).unwrap();
                            iv.copy_from_slice(&encrypted_block[..]);
                            encrypted_block.into_iter()
                        })
                        .collect())
                } else {
                    Err(AesError::InvalidBlockSize(x))
                }
            }
        }
    }
}

pub fn decrypt<K: ?Sized + AsRef<[u8]>, IV: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
    key: &K,
    iv: &IV,
    ciphertext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = AesKey::try_copy_from_slice(key)?;
    let iv = AesCbcIv::try_copy_from_slice(iv)?;
    let cipher = AesCbcCipher::new(&key, &iv);
    cipher.decrypt(ciphertext)
}

pub fn encrypt<K: ?Sized + AsRef<[u8]>, IV: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
    key: &K,
    iv: &IV,
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = AesKey::try_copy_from_slice(key)?;
    let iv = AesCbcIv::try_copy_from_slice(iv)?;
    let cipher = AesCbcCipher::new(&key, &iv);
    cipher.encrypt(plaintext)
}
