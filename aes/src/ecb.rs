use crate::error::AesError;
use crate::key::AesKey;

pub enum AesEcbBlockCipher {
    Aes128BlockCipher(Box<aesimpl::Aes128>),
    Aes192BlockCipher(Box<aesimpl::Aes192>),
    Aes256BlockCipher(Box<aesimpl::Aes256>),
}

impl AesEcbBlockCipher {
    pub fn new(aes_key: &AesKey) -> Self {
        use aesimpl::cipher::{generic_array::GenericArray, KeyInit};
        match aes_key {
            AesKey::Aes128Key(ref key) => Self::Aes128BlockCipher(Box::new(aesimpl::Aes128::new(
                &GenericArray::clone_from_slice(&key[..]),
            ))),
            AesKey::Aes192Key(ref key) => Self::Aes192BlockCipher(Box::new(aesimpl::Aes192::new(
                &GenericArray::clone_from_slice(&key[..]),
            ))),
            AesKey::Aes256Key(ref key) => Self::Aes256BlockCipher(Box::new(aesimpl::Aes256::new(
                &GenericArray::clone_from_slice(&key[..]),
            ))),
        }
    }

    pub fn decrypt_block<T: ?Sized + AsRef<[u8]>>(
        &self,
        ciphertext: &T,
    ) -> Result<Vec<u8>, AesError> {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.len() == 16 {
            use aesimpl::cipher::{generic_array::GenericArray, BlockDecrypt};
            let mut plaintext = GenericArray::clone_from_slice(ciphertext);
            match self {
                Self::Aes128BlockCipher(aes128) => aes128.decrypt_block(&mut plaintext),
                Self::Aes192BlockCipher(aes192) => aes192.decrypt_block(&mut plaintext),
                Self::Aes256BlockCipher(aes256) => aes256.decrypt_block(&mut plaintext),
            };
            Ok(plaintext.to_vec())
        } else {
            Err(AesError::InvalidBlockSize(ciphertext.len()))
        }
    }

    pub fn encrypt_block<T: ?Sized + AsRef<[u8]>>(
        &self,
        plaintext: &T,
    ) -> Result<Vec<u8>, AesError> {
        let plaintext = plaintext.as_ref();
        if plaintext.len() == 16 {
            use aesimpl::cipher::{generic_array::GenericArray, BlockEncrypt};
            let mut ciphertext = GenericArray::clone_from_slice(plaintext);
            match self {
                Self::Aes128BlockCipher(aes128) => aes128.encrypt_block(&mut ciphertext),
                Self::Aes192BlockCipher(aes192) => aes192.encrypt_block(&mut ciphertext),
                Self::Aes256BlockCipher(aes256) => aes256.encrypt_block(&mut ciphertext),
            };
            Ok(ciphertext.to_vec())
        } else {
            Err(AesError::InvalidBlockSize(plaintext.len()))
        }
    }
}

pub struct AesEcbCipher<'k> {
    key: &'k AesKey,
}

impl<'k> AesEcbCipher<'k> {
    pub fn new(key: &'k AesKey) -> AesEcbCipher<'k> {
        AesEcbCipher { key }
    }

    pub fn decrypt<T: ?Sized + AsRef<[u8]>>(&self, ciphertext: &T) -> Result<Vec<u8>, AesError> {
        let ciphertext = ciphertext.as_ref();
        match ciphertext.len() {
            0 => Ok(vec![]),
            x => {
                if x % 16 == 0 {
                    let block_cipher = AesEcbBlockCipher::new(&self.key);
                    Ok(ciphertext
                        .chunks(16_usize)
                        .flat_map(|block| block_cipher.decrypt_block(&block).unwrap().into_iter())
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
                    Ok(plaintext
                        .chunks(16_usize)
                        .flat_map(|block| block_cipher.encrypt_block(&block).unwrap().into_iter())
                        .collect())
                } else {
                    Err(AesError::InvalidBlockSize(x))
                }
            }
        }
    }
}

pub fn decrypt<K: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
    key: &K,
    ciphertext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = AesKey::try_copy_from_slice(key)?;
    let cipher = AesEcbCipher::new(&key);
    cipher.decrypt(ciphertext)
}

pub fn encrypt<K: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
    key: &K,
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    let key = AesKey::try_copy_from_slice(key)?;
    let cipher = AesEcbCipher::new(&key);
    cipher.encrypt(plaintext)
}
