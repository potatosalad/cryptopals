use aes::cbc::encrypt as aes_cbc_encrypt;
use aes::ctr::encrypt as aes_ctr_encrypt;
use aes::ecb::encrypt as aes_ecb_encrypt;
use pkcs7;
use rand::prelude::*;

pub type EncryptionResult<T> =
    std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub trait EncryptionOracle {
    fn encrypt<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &self,
        _: &T,
    ) -> EncryptionResult<I>;

    fn encrypt_as_vec<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> EncryptionResult<Vec<u8>> {
        self.encrypt(input)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EncryptionAlgorithm {
    AesCbc,
    AesCtr,
    AesEcb,
}

impl EncryptionAlgorithm {
    pub fn block_size(&self) -> Option<u8> {
        match self {
            Self::AesCbc => Some(16_u8),
            Self::AesCtr => None,
            Self::AesEcb => Some(16_u8),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PaddingAlgorithm {
    Nothing,
    Pkcs7,
}

impl PaddingAlgorithm {
    pub fn padding_size(&self, block_size: u8, unpadded_size: usize) -> Option<usize> {
        match self {
            Self::Nothing => None,
            Self::Pkcs7 => Some(block_size as usize - (unpadded_size % block_size as usize)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionContext {
    pub key: Vec<u8>,
    pub iv: Option<Vec<u8>>,
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub encryption_algorithm: EncryptionAlgorithm,
    pub padding_algorithm: PaddingAlgorithm,
}

impl EncryptionContext {
    pub fn new(
        key: &[u8],
        prefix: &[u8],
        suffix: &[u8],
        encryption_algorithm: EncryptionAlgorithm,
        padding_algorithm: PaddingAlgorithm,
    ) -> Self {
        Self {
            key: key.to_vec(),
            iv: None,
            prefix: prefix.to_vec(),
            suffix: suffix.to_vec(),
            encryption_algorithm,
            padding_algorithm,
        }
    }

    pub fn random(
        encryption_algorithm: EncryptionAlgorithm,
        padding_algorithm: PaddingAlgorithm,
    ) -> Self {
        let key = Self::generate_key(&encryption_algorithm);
        Self::static_key(key.as_slice(), encryption_algorithm, padding_algorithm)
    }

    pub fn static_content(
        prefix: &[u8],
        suffix: &[u8],
        encryption_algorithm: EncryptionAlgorithm,
        padding_algorithm: PaddingAlgorithm,
    ) -> Self {
        let key = Self::generate_key(&encryption_algorithm);
        Self::new(
            key.as_slice(),
            prefix,
            suffix,
            encryption_algorithm,
            padding_algorithm,
        )
    }

    pub fn static_key(
        key: &[u8],
        encryption_algorithm: EncryptionAlgorithm,
        padding_algorithm: PaddingAlgorithm,
    ) -> Self {
        let mut csprng = thread_rng();
        let mut prefix = vec![0_u8; csprng.gen_range(5..10)];
        csprng.fill_bytes(&mut prefix);
        let mut suffix = vec![0_u8; csprng.gen_range(5..10)];
        csprng.fill_bytes(&mut suffix);
        Self::new(
            key,
            prefix.as_slice(),
            suffix.as_slice(),
            encryption_algorithm,
            padding_algorithm,
        )
    }

    fn generate_key(encryption_algorithm: &EncryptionAlgorithm) -> Vec<u8> {
        let mut csprng = thread_rng();
        match encryption_algorithm {
            EncryptionAlgorithm::AesCbc
            | EncryptionAlgorithm::AesCtr
            | EncryptionAlgorithm::AesEcb => match csprng.gen_range(0..3) {
                0 => {
                    let mut key = vec![0_u8; 16];
                    csprng.fill_bytes(&mut key);
                    key
                }
                1 => {
                    let mut key = vec![0_u8; 24];
                    csprng.fill_bytes(&mut key);
                    key
                }
                _ => {
                    let mut key = vec![0_u8; 32];
                    csprng.fill_bytes(&mut key);
                    key
                }
            },
        }
    }

    pub fn block_size(&self) -> Option<u8> {
        self.encryption_algorithm.block_size()
    }

    pub fn padded_size(&self, input_size: usize) -> Option<usize> {
        let unpadded_size = self.unpadded_size(input_size);
        self.padding_size(unpadded_size)
            .and_then(|padding_size| Some(padding_size + unpadded_size))
    }

    pub fn padding_size(&self, input_size: usize) -> Option<usize> {
        let unpadded_size = self.unpadded_size(input_size);
        self.block_size().and_then(|block_size| {
            self.padding_algorithm
                .padding_size(block_size, unpadded_size)
        })
    }

    pub fn unpadded_size(&self, input_size: usize) -> usize {
        self.prefix.len() + input_size + self.suffix.len()
    }
}

pub trait DeterministicEncryptionOracle: EncryptionOracle {}

impl EncryptionOracle for EncryptionContext {
    fn encrypt<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &self,
        input: &T,
    ) -> EncryptionResult<I> {
        let input = input.as_ref();
        let padded_size = self.padded_size(input.len());
        let unpadded_size = self.unpadded_size(input.len());
        let plaintext_size = padded_size.unwrap_or(unpadded_size);

        let mut plaintext = Vec::with_capacity(plaintext_size);
        plaintext.extend_from_slice(&self.prefix);
        plaintext.extend_from_slice(input);
        plaintext.extend_from_slice(&self.suffix);

        if let Some(block_size) = self.block_size() {
            match self.padding_algorithm {
                PaddingAlgorithm::Nothing => (),
                PaddingAlgorithm::Pkcs7 => pkcs7::pad_mut(&mut plaintext, block_size)?,
            };
        }

        match self.encryption_algorithm {
            EncryptionAlgorithm::AesCbc => {
                let iv = if let Some(iv) = self.iv.as_ref() {
                    // println!("about to encrypt: {:?}", String::from_utf8(plaintext.clone()));
                    iv.to_vec()
                } else {
                    let mut csprng = thread_rng();
                    let mut iv: Vec<u8> = vec![0_u8; 16];
                    csprng.fill_bytes(&mut iv);
                    iv
                };
                let ciphertext = aes_cbc_encrypt(&self.key, &iv, &plaintext)?;
                Ok(ciphertext.into_iter().collect())
            }
            EncryptionAlgorithm::AesCtr => {
                let iv = if let Some(iv) = self.iv.as_ref() {
                    // println!("about to encrypt: {:?}", String::from_utf8(plaintext.clone()));
                    iv.to_vec()
                } else {
                    let mut csprng = thread_rng();
                    let mut iv: Vec<u8> = vec![0_u8; 16];
                    csprng.fill_bytes(&mut iv);
                    iv
                };
                let ciphertext = aes_ctr_encrypt(&self.key, &iv, &plaintext)?;
                Ok(ciphertext.into_iter().collect())
            }
            EncryptionAlgorithm::AesEcb => {
                let ciphertext = aes_ecb_encrypt(&self.key, &plaintext)?;
                Ok(ciphertext.into_iter().collect())
            }
        }
    }
}
