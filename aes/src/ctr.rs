use quickcheck::{single_shrinker, Arbitrary, Gen};
use rand::prelude::*;

use crate::ecb::AesEcbBlockCipher;
use crate::error::AesError;
use crate::key::AesKey;

#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum AesCtrMode {
    NIST_SP800_38A, // NIST SP 800-38A mode (128-bit BE nonce + 128-bit BE counter)
    CRYPTOPALS,     // cryptopals mode (64-bit LE nonce + 64-bit LE counter)
}

impl AesCtrMode {
    pub fn decrypt<K: ?Sized + AsRef<[u8]>, IV: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
        self,
        key: &K,
        iv: &IV,
        ciphertext: &T,
    ) -> Result<Vec<u8>, AesError> {
        let key = AesKey::try_copy_from_slice(key)?;
        let iv = AesCtrIv::try_copy_from_slice(iv)?;
        let cipher = AesCtrCipher::new(&key, &iv, self);
        cipher.decrypt(ciphertext)
    }

    pub fn encrypt<K: ?Sized + AsRef<[u8]>, IV: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
        self,
        key: &K,
        iv: &IV,
        plaintext: &T,
    ) -> Result<Vec<u8>, AesError> {
        let key = AesKey::try_copy_from_slice(key)?;
        let iv = AesCtrIv::try_copy_from_slice(iv)?;
        let cipher = AesCtrCipher::new(&key, &iv, self);
        cipher.encrypt(plaintext)
    }
}

impl Distribution<AesCtrMode> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> AesCtrMode {
        match rng.gen_range(0, 2) {
            0 => AesCtrMode::NIST_SP800_38A,
            _ => AesCtrMode::CRYPTOPALS,
        }
    }
}

impl Arbitrary for AesCtrMode {
    fn arbitrary<G: Gen>(g: &mut G) -> AesCtrMode {
        g.gen()
    }
}

#[derive(Clone, Debug)]
pub struct AesCtrIv([u8; 16]);

impl AesCtrIv {
    pub fn aes_ctr_iv(value: [u8; 16]) -> AesCtrIv {
        AesCtrIv(value)
    }

    pub fn try_copy_from_slice<IV: ?Sized + AsRef<[u8]>>(bytes: &IV) -> Result<AesCtrIv, AesError> {
        let bytes = bytes.as_ref();
        match bytes.len() {
            16 => {
                let mut iv: [u8; 16] = [0u8; 16];
                iv.copy_from_slice(&bytes);
                Ok(Self::aes_ctr_iv(iv))
            }
            x => Err(AesError::InvalidInitializationVectorSize {
                was: x,
                explanation: "must be 16 bytes",
            }),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn increment(&mut self, mode: AesCtrMode) {
        match mode {
            AesCtrMode::NIST_SP800_38A => {
                for c in self.0[..].iter_mut().rev() {
                    *c = c.wrapping_add(1);
                    if *c != 0 {
                        break;
                    }
                }
            }
            AesCtrMode::CRYPTOPALS => {
                for c in self.0[8..].iter_mut() {
                    *c = c.wrapping_add(1);
                    if *c != 0 {
                        break;
                    }
                }
            }
        }
    }
}

impl Distribution<AesCtrIv> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> AesCtrIv {
        AesCtrIv(rng.gen())
    }
}

impl Arbitrary for AesCtrIv {
    fn arbitrary<G: Gen>(g: &mut G) -> AesCtrIv {
        g.gen()
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = AesCtrIv>> {
        single_shrinker(AesCtrIv([0_u8; 16]))
    }
}

#[derive(Clone, Debug)]
pub struct AesCtrKeystream<'k> {
    key: &'k AesKey,
    iv: AesCtrIv,
    mode: AesCtrMode,
    bytes: [u8; 16],
    offset: usize,
}

impl<'k> AesCtrKeystream<'k> {
    pub fn new(key: &'k AesKey, iv: &AesCtrIv, mode: AesCtrMode) -> AesCtrKeystream<'k> {
        AesCtrKeystream {
            key,
            iv: iv.clone(),
            mode,
            bytes: [0_u8; 16],
            offset: 16_usize,
        }
    }
}

impl<'k> Iterator for AesCtrKeystream<'k> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            let block_cipher = AesEcbBlockCipher::new(&self.key);
            let encrypted_block = block_cipher.encrypt_block(&self.iv.0[..]).unwrap();
            self.bytes.copy_from_slice(&encrypted_block[..]);
            self.offset = 0_usize;
            self.iv.increment(self.mode);
        }
        let byte = self.bytes[self.offset];
        self.offset += 1;
        Some(byte)
    }
}

pub struct AesCtrCipher<'k, 'iv> {
    key: &'k AesKey,
    iv: &'iv AesCtrIv,
    mode: AesCtrMode,
}

impl<'k, 'iv> AesCtrCipher<'k, 'iv> {
    pub fn new(key: &'k AesKey, iv: &'iv AesCtrIv, mode: AesCtrMode) -> AesCtrCipher<'k, 'iv> {
        AesCtrCipher { key, iv, mode }
    }

    fn crypt<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Result<Vec<u8>, AesError> {
        let input = input.as_ref();
        if input.is_empty() {
            Ok(vec![])
        } else {
            let keystream = AesCtrKeystream::new(&self.key, &self.iv, self.mode);
            Ok(input.iter().zip(keystream).map(|(a, b)| a ^ b).collect())
        }
    }

    pub fn decrypt<T: ?Sized + AsRef<[u8]>>(&self, ciphertext: &T) -> Result<Vec<u8>, AesError> {
        self.crypt(ciphertext)
    }

    pub fn encrypt<T: ?Sized + AsRef<[u8]>>(&self, plaintext: &T) -> Result<Vec<u8>, AesError> {
        self.crypt(plaintext)
    }
}

pub fn decrypt<K: ?Sized + AsRef<[u8]>, IV: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
    key: &K,
    iv: &IV,
    ciphertext: &T,
) -> Result<Vec<u8>, AesError> {
    AesCtrMode::CRYPTOPALS.decrypt(key, iv, ciphertext)
}

pub fn encrypt<K: ?Sized + AsRef<[u8]>, IV: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
    key: &K,
    iv: &IV,
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    AesCtrMode::CRYPTOPALS.encrypt(key, iv, plaintext)
}

pub fn decrypt_cryptopals<
    K: ?Sized + AsRef<[u8]>,
    IV: ?Sized + AsRef<[u8]>,
    T: ?Sized + AsRef<[u8]>,
>(
    key: &K,
    iv: &IV,
    ciphertext: &T,
) -> Result<Vec<u8>, AesError> {
    AesCtrMode::CRYPTOPALS.decrypt(key, iv, ciphertext)
}

pub fn encrypt_cryptopals<
    K: ?Sized + AsRef<[u8]>,
    IV: ?Sized + AsRef<[u8]>,
    T: ?Sized + AsRef<[u8]>,
>(
    key: &K,
    iv: &IV,
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    AesCtrMode::CRYPTOPALS.encrypt(key, iv, plaintext)
}

pub fn decrypt_nist_sp800_38a<
    K: ?Sized + AsRef<[u8]>,
    IV: ?Sized + AsRef<[u8]>,
    T: ?Sized + AsRef<[u8]>,
>(
    key: &K,
    iv: &IV,
    ciphertext: &T,
) -> Result<Vec<u8>, AesError> {
    AesCtrMode::NIST_SP800_38A.decrypt(key, iv, ciphertext)
}

pub fn encrypt_nist_sp800_38a<
    K: ?Sized + AsRef<[u8]>,
    IV: ?Sized + AsRef<[u8]>,
    T: ?Sized + AsRef<[u8]>,
>(
    key: &K,
    iv: &IV,
    plaintext: &T,
) -> Result<Vec<u8>, AesError> {
    AesCtrMode::NIST_SP800_38A.encrypt(key, iv, plaintext)
}

#[cfg(test)]
mod tests {
    use crate::ctr::{AesCtrCipher, AesCtrIv, AesCtrMode};
    use crate::key::AesKey;

    #[quickcheck]
    fn encrypt_and_decrypt_is_identity(
        key: AesKey,
        iv: AesCtrIv,
        mode: AesCtrMode,
        plaintext: Vec<u8>,
    ) -> bool {
        let cipher = AesCtrCipher::new(&key, &iv, mode);
        let ciphertext: Vec<u8> = cipher.encrypt(&plaintext).unwrap();
        let challenge: Vec<u8> = cipher.decrypt(&ciphertext).unwrap();
        plaintext == challenge
    }
}
