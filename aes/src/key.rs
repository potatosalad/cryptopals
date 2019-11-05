use quickcheck::{single_shrinker, Arbitrary, Gen};
use rand::prelude::*;

use crate::error::AesError;

#[derive(Clone, Debug)]
pub enum AesKey {
    Aes128Key([u8; 16]),
    Aes192Key([u8; 24]),
    Aes256Key([u8; 32]),
}

impl AesKey {
    pub fn aes_128_key(value: [u8; 16]) -> AesKey {
        AesKey::Aes128Key(value)
    }

    pub fn aes_192_key(value: [u8; 24]) -> AesKey {
        AesKey::Aes192Key(value)
    }

    pub fn aes_256_key(value: [u8; 32]) -> AesKey {
        AesKey::Aes256Key(value)
    }

    pub fn try_copy_from_slice<K: ?Sized + AsRef<[u8]>>(bytes: &K) -> Result<AesKey, AesError> {
        let bytes = bytes.as_ref();
        match bytes.len() {
            16 => {
                let mut key: [u8; 16] = [0u8; 16];
                key.copy_from_slice(&bytes);
                Ok(Self::aes_128_key(key))
            }
            24 => {
                let mut key: [u8; 24] = [0u8; 24];
                key.copy_from_slice(&bytes);
                Ok(Self::aes_192_key(key))
            }
            32 => {
                let mut key: [u8; 32] = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Self::aes_256_key(key))
            }
            x => Err(AesError::InvalidKeySize(x)),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            AesKey::Aes128Key(key) => key,
            AesKey::Aes192Key(key) => key,
            AesKey::Aes256Key(key) => key,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            AesKey::Aes128Key(ref key) => key.to_vec(),
            AesKey::Aes192Key(ref key) => key.to_vec(),
            AesKey::Aes256Key(ref key) => key.to_vec(),
        }
    }
}

impl Distribution<AesKey> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> AesKey {
        match rng.gen_range(0, 3) {
            0 => AesKey::Aes128Key(rng.gen()),
            1 => AesKey::Aes192Key(rng.gen()),
            _ => AesKey::Aes256Key(rng.gen()),
        }
    }
}

impl Arbitrary for AesKey {
    fn arbitrary<G: Gen>(g: &mut G) -> AesKey {
        g.gen()
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = AesKey>> {
        match self {
            AesKey::Aes128Key(_) => single_shrinker(AesKey::Aes128Key([0_u8; 16])),
            AesKey::Aes192Key(_) => single_shrinker(AesKey::Aes192Key([0_u8; 24])),
            AesKey::Aes256Key(_) => single_shrinker(AesKey::Aes256Key([0_u8; 32])),
        }
    }
}
