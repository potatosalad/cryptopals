pub use aes::error::AesError;
pub use oracles::encryption_oracle::{
    EncryptionAlgorithm, EncryptionContext, EncryptionOracle, EncryptionResult, PaddingAlgorithm,
};
use rand::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct Oracle {
    context: EncryptionContext,
}

impl Default for Oracle {
    fn default() -> Self {
        let mut csprng = thread_rng();
        let encryption_algorithm = if csprng.gen() {
            EncryptionAlgorithm::AesCbc
        } else {
            EncryptionAlgorithm::AesEcb
        };
        Self {
            context: EncryptionContext::random(encryption_algorithm, PaddingAlgorithm::Pkcs7),
        }
    }
}

impl EncryptionOracle for Oracle {
    fn encrypt<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &self,
        input: &T,
    ) -> EncryptionResult<I> {
        self.context.encrypt(input)
    }
}

pub fn detect_aes_ecb_mode<T: ?Sized + AsRef<[u8]>>(ciphertext: &T, skip_blocks: usize) -> bool {
    let blocks: Vec<&[u8]> = ciphertext
        .as_ref()
        .chunks(16)
        .skip(skip_blocks)
        .take(2)
        .collect();
    blocks[0] == blocks[1]
}

#[cfg(test)]
mod tests {
    use super::{detect_aes_ecb_mode, EncryptionAlgorithm, EncryptionOracle, Oracle};

    #[test]
    fn encryption_oracle_sanity_check() {
        let plaintext = vec![0u8; 16 * 3];
        let oracle = Oracle::default();
        let ciphertext: Vec<u8> = oracle.encrypt(&plaintext).unwrap();
        if detect_aes_ecb_mode(&ciphertext, 1) {
            assert_eq!(
                EncryptionAlgorithm::AesEcb,
                oracle.context.encryption_algorithm
            );
        } else {
            assert_ne!(
                EncryptionAlgorithm::AesEcb,
                oracle.context.encryption_algorithm
            );
        }
    }

    #[quickcheck]
    fn encryption_oracle_detects_aes_ecb_mode(x: usize) -> bool {
        let x = x % 21841; // prime, results in maximum of roughly 1MB
        let plaintext = vec![0u8; 16 * (3 + x)];
        let oracle = Oracle::default();
        let ciphertext: Vec<u8> = oracle.encrypt(&plaintext).unwrap();
        if detect_aes_ecb_mode(&ciphertext, 1) {
            EncryptionAlgorithm::AesEcb == oracle.context.encryption_algorithm
        } else {
            EncryptionAlgorithm::AesEcb != oracle.context.encryption_algorithm
        }
    }
}
