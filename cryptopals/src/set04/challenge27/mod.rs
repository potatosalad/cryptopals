pub use aes::error::AesError;
pub use aes::key::AesKey;
pub use oracles::encryption_oracle::{
    DeterministicEncryptionOracle, EncryptionAlgorithm, EncryptionContext, EncryptionOracle,
    EncryptionResult, PaddingAlgorithm,
};
pub use pkcs7;
pub use xor::exor;

#[derive(Clone, Debug, PartialEq)]
pub struct Oracle {
    key: [u8; 16],
}

impl DeterministicEncryptionOracle for Oracle {}

impl Default for Oracle {
    fn default() -> Self {
        Self::random()
    }
}

impl EncryptionOracle for Oracle {
    fn encrypt<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &self,
        input: &T,
    ) -> EncryptionResult<I> {
        let input = String::from_utf8(input.as_ref().to_vec())?;
        let input = url::Url::parse(input.as_str())?;
        let input = input.to_string();
        let mut encryption_context = EncryptionContext::new(
            &self.key[..],
            &[],
            &[],
            EncryptionAlgorithm::AesCbc,
            PaddingAlgorithm::Pkcs7,
        );
        encryption_context.iv = Some(self.key.to_vec());
        encryption_context.encrypt(input.as_bytes())
    }
}

impl Oracle {
    pub fn random() -> Self {
        use rand::prelude::*;
        let mut csprng = thread_rng();
        let mut key: [u8; 16] = [0_u8; 16];
        csprng.fill_bytes(&mut key[..]);
        Self::new(key)
    }

    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    pub fn decrypt<T: ?Sized + AsRef<[u8]>>(&self, ciphertext: &T) -> Result<String, Vec<u8>> {
        self.verify_decrypt(&self.key, ciphertext)
    }

    pub fn verify_decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        key: &[u8],
        ciphertext: &T,
    ) -> Result<String, Vec<u8>> {
        let padded_plaintext: Vec<u8> =
            aes::cbc::decrypt(key, key, ciphertext).map_err(|_| vec![])?;
        let mut plaintext = padded_plaintext.clone();
        pkcs7::unpad_mut(&mut plaintext, 16).map_err(|_| padded_plaintext.clone())?;
        let output = String::from_utf8(plaintext).map_err(|_| padded_plaintext.clone())?;
        let output = url::Url::parse(output.as_str()).map_err(|_| padded_plaintext.clone())?;
        let output = output.to_string();
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_the_key_from_cbc_with_iv_eq_key() {
        let input = "https://example.com/foo/bar?baz=qux&quux=1234567";
        let oracle = Oracle::default();
        let ciphertext: Vec<u8> = oracle.encrypt(&input).unwrap();
        let mut attack_block: u128 = 0;
        let key: Vec<u8>;
        loop {
            let attack_ciphertext: Vec<u8> = ciphertext
                .iter()
                .take(16)
                .chain(attack_block.to_be_bytes().iter())
                .chain(ciphertext.iter().take(16))
                .cloned()
                .collect();
            if let Err(attack_plaintext) = oracle.decrypt(&attack_ciphertext) {
                key = exor::exor(&attack_plaintext[0..16], &attack_plaintext[32..48]).unwrap();
                break;
            } else {
                attack_block += 1;
            }
        }
        let challenge: String = oracle.verify_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(input, challenge);
    }
}
