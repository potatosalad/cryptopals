pub use aes::error::AesError;
pub use aes::key::AesKey;
pub use oracles::encryption_oracle::{
    DeterministicEncryptionOracle, EncryptionAlgorithm, EncryptionContext, EncryptionOracle,
    EncryptionResult, PaddingAlgorithm,
};
pub use pkcs7;
use serde::{Deserialize, Serialize};
use serde_urlencoded;

use crate::set02::challenge12::Oracle as Challenge12Oracle;

#[derive(Clone, Debug, PartialEq)]
pub struct Oracle {
    key: Vec<u8>,
}

impl DeterministicEncryptionOracle for Oracle {}

impl Default for Oracle {
    fn default() -> Self {
        let key: Vec<u8> = base64::decode("5QMYGvkoPsrN5hcBwZc00g==").unwrap();
        Self::new(key.as_slice())
    }
}

impl EncryptionOracle for Oracle {
    fn encrypt<I: std::iter::FromIterator<u8>, T: ?Sized + AsRef<[u8]>>(
        &self,
        input: &T,
    ) -> EncryptionResult<I> {
        let email = String::from_utf8(input.as_ref().to_vec())?;
        let (input, oracle) = self.to_input_and_challenge12_oracle_for_email(email.as_str());
        oracle.encrypt(input.as_bytes())
    }
}

impl Oracle {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    pub fn detect_block_size(&self) -> EncryptionResult<usize> {
        self.as_challenge12_oracle().detect_block_size(b'x')
    }

    pub fn detect_uses_aes_ecb_mode(&self, block_size: usize) -> EncryptionResult<bool> {
        self.as_challenge12_oracle()
            .detect_uses_aes_ecb_mode(block_size, b'x')
    }

    pub fn detect_uses_padding(&self, block_size: usize) -> EncryptionResult<bool> {
        self.as_challenge12_oracle()
            .detect_uses_padding(block_size, b'x')
    }

    pub fn count_prefix_blocks(&self, block_size: usize) -> EncryptionResult<usize> {
        self.as_challenge12_oracle()
            .count_prefix_blocks(block_size, b'x', b'y')
    }

    pub fn detect_prefix_offset(
        &self,
        block_size: usize,
        byte_offset: usize,
        byte: u8,
    ) -> EncryptionResult<usize> {
        self.as_challenge12_oracle()
            .detect_prefix_offset(block_size, byte_offset, byte)
    }

    pub fn detect_prefix_size(
        &self,
        block_size: usize,
        prefix_blocks: usize,
    ) -> EncryptionResult<usize> {
        self.as_challenge12_oracle()
            .detect_prefix_size(block_size, prefix_blocks, b'x', b'y')
    }

    pub fn detect_prefix_size_plus_suffix_size(
        &self,
        block_size: usize,
    ) -> EncryptionResult<usize> {
        self.as_challenge12_oracle()
            .detect_prefix_size_plus_suffix_size(block_size, b'x')
    }

    pub fn detect_prefix_size_and_suffix_size(
        &self,
        block_size: usize,
    ) -> EncryptionResult<(usize, usize)> {
        self.as_challenge12_oracle()
            .detect_prefix_size_and_suffix_size(block_size, b'x', b'y')
    }

    fn as_challenge12_oracle(&self) -> Challenge12Oracle {
        let (_, oracle) = self.to_input_and_challenge12_oracle_for_email("");
        oracle
    }

    fn to_input_and_challenge12_oracle_for_email(
        &self,
        email: &str,
    ) -> (String, Challenge12Oracle) {
        let (prefix, input, suffix) = Profile::for_email(email).encode_and_split();
        (
            input,
            Challenge12Oracle::new(self.key.as_slice(), prefix.as_bytes(), suffix.as_bytes()),
        )
    }

    pub fn set_role(&self, role: &str) -> EncryptionResult<Vec<u8>> {
        let block_size = self.detect_block_size()?;
        if block_size == 0 || block_size > 255 {
            return Err("block_size must be between 1 and 255".into());
        }
        let (prefix_size, suffix_size) = self.detect_prefix_size_and_suffix_size(block_size)?;
        let prefix_blocks: usize = (prefix_size + block_size - 1) / block_size;
        let prefix_padding_size: usize = if prefix_size % block_size == 0 {
            0
        } else {
            block_size - (prefix_size % block_size)
        };
        // let suffix_blocks: usize = (suffix_size + block_size - 1) / block_size;
        let suffix_padding_size: usize = if suffix_size % block_size == 0 {
            0
        } else {
            block_size - (suffix_size % block_size)
        };
        let padded_role: Vec<u8> = pkcs7::pad(role.as_bytes(), block_size as u8)?;
        let padded_role_size: usize = padded_role.len();
        let mut input: Vec<u8> = vec![b'x'; prefix_padding_size];
        input.extend(padded_role);
        let oracle = self.as_challenge12_oracle();
        let encrypted_role = &oracle
            .encrypt_as_vec(&input)?
            .split_off(prefix_blocks * block_size)[0..padded_role_size];
        let mut encrypted = oracle.encrypt_as_vec(&vec![
            b'x';
            prefix_padding_size
                + suffix_padding_size
                + "user".len()
        ])?;
        encrypted.truncate(prefix_size + prefix_padding_size + suffix_padding_size + suffix_size);
        encrypted.extend(encrypted_role);
        Ok(encrypted)
    }

    pub fn decrypt_to_profile<T: ?Sized + AsRef<[u8]>>(
        &self,
        ciphertext: &T,
    ) -> EncryptionResult<Profile> {
        let block_size = self.detect_block_size()?;
        if block_size == 0 || block_size > 255 {
            return Err("block_size must be between 1 and 255".into());
        }
        let mut plaintext: Vec<u8> = aes::ecb::decrypt(&self.key, ciphertext)?;
        pkcs7::unpad_mut(&mut plaintext, block_size as u8)?;
        let encoded = String::from_utf8(plaintext)?;
        let profile: Profile = decode_querystring(encoded.as_str())?;
        Ok(profile)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Profile {
    pub email: String,
    pub uid: u32,
    pub role: String,
}

impl Profile {
    pub fn for_email(email: &str) -> Profile {
        Profile {
            email: email.to_string(),
            uid: 10,
            role: "user".to_string(),
        }
    }

    pub fn encode_and_split(&self) -> (String, String, String) {
        let encoded = encode_querystring(self).unwrap();
        let pos0 = encoded.find("email=").unwrap() + "email=".len();
        let (prefix, input_and_suffix) = encoded.split_at(pos0);
        let pos1 = input_and_suffix.find('&').unwrap();
        let (input, suffix) = input_and_suffix.split_at(pos1);
        (prefix.to_string(), input.to_string(), suffix.to_string())
    }
}

pub fn decode_querystring<'de, T>(input: &'de str) -> Result<T, serde_urlencoded::de::Error>
where
    T: Deserialize<'de>,
{
    serde_urlencoded::from_str(input)
}

pub fn encode_querystring<T: Serialize>(input: T) -> Result<String, serde_urlencoded::ser::Error> {
    serde_urlencoded::to_string(input)
}

pub fn block_encode<T: ?Sized + AsRef<[u8]>>(t: &T) -> String {
    t.as_ref()
        .chunks(16)
        .map(hex::encode)
        .collect::<Vec<String>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    #[test]
    fn ecb_cut_and_paste() {
        use super::EncryptionOracle;
        let oracle = super::Oracle::default();
        let block_size = 16_usize;
        let prefix_blocks = 0_usize;
        let prefix_size = 6_usize;
        let suffix_size = 17_usize;
        assert_eq!(block_size, oracle.detect_block_size().unwrap());
        assert_eq!(true, oracle.detect_uses_aes_ecb_mode(block_size).unwrap());
        assert_eq!(true, oracle.detect_uses_padding(block_size).unwrap());
        assert_eq!(
            prefix_blocks,
            oracle.count_prefix_blocks(block_size).unwrap()
        );
        assert_eq!(
            (prefix_size, suffix_size),
            oracle
                .detect_prefix_size_and_suffix_size(block_size)
                .unwrap()
        );
        let user_profile = super::Profile {
            email: "foo@bar.com".to_string(),
            uid: 10,
            role: "user".to_string(),
        };
        let user_ciphertext = oracle.encrypt_as_vec("foo@bar.com").unwrap();
        assert_eq!(
            user_profile,
            oracle.decrypt_to_profile(&user_ciphertext).unwrap()
        );
        let admin_profile = super::Profile {
            email: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string(),
            uid: 10,
            role: "admin".to_string(),
        };
        let admin_ciphertext = oracle.set_role("admin").unwrap();
        assert_eq!(
            admin_profile,
            oracle.decrypt_to_profile(&admin_ciphertext).unwrap()
        );
        let superuserrootadmin_profile = super::Profile {
            email: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string(),
            uid: 10,
            role: "superuserrootadmin".to_string(),
        };
        let superuserrootadmin_ciphertext = oracle.set_role("superuserrootadmin").unwrap();
        assert_eq!(
            superuserrootadmin_profile,
            oracle
                .decrypt_to_profile(&superuserrootadmin_ciphertext)
                .unwrap()
        );
    }
}
