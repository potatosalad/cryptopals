pub use aes::ctr::AesCtrIv;
pub use aes::error::AesError;
pub use aes::key::AesKey;
pub use oracles::encryption_oracle::{
    DeterministicEncryptionOracle, EncryptionAlgorithm, EncryptionContext, EncryptionOracle,
    EncryptionResult, PaddingAlgorithm,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_urlencoded;
pub use xor::exor;

#[derive(Clone, Debug)]
pub struct Oracle {
    key: AesKey,
    iv: AesCtrIv,
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
        let (input, encryption_context) =
            self.to_input_and_encryption_context_for_userdata(input.as_str());
        encryption_context.encrypt(input.as_bytes())
    }
}

impl Oracle {
    pub fn random() -> Self {
        use rand::prelude::*;
        let mut csprng = thread_rng();
        Self::new(csprng.gen(), csprng.gen())
    }

    pub fn new(key: AesKey, iv: AesCtrIv) -> Self {
        Self { key, iv }
    }

    pub fn detect_prefix_size(&self, byte0: u8, byte1: u8) -> EncryptionResult<usize> {
        Ok(self
            .encrypt_as_vec(&[byte0])?
            .into_iter()
            .zip(self.encrypt_as_vec(&[byte1])?.into_iter())
            .position(|(a, b)| a != b)
            .expect("oracle produced same output for different input (broken oracle)"))
    }

    pub fn add_cookiestring(&self, cookiestring: &str) -> EncryptionResult<Vec<u8>> {
        let prefix_size = self.detect_prefix_size(b'x', b'y')?;
        let attack_input: Vec<u8> = vec![b'x'; cookiestring.len()];
        let mut ciphertext: Vec<u8> = self.encrypt_as_vec(&attack_input)?;
        exor::exor_mut(
            &mut ciphertext[prefix_size..(prefix_size + cookiestring.len())],
            &attack_input,
        )?;
        exor::exor_mut(
            &mut ciphertext[prefix_size..(prefix_size + cookiestring.len())],
            &cookiestring,
        )?;
        Ok(ciphertext)
    }

    pub fn decrypt_cookies<T: ?Sized + AsRef<[u8]>>(
        &self,
        ciphertext: &T,
    ) -> EncryptionResult<Vec<(String, String)>> {
        let mut plaintext: Vec<u8> =
            aes::ctr::decrypt(self.key.as_slice(), self.iv.as_slice(), ciphertext)?;
        plaintext.retain(|&c| is_valid_cookiechar(c));
        let encoded = String::from_utf8(plaintext)?;
        let cookies: Vec<(String, String)> = decode_cookiestring(encoded.as_str())?;
        Ok(cookies)
    }

    fn to_input_and_encryption_context_for_userdata(
        &self,
        userdata: &str,
    ) -> (String, EncryptionContext) {
        let cookie: Vec<(&str, &str)> = vec![
            ("comment1", "cooking MCs"),
            ("userdata", userdata),
            ("comment2", " like a pound of bacon"),
        ];
        let encoded = encode_cookiestring(&cookie).unwrap();
        let pos0 = encoded.find("userdata=").unwrap() + "userdata=".len();
        let (prefix, input_and_suffix) = encoded.split_at(pos0);
        let pos1 = input_and_suffix.find(';').unwrap();
        let (input, suffix) = input_and_suffix.split_at(pos1);
        let mut encryption_context = EncryptionContext::new(
            self.key.as_slice(),
            prefix.as_bytes(),
            suffix.as_bytes(),
            EncryptionAlgorithm::AesCtr,
            PaddingAlgorithm::Nothing,
        );
        encryption_context.iv = Some(self.iv.to_vec());
        (input.to_string(), encryption_context)
    }
}

pub fn is_valid_cookiechar(c: u8) -> bool {
    match c {
        b'=' | b';' | b'%' | b'!' | b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'_' | b'~' => true,
        _ => c.is_ascii_alphanumeric(),
    }
}

pub fn decode_cookiestring<T>(input: &str) -> Result<T, serde_urlencoded::de::Error>
where
    T: DeserializeOwned,
{
    serde_urlencoded::from_str(input.replace(";", "&").as_str())
}

pub fn encode_cookiestring<T: Serialize>(input: T) -> Result<String, serde_urlencoded::ser::Error> {
    serde_urlencoded::to_string(input).map(|s| s.replace("&", ";"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn ctr_bitflipping_attacks() {
        let oracle = super::Oracle::default();
        let prefix_size: usize = 30_usize;
        assert_eq!(prefix_size, oracle.detect_prefix_size(b'x', b'y').unwrap());
        let ciphertext = oracle.add_cookiestring(";admin=true;").unwrap();
        let cookies = oracle.decrypt_cookies(&ciphertext).unwrap();
        println!("cookies = {:?}", cookies);
        assert_eq!(
            &("admin".to_string(), "true".to_string()),
            cookies.get(cookies.len() - 2).unwrap()
        );
    }
}
