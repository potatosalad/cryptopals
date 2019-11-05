pub use aes::error::AesError;
pub use aes::key::AesKey;
pub use oracles::encryption_oracle::{
    DeterministicEncryptionOracle, EncryptionAlgorithm, EncryptionContext, EncryptionOracle,
    EncryptionResult, PaddingAlgorithm,
};
pub use pkcs7;
use serde::{de::DeserializeOwned, Serialize};
use serde_urlencoded;
pub use xor::exor;

#[derive(Clone, Debug, PartialEq)]
pub struct Oracle {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl DeterministicEncryptionOracle for Oracle {}

impl Default for Oracle {
    fn default() -> Self {
        use rand::prelude::*;
        // let key: Vec<u8> = base64::decode("q390RWHAI3APOYnNaq07oQ==").unwrap();
        // let iv: Vec<u8> = base64::decode("IK6Zfme4P4QrCxamu7QXxw==").unwrap();
        let mut key: Vec<u8> = vec![0_u8; 16];
        let mut iv: Vec<u8> = vec![0_u8; 16];
        let mut csprng = thread_rng();
        csprng.fill_bytes(&mut key);
        csprng.fill_bytes(&mut iv);
        Self::new(key.as_slice(), iv.as_slice())
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
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            iv: iv.to_vec(),
        }
    }

    pub fn detect_block_size(&self, byte: u8) -> EncryptionResult<usize> {
        let mut input: Vec<u8> = Vec::new();
        let alen = self.encrypt_as_vec(&input)?.len();
        let mut blen = alen;
        while alen == blen {
            input.push(byte);
            blen = self.encrypt_as_vec(&input)?.len();
        }
        Ok(blen - alen)
    }

    pub fn detect_uses_aes_ecb_mode(
        &self,
        block_size: usize,
        byte0: u8,
        byte1: u8,
    ) -> EncryptionResult<bool> {
        let input: Vec<u8> = vec![byte0; block_size * 3];
        let ciphertext: Vec<u8> = self.encrypt(&input)?;
        let prefix_blocks = self.count_prefix_blocks(block_size, byte0, byte1)?;
        let blocks: Vec<&[u8]> = ciphertext
            .chunks(16)
            .skip(prefix_blocks + 1)
            .take(2)
            .collect();
        Ok(blocks[0] == blocks[1])
    }

    pub fn count_prefix_blocks(
        &self,
        block_size: usize,
        byte0: u8,
        byte1: u8,
    ) -> EncryptionResult<usize> {
        Ok(self
            .encrypt_as_vec(&[byte0])?
            .chunks(block_size)
            .zip(self.encrypt_as_vec(&[byte1])?.chunks(block_size))
            .position(|(a, b)| a != b)
            .expect("oracle produced same output for different input (broken oracle)"))
    }

    pub fn detect_uses_padding(&self, block_size: usize, byte: u8) -> EncryptionResult<bool> {
        let alen = self.encrypt_as_vec(&[byte])?.len();
        let blen = self.encrypt_as_vec(&[])?.len();
        Ok((alen - blen) % block_size == 0)
    }

    pub fn detect_prefix_size_plus_suffix_size(
        &self,
        block_size: usize,
        byte: u8,
    ) -> EncryptionResult<usize> {
        let alen = self.encrypt_as_vec(&[])?.len();
        if !self.detect_uses_padding(block_size, byte)? || alen == 0 {
            return Ok(alen);
        }
        let block = vec![byte; block_size];
        for position in 1..=block_size {
            let blen = self.encrypt_as_vec(&block[..position])?.len();
            if alen != blen {
                return Ok(alen - position);
            }
        }
        panic!("oracle output length does not change with different length input (broken oracle)")
    }

    pub fn add_cookiestring(&self, cookiestring: &str) -> EncryptionResult<Vec<u8>> {
        let block_size = self.detect_block_size(b'x')?;
        if block_size == 0 || block_size > 255 {
            return Err("block_size must be between 1 and 255".into());
        }
        let prefix_plus_suffix_size = self.detect_prefix_size_plus_suffix_size(block_size, b'x')?;
        let prefix_plus_suffix_blocks: usize =
            (prefix_plus_suffix_size + block_size - 1) / block_size;
        let prefix_plus_suffix_padding_size: usize = if prefix_plus_suffix_size % block_size == 0 {
            0
        } else {
            block_size - (prefix_plus_suffix_size % block_size)
        };
        let filled_input: Vec<u8> = vec![b'x'; prefix_plus_suffix_padding_size];
        let mut ciphertext: Vec<u8> = self.encrypt_as_vec(&filled_input)?;
        let wanted_block: Vec<u8> = pkcs7::pad(cookiestring.as_bytes(), block_size as u8)?;
        let target_block: Vec<u8> = vec![block_size as u8; block_size];
        let attack_block: Vec<u8> = exor::exor(&wanted_block, &target_block)?;
        exor::exor_mut(
            &mut ciphertext[(prefix_plus_suffix_blocks - 1) * block_size
                ..prefix_plus_suffix_blocks * block_size],
            &attack_block,
        )?;
        Ok(ciphertext)
    }

    pub fn decrypt_cookies<T: ?Sized + AsRef<[u8]>>(
        &self,
        ciphertext: &T,
    ) -> EncryptionResult<Vec<(String, String)>> {
        let block_size = self.detect_block_size(b'x')?;
        if block_size == 0 || block_size > 255 {
            return Err("block_size must be between 1 and 255".into());
        }
        let mut plaintext: Vec<u8> = aes::cbc::decrypt(&self.key, &self.iv, ciphertext)?;
        pkcs7::unpad_mut(&mut plaintext, block_size as u8)?;
        plaintext.retain(is_valid_cookiechar);
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
            &self.key,
            prefix.as_bytes(),
            suffix.as_bytes(),
            EncryptionAlgorithm::AesCbc,
            PaddingAlgorithm::Pkcs7,
        );
        encryption_context.iv = Some(self.iv.clone());
        (input.to_string(), encryption_context)
    }
}

pub fn is_valid_cookiechar(c: &u8) -> bool {
    match *c {
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
    fn cbc_bitflipping_attacks() {
        let oracle = super::Oracle::default();
        let block_size = 16_usize;
        let prefix_blocks = 1_usize;
        let prefix_plus_suffix_size = 62_usize;
        assert_eq!(block_size, oracle.detect_block_size(b'x').unwrap());
        assert_eq!(
            false,
            oracle
                .detect_uses_aes_ecb_mode(block_size, b'x', b'y')
                .unwrap()
        );
        assert_eq!(true, oracle.detect_uses_padding(block_size, b'x').unwrap());
        assert_eq!(
            prefix_blocks,
            oracle.count_prefix_blocks(block_size, b'x', b'y').unwrap()
        );
        assert_eq!(
            prefix_plus_suffix_size,
            oracle
                .detect_prefix_size_plus_suffix_size(block_size, b'x')
                .unwrap()
        );
        let ciphertext = oracle.add_cookiestring(";admin=true;").unwrap();
        let cookies = oracle.decrypt_cookies(&ciphertext).unwrap();
        assert_eq!(
            &("admin".to_string(), "true".to_string()),
            cookies.last().unwrap()
        );
    }

    #[quickcheck]
    fn cbc_bitflipping_attacks_property(key: aes::key::AesKey, iv: aes::cbc::AesCbcIv) -> bool {
        let oracle = super::Oracle::new(key.as_slice(), iv.as_slice());
        let block_size = 16_usize;
        let prefix_blocks = 1_usize;
        let prefix_plus_suffix_size = 62_usize;
        assert_eq!(block_size, oracle.detect_block_size(b'x').unwrap());
        assert_eq!(
            false,
            oracle
                .detect_uses_aes_ecb_mode(block_size, b'x', b'y')
                .unwrap()
        );
        assert_eq!(true, oracle.detect_uses_padding(block_size, b'x').unwrap());
        assert_eq!(
            prefix_blocks,
            oracle.count_prefix_blocks(block_size, b'x', b'y').unwrap()
        );
        assert_eq!(
            prefix_plus_suffix_size,
            oracle
                .detect_prefix_size_plus_suffix_size(block_size, b'x')
                .unwrap()
        );
        let ciphertext = oracle.add_cookiestring(";admin=true;").unwrap();
        let cookies = oracle.decrypt_cookies(&ciphertext).unwrap();
        &("admin".to_string(), "true".to_string()) == cookies.last().unwrap()
    }
}
