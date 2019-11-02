pub use aes::error::AesError;
pub use aes::key::AesKey;
pub use oracles::encryption_oracle::{
    DeterministicEncryptionOracle, EncryptionAlgorithm, EncryptionContext, EncryptionOracle,
    EncryptionResult, PaddingAlgorithm,
};

#[derive(Clone, Debug, PartialEq)]
pub struct Oracle {
    pub(crate) context: EncryptionContext,
}

impl DeterministicEncryptionOracle for Oracle {}

impl Default for Oracle {
    fn default() -> Self {
        let prefix: Vec<u8> = vec![];
        let suffix: Vec<u8> = base64::decode(concat!(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg",
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq",
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg",
            "YnkK"
        ))
        .unwrap();
        let key: Vec<u8> = base64::decode("NQwfQA0YVgRvHdWtq1WqsA==").unwrap();
        Self::new(key.as_slice(), prefix.as_slice(), suffix.as_slice())
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

impl Oracle {
    pub fn new(key: &[u8], prefix: &[u8], suffix: &[u8]) -> Self {
        Self {
            context: EncryptionContext::new(
                key,
                prefix,
                suffix,
                EncryptionAlgorithm::AesEcb,
                PaddingAlgorithm::Pkcs7,
            ),
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

    pub fn detect_uses_aes_ecb_mode(&self, block_size: usize, byte: u8) -> EncryptionResult<bool> {
        let input: Vec<u8> = vec![byte; block_size * 3];
        let ciphertext: Vec<u8> = self.encrypt(&input)?;
        let prefix_blocks = self.count_prefix_blocks(block_size, 0, 1)?;
        let blocks: Vec<&[u8]> = ciphertext
            .chunks(16)
            .skip(prefix_blocks + 1)
            .take(2)
            .collect();
        Ok(blocks[0] == blocks[1])
    }

    pub fn detect_uses_padding(&self, block_size: usize, byte: u8) -> EncryptionResult<bool> {
        let alen = self.encrypt_as_vec(&[byte])?.len();
        let blen = self.encrypt_as_vec(&[])?.len();
        Ok((alen - blen) % block_size == 0)
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

    pub fn detect_prefix_offset(
        &self,
        block_size: usize,
        byte_offset: usize,
        byte: u8,
    ) -> EncryptionResult<usize> {
        let block = vec![byte; block_size];
        let first_non_prefix_block =
            &self.encrypt_as_vec(&block)?[byte_offset..(byte_offset + block_size)];
        for position in 0..block_size {
            let current = self.encrypt_as_vec(&block[position + 1..])?;
            let current_non_prefix_block = &current[byte_offset..(byte_offset + block_size)];
            if current.len() < byte_offset + block_size
                || first_non_prefix_block != current_non_prefix_block
            {
                return Ok(position);
            }
        }
        Ok(block_size)
    }

    pub fn detect_prefix_size(
        &self,
        block_size: usize,
        prefix_blocks: usize,
        byte0: u8,
        byte1: u8,
    ) -> EncryptionResult<usize> {
        let byte_offset = prefix_blocks * block_size;
        let prefix_offset0 = self.detect_prefix_offset(block_size, byte_offset, byte0)?;
        let prefix_offset1 = self.detect_prefix_offset(block_size, byte_offset, byte1)?;
        Ok(byte_offset + std::cmp::min(prefix_offset0, prefix_offset1))
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

    pub fn detect_prefix_size_and_suffix_size(
        &self,
        block_size: usize,
        byte0: u8,
        byte1: u8,
    ) -> EncryptionResult<(usize, usize)> {
        let prefix_blocks = self.count_prefix_blocks(block_size, byte0, byte1)?;
        let prefix_size = self.detect_prefix_size(block_size, prefix_blocks, byte0, byte1)?;
        let suffix_size =
            self.detect_prefix_size_plus_suffix_size(block_size, byte0)? - prefix_size;
        Ok((prefix_size, suffix_size))
    }

    pub fn decrypt_suffix(
        &self,
        block_size: usize,
        prefix_size: usize,
        suffix_size: usize,
    ) -> EncryptionResult<Vec<u8>> {
        if suffix_size == 0 {
            return Ok(vec![]);
        }
        let prefix_blocks: usize = (prefix_size + block_size - 1) / block_size;
        let prefix_padding_size: usize = if prefix_size % block_size == 0 {
            0
        } else {
            block_size - (prefix_size % block_size)
        };
        let mut suffix: Vec<u8> = Vec::with_capacity(suffix_size);
        let mut blocks = vec![0_u8; prefix_padding_size + block_size - 1];
        let table: Vec<Vec<u8>> = (0_usize..block_size)
            .map(|skip_bytes| self.encrypt_as_vec(&blocks[skip_bytes..]))
            .collect::<EncryptionResult<_>>()?;
        for index in 0..suffix_size {
            let skip_index = prefix_blocks + index / block_size;
            let skip_bytes = index % block_size;
            let a = &table[skip_bytes][skip_index * block_size..(skip_index + 1) * block_size];
            let blen = blocks.len();
            for byte in 0x00_u8..=0xff_u8 {
                blocks.push(byte);
                let b = &self.encrypt_as_vec(&blocks[skip_bytes..])?
                    [skip_index * block_size..(skip_index + 1) * block_size];
                if a == b {
                    suffix.push(byte);
                    break;
                }
                blocks.pop();
            }
            if blen == blocks.len() {
                return Err("unable to match byte".into());
            }
        }
        Ok(suffix)
    }
}

// fn block_encode<T: ?Sized + AsRef<[u8]>>(t: &T) -> String {
//     t.as_ref().chunks(16).map(hex::encode).collect::<Vec<String>>().join(" ")
// }

#[cfg(test)]
mod tests {
    use super::{AesKey, Oracle};

    #[test]
    fn static_encryption_oracle_decrypt_byte_at_a_time_aes_ecb_mode() {
        let oracle = Oracle::default();
        let block_size = 16_usize;
        let prefix_blocks = 0_usize;
        let prefix_size = 0_usize;
        let suffix_size = 138_usize;
        assert_eq!(block_size, oracle.detect_block_size(0_u8).unwrap());
        assert_eq!(
            true,
            oracle.detect_uses_aes_ecb_mode(block_size, 0_u8).unwrap()
        );
        assert_eq!(true, oracle.detect_uses_padding(block_size, 0_u8).unwrap());
        assert_eq!(
            prefix_blocks,
            oracle.count_prefix_blocks(block_size, 0, 1).unwrap()
        );
        assert_eq!(
            (prefix_size, suffix_size),
            oracle
                .detect_prefix_size_and_suffix_size(block_size, 0_u8, 1_u8)
                .unwrap()
        );
        assert_eq!(
            &oracle.context.suffix,
            &oracle
                .decrypt_suffix(block_size, prefix_size, suffix_size)
                .unwrap()
        );
    }

    #[ignore]
    #[quickcheck]
    fn random_encryption_oracle_decrypt_byte_at_a_time_aes_ecb_mode(
        key: AesKey,
        prefix: Vec<u8>,
        suffix: Vec<u8>,
    ) -> bool {
        let oracle = Oracle::new(
            key.to_vec().as_slice(),
            prefix.as_slice(),
            suffix.as_slice(),
        );
        let block_size = oracle.detect_block_size(0_u8).unwrap();
        let (prefix_size, suffix_size) = oracle
            .detect_prefix_size_and_suffix_size(block_size, 0_u8, 1_u8)
            .unwrap();
        let result = oracle.context.suffix
            == oracle
                .decrypt_suffix(block_size, prefix_size, suffix_size)
                .unwrap();
        if !result {
            println!("oracle = {:?}", oracle);
            println!("block_size = {:?}", block_size);
            println!("prefix_size = {:?}", prefix_size);
            println!("suffix_size = {:?}", suffix_size);
            println!(
                "decrypt_suffix = {:?}",
                oracle
                    .decrypt_suffix(block_size, prefix_size, suffix_size)
                    .unwrap()
            );
        }
        result
    }
}
