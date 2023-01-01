use rand::prelude::*;

use crate::set02::challenge12::Oracle as Challenge12Oracle;

pub fn random_prefix_and_key_oracle(suffix: &[u8]) -> Challenge12Oracle {
    let mut csprng = thread_rng();
    let mut key: [u8; 16] = [0_u8; 16];
    csprng.fill_bytes(&mut key);
    let mut prefix: Vec<u8> = vec![0_u8; csprng.gen_range(1_usize..=200_usize)];
    csprng.fill_bytes(&mut prefix);
    Challenge12Oracle::new(&key, prefix.as_slice(), suffix)
}

#[cfg(test)]
mod tests {
    #[test]
    fn random_encryption_oracle_decrypt_byte_at_a_time_aes_ecb_mode_harder() {
        let suffix: Vec<u8> = base64::decode(concat!(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg",
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq",
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg",
            "YnkK"
        ))
        .unwrap();
        let oracle = super::random_prefix_and_key_oracle(suffix.as_slice());
        let block_size = oracle.detect_block_size(0_u8).unwrap();
        let (prefix_size, suffix_size) = oracle
            .detect_prefix_size_and_suffix_size(block_size, 0_u8, 1_u8)
            .unwrap();
        assert_eq!(
            oracle.context.suffix,
            oracle
                .decrypt_suffix(block_size, prefix_size, suffix_size)
                .unwrap()
        );
    }
}
