pub mod byte_xor;
pub mod english_decrypter;
pub mod english_distribution;

pub use byte_xor::single_byte_xor;

#[cfg(test)]
mod tests {
    #[test]
    fn single_byte_xor_should_decrypt_plaintext() {
        let encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected = "Cooking MC\'s like a pound of bacon";
        let ciphertext = hex::decode(&encrypted).unwrap();
        let challenge = super::english_decrypter::decrypt(&ciphertext, 0).unwrap();
        assert_eq!(expected, challenge.output);
    }
}
