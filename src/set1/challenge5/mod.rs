pub mod repeating_key_xor;

pub use repeating_key_xor::RepeatingKeyXor;

#[cfg(test)]
mod tests {
    #[test]
    fn implement_repeating_key_xor() {
        use super::RepeatingKeyXor;
        use crate::set1::challenge1::base16;
        let plaintext =
            "Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let mut cipher = RepeatingKeyXor::new(&key);
        let ciphertext = base16::encode(&cipher.encrypt(plaintext));
        assert_eq!(expected, ciphertext);
    }
}
