pub use aes::ctr::{decrypt as aes_ctr_decrypt, encrypt as aes_ctr_encrypt};

#[cfg(test)]
mod tests {
    #[test]
    fn sanity_check_aes_128_ctr() {
        let key: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
        let iv: Vec<u8> = vec![0_u8; 16];
        let ciphertext: Vec<u8> = base64::decode(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        )
        .unwrap();
        let expected: Vec<u8> = b"Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ".to_vec();
        let plaintext: Vec<u8> = super::aes_ctr_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(expected, plaintext);
        let challenge: Vec<u8> = super::aes_ctr_encrypt(&key, &iv, &plaintext).unwrap();
        assert_eq!(ciphertext, challenge);
    }
}
