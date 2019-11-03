pub use pkcs7;

#[cfg(test)]
mod tests {
    use super::pkcs7;

    #[test]
    fn pkcs7_padding_validation() {
        let expected = b"ICE ICE BABY".to_vec();
        let challenge: Vec<u8> = pkcs7::unpad("ICE ICE BABY\x04\x04\x04\x04", 16).unwrap();
        assert_eq!(expected, challenge);
        assert!(pkcs7::unpad::<Vec<u8>, _>("ICE ICE BABY\x05\x05\x05\x05", 16).is_err());
        assert!(pkcs7::unpad::<Vec<u8>, _>("ICE ICE BABY\x01\x02\x03\x04", 16).is_err());
    }
}
