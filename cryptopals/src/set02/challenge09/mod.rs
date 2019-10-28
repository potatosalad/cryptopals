pub use pkcs7;

#[cfg(test)]
mod tests {
    use super::pkcs7;

    #[test]
    fn implement_pkcs7_padding() {
        let plaintext = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        let challenge: Vec<u8> = pkcs7::pad(&plaintext, 20).unwrap();
        assert_eq!(&expected[..], &challenge[..]);
        let challenge: Vec<u8> = pkcs7::unpad(&expected, 20).unwrap();
        assert_eq!(&plaintext[..], &challenge[..]);
    }
}
