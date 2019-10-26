pub mod decoder;
pub mod encoder;

pub use decoder::{decode, decode_config, decode_lowercase, decode_uppercase};
pub use encoder::{encode, encode_config, encode_uppercase};

#[cfg(test)]
mod tests {
    #[test]
    fn test_base16_decode() {
        let decoded: Vec<u8> = vec![0, 1, 2, 220, 255];
        let encoded_lowercase = "000102dcff";
        let encoded_mixedcase = "000102DcfF";
        let encoded_uppercase = "000102DCFF";
        let config_lowercase = super::decoder::Base16DecoderConfig::default().lowercase();
        let config_mixedcase = super::decoder::Base16DecoderConfig::default().mixedcase();
        let config_uppercase = super::decoder::Base16DecoderConfig::default().uppercase();
        let decoded_lowercase: Vec<u8> =
            super::decode_config(&encoded_lowercase, &config_lowercase).unwrap();
        let decoded_mixedcase: Vec<u8> =
            super::decode_config(&encoded_mixedcase, &config_mixedcase).unwrap();
        let decoded_uppercase: Vec<u8> =
            super::decode_config(&encoded_uppercase, &config_uppercase).unwrap();
        assert_eq!(decoded, decoded_lowercase);
        assert_eq!(decoded, decoded_mixedcase);
        assert_eq!(decoded, decoded_uppercase);
    }

    #[test]
    fn test_base16_encode() {
        let decoded: Vec<u8> = vec![0, 1, 2, 220, 255];
        let config_lowercase = super::encoder::Base16EncoderConfig::default().lowercase();
        let config_uppercase = super::encoder::Base16EncoderConfig::default().uppercase();
        let encoded_lowercase: String = super::encode_config(&decoded, &config_lowercase);
        let encoded_uppercase: String = super::encode_config(&decoded, &config_uppercase);
        assert_eq!("000102dcff", encoded_lowercase);
        assert_eq!("000102DCFF", encoded_uppercase);
    }

    #[quickcheck]
    fn encode_and_decode_is_identity(xs: Vec<u8>) -> bool {
        xs == super::decode(&super::encode(&xs)).unwrap()
    }

    #[quickcheck]
    fn encode_and_hex_encode_matches(xs: Vec<u8>) -> bool {
        super::encode(&xs) == hex::encode(&xs)
    }

    #[quickcheck]
    fn encode_and_hex_decode_is_identity(xs: Vec<u8>) -> bool {
        xs == hex::decode(&super::encode(&xs)).unwrap()
    }

    #[quickcheck]
    fn encode_uppercase_and_decode_is_identity(xs: Vec<u8>) -> bool {
        xs == super::decode(&super::encode_uppercase(&xs)).unwrap()
    }

    #[quickcheck]
    fn encode_uppercase_and_hex_encode_upper_matches(xs: Vec<u8>) -> bool {
        super::encode_uppercase(&xs) == hex::encode_upper(&xs)
    }

    #[quickcheck]
    fn encode_uppercase_and_hex_decode_is_identity(xs: Vec<u8>) -> bool {
        xs == hex::decode(&super::encode_uppercase(&xs)).unwrap()
    }
}
