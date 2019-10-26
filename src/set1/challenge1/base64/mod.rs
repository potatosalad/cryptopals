// pub mod decoder;
pub mod encoder;

// pub use decoder::{decode, decode_config, decode_lowercase, decode_uppercase};
pub use encoder::{encode, encode_config, encode_no_padding};

#[cfg(test)]
mod tests {
    // #[test]
    // fn test_base16_decode() {
    //     let decoded: Vec<u8> = vec![0, 1, 2, 220, 255];
    //     let encoded_lowercase = "000102dcff";
    //     let encoded_mixedcase = "000102DcfF";
    //     let encoded_uppercase = "000102DCFF";
    //     let config_lowercase = super::decoder::Base16DecoderConfig::default().lowercase();
    //     let config_mixedcase = super::decoder::Base16DecoderConfig::default().mixedcase();
    //     let config_uppercase = super::decoder::Base16DecoderConfig::default().uppercase();
    //     let decoded_lowercase: Vec<u8> =
    //         super::decode_config(&encoded_lowercase, &config_lowercase).unwrap();
    //     let decoded_mixedcase: Vec<u8> =
    //         super::decode_config(&encoded_mixedcase, &config_mixedcase).unwrap();
    //     let decoded_uppercase: Vec<u8> =
    //         super::decode_config(&encoded_uppercase, &config_uppercase).unwrap();
    //     assert_eq!(decoded, decoded_lowercase);
    //     assert_eq!(decoded, decoded_mixedcase);
    //     assert_eq!(decoded, decoded_uppercase);
    // }

    #[test]
    fn test_base64_encode() {
        let decoded: Vec<u8> = vec![130, 65, 130, 65, 130, 65];
        let config_padding = super::encoder::Base64EncoderConfig::default().padding();
        let config_no_padding = super::encoder::Base64EncoderConfig::default().no_padding();
        let encoded_padding: String = super::encode_config(&decoded, &config_padding);
        let encoded_no_padding: String = super::encode_config(&decoded, &config_no_padding);
        assert_eq!("gkGCQYJB", encoded_padding);
        assert_eq!("gkGCQYJB", encoded_no_padding);
        let decoded: Vec<u8> = vec![130, 65, 130, 65, 130, 65, 0];
        let encoded_padding: String = super::encode_config(&decoded, &config_padding);
        let encoded_no_padding: String = super::encode_config(&decoded, &config_no_padding);
        assert_eq!("gkGCQYJBAA==", encoded_padding);
        assert_eq!("gkGCQYJBAA", encoded_no_padding);
        let decoded: Vec<u8> = vec![130, 65, 130, 65, 130, 65, 130, 0];
        let encoded_padding: String = super::encode_config(&decoded, &config_padding);
        let encoded_no_padding: String = super::encode_config(&decoded, &config_no_padding);
        assert_eq!("gkGCQYJBggA=", encoded_padding);
        assert_eq!("gkGCQYJBggA", encoded_no_padding);
        let decoded: Vec<u8> = vec![130, 65, 130, 65, 130, 65, 130, 65, 0];
        let encoded_padding: String = super::encode_config(&decoded, &config_padding);
        let encoded_no_padding: String = super::encode_config(&decoded, &config_no_padding);
        assert_eq!("gkGCQYJBgkEA", encoded_padding);
        assert_eq!("gkGCQYJBgkEA", encoded_no_padding);
    }

    #[quickcheck]
    fn encode_and_base64_encode_matches(xs: Vec<u8>) -> bool {
        super::encode(&xs) == base64::encode(&xs)
    }

    #[quickcheck]
    fn encode_no_padding_and_base64_encode_config_standard_no_pad_matches(xs: Vec<u8>) -> bool {
        super::encode_no_padding(&xs) == base64::encode_config(&xs, base64::STANDARD_NO_PAD)
    }
}
