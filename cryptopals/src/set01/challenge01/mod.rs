pub mod base16;
pub mod base64;

#[cfg(test)]
mod tests {
    #[test]
    fn convert_hex_to_base64() {
        let the_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let should_produce = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(
            should_produce,
            super::base64::encode(&super::base16::decode(&the_string).unwrap())
        );
    }
}
