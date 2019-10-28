pub use aes::ecb::{decrypt as aes_ecb_decrypt, encrypt as aes_ecb_encrypt};

#[cfg(test)]
mod tests {
    use super::{aes_ecb_decrypt, aes_ecb_encrypt};

    lazy_static! {
        #[derive(Clone, Copy, Debug, PartialEq)]
        static ref TEST_VECTOR: String = {
            let contents = include_str!("7.txt");
            contents.chars().filter(|c| !c.is_whitespace()).collect::<String>()
        };
    }

    #[test]
    fn aes_ecb_sanity_check() {
        let aes_128_key = "YELLOW SUBMARINE";
        let aes_192_key = "YELLOW SUBMARINE FOREVER";
        let aes_256_key = "YELLOW SUBMARINE FOREVER & EVER!";
        let plaintext = "abcdefghijklmnopqrstuvwxyz012345";
        let aes_128_ecb_ciphertext =
            "bdb184d44e1fc1d3060945b53c994f48fc2038858f1a6c91d312c5a0d554bacb";
        let aes_192_ecb_ciphertext =
            "a713d164c85cad00cced99b1390c60cb554f37382a93bd6a1a07663758a0adf6";
        let aes_256_ecb_ciphertext =
            "7d2983a43521deb4e466c19d9ec2da0a78c55d0746ca603d16cad1bef78fa55e";
        let challenge_aes_128_ecb_ciphertext = aes_ecb_encrypt(&aes_128_key, &plaintext).unwrap();
        let challenge_aes_192_ecb_ciphertext = aes_ecb_encrypt(&aes_192_key, &plaintext).unwrap();
        let challenge_aes_256_ecb_ciphertext = aes_ecb_encrypt(&aes_256_key, &plaintext).unwrap();
        assert_eq!(
            aes_128_ecb_ciphertext,
            hex::encode(&challenge_aes_128_ecb_ciphertext)
        );
        assert_eq!(
            aes_192_ecb_ciphertext,
            hex::encode(&challenge_aes_192_ecb_ciphertext)
        );
        assert_eq!(
            aes_256_ecb_ciphertext,
            hex::encode(&challenge_aes_256_ecb_ciphertext)
        );
        let challenge_aes_128_ecb_plaintext =
            aes_ecb_decrypt(&aes_128_key, &challenge_aes_128_ecb_ciphertext)
                .map(|decrypted| String::from_utf8(decrypted).unwrap())
                .unwrap();
        let challenge_aes_192_ecb_plaintext =
            aes_ecb_decrypt(&aes_192_key, &challenge_aes_192_ecb_ciphertext)
                .map(|decrypted| String::from_utf8(decrypted).unwrap())
                .unwrap();
        let challenge_aes_256_ecb_plaintext =
            aes_ecb_decrypt(&aes_256_key, &challenge_aes_256_ecb_ciphertext)
                .map(|decrypted| String::from_utf8(decrypted).unwrap())
                .unwrap();
        assert_eq!(plaintext, &challenge_aes_128_ecb_plaintext);
        assert_eq!(plaintext, &challenge_aes_192_ecb_plaintext);
        assert_eq!(plaintext, &challenge_aes_256_ecb_plaintext);
    }

    #[test]
    fn aes_in_ecb_mode() {
        let key = "YELLOW SUBMARINE";
        let ciphertext = base64::decode(&*TEST_VECTOR).unwrap();
        let plaintext = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}";
        let challenge = aes_ecb_decrypt(&key, &ciphertext)
            .map(|decrypted| String::from_utf8(decrypted).unwrap())
            .unwrap();
        assert_eq!(plaintext, challenge);
    }
}
