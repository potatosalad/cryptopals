pub use crate::set01::challenge07::{AesEcb, AesEcbBlockCipher, AesEcbCipher, AesError, AesKey};

pub struct AesCbcInitializationVector([u8; 16]);

impl AesCbcInitializationVector {
    pub fn aes_cbc_iv(value: [u8; 16]) -> AesCbcInitializationVector {
        AesCbcInitializationVector(value)
    }

    pub fn try_copy_bytes<IV: ?Sized + AsRef<[u8]>>(
        bytes: &IV,
    ) -> Result<AesCbcInitializationVector, AesError> {
        let bytes = bytes.as_ref();
        match bytes.len() {
            16 => {
                let mut iv: [u8; 16] = [0u8; 16];
                iv.copy_from_slice(&bytes);
                Ok(Self::aes_cbc_iv(iv))
            }
            x => Err(AesError::InvalidInitializationVectorSize {
                was: x,
                explanation: "must be 16 bytes",
            }),
        }
    }
}

pub struct AesCbcCipher<'k, 'iv> {
    key: &'k AesKey,
    iv: &'iv AesCbcInitializationVector,
}

impl<'k, 'iv> AesCbcCipher<'k, 'iv> {
    pub fn new(key: &'k AesKey, iv: &'iv AesCbcInitializationVector) -> AesCbcCipher<'k, 'iv> {
        AesCbcCipher { key, iv }
    }

    pub fn decrypt<T: ?Sized + AsRef<[u8]>>(&self, ciphertext: &T) -> Result<Vec<u8>, AesError> {
        let ciphertext = ciphertext.as_ref();
        match ciphertext.len() {
            0 => Ok(vec![]),
            x => {
                if x % 16 == 0 {
                    let aes_ecb_block_cipher = self.key.as_aes_ecb_block_cipher();
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(&self.iv.0[..]);
                    Ok(ciphertext
                        .chunks(16_usize)
                        .flat_map(|encrypted_block| {
                            let decrypted_block = aes_ecb_block_cipher
                                .decrypt_block(&encrypted_block)
                                .unwrap();
                            let decrypted_block = Self::exor(&decrypted_block, &iv);
                            iv.copy_from_slice(&encrypted_block[..]);
                            decrypted_block.into_iter()
                        })
                        .collect())
                } else {
                    Err(AesError::InvalidBlockSize(x))
                }
            }
        }
    }

    pub fn encrypt<T: ?Sized + AsRef<[u8]>>(&self, plaintext: &T) -> Result<Vec<u8>, AesError> {
        let plaintext = plaintext.as_ref();
        match plaintext.len() {
            0 => Ok(vec![]),
            x => {
                if x % 16 == 0 {
                    let aes_ecb_block_cipher = self.key.as_aes_ecb_block_cipher();
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(&self.iv.0[..]);
                    Ok(plaintext
                        .chunks(16_usize)
                        .flat_map(|decrypted_block| {
                            let decrypted_block = Self::exor(&decrypted_block, &iv);
                            let encrypted_block = aes_ecb_block_cipher
                                .encrypt_block(&decrypted_block)
                                .unwrap();
                            iv.copy_from_slice(&encrypted_block[..]);
                            encrypted_block.into_iter()
                        })
                        .collect())
                } else {
                    Err(AesError::InvalidBlockSize(x))
                }
            }
        }
    }

    fn exor(block: &[u8], iv: &[u8]) -> Vec<u8> {
        block.iter().zip(iv.iter()).map(|(a, b)| a ^ b).collect()
    }
}

pub struct AesCbc;

impl AesCbc {
    pub fn decrypt<K: ?Sized + AsRef<[u8]>, IV: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
        key: &K,
        iv: &IV,
        ciphertext: &T,
    ) -> Result<Vec<u8>, AesError> {
        let key = AesKey::try_copy_bytes(key)?;
        let iv = AesCbcInitializationVector::try_copy_bytes(iv)?;
        let cipher = AesCbcCipher::new(&key, &iv);
        cipher.decrypt(ciphertext)
    }

    pub fn encrypt<K: ?Sized + AsRef<[u8]>, IV: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
        key: &K,
        iv: &IV,
        plaintext: &T,
    ) -> Result<Vec<u8>, AesError> {
        let key = AesKey::try_copy_bytes(key)?;
        let iv = AesCbcInitializationVector::try_copy_bytes(iv)?;
        let cipher = AesCbcCipher::new(&key, &iv);
        cipher.encrypt(plaintext)
    }
}

#[cfg(test)]
mod tests {
    lazy_static! {
        #[derive(Clone, Copy, Debug, PartialEq)]
        static ref TEST_VECTOR: String = {
            let contents = include_str!("10.txt");
            contents.chars().filter(|c| !c.is_whitespace()).collect::<String>()
        };
    }

    #[test]
    fn aes_cbc_sanity_check() {
        use super::AesCbc;
        let aes_128_key = "YELLOW SUBMARINE";
        let aes_192_key = "YELLOW SUBMARINE FOREVER";
        let aes_256_key = "YELLOW SUBMARINE FOREVER & EVER!";
        let iv = b"abcdefghijklmnop";
        let plaintext = "abcdefghijklmnopqrstuvwxyz012345";
        let aes_128_cbc_ciphertext =
            "76d1cb4bafa246e2e3af035d6c13c372b29138f7558637fdab24c0b0e80cd8a2";
        let aes_192_cbc_ciphertext =
            "317a6df7954d3e1acbfb4a4ceba42bb4fd86b70fb6d98b6c3ad4d987c9c57ac5";
        let aes_256_cbc_ciphertext =
            "4a4c74f37f4eb88d01bf3c85b97e671aae5036e2940c90b72bc698af2a1382b4";
        let challenge_aes_128_cbc_ciphertext =
            AesCbc::encrypt(&aes_128_key, &iv, &plaintext).unwrap();
        let challenge_aes_192_cbc_ciphertext =
            AesCbc::encrypt(&aes_192_key, &iv, &plaintext).unwrap();
        let challenge_aes_256_cbc_ciphertext =
            AesCbc::encrypt(&aes_256_key, &iv, &plaintext).unwrap();
        assert_eq!(
            aes_128_cbc_ciphertext,
            hex::encode(&challenge_aes_128_cbc_ciphertext)
        );
        assert_eq!(
            aes_192_cbc_ciphertext,
            hex::encode(&challenge_aes_192_cbc_ciphertext)
        );
        assert_eq!(
            aes_256_cbc_ciphertext,
            hex::encode(&challenge_aes_256_cbc_ciphertext)
        );
        let challenge_aes_128_cbc_plaintext = AesCbc::decrypt(
            &aes_128_key,
            &iv,
            &hex::decode(aes_128_cbc_ciphertext).unwrap(),
        )
        .map(|decrypted| String::from_utf8(decrypted).unwrap())
        .unwrap();
        let challenge_aes_192_cbc_plaintext = AesCbc::decrypt(
            &aes_192_key,
            &iv,
            &hex::decode(aes_192_cbc_ciphertext).unwrap(),
        )
        .map(|decrypted| String::from_utf8(decrypted).unwrap())
        .unwrap();
        let challenge_aes_256_cbc_plaintext = AesCbc::decrypt(
            &aes_256_key,
            &iv,
            &hex::decode(aes_256_cbc_ciphertext).unwrap(),
        )
        .map(|decrypted| String::from_utf8(decrypted).unwrap())
        .unwrap();
        assert_eq!(plaintext, &challenge_aes_128_cbc_plaintext);
        assert_eq!(plaintext, &challenge_aes_192_cbc_plaintext);
        assert_eq!(plaintext, &challenge_aes_256_cbc_plaintext);
    }

    #[test]
    fn implement_cbc_mode() {
        use super::AesCbc;
        let key = "YELLOW SUBMARINE";
        let iv = vec![0u8; 16];
        let ciphertext = base64::decode(&*TEST_VECTOR).unwrap();
        let plaintext = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}";
        let challenge = AesCbc::decrypt(&key, &iv, &ciphertext)
            .map(|decrypted| String::from_utf8(decrypted).unwrap())
            .unwrap();
        assert_eq!(plaintext, challenge);
    }
}
