pub use crate::set04::challenge28::*;
pub use hash::fixed_hash::*;

#[derive(Clone, Debug)]
pub struct Sha1Forgery {
    pub digest: [u8; 20],
    pub message: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Sha1KeyedLengthExtensionAttack {
    pub digest: [u8; 20],
    pub bit_size: u64,
    pub key_size: usize,
    pub message: Vec<u8>,
}

impl Sha1KeyedLengthExtensionAttack {
    pub fn brute_force<T: ?Sized + AsRef<[u8]>>(
        oracle: &Sha1Mac,
        message: &T,
        max_key_size: usize,
    ) -> Result<Self, &'static str> {
        use std::convert::TryInto;
        let message_size: usize = message.as_ref().len();
        let mac = oracle.authenticate(&message);
        let digest: [u8; 20] = (&mac[..]).try_into().unwrap();
        for key_size in 0..=max_key_size {
            let byte_size: u64 = key_size as u64 + message_size as u64;
            let attack_padding: Vec<u8> = sha1_padding(byte_size);
            let bit_size: u64 = (byte_size + attack_padding.len() as u64) * 8;
            let mut hsh = hash::sha1::Sha1Context::recover(digest, bit_size).unwrap();
            let attack_mac = hsh.output().unwrap().to_vec();
            let attack_message: Vec<u8> = message
                .as_ref()
                .iter()
                .chain(attack_padding.iter())
                .copied()
                .collect();
            if oracle.validate(&attack_message, &attack_mac) {
                return Ok(Self {
                    digest,
                    bit_size,
                    key_size,
                    message: attack_message,
                });
            }
        }
        Err("unable to find a valid key size")
    }

    pub fn forge<T: ?Sized + AsRef<[u8]>>(&self, extension: &T) -> Sha1Forgery {
        let mut hsh = hash::sha1::Sha1Context::recover(self.digest, self.bit_size).unwrap();
        hsh.update(&extension).unwrap();
        let digest: [u8; 20] = hsh.output().unwrap().bytes();
        let message: Vec<u8> = self
            .message
            .iter()
            .chain(extension.as_ref())
            .copied()
            .collect();
        Sha1Forgery { digest, message }
    }
}

pub fn sha1_padding(byte_size: u64) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut index: usize = byte_size as usize % 64;
    if index > 55 {
        output.push(0x80);
        index += 1;
        while index < 64 {
            output.push(0x00);
            index += 1;
        }
        index = 0;
        while index < 56 {
            output.push(0x00);
            index += 1;
        }
    } else {
        output.push(0x80);
        index += 1;
        while index < 56 {
            output.push(0x00);
            index += 1;
        }
    }
    output.extend(&(byte_size * 8).to_be_bytes());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn break_a_sha1_keyed_mac_using_length_extension() {
        let oracle = Sha1Mac::default();
        let message =
            "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let attack = Sha1KeyedLengthExtensionAttack::brute_force(&oracle, &message, 1024).unwrap();
        assert_eq!(oracle.get_key_size(), attack.key_size);
        let forgery = attack.forge(";admin=true");
        assert_eq!(true, oracle.validate(&forgery.message, &forgery.digest));
    }

    #[quickcheck]
    fn break_any_sha1_keyed_mac_using_length_extension(
        key: Vec<u8>,
        message: Vec<u8>,
        extension: Vec<u8>,
    ) -> bool {
        let key_size = key.len();
        let oracle = Sha1Mac::new(key);
        let attack =
            Sha1KeyedLengthExtensionAttack::brute_force(&oracle, &message, key_size + 1).unwrap();
        assert_eq!(oracle.get_key_size(), attack.key_size);
        let forgery = attack.forge(&extension);
        oracle.validate(&forgery.message, &forgery.digest)
    }
}
