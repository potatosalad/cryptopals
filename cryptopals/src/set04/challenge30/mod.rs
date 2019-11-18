pub use hash::fixed_hash::*;

#[derive(Clone, Debug, PartialEq)]
pub struct Md4Mac {
    key: Vec<u8>,
}

impl Default for Md4Mac {
    fn default() -> Self {
        Self::random()
    }
}

fn constant_time_compare<A: ?Sized + AsRef<[u8]>, B: ?Sized + AsRef<[u8]>>(a: &A, b: &B) -> bool {
    let a = a.as_ref();
    let b = b.as_ref();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
}

impl Md4Mac {
    pub fn random() -> Self {
        use rand::prelude::*;
        let mut csprng = thread_rng();
        let size: usize = csprng.gen_range(1, 128);
        let mut key: Vec<u8> = vec![0_u8; size];
        csprng.fill_bytes(&mut key);
        Self::new(key)
    }

    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn authenticate<M: ?Sized + AsRef<[u8]>>(&self, message: &M) -> Vec<u8> {
        let mut hsh = hash::md4::Md4Context::init();
        hsh.update(&self.key).unwrap();
        hsh.update(message).unwrap();
        hsh.output().unwrap().to_vec()
    }

    pub fn validate<M: ?Sized + AsRef<[u8]>, C: ?Sized + AsRef<[u8]>>(
        &self,
        message: &M,
        code: &C,
    ) -> bool {
        let challenge = self.authenticate(message);
        constant_time_compare(&challenge, code)
    }

    pub fn get_key_size(&self) -> usize {
        self.key.len()
    }
}

#[derive(Clone, Debug)]
pub struct Md4Forgery {
    pub digest: [u8; 16],
    pub message: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Md4KeyedLengthExtensionAttack {
    pub digest: [u8; 16],
    pub bit_size: u64,
    pub key_size: usize,
    pub message: Vec<u8>,
}

impl Md4KeyedLengthExtensionAttack {
    pub fn brute_force<T: ?Sized + AsRef<[u8]>>(
        oracle: &Md4Mac,
        message: &T,
        max_key_size: usize,
    ) -> Result<Self, &'static str> {
        use std::convert::TryInto;
        let message_size: usize = message.as_ref().len();
        let mac = oracle.authenticate(&message);
        let digest: [u8; 16] = (&mac[..]).try_into().unwrap();
        for key_size in 0..=max_key_size {
            let byte_size: u64 = key_size as u64 + message_size as u64;
            let attack_padding: Vec<u8> = md4_padding(byte_size);
            let bit_size: u64 = (byte_size + attack_padding.len() as u64) * 8;
            let mut hsh = hash::md4::Md4Context::recover(digest, bit_size).unwrap();
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

    pub fn forge<T: ?Sized + AsRef<[u8]>>(&self, extension: &T) -> Md4Forgery {
        let mut hsh = hash::md4::Md4Context::recover(self.digest, self.bit_size).unwrap();
        hsh.update(&extension).unwrap();
        let digest: [u8; 16] = hsh.output().unwrap().bytes();
        let message: Vec<u8> = self
            .message
            .iter()
            .chain(extension.as_ref())
            .copied()
            .collect();
        Md4Forgery { digest, message }
    }
}

pub fn md4_padding(byte_size: u64) -> Vec<u8> {
    const PADDING: [u8; 64] = [
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let mut output: Vec<u8> = Vec::new();
    // Pad out to 56 mod 64.
    let bit_size: u64 = byte_size * 8;
    let count: [u8; 8] = bit_size.to_le_bytes();
    let index: usize = ((bit_size as usize) >> 3) & 0x3F;
    let pad_size: usize = if index < 56 { 56 - index } else { 120 - index };
    output.extend_from_slice(&PADDING[0..pad_size]);
    output.extend_from_slice(&count);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn break_a_md4_keyed_mac_using_length_extension() {
        let oracle = Md4Mac::default();
        let message =
            "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let attack = Md4KeyedLengthExtensionAttack::brute_force(&oracle, &message, 1024).unwrap();
        assert_eq!(oracle.get_key_size(), attack.key_size);
        let forgery = attack.forge(";admin=true");
        assert_eq!(true, oracle.validate(&forgery.message, &forgery.digest));
    }

    #[quickcheck]
    fn break_any_md4_keyed_mac_using_length_extension(
        key: Vec<u8>,
        message: Vec<u8>,
        extension: Vec<u8>,
    ) -> bool {
        let key_size = key.len();
        let oracle = Md4Mac::new(key);
        let attack =
            Md4KeyedLengthExtensionAttack::brute_force(&oracle, &message, key_size + 1).unwrap();
        assert_eq!(oracle.get_key_size(), attack.key_size);
        let forgery = attack.forge(&extension);
        oracle.validate(&forgery.message, &forgery.digest)
    }
}
