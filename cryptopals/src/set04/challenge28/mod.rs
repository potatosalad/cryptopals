#[derive(Clone, Debug, PartialEq)]
pub struct Sha1Mac {
    key: Vec<u8>,
}

impl Default for Sha1Mac {
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

impl Sha1Mac {
    pub fn random() -> Self {
        use rand::prelude::*;
        let mut csprng = thread_rng();
        let size: usize = csprng.gen_range(1..=128);
        let mut key: Vec<u8> = vec![0_u8; size];
        csprng.fill_bytes(&mut key);
        Self::new(key)
    }

    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn authenticate<M: ?Sized + AsRef<[u8]>>(&self, message: &M) -> Vec<u8> {
        use hash::fixed_hash::*;
        let mut hsh = hash::sha1::Sha1Context::init();
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

#[cfg(test)]
mod tests {
    use super::*;
    use hash::fixed_hash::*;
    use quickcheck::TestResult;

    #[test]
    fn implement_a_sha1_keyed_mac() {
        let ctx = Sha1Mac::default();
        let message = "my protected message";
        let mac = ctx.authenticate(&message);
        let invalid_message = "my protected messagf";
        assert_eq!(false, ctx.validate(&invalid_message, &mac));
        assert_eq!(true, ctx.validate(&message, &mac));
    }

    #[quickcheck]
    fn sha1_keyed_mac_properties(key: Vec<u8>, message: Vec<u8>) -> TestResult {
        // Verify that you cannot tamper with the message without breaking
        // the MAC you've produced, and that you can't produce a new MAC
        // without knowing the secret key.
        if key.is_empty() {
            TestResult::discard()
        } else {
            TestResult::from_bool(test_sha1_keyed_mac_properties(key, message))
        }
    }

    fn test_sha1_keyed_mac_properties(key: Vec<u8>, message: Vec<u8>) -> bool {
        let ctx = Sha1Mac::new(key);
        let empty_mac = hash::sha1::hash(&[]).to_vec();
        let mac = ctx.authenticate(&message);
        if !ctx.validate(&[], &empty_mac) {
            ctx.validate(&message, &mac)
        } else {
            false
        }
    }
}
