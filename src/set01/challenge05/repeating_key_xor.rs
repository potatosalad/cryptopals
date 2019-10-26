pub struct RepeatingKeyXor<'key> {
    key: &'key [u8],
    key_length: usize,
    key_offset: usize,
}

impl<'key> RepeatingKeyXor<'key> {
    pub fn new<K: ?Sized + AsRef<[u8]>>(key: &'key K) -> RepeatingKeyXor<'key> {
        let key = key.as_ref();
        let key_length = key.len();
        if key_length == 0 {
            panic!("key.len() must be non-zero");
        }
        RepeatingKeyXor {
            key,
            key_length,
            key_offset: 0,
        }
    }

    pub fn encrypt<T: ?Sized + AsRef<[u8]>>(&mut self, plaintext: &T) -> Vec<u8> {
        plaintext
            .as_ref()
            .iter()
            .map(|target| {
                let key = self.key[self.key_offset];
                self.key_offset = (self.key_offset + 1) % self.key_length;
                target ^ key
            })
            .collect()
    }
}
