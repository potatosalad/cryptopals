// See: https://tools.ietf.org/html/rfc2104

use hash::fixed_hash::{FixedHashContext, FixedHashOutput};
use hash::md4::{Md4Context, Md4Output};
use hash::sha1::{Sha1Context, Sha1Output};
use hash::sha256::{Sha256Context, Sha256Output};
use xor::sxor::sxor;

#[derive(Clone)]
pub struct HmacContext<H: FixedHashContext> {
    outer_context: H,
    inner_context: H,
}

impl<H: FixedHashContext> FixedHashContext for HmacContext<H> {
    type Error = H::Error;
    type Output = H::Output;

    fn init() -> Self {
        Self {
            outer_context: H::init(),
            inner_context: H::init(),
        }
    }

    fn update<T: ?Sized + AsRef<[u8]>>(&mut self, input: &T) -> Result<(), Self::Error> {
        self.inner_context.update(input)
    }

    fn output(&mut self) -> Result<Self::Output, Self::Error> {
        self.outer_context
            .update(self.inner_context.output()?.as_slice())?;
        self.outer_context.output()
    }

    fn reset(&mut self) {
        self.outer_context.reset();
        self.inner_context.reset();
    }

    fn block_size() -> usize {
        H::block_size()
    }

    fn hash_size() -> usize {
        H::hash_size()
    }
}

impl<H: FixedHashContext> HmacContext<H> {
    pub fn new<K: ?Sized + AsRef<[u8]>>(key: &K) -> Result<Self, H::Error> {
        let mut context = Self::init();
        context.set_key(key)?;
        Ok(context)
    }

    pub fn set_key<K: ?Sized + AsRef<[u8]>>(&mut self, key: &K) -> Result<(), H::Error> {
        let block_size = H::block_size();

        let mut pad_key = if key.as_ref().len() > block_size {
            let mut ctx = H::init();
            ctx.update(key)?;
            ctx.output()?.to_vec()
        } else {
            key.as_ref().to_vec()
        };

        if pad_key.len() < block_size {
            pad_key.resize(block_size, 0);
        }

        let pad_key_outer: Vec<u8> = sxor(&pad_key, 0x5c);
        let pad_key_inner: Vec<u8> = sxor(&pad_key, 0x36);

        self.outer_context.update(&pad_key_outer)?;
        self.inner_context.update(&pad_key_inner)?;

        Ok(())
    }
}

pub type HmacMd4Context = HmacContext<Md4Context>;
pub type HmacSha1Context = HmacContext<Sha1Context>;
pub type HmacSha256Context = HmacContext<Sha256Context>;

pub fn hmac_md4<K: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(key: &K, input: &T) -> Md4Output {
    let mut ctx = HmacMd4Context::new(key).unwrap();
    ctx.update(input).unwrap();
    ctx.output().unwrap()
}

pub fn hmac_sha1<K: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
    key: &K,
    input: &T,
) -> Sha1Output {
    let mut ctx = HmacSha1Context::new(key).unwrap();
    ctx.update(input).unwrap();
    ctx.output().unwrap()
}

pub fn hmac_sha256<K: ?Sized + AsRef<[u8]>, T: ?Sized + AsRef<[u8]>>(
    key: &K,
    input: &T,
) -> Sha256Output {
    let mut ctx = HmacSha256Context::new(key).unwrap();
    ctx.update(input).unwrap();
    ctx.output().unwrap()
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_hmac_sha1_matches_extern_hmac_sha1() {
        let mut key: Vec<u8> = Vec::new();
        let mut input: Vec<u8> = Vec::new();
        for _ in 0..1024 {
            assert_eq!(
                hmacsha1impl::hmac_sha1(key.as_slice(), input.as_slice())[..],
                crate::hmac::hmac_sha1(&key, &input).bytes()[..]
            );
            key.push(0x01);
            input.push(0x03);
        }
    }

    #[quickcheck]
    fn crate_hmac_sha1_matches_extern_hmac_sha1_property(key: Vec<u8>, input: Vec<u8>) -> bool {
        hmacsha1impl::hmac_sha1(key.as_slice(), input.as_slice())[..]
            == crate::hmac::hmac_sha1(&key, &input).bytes()[..]
    }
}
