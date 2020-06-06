pub use num_bigint_dig::BigUint;
use num_bigint_dig::{RandBigInt, RandPrime};
pub use num_traits::Num;
use rand::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct DiffieHellmanBase {
    p: BigUint,
    g: BigUint,
}

impl DiffieHellmanBase {
    pub fn new(p: BigUint, g: BigUint) -> Self {
        Self { p, g }
    }

    pub fn gen(bits: usize) -> Self {
        let mut rng = thread_rng();
        let p = rng.gen_prime(bits);
        let g = rng.gen_prime(bits);
        Self::new(p, g)
    }

    pub fn gen_secret_key(&self) -> DiffieHellmanSecretKey {
        let mut rng = thread_rng();
        let secret = rng.gen_biguint(self.p.bits());
        DiffieHellmanSecretKey::new(self.clone(), secret)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiffieHellmanSecretKey {
    base: DiffieHellmanBase,
    secret: BigUint,
    public: BigUint,
}

impl DiffieHellmanSecretKey {
    pub fn new(base: DiffieHellmanBase, secret: BigUint) -> Self {
        let secret = secret % &base.p;
        let public = base.g.modpow(&secret, &base.p);
        Self {
            base,
            secret,
            public,
        }
    }

    pub fn compute_shared_secret(
        &self,
        other: &DiffieHellmanPublicKey,
    ) -> Result<DiffieHellmanSharedSecret, String> {
        if self.base != other.base {
            Err(format!(
                "DiffieHellmanBase does not match: self.base = {:?}, other.base = {:?}",
                self.base, other.base
            ))
        } else {
            Ok(DiffieHellmanSharedSecret::new(
                self.base.clone(),
                other.public.modpow(&self.secret, &self.base.p),
            ))
        }
    }

    pub fn to_public_key(&self) -> DiffieHellmanPublicKey {
        self.clone().into()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiffieHellmanPublicKey {
    base: DiffieHellmanBase,
    public: BigUint,
}

impl DiffieHellmanPublicKey {
    pub fn new(base: DiffieHellmanBase, public: BigUint) -> Self {
        let public = public % &base.p;
        Self { base, public }
    }
}

impl From<DiffieHellmanSecretKey> for DiffieHellmanPublicKey {
    fn from(secret: DiffieHellmanSecretKey) -> DiffieHellmanPublicKey {
        DiffieHellmanPublicKey::new(secret.base, secret.public)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiffieHellmanSharedSecret {
    base: DiffieHellmanBase,
    shared_secret: BigUint,
}

impl DiffieHellmanSharedSecret {
    pub fn new(base: DiffieHellmanBase, shared_secret: BigUint) -> Self {
        Self {
            base,
            shared_secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::TestResult;

    #[quickcheck]
    fn diffie_hellman_property(bits: u8) -> TestResult {
        let bits = bits as usize;
        if bits < 2 {
            TestResult::discard()
        } else {
            let base = DiffieHellmanBase::gen(bits);
            let a_secret_key = base.gen_secret_key();
            let a_public_key = a_secret_key.to_public_key();
            let b_secret_key = base.gen_secret_key();
            let b_public_key = b_secret_key.to_public_key();
            let a_shared_secret = a_secret_key.compute_shared_secret(&b_public_key).unwrap();
            let b_shared_secret = b_secret_key.compute_shared_secret(&a_public_key).unwrap();
            TestResult::from_bool(a_shared_secret == b_shared_secret)
        }
    }
}
