pub use num_bigint_dig::BigUint;
use num_bigint_dig::{RandBigInt, RandPrime, ToBigUint};
pub use num_traits::Num;
use rand::prelude::*;

pub use num_integer;
pub use num_traits;

use num_integer::Integer;
use num_traits::{One, Zero};

use hash::sha256::{FixedHashContext, Sha256Context};

pub trait ToFieldElementBytes {
    fn to_field_element_bytes(&self, prime: &Self) -> Vec<u8>;
}

impl ToFieldElementBytes for BigUint {
    fn to_field_element_bytes(&self, prime: &Self) -> Vec<u8> {
        let mut bytes = self.to_bytes_le();
        let length = (prime.bits() + 7) / 8;
        while bytes.len() < length {
            bytes.push(0);
        }
        bytes
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecureRemotePasswordBase {
    pub prime_n: BigUint,
    pub group_g: BigUint,
    pub param_k: BigUint,
}

impl SecureRemotePasswordBase {
    pub fn new(prime_n: BigUint, group_g: BigUint, param_k: BigUint) -> Self {
        Self {
            prime_n,
            group_g,
            param_k,
        }
    }

    pub fn gen(bits: usize) -> Self {
        let mut bits = bits;
        let mut rng = thread_rng();
        let mut prime_n = rng.gen_prime(bits);
        let one: BigUint = One::one();
        let low = 2.to_biguint().unwrap();
        let min = &low + &one;
        while prime_n <= min {
            bits += 1;
            prime_n = rng.gen_prime(bits);
        }
        let high = &prime_n - &one;
        let mut group_g = rng.gen_biguint_range(&low, &high);
        if !group_g.gcd(&high).is_one() {
            group_g = low.clone();
            while !group_g.gcd(&high).is_one() {
                group_g += &one;
            }
        }
        let param_k = rng.gen_biguint_range(&low, &high);
        Self::new(prime_n, group_g, param_k)
    }

    pub fn gen_unsalted_secret(&self) -> SecureRemotePasswordUnsaltedSecret {
        let mut rng = thread_rng();
        let mut secret = rng.gen_biguint(self.prime_n.bits());
        while secret.is_zero() && self.prime_n.bits() > 0 {
            secret = rng.gen_biguint(self.prime_n.bits());
        }
        SecureRemotePasswordUnsaltedSecret::new(self.clone(), secret)
    }

    pub fn gen_salted_secret(
        &self,
        password: impl AsRef<[u8]>,
    ) -> SecureRemotePasswordSaltedSecret {
        let mut rng = thread_rng();
        let mut bits = self.prime_n.bits();
        let mut salt = rng.gen_biguint(bits);
        while salt.is_zero() {
            bits += 1;
            salt = rng.gen_biguint(bits);
        }
        let mut bits = self.prime_n.bits();
        let mut secret_b = rng.gen_biguint(bits);
        while secret_b.is_zero() {
            bits += 1;
            secret_b = rng.gen_biguint(bits);
        }
        SecureRemotePasswordSaltedSecret::new(self.clone(), salt, password, secret_b)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecureRemotePasswordUnsaltedSecret {
    pub base: SecureRemotePasswordBase,
    pub secret_a: BigUint,
    pub public_a: BigUint,
}

impl SecureRemotePasswordUnsaltedSecret {
    pub fn new(base: SecureRemotePasswordBase, secret_a: BigUint) -> Self {
        let secret_a = secret_a % &base.prime_n;
        let public_a = base.group_g.modpow(&secret_a, &base.prime_n);
        Self {
            base,
            secret_a,
            public_a,
        }
    }

    pub fn compute_shared_secret(
        &self,
        other: &SecureRemotePasswordSaltedPublic,
        password: impl AsRef<[u8]>,
    ) -> Result<SecureRemotePasswordSharedSecret, String> {
        if self.base != other.base {
            Err(format!(
                "SecureRemotePasswordBase does not match: self.base = {:?}, other.base = {:?}",
                self.base, other.base
            ))
        } else {
            let mut sha256 = Sha256Context::init();
            sha256
                .update(&self.public_a.to_field_element_bytes(&self.base.prime_n))
                .unwrap();
            sha256
                .update(&other.public_b.to_field_element_bytes(&self.base.prime_n))
                .unwrap();
            let public_u_hash = sha256.output().unwrap().bytes();
            let public_u = BigUint::from_bytes_le(&public_u_hash) % &self.base.prime_n;
            let mut sha256 = Sha256Context::init();
            sha256
                .update(&other.salt.to_field_element_bytes(&self.base.prime_n))
                .unwrap();
            sha256.update(&password).unwrap();
            let secret_x_hash = sha256.output().unwrap().bytes();
            let secret_x = BigUint::from_bytes_le(&secret_x_hash) % &self.base.prime_n;
            let secret_v = self.base.group_g.modpow(&secret_x, &self.base.prime_n);
            let secret_kv = (&self.base.param_k * &secret_v) % &self.base.prime_n;
            let public_b_sub_kv = if other.public_b < secret_kv {
                (&self.base.prime_n - &secret_kv + &other.public_b) % &self.base.prime_n
            } else {
                (&other.public_b - &secret_kv) % &self.base.prime_n
            };
            let secret_a_add_ux = &self.secret_a + (&public_u * &secret_x);
            let shared_s = public_b_sub_kv.modpow(&secret_a_add_ux, &self.base.prime_n);
            Ok(SecureRemotePasswordSharedSecret::new(
                self.base.clone(),
                other.salt.clone(),
                shared_s,
            ))
        }
    }

    pub fn to_unsalted_public(&self) -> SecureRemotePasswordUnsaltedPublic {
        self.clone().into()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecureRemotePasswordUnsaltedPublic {
    pub base: SecureRemotePasswordBase,
    pub public_a: BigUint,
}

impl SecureRemotePasswordUnsaltedPublic {
    pub fn new(base: SecureRemotePasswordBase, public_a: BigUint) -> Self {
        let public_a = public_a % &base.prime_n;
        Self { base, public_a }
    }
}

impl From<SecureRemotePasswordUnsaltedSecret> for SecureRemotePasswordUnsaltedPublic {
    fn from(secret: SecureRemotePasswordUnsaltedSecret) -> SecureRemotePasswordUnsaltedPublic {
        SecureRemotePasswordUnsaltedPublic::new(secret.base, secret.public_a)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecureRemotePasswordSaltedSecret {
    pub base: SecureRemotePasswordBase,
    pub salt: BigUint,
    pub secret_v: BigUint,
    pub secret_b: BigUint,
    pub public_b: BigUint,
}

impl SecureRemotePasswordSaltedSecret {
    pub fn new(
        base: SecureRemotePasswordBase,
        salt: BigUint,
        password: impl AsRef<[u8]>,
        secret_b: BigUint,
    ) -> Self {
        let mut sha256 = Sha256Context::init();
        sha256
            .update(&salt.to_field_element_bytes(&base.prime_n))
            .unwrap();
        sha256.update(&password).unwrap();
        let secret_x_hash = sha256.output().unwrap().bytes();
        let secret_x = BigUint::from_bytes_le(&secret_x_hash) % &base.prime_n;
        let secret_v = base.group_g.modpow(&secret_x, &base.prime_n);
        let secret_b = secret_b % &base.prime_n;
        let mut public_b = base.group_g.modpow(&secret_b, &base.prime_n);
        public_b += &base.param_k * &secret_v;
        public_b %= &base.prime_n;
        Self {
            base,
            salt,
            secret_v,
            secret_b,
            public_b,
        }
    }

    pub fn compute_shared_secret(
        &self,
        other: &SecureRemotePasswordUnsaltedPublic,
    ) -> Result<SecureRemotePasswordSharedSecret, String> {
        if self.base != other.base {
            Err(format!(
                "SecureRemotePasswordBase does not match: self.base = {:?}, other.base = {:?}",
                self.base, other.base
            ))
        } else {
            let mut sha256 = Sha256Context::init();
            sha256
                .update(&other.public_a.to_field_element_bytes(&self.base.prime_n))
                .unwrap();
            sha256
                .update(&self.public_b.to_field_element_bytes(&self.base.prime_n))
                .unwrap();
            let public_u_hash = sha256.output().unwrap().bytes();
            let public_u = BigUint::from_bytes_le(&public_u_hash) % &self.base.prime_n;
            let secret_v_pow_u = self.secret_v.modpow(&public_u, &self.base.prime_n);
            let public_a_mul_vu = (&other.public_a * &secret_v_pow_u) % &self.base.prime_n;
            let shared_s = public_a_mul_vu.modpow(&self.secret_b, &self.base.prime_n);
            Ok(SecureRemotePasswordSharedSecret::new(
                self.base.clone(),
                self.salt.clone(),
                shared_s,
            ))
        }
    }

    pub fn to_salted_public(&self) -> SecureRemotePasswordSaltedPublic {
        self.clone().into()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecureRemotePasswordSaltedPublic {
    pub base: SecureRemotePasswordBase,
    pub salt: BigUint,
    pub public_b: BigUint,
}

impl SecureRemotePasswordSaltedPublic {
    pub fn new(base: SecureRemotePasswordBase, salt: BigUint, public_b: BigUint) -> Self {
        let public_b = public_b % &base.prime_n;
        Self {
            base,
            salt,
            public_b,
        }
    }
}

impl From<SecureRemotePasswordSaltedSecret> for SecureRemotePasswordSaltedPublic {
    fn from(secret: SecureRemotePasswordSaltedSecret) -> SecureRemotePasswordSaltedPublic {
        SecureRemotePasswordSaltedPublic::new(secret.base, secret.salt, secret.public_b)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecureRemotePasswordSharedSecret {
    pub base: SecureRemotePasswordBase,
    pub salt: BigUint,
    pub shared_k: BigUint,
}

impl SecureRemotePasswordSharedSecret {
    pub fn new(base: SecureRemotePasswordBase, salt: BigUint, shared_s: BigUint) -> Self {
        let mut sha256 = Sha256Context::init();
        sha256
            .update(&shared_s.to_field_element_bytes(&base.prime_n))
            .unwrap();
        let shared_k_hash = sha256.output().unwrap().bytes();
        let shared_k = BigUint::from_bytes_le(&shared_k_hash) % &base.prime_n;
        Self {
            base,
            salt,
            shared_k,
        }
    }

    pub fn generate(&self) -> Vec<u8> {
        mac::hmac::hmac_sha256(
            &self.shared_k.to_field_element_bytes(&self.base.prime_n),
            &self.salt.to_field_element_bytes(&self.base.prime_n),
        )
        .bytes()
        .to_vec()
    }

    pub fn verify(&self, challenge: &[u8]) -> bool {
        let mac = self.generate();
        &mac[..] == challenge
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::TestResult;

    #[quickcheck]
    fn secure_remote_password_property(bits: u8, password: String) -> TestResult {
        let bits = bits as usize;
        if bits < 2 {
            TestResult::discard()
        } else {
            let base = SecureRemotePasswordBase::gen(bits);
            let a_secret = base.gen_unsalted_secret();
            let a_public = a_secret.to_unsalted_public();
            let b_secret = base.gen_salted_secret(&password);
            let b_public = b_secret.to_salted_public();
            let a_shared_secret = a_secret
                .compute_shared_secret(&b_public, &password)
                .unwrap();
            let b_shared_secret = b_secret.compute_shared_secret(&a_public).unwrap();
            let a_mac = a_shared_secret.generate();
            let b_mac = b_shared_secret.generate();
            TestResult::from_bool(a_mac == b_mac)
        }
    }
}
