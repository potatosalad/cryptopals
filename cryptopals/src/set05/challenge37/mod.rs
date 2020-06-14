pub use kex::srp::*;

#[derive(Clone, Debug)]
pub enum BreakSecureRemotePassword {
    ZeroKey,
    PrimeKey,
    PrimeDoubleKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn break_srp_with_a_zero_key() {
        let password = b"";
        let base = SecureRemotePasswordBase::new(
            BigUint::from_str_radix(
                "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                 fffffffffffff",
                16,
            )
            .unwrap(),
            BigUint::from_str_radix("2", 10).unwrap(),
            BigUint::from_str_radix("3", 10).unwrap(),
        );
        break_srp(&base, &password, BreakSecureRemotePassword::ZeroKey);
    }

    #[test]
    fn break_srp_with_a_prime_key() {
        let password = b"";
        let base = SecureRemotePasswordBase::new(
            BigUint::from_str_radix(
                "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                 fffffffffffff",
                16,
            )
            .unwrap(),
            BigUint::from_str_radix("2", 10).unwrap(),
            BigUint::from_str_radix("3", 10).unwrap(),
        );
        break_srp(&base, &password, BreakSecureRemotePassword::PrimeKey);
    }

    #[test]
    fn break_srp_with_a_prime_double_key() {
        let password = b"";
        let base = SecureRemotePasswordBase::new(
            BigUint::from_str_radix(
                "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                 fffffffffffff",
                16,
            )
            .unwrap(),
            BigUint::from_str_radix("2", 10).unwrap(),
            BigUint::from_str_radix("3", 10).unwrap(),
        );
        break_srp(&base, &password, BreakSecureRemotePassword::PrimeDoubleKey);
    }

    fn break_srp(
        base: &SecureRemotePasswordBase,
        password: impl AsRef<[u8]>,
        mode: BreakSecureRemotePassword,
    ) {
        let public_a = match mode {
            BreakSecureRemotePassword::ZeroKey => BigUint::from_str_radix("0", 10).unwrap(),
            BreakSecureRemotePassword::PrimeKey => base.prime_n.clone(),
            BreakSecureRemotePassword::PrimeDoubleKey => {
                &base.prime_n * BigUint::from_str_radix("2", 10).unwrap()
            }
        };
        let a_public = SecureRemotePasswordUnsaltedPublic::new(base.clone(), public_a);
        let b_secret = base.gen_salted_secret(&password);
        let b_public = b_secret.to_salted_public();
        let a_shared_secret = SecureRemotePasswordSharedSecret::new(
            base.clone(),
            b_public.salt,
            BigUint::from_str_radix("0", 10).unwrap(),
        );
        let b_shared_secret = b_secret.compute_shared_secret(&a_public).unwrap();
        assert_eq!(a_shared_secret, b_shared_secret);
        let a_mac = a_shared_secret.generate();
        let b_mac = b_shared_secret.generate();
        assert_eq!(a_mac, b_mac);
    }
}
