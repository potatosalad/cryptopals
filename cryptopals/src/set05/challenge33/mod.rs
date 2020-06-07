pub use kex::dh::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn just_do_what_i_do() {
        let base = DiffieHellmanBase::new(
            BigUint::from_str_radix("37", 10).unwrap(),
            BigUint::from_str_radix("5", 10).unwrap(),
        );
        let a_secret_key = base.gen_secret_key();
        let a_public_key = a_secret_key.to_public_key();
        let b_secret_key = base.gen_secret_key();
        let b_public_key = b_secret_key.to_public_key();
        let a_shared_secret = a_secret_key.compute_shared_secret(&b_public_key).unwrap();
        let b_shared_secret = b_secret_key.compute_shared_secret(&a_public_key).unwrap();
        println!("a_secret_key = {:?}", a_secret_key);
        println!("a_public_key = {:?}", a_public_key);
        println!("b_secret_key = {:?}", b_secret_key);
        println!("b_public_key = {:?}", b_public_key);
        println!("a_shared_secret = {:?}", a_shared_secret);
        println!("b_shared_secret = {:?}", b_shared_secret);
        assert_eq!(a_shared_secret, b_shared_secret);
    }

    #[test]
    fn here_are_parameters_nist_likes() {
        let base = DiffieHellmanBase::new(
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
            BigUint::from_str_radix("2", 16).unwrap(),
        );
        let a_secret_key = base.gen_secret_key();
        let a_public_key = a_secret_key.to_public_key();
        let b_secret_key = base.gen_secret_key();
        let b_public_key = b_secret_key.to_public_key();
        let a_shared_secret = a_secret_key.compute_shared_secret(&b_public_key).unwrap();
        let b_shared_secret = b_secret_key.compute_shared_secret(&a_public_key).unwrap();
        assert_eq!(a_shared_secret, b_shared_secret);
    }
}
