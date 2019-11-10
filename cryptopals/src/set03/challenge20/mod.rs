pub use crate::set03::challenge19::*;

#[cfg(test)]
mod tests {
    use super::*;

    lazy_static! {
        #[derive(Clone, Copy, Debug, PartialEq)]
        static ref TEST_VECTORS: Vec<Vec<u8>> = {
            let contents = include_str!("20.txt");
            contents.split('\n').filter_map(|line| base64::decode(&line).ok()).collect::<Vec<Vec<u8>>>()
        };
    }

    #[test]
    fn break_fixed_nonce_ctr_mode_statistically() {
        use rand::prelude::*;
        let mut csprng = thread_rng();
        let mut key: [u8; 16] = [0_u8; 16];
        let mut iv: [u8; 16] = [0_u8; 16];
        csprng.fill_bytes(&mut key);
        csprng.fill_bytes(&mut iv);
        let mut solver = FixedNonceCtrSolver::new(&key, &iv, AesCtrMode::CRYPTOPALS).unwrap();
        solver.extend(TEST_VECTORS.iter().cloned());
        solver.generate_extra();
        let keystream = solver.keystream().unwrap();
        let decrypted = solver.decrypt(&keystream);
        assert_eq!(solver.plaintexts, decrypted);
    }

    #[test]
    fn break_fixed_nonce_ctr_mode_statistically_nist_sp800_38a() {
        use rand::prelude::*;
        let mut csprng = thread_rng();
        let mut key: [u8; 16] = [0_u8; 16];
        let mut iv: [u8; 16] = [0_u8; 16];
        csprng.fill_bytes(&mut key);
        csprng.fill_bytes(&mut iv);
        let mut solver = FixedNonceCtrSolver::new(&key, &iv, AesCtrMode::NIST_SP800_38A).unwrap();
        solver.extend(TEST_VECTORS.iter().cloned());
        solver.generate_extra();
        let keystream = solver.keystream().unwrap();
        let decrypted = solver.decrypt(&keystream);
        assert_eq!(solver.plaintexts, decrypted);
    }
}
