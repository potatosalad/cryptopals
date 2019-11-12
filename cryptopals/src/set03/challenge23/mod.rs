pub use crate::set03::challenge21::*;

pub fn clone_mt19937(mt: &mut MersenneTwister19937) -> MersenneTwister19937 {
    let mut state: Vec<u32> = vec![0; MT19937_COEFFICIENTS.n];
    for element in state.iter_mut() {
        let output = mt.generate();
        *element = mt.untemper(output);
    }
    MersenneTwister19937::from_state(state, MT19937_COEFFICIENTS.n + 1).unwrap()
}

pub fn clone_mt19937_64(mt: &mut MersenneTwister19937_64) -> MersenneTwister19937_64 {
    let mut state: Vec<u64> = vec![0; MT19937_64_COEFFICIENTS.n];
    for element in state.iter_mut() {
        let output = mt.generate();
        *element = mt.untemper(output);
    }
    MersenneTwister19937_64::from_state(state, MT19937_64_COEFFICIENTS.n + 1).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    const NUM_TESTS: usize = 10_000;

    #[test]
    fn clone_an_mt19937_rng_from_its_output() {
        let mut csprng = thread_rng();
        let seed: u32 = csprng.gen();
        let mut mt0 = mt19937_init(seed);
        let mt1 = clone_mt19937(&mut mt0);
        for (i, (a, b)) in mt0.zip(mt1).enumerate().take(NUM_TESTS) {
            assert_eq!(a, b, "mt19937({}) mismatch on {} generation", seed, i);
        }
    }

    #[test]
    fn clone_an_mt19937_64_rng_from_its_output() {
        let mut csprng = thread_rng();
        let seed: u64 = csprng.gen();
        let mut mt0 = mt19937_64_init(seed);
        let mt1 = clone_mt19937_64(&mut mt0);
        for (i, (a, b)) in mt0.zip(mt1).enumerate().take(NUM_TESTS) {
            assert_eq!(a, b, "mt19937_64({}) mismatch on {} generation", seed, i);
        }
    }

    #[quickcheck]
    fn mt19937_temper_and_untemper_is_identity(seed: u32, value: u32) -> bool {
        let mt = mt19937_init(seed);
        let tempered = mt.temper(value);
        let untempered = mt.untemper(tempered);
        value == untempered
    }

    #[quickcheck]
    fn mt19937_64_temper_and_untemper_is_identity(seed: u64, value: u64) -> bool {
        let mt = mt19937_64_init(seed);
        let tempered = mt.temper(value);
        let untempered = mt.untemper(tempered);
        value == untempered
    }
}
