use std::time::{Duration, SystemTime};

pub use crate::set03::challenge21::*;

#[derive(Clone, Debug)]
pub struct FakeSystemSeconds {
    initial: u64,
    elapsed: u64,
}

impl From<SystemTime> for FakeSystemSeconds {
    fn from(value: SystemTime) -> Self {
        Self::new(
            value
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }
}

impl FakeSystemSeconds {
    pub fn now() -> Self {
        Self::from(SystemTime::now())
    }

    pub fn new(initial: u64) -> Self {
        Self {
            initial,
            elapsed: 0,
        }
    }

    pub fn sleep(&mut self, duration: Duration) {
        let elapsed = self.elapsed.checked_add(duration.as_secs()).unwrap();
        self.initial.checked_add(elapsed).unwrap();
        self.elapsed = elapsed;
    }

    pub fn as_secs(&self) -> u64 {
        self.initial + self.elapsed
    }
}

#[derive(Clone, Debug)]
pub struct OracleU32 {
    mt: MersenneTwister19937,
    seed: u32,
}

impl OracleU32 {
    pub fn new(seed: u32) -> Self {
        Self {
            mt: MersenneTwister19937::new(seed),
            seed,
        }
    }

    pub fn generate(&mut self) -> u32 {
        self.mt.generate()
    }

    pub fn verify_seed(&self, seed: u32) -> bool {
        self.seed == seed
    }
}

#[derive(Clone, Debug)]
pub struct OracleU64 {
    mt: MersenneTwister19937_64,
    seed: u64,
}

impl OracleU64 {
    pub fn new(seed: u64) -> Self {
        Self {
            mt: MersenneTwister19937_64::new(seed),
            seed,
        }
    }

    pub fn generate(&mut self) -> u64 {
        self.mt.generate()
    }

    pub fn verify_seed(&self, seed: u64) -> bool {
        self.seed == seed
    }
}

pub fn brute_force_an_mt19937_seed(output: u32, hours: u64) -> Option<u32> {
    let mut system_time = FakeSystemSeconds::from(
        SystemTime::now()
            .checked_sub(Duration::from_secs(hours * 60 * 60))
            .unwrap(),
    );
    let mut seconds: u64 = 0;
    let mut rng = mt19937_init(0);
    loop {
        let seed = system_time.as_secs() as u32;
        rng.reseed(seed);
        let challenge = rng.generate();
        if challenge == output {
            return Some(seed);
        } else {
            seconds += 1;
            system_time.sleep(Duration::from_secs(1));
            if seconds % 3600 == 0 {
                // println!("{} hours have passed", seconds / 3600);
                if seconds / 3600 > hours * 2 {
                    break;
                }
            }
        }
    }
    None
}

pub fn brute_force_an_mt19937_64_seed(output: u64, hours: u64) -> Option<u64> {
    let mut system_time = FakeSystemSeconds::from(
        SystemTime::now()
            .checked_sub(Duration::from_secs(hours * 60 * 60))
            .unwrap(),
    );
    let mut seconds: u64 = 0;
    let mut rng = mt19937_64_init(0);
    loop {
        let seed = system_time.as_secs();
        rng.reseed(seed);
        let challenge = rng.generate();
        if challenge == output {
            return Some(seed);
        } else {
            seconds += 1;
            system_time.sleep(Duration::from_secs(1));
            if seconds % 3600 == 0 {
                // println!("{} hours have passed", seconds / 3600);
                if seconds / 3600 > hours * 2 {
                    break;
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[ignore]
    #[test]
    fn crack_an_mt19937_seed() {
        let mut csprng = thread_rng();
        let mut system_time = FakeSystemSeconds::now();
        system_time.sleep(Duration::from_secs(csprng.gen_range(40..=1000)));
        let mut oracle = OracleU32::new(system_time.as_secs() as u32);
        system_time.sleep(Duration::from_secs(csprng.gen_range(40..=1000)));
        let output = oracle.generate();
        let solution = brute_force_an_mt19937_seed(output, 2).unwrap();
        assert!(oracle.verify_seed(solution));
    }

    #[ignore]
    #[test]
    fn crack_an_mt19937_64_seed() {
        let mut csprng = thread_rng();
        let mut system_time = FakeSystemSeconds::now();
        system_time.sleep(Duration::from_secs(csprng.gen_range(40..=1000)));
        let mut oracle = OracleU64::new(system_time.as_secs());
        system_time.sleep(Duration::from_secs(csprng.gen_range(40..=1000)));
        let output = oracle.generate();
        let solution = brute_force_an_mt19937_64_seed(output, 2).unwrap();
        assert!(oracle.verify_seed(solution));
    }
}
