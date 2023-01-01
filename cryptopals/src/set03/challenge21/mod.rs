#[derive(Clone, Debug)]
pub enum MersenneTwisterError {
    InvalidCoefficients,
    InvalidSeed,
    InvalidState,
    InvalidIndex,
}

// This is important for other errors to wrap this one.
impl std::error::Error for MersenneTwisterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl std::fmt::Display for MersenneTwisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MersenneTwisterError::InvalidCoefficients => {
                write!(f, "invalid mersenne twister coefficients")
            }
            MersenneTwisterError::InvalidSeed => write!(f, "invalid mersenne twister seed"),
            MersenneTwisterError::InvalidState => write!(f, "invalid mersenne twister state"),
            MersenneTwisterError::InvalidIndex => write!(f, "invalid mersenne twister index"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MersenneTwisterCoefficients<T> {
    pub w: usize,
    pub n: usize,
    pub m: usize,
    pub r: usize,
    pub a: T,
    pub u: usize,
    pub d: T,
    pub s: usize,
    pub b: T,
    pub t: usize,
    pub c: T,
    pub l: usize,
    pub f: T,
}

impl MersenneTwisterCoefficients<u32> {
    pub fn validate(&self) -> Result<(), MersenneTwisterError> {
        let co = &self;
        if co.w > 32 || co.r > co.w || co.u > co.w || co.s > co.w || co.t > co.w || co.l > co.w {
            Err(MersenneTwisterError::InvalidCoefficients)
        } else {
            Ok(())
        }
    }
}

impl MersenneTwisterCoefficients<u64> {
    pub fn validate(&self) -> Result<(), MersenneTwisterError> {
        let co = &self;
        if co.w > 64 || co.r > co.w || co.u > co.w || co.s > co.w || co.t > co.w || co.l > co.w {
            Err(MersenneTwisterError::InvalidCoefficients)
        } else {
            Ok(())
        }
    }
}

pub const MT19937_COEFFICIENTS: MersenneTwisterCoefficients<u32> = MersenneTwisterCoefficients {
    w: 32,
    n: 624,
    m: 397,
    r: 31,
    a: 0x9908_B0DF,
    u: 11,
    d: 0xFFFF_FFFF,
    s: 7,
    b: 0x9D2C_5680,
    t: 15,
    c: 0xEFC6_0000,
    l: 18,
    f: 0x6C07_8965,
};

pub const MT19937_64_COEFFICIENTS: MersenneTwisterCoefficients<u64> = MersenneTwisterCoefficients {
    w: 64,
    n: 312,
    m: 156,
    r: 31,
    a: 0xB502_6F5A_A966_19E9,
    u: 29,
    d: 0x5555_5555_5555_5555,
    s: 17,
    b: 0x71D6_7FFF_EDA6_0000,
    t: 37,
    c: 0xFFF7_EEE0_0000_0000,
    l: 43,
    f: 0x5851_F42D_4C95_7F2D,
};

fn inverse_bitshift_right_xor_u32(y: u32, shift: u32, width: u32) -> u32 {
    let mut i = 0;
    let mut y = y;
    let mut r = 0;
    while i * shift < width {
        let part_mask = (!0 << (width - shift)) >> (shift * i);
        let part = y & part_mask;
        y ^= part >> shift;
        r |= part;
        i += 1;
    }
    r
}

fn inverse_bitshift_left_xor_u32(y: u32, shift: u32, width: u32, mask: u32) -> u32 {
    let mut i = 0;
    let mut y = y;
    let mut r = 0;
    while i * shift < width {
        let part_mask = (!0 >> (width - shift)) << (shift * i);
        let part = y & part_mask;
        y ^= (part << shift) & mask;
        r |= part;
        i += 1;
    }
    r
}

fn inverse_bitshift_right_xor_u64(y: u64, shift: u64, width: u64) -> u64 {
    let mut i = 0;
    let mut y = y;
    let mut r = 0;
    while i * shift < width {
        let part_mask = (!0 << (width - shift)) >> (shift * i);
        let part = y & part_mask;
        y ^= part >> shift;
        r |= part;
        i += 1;
    }
    r
}

fn inverse_bitshift_left_xor_u64(y: u64, shift: u64, width: u64, mask: u64) -> u64 {
    let mut i = 0;
    let mut y = y;
    let mut r = 0;
    while i * shift < width {
        let part_mask = (!0 >> (width - shift)) << (shift * i);
        let part = y & part_mask;
        y ^= (part << shift) & mask;
        r |= part;
        i += 1;
    }
    r
}

#[derive(Clone, Debug)]
pub struct MersenneTwister<'co, T> {
    co: &'co MersenneTwisterCoefficients<T>,
    inner_mask: T,
    lower_mask: T,
    upper_mask: T,
    mt: Vec<T>,
    index: usize,
}

impl<'co> MersenneTwister<'co, u32> {
    pub fn from_state(
        co: &'co MersenneTwisterCoefficients<u32>,
        state: Vec<u32>,
        index: usize,
    ) -> Result<Self, MersenneTwisterError> {
        co.validate()?;
        if state.len() != co.n {
            return Err(MersenneTwisterError::InvalidState);
        }
        if index > co.n + 1 {
            return Err(MersenneTwisterError::InvalidIndex);
        }
        let inner_mask: u32 = if co.w == 32 {
            !0
        } else {
            (1 << (co.w as u32)) - 1
        };
        let lower_mask: u32 = if co.r == 32 {
            !0
        } else {
            (1 << (co.r as u32)) - 1
        };
        let upper_mask: u32 = (!lower_mask) & inner_mask;
        Ok(MersenneTwister {
            co,
            inner_mask,
            lower_mask,
            upper_mask,
            mt: state,
            index,
        })
    }

    pub fn init(
        co: &'co MersenneTwisterCoefficients<u32>,
        seed: u32,
    ) -> Result<Self, MersenneTwisterError> {
        let mut mt = Self::from_state(co, vec![0; co.n], co.n + 1)?;
        mt.reseed(seed);
        Ok(mt)
    }

    pub fn reseed(&mut self, seed: u32) {
        if self.index != self.co.n + 1 {
            self.mt = vec![0; self.co.n];
        }
        let mt = &mut self.mt;
        mt[0] = seed;
        for i in 1..self.co.n {
            mt[i] = (mt[i - 1] ^ (mt[i - 1] >> (self.co.w - 2)))
                .wrapping_mul(self.co.f)
                .wrapping_add(i as u32);
        }
        self.index = self.co.n;
    }

    // Extract a tempered value based on MT[index] calling twist() every n numbers
    pub fn extract_number(&mut self) -> Result<u32, MersenneTwisterError> {
        if self.index >= self.co.n {
            if self.index > self.co.n {
                return Err(MersenneTwisterError::InvalidSeed);
            }
            self.twist();
        }
        let y = self.temper(self.mt[self.index]);
        self.index += 1;
        Ok(y)
    }

    // Generate the next n values from the series x_i
    pub fn twist(&mut self) {
        for i in 0..self.co.n {
            let x =
                (self.mt[i] & self.upper_mask) + (self.mt[(i + 1) % self.co.n] & self.lower_mask);
            let mut xa = x >> 1;
            if x % 2 != 0 {
                // lowest bit of x is 1
                xa ^= self.co.a;
            }
            self.mt[i] = self.mt[(i + self.co.m) % self.co.n] ^ xa;
        }
        self.index = 0;
    }

    pub fn temper(&self, mut y: u32) -> u32 {
        y ^= (y >> self.co.u as u32) & self.co.d;
        y ^= (y << self.co.s as u32) & self.co.b;
        y ^= (y << self.co.t as u32) & self.co.c;
        y ^= y >> self.co.l as u32;
        y & self.inner_mask
    }

    pub fn untemper(&self, mut y: u32) -> u32 {
        y = inverse_bitshift_right_xor_u32(y, self.co.l as u32, self.co.w as u32);
        y = inverse_bitshift_left_xor_u32(y, self.co.t as u32, self.co.w as u32, self.co.c);
        y = inverse_bitshift_left_xor_u32(y, self.co.s as u32, self.co.w as u32, self.co.b);
        y = inverse_bitshift_right_xor_u32(y, self.co.u as u32, self.co.w as u32);
        y
    }
}

impl<'co> MersenneTwister<'co, u64> {
    pub fn from_state(
        co: &'co MersenneTwisterCoefficients<u64>,
        state: Vec<u64>,
        index: usize,
    ) -> Result<Self, MersenneTwisterError> {
        co.validate()?;
        if state.len() != co.n {
            return Err(MersenneTwisterError::InvalidState);
        }
        if index > co.n + 1 {
            return Err(MersenneTwisterError::InvalidIndex);
        }
        let inner_mask: u64 = if co.w == 64 {
            !0
        } else {
            (1 << (co.w as u64)) - 1
        };
        let lower_mask: u64 = if co.r == 64 {
            !0
        } else {
            (1 << (co.r as u64)) - 1
        };
        let upper_mask: u64 = (!lower_mask) & inner_mask;
        Ok(MersenneTwister {
            co,
            inner_mask,
            lower_mask,
            upper_mask,
            mt: state,
            index,
        })
    }

    pub fn init(
        co: &'co MersenneTwisterCoefficients<u64>,
        seed: u64,
    ) -> Result<Self, MersenneTwisterError> {
        let mut mt = Self::from_state(co, vec![0; co.n], co.n + 1)?;
        mt.reseed(seed);
        Ok(mt)
    }

    pub fn reseed(&mut self, seed: u64) {
        if self.index != self.co.n + 1 {
            self.mt = vec![0; self.co.n];
        }
        let mt = &mut self.mt;
        mt[0] = seed;
        for i in 1..self.co.n {
            mt[i] = (mt[i - 1] ^ (mt[i - 1] >> (self.co.w - 2)))
                .wrapping_mul(self.co.f)
                .wrapping_add(i as u64);
        }
        self.index = self.co.n;
    }

    // Extract a tempered value based on MT[index] calling twist() every n numbers
    pub fn extract_number(&mut self) -> Result<u64, MersenneTwisterError> {
        if self.index >= self.co.n {
            if self.index > self.co.n {
                return Err(MersenneTwisterError::InvalidSeed);
            }
            self.twist();
        }
        let y = self.temper(self.mt[self.index]);
        self.index += 1;
        Ok(y)
    }

    // Generate the next n values from the series x_i
    pub fn twist(&mut self) {
        for i in 0..self.co.n {
            let x =
                (self.mt[i] & self.upper_mask) + (self.mt[(i + 1) % self.co.n] & self.lower_mask);
            let mut xa = x >> 1;
            if x % 2 != 0 {
                // lowest bit of x is 1
                xa ^= self.co.a;
            }
            self.mt[i] = self.mt[(i + self.co.m) % self.co.n] ^ xa;
        }
        self.index = 0;
    }

    pub fn temper(&self, mut y: u64) -> u64 {
        y ^= (y >> self.co.u as u64) & self.co.d;
        y ^= (y << self.co.s as u64) & self.co.b;
        y ^= (y << self.co.t as u64) & self.co.c;
        y ^= y >> self.co.l as u64;
        y & self.inner_mask
    }

    pub fn untemper(&self, mut y: u64) -> u64 {
        if self.co.w == 64 {
            // reverse "y ^=  y >> 43;"
            y ^= y >> self.co.l as u64;

            // reverse "y ^= (y << 37) & 0xFFF7EEE000000000;"
            y ^= (y << self.co.t as u64) & self.co.c as u64;

            // reverse "y ^= (y << 17) & 0x71D67FFFEDA60000;"
            y ^= (y << self.co.s as u64) & 0x00000003eda60000;
            y ^= (y << self.co.s as u64) & 0x00067ffc00000000;
            y ^= (y << self.co.s as u64) & 0x71d0000000000000;

            // reverse "y ^= (y >> 29) & 0x5555555555555555;"
            y ^= (y >> self.co.u as u64) & 0x0000000555555540;
            y ^= (y >> self.co.u as u64) & 0x0000000000000015;

            y
        } else {
            y = inverse_bitshift_right_xor_u64(y, self.co.l as u64, self.co.w as u64);
            y = inverse_bitshift_left_xor_u64(y, self.co.t as u64, self.co.w as u64, self.co.c);
            y = inverse_bitshift_left_xor_u64(y, self.co.s as u64, self.co.w as u64, self.co.b);
            y = inverse_bitshift_right_xor_u64(y, self.co.u as u64, self.co.w as u64);
            y
        }
    }
}

impl<'co> Iterator for MersenneTwister<'co, u32> {
    type Item = u32;
    fn next(&mut self) -> Option<Self::Item> {
        self.extract_number().ok()
    }
}

impl<'co> Iterator for MersenneTwister<'co, u64> {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        self.extract_number().ok()
    }
}

pub trait MersenneTwisterU32 {
    fn new(seed: u32) -> Self;
    fn generate(&mut self) -> u32;
}

#[derive(Clone, Debug)]
pub struct MersenneTwister19937(MersenneTwister<'static, u32>);

impl MersenneTwister19937 {
    pub fn from_state(state: Vec<u32>, index: usize) -> Result<Self, MersenneTwisterError> {
        MersenneTwister::<'static, u32>::from_state(&MT19937_COEFFICIENTS, state, index)
            .map(MersenneTwister19937)
    }

    pub fn reseed(&mut self, seed: u32) {
        self.0.reseed(seed);
    }

    pub fn temper(&self, value: u32) -> u32 {
        self.0.temper(value)
    }

    pub fn untemper(&self, value: u32) -> u32 {
        self.0.untemper(value)
    }
}

impl MersenneTwisterU32 for MersenneTwister19937 {
    fn new(seed: u32) -> Self {
        MersenneTwister19937(
            MersenneTwister::<'static, u32>::init(&MT19937_COEFFICIENTS, seed).unwrap(),
        )
    }

    fn generate(&mut self) -> u32 {
        self.0.extract_number().unwrap()
    }
}

impl Default for MersenneTwister19937 {
    fn default() -> Self {
        Self::new(5489)
    }
}

impl Iterator for MersenneTwister19937 {
    type Item = u32;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

pub trait MersenneTwisterU64 {
    fn new(seed: u64) -> Self;
    fn generate(&mut self) -> u64;
}

#[derive(Clone, Debug)]
pub struct MersenneTwister19937_64(MersenneTwister<'static, u64>);

impl MersenneTwister19937_64 {
    pub fn from_state(state: Vec<u64>, index: usize) -> Result<Self, MersenneTwisterError> {
        MersenneTwister::<'static, u64>::from_state(&MT19937_64_COEFFICIENTS, state, index)
            .map(MersenneTwister19937_64)
    }

    pub fn reseed(&mut self, seed: u64) {
        self.0.reseed(seed);
    }

    pub fn temper(&self, value: u64) -> u64 {
        self.0.temper(value)
    }

    pub fn untemper(&self, value: u64) -> u64 {
        self.0.untemper(value)
    }
}

impl MersenneTwisterU64 for MersenneTwister19937_64 {
    fn new(seed: u64) -> Self {
        MersenneTwister19937_64(
            MersenneTwister::<'static, u64>::init(&MT19937_64_COEFFICIENTS, seed).unwrap(),
        )
    }

    fn generate(&mut self) -> u64 {
        self.0.extract_number().unwrap()
    }
}

impl Default for MersenneTwister19937_64 {
    fn default() -> Self {
        Self::new(5489)
    }
}

impl Iterator for MersenneTwister19937_64 {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

extern "C" {
    fn cstd_mt19937_default() -> *mut ::core::ffi::c_void;
    fn cstd_mt19937_create(seed: u32) -> *mut ::core::ffi::c_void;
    fn cstd_mt19937_release(prng: *mut ::core::ffi::c_void);
    fn cstd_mt19937_generate(prng: *mut ::core::ffi::c_void) -> u32;
    fn cstd_mt19937_64_default() -> *mut ::core::ffi::c_void;
    fn cstd_mt19937_64_create(seed: u64) -> *mut ::core::ffi::c_void;
    fn cstd_mt19937_64_release(prng: *mut ::core::ffi::c_void);
    fn cstd_mt19937_64_generate(prng: *mut ::core::ffi::c_void) -> u64;
}

pub struct CMersenneTwister19937 {
    cptr: *mut ::core::ffi::c_void,
}

impl MersenneTwisterU32 for CMersenneTwister19937 {
    fn new(seed: u32) -> CMersenneTwister19937 {
        CMersenneTwister19937 {
            cptr: unsafe { cstd_mt19937_create(seed) },
        }
    }

    fn generate(&mut self) -> u32 {
        unsafe { cstd_mt19937_generate(self.cptr) }
    }
}

impl Default for CMersenneTwister19937 {
    fn default() -> Self {
        CMersenneTwister19937 {
            cptr: unsafe { cstd_mt19937_default() },
        }
    }
}

impl Drop for CMersenneTwister19937 {
    fn drop(&mut self) {
        unsafe { cstd_mt19937_release(self.cptr) }
    }
}

impl Iterator for CMersenneTwister19937 {
    type Item = u32;
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.generate())
    }
}

pub struct CMersenneTwister19937_64 {
    cptr: *mut ::core::ffi::c_void,
}

impl MersenneTwisterU64 for CMersenneTwister19937_64 {
    fn new(seed: u64) -> CMersenneTwister19937_64 {
        CMersenneTwister19937_64 {
            cptr: unsafe { cstd_mt19937_64_create(seed) },
        }
    }

    fn generate(&mut self) -> u64 {
        unsafe { cstd_mt19937_64_generate(self.cptr) }
    }
}

impl Default for CMersenneTwister19937_64 {
    fn default() -> Self {
        CMersenneTwister19937_64 {
            cptr: unsafe { cstd_mt19937_64_default() },
        }
    }
}

impl Drop for CMersenneTwister19937_64 {
    fn drop(&mut self) {
        unsafe { cstd_mt19937_64_release(self.cptr) }
    }
}

impl Iterator for CMersenneTwister19937_64 {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.generate())
    }
}

pub fn mt19937_init(seed: u32) -> MersenneTwister19937 {
    MersenneTwister19937::new(seed)
}

pub fn mt19937_64_init(seed: u64) -> MersenneTwister19937_64 {
    MersenneTwister19937_64::new(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NUM_TESTS: usize = 10_000;

    #[test]
    fn implement_the_mt19937_mersenne_twister_rng() {
        let seed: u32 = 10_2013;
        let mt19937 = MersenneTwister19937::default();
        let cmt19937 = CMersenneTwister19937::default();
        for (i, (a, b)) in mt19937.zip(cmt19937).enumerate().take(NUM_TESTS) {
            assert_eq!(a, b, "mt19937() mismatch on {} generation", i);
        }
        let mt19937 = mt19937_init(seed);
        let cmt19937 = CMersenneTwister19937::new(seed);
        for (i, (a, b)) in mt19937.zip(cmt19937).enumerate().take(NUM_TESTS) {
            assert_eq!(a, b, "mt19937({}) mismatch on {} generation", seed, i);
        }
    }

    #[test]
    fn implement_the_mt19937_64_mersenne_twister_rng() {
        let seed: u64 = 10_2013;
        let mt19937_64 = MersenneTwister19937_64::default();
        let cmt19937_64 = CMersenneTwister19937_64::default();
        for (i, (a, b)) in mt19937_64.zip(cmt19937_64).enumerate().take(NUM_TESTS) {
            assert_eq!(a, b, "mt19937_64() mismatch on {} generation", i);
        }
        let mt19937_64 = mt19937_64_init(seed);
        let cmt19937_64 = CMersenneTwister19937_64::new(seed);
        for (i, (a, b)) in mt19937_64.zip(cmt19937_64).enumerate().take(NUM_TESTS) {
            assert_eq!(a, b, "mt19937_64({}) mismatch on {} generation", seed, i);
        }
    }

    #[quickcheck]
    fn mt19937_is_the_same_as_the_c_version(seed: u32) -> bool {
        let rng = mt19937_init(seed);
        let crng = CMersenneTwister19937::new(seed);
        rng.zip(crng).take(NUM_TESTS).all(|(a, b)| a == b)
    }

    #[quickcheck]
    fn mt19937_64_is_the_same_as_the_c_version(seed: u64) -> bool {
        let rng = mt19937_64_init(seed);
        let crng = CMersenneTwister19937_64::new(seed);
        rng.zip(crng).take(NUM_TESTS).all(|(a, b)| a == b)
    }
}
