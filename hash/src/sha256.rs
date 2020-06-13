pub use crate::fixed_hash::{FixedHashContext, FixedHashOutput};
use sha2impl::{Digest, Sha256};

#[derive(Clone, Debug, Default)]
pub struct Sha256Context {
    internal: Sha256,
    computed: bool,
    corrupted: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Sha256Error {
    InputTooLong,
    StateError,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sha256Output([u8; 32]);

impl Sha256Output {
    pub fn bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl FixedHashOutput for Sha256Output {
    fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl FixedHashContext for Sha256Context {
    type Error = Sha256Error;
    type Output = Sha256Output;

    fn init() -> Self {
        let mut context = Self::default();
        context.reset();
        context
    }

    fn update<T: ?Sized + AsRef<[u8]>>(&mut self, input: &T) -> Result<(), Self::Error> {
        let input = input.as_ref();
        if input.is_empty() {
            return Ok(());
        }
        if self.computed {
            return Err(Sha256Error::StateError);
        }
        if self.corrupted {
            return Err(Sha256Error::InputTooLong);
        }
        self.internal.update(input);
        Ok(())
    }

    fn output(&mut self) -> Result<Self::Output, Self::Error> {
        if self.corrupted {
            return Err(Sha256Error::InputTooLong);
        }
        if !self.computed {
            self.computed = true;
        }
        let mut output: [u8; 32] = [0_u8; 32];
        let internal = std::mem::take(&mut self.internal);
        let intermediate_hash = internal.finalize();
        #[allow(clippy::needless_range_loop)]
        for i in 0..32_usize {
            output[i] = intermediate_hash[i];
        }
        Ok(Sha256Output(output))
    }

    fn reset(&mut self) {
        self.internal = Sha256::default();
        self.computed = false;
        self.corrupted = false;
    }

    fn block_size() -> usize {
        64
    }

    fn hash_size() -> usize {
        32
    }
}

pub fn hash<T: ?Sized + AsRef<[u8]>>(input: &T) -> Sha256Output {
    let mut ctx = Sha256Context::init();
    ctx.update(input).unwrap();
    ctx.output().unwrap()
}
