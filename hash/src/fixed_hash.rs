pub trait FixedHashContext: Clone {
    type Error;
    type Output: FixedHashOutput;
    fn init() -> Self;
    fn update<T: ?Sized + AsRef<[u8]>>(&mut self, input: &T) -> Result<(), Self::Error>;
    fn output(&mut self) -> Result<Self::Output, Self::Error>;
    fn reset(&mut self);
}

pub trait FixedHashOutput: Clone {
    fn as_slice(&self) -> &[u8];
    fn to_vec(&self) -> Vec<u8>;

    fn to_hex(&self) -> String {
        hex::encode(self.as_slice())
    }
}
