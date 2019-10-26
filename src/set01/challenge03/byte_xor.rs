pub trait SingleByteXor {
    fn single_byte_xor<I: std::iter::FromIterator<u8>>(&self, byte: u8) -> I;
}

struct SingleByteXorIterator<'a> {
    inner: ::core::slice::Iter<'a, u8>,
    byte: u8,
}

impl<'a> SingleByteXorIterator<'a> {
    fn new(inner: &'a [u8], byte: u8) -> SingleByteXorIterator<'a> {
        SingleByteXorIterator {
            inner: inner.iter(),
            byte,
        }
    }
}

impl<'a> Iterator for SingleByteXorIterator<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|target| target ^ self.byte)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.len();
        (length, Some(length))
    }
}

impl<'a> std::iter::ExactSizeIterator for SingleByteXorIterator<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<T: ?Sized + AsRef<[u8]>> SingleByteXor for T {
    fn single_byte_xor<I: std::iter::FromIterator<u8>>(&self, byte: u8) -> I {
        SingleByteXorIterator::new(self.as_ref(), byte).collect()
    }
}

pub fn single_byte_xor<T: ?Sized + AsRef<[u8]>>(input: &T, byte: u8) -> Vec<u8> {
    input.single_byte_xor(byte)
}
