// Single-byte XOR

pub trait SingleByteXor {
    fn sxor<I: std::iter::FromIterator<u8>>(&self, _: u8) -> I;
}

pub trait SingleByteXorMut {
    fn sxor_mut(&mut self, _: u8);
}

impl<U: ?Sized + AsRef<[u8]>> SingleByteXor for U {
    fn sxor<I: std::iter::FromIterator<u8>>(&self, b: u8) -> I {
        let a = self.as_ref();
        a.iter().map(|&c| c ^ b).collect()
    }
}

impl<U: ?Sized + AsMut<[u8]>> SingleByteXorMut for U {
    fn sxor_mut(&mut self, b: u8) {
        let a = self.as_mut();
        a.iter_mut().for_each(|c| {
            *c ^= b;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{SingleByteXor, SingleByteXorMut};

    #[test]
    fn sxor_sanity_check() {
        let a = "abc";
        let b = 120_u8;
        let c: Vec<u8> = a.sxor(b);
        let expected = vec![25_u8, 26_u8, 27_u8];
        assert_eq!(expected, c);
    }

    #[test]
    fn sxor_mut_sanity_check() {
        let mut a = b"abc".to_vec();
        let b = 120_u8;
        a.sxor_mut(b);
        let expected = vec![25_u8, 26_u8, 27_u8];
        assert_eq!(expected, a);
    }

    #[quickcheck]
    fn prop_sxor_twice_is_identity(xs: Vec<u8>, b: u8) -> bool {
        let mut ys: Vec<u8> = xs.sxor(b);
        ys.sxor_mut(b);
        ys == xs
    }
}
