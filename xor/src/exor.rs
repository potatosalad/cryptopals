// Exclusive (fixed-length) XOR

pub trait ExclusiveFixedXor<T> {
    fn exor<I: std::iter::FromIterator<u8>>(&self, _: &T) -> crate::Result<I>;
}

pub trait ExclusiveFixedXorMut<T> {
    fn exor_mut(&mut self, _: &T) -> crate::Result<()>;
}

impl<T: Sized + AsRef<[u8]>, U: ?Sized + AsRef<[u8]>> ExclusiveFixedXor<T> for U {
    fn exor<I: std::iter::FromIterator<u8>>(&self, t: &T) -> crate::Result<I> {
        let a = self.as_ref();
        let b = t.as_ref();
        if a.len() != b.len() {
            return Err("exor may only be performed on same-length inputs".into());
        }
        Ok(a.iter().zip(b.iter()).map(|(&c, &d)| c ^ d).collect())
    }
}

impl<T: Sized + AsRef<[u8]>, U: ?Sized + AsMut<[u8]>> ExclusiveFixedXorMut<T> for U {
    fn exor_mut(&mut self, t: &T) -> crate::Result<()> {
        let a = self.as_mut();
        let b = t.as_ref();
        if a.len() != b.len() {
            return Err("exor may only be performed on same-length inputs".into());
        }
        a.iter_mut().zip(b.iter()).for_each(|(c, &d)| {
            *c ^= d;
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ExclusiveFixedXor, ExclusiveFixedXorMut};

    #[test]
    fn exor_sanity_check() -> crate::Result<()> {
        let a = "abc";
        let b = "xyz";
        let c: Vec<u8> = a.exor(&b)?;
        let expected = vec![25_u8, 27_u8, 25_u8];
        assert_eq!(expected, c);
        Ok(())
    }

    #[test]
    fn exor_mut_sanity_check() -> crate::Result<()> {
        let mut a = b"abc".to_vec();
        let b = "xyz";
        a.exor_mut(&b)?;
        let expected = vec![25_u8, 27_u8, 25_u8];
        assert_eq!(expected, a);
        Ok(())
    }

    #[quickcheck]
    fn prop_exor_twice_is_identity(xs: Vec<u8>) -> bool {
        let mut ys: Vec<u8> = xs.exor(&xs).unwrap();
        ys.exor_mut(&xs).unwrap();
        ys == xs
    }

    #[quickcheck]
    fn prop_exor_is_reversible(xs: Vec<u8>) -> bool {
        let ys: Vec<u8> = vec![1_u8; xs.len()];
        let mut zs: Vec<u8> = xs.exor(&ys).unwrap();
        zs.exor_mut(&xs).unwrap();
        ys == zs
    }
}
