// Exclusive (fixed-length) XOR

#[derive(Debug, Clone)]
pub struct ExclusiveFixedXorError;

// This is important for other errors to wrap this one.
impl std::error::Error for ExclusiveFixedXorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl std::fmt::Display for ExclusiveFixedXorError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "exor may only be performed on same-length inputs")
    }
}

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
            return Err(ExclusiveFixedXorError.into());
            // return Err("exor may only be performed on same-length inputs".into());
        }
        Ok(a.iter().zip(b.iter()).map(|(&c, &d)| c ^ d).collect())
    }
}

impl<T: Sized + AsRef<[u8]>, U: ?Sized + AsMut<[u8]>> ExclusiveFixedXorMut<T> for U {
    fn exor_mut(&mut self, t: &T) -> crate::Result<()> {
        let a = self.as_mut();
        let b = t.as_ref();
        if a.len() != b.len() {
            return Err(ExclusiveFixedXorError.into());
            // return Err("exor may only be performed on same-length inputs".into());
        }
        a.iter_mut().zip(b.iter()).for_each(|(c, &d)| {
            *c ^= d;
        });
        Ok(())
    }
}

pub fn exor<I: std::iter::FromIterator<u8>, A: ?Sized + AsRef<[u8]>, B: ?Sized + AsRef<[u8]>>(
    a: &A,
    b: &B,
) -> crate::Result<I> {
    a.exor(&b)
}

pub fn exor_mut<A: ?Sized + AsMut<[u8]>, B: ?Sized + AsRef<[u8]>>(
    a: &mut A,
    b: &B,
) -> crate::Result<()> {
    a.exor_mut(&b)
}

#[cfg(test)]
mod tests {
    use super::{ExclusiveFixedXor, ExclusiveFixedXorMut};
    use quickcheck::TestResult;

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
    fn prop_exor_twice_is_identity(xs: Vec<u8>, ys: Vec<u8>) -> TestResult {
        let xlen = xs.len();
        let ylen = ys.len();
        let test = test_exor_twice_is_identity(xs, ys);
        if xlen != ylen {
            TestResult::must_fail(move || test.unwrap())
        } else {
            TestResult::from_bool(test.unwrap())
        }
    }

    fn test_exor_twice_is_identity(xs: Vec<u8>, ys: Vec<u8>) -> crate::Result<bool> {
        let mut zs: Vec<u8> = xs.exor(&ys)?;
        zs.exor_mut(&ys)?;
        Ok(zs == xs)
    }
}
