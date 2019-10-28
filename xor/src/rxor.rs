// Repeating-key XOR

pub trait RepeatingKeyXor<T> {
    fn rxor<I: std::iter::FromIterator<u8>>(&self, _: &T) -> I;
}

pub trait RepeatingKeyXorMut<T> {
    fn rxor_mut(&mut self, _: &T);
}

impl<T: Sized + AsRef<[u8]>, U: ?Sized + AsRef<[u8]>> RepeatingKeyXor<T> for U {
    fn rxor<I: std::iter::FromIterator<u8>>(&self, t: &T) -> I {
        let a = self.as_ref();
        let b = t.as_ref();
        if b.is_empty() {
            a.iter().copied().collect()
        } else {
            a.chunks(b.len())
                .flat_map(|chunk| {
                    let len = chunk.len();
                    chunk.iter().zip(b[..len].iter()).map(|(&c, &d)| c ^ d)
                })
                .collect()
        }
    }
}

impl<T: Sized + AsRef<[u8]>, U: ?Sized + AsMut<[u8]>> RepeatingKeyXorMut<T> for U {
    fn rxor_mut(&mut self, t: &T) {
        let a = self.as_mut();
        let b = t.as_ref();
        if !b.is_empty() {
            a.chunks_mut(b.len()).for_each(|chunk| {
                let len = chunk.len();
                chunk.iter_mut().zip(b[..len].iter()).for_each(|(c, &d)| {
                    *c ^= d;
                });
            });
        }
    }
}

pub fn rxor<I: std::iter::FromIterator<u8>, A: ?Sized + AsRef<[u8]>, B: ?Sized + AsRef<[u8]>>(
    a: &A,
    b: &B,
) -> I {
    a.rxor(&b)
}

pub fn rxor_mut<A: ?Sized + AsMut<[u8]>, B: ?Sized + AsRef<[u8]>>(a: &mut A, b: &B) {
    a.rxor_mut(&b);
}

#[cfg(test)]
mod tests {
    use super::{RepeatingKeyXor, RepeatingKeyXorMut};

    #[test]
    fn rxor_sanity_check() {
        let a = "abc";
        let b = "xy";
        let c: Vec<u8> = a.rxor(&b);
        let expected = vec![25_u8, 27_u8, 27_u8];
        assert_eq!(expected, c);
    }

    #[test]
    fn rxor_mut_sanity_check() {
        let mut a = b"abc".to_vec();
        let b = "xy";
        a.rxor_mut(&b);
        let expected = vec![25_u8, 27_u8, 27_u8];
        assert_eq!(expected, a);
    }

    #[quickcheck]
    fn prop_rxor_twice_is_identity(xs: Vec<u8>, ys: Vec<u8>) -> bool {
        let mut zs: Vec<u8> = xs.rxor(&ys);
        zs.rxor_mut(&ys);
        zs == xs
    }
}
