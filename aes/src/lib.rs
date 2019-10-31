#![warn(
    clippy::all,
    // clippy::restriction,
    // clippy::pedantic,
    // clippy::nursery,
    // clippy::cargo,
)]

extern crate quickcheck;
// #[cfg(test)]
// #[macro_use(quickcheck)]
// extern crate quickcheck_macros;

pub mod cbc;
pub mod ecb;
pub mod error;
pub mod key;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
