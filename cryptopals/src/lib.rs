#![warn(
    clippy::all,
    // clippy::restriction,
    // clippy::pedantic,
    // clippy::nursery,
    // clippy::cargo,
)]

#[cfg(test)]
#[macro_use(lazy_static)]
extern crate lazy_static;
#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;
// #[macro_use]
extern crate serde;

pub mod set01;
pub mod set02;
pub mod set03;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
