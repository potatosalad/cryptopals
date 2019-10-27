#![warn(
    clippy::all,
    // clippy::restriction,
    // clippy::pedantic,
    // clippy::nursery,
    // clippy::cargo,
)]

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub mod exor;
pub mod rxor;
pub mod sxor;

pub mod prelude {
    pub use crate::exor::*;
    pub use crate::rxor::*;
    pub use crate::sxor::*;
}
