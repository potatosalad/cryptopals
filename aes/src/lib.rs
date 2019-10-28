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
