mod fixed_xor;

pub use fixed_xor::*;

#[cfg(test)]
mod tests {
    #[test]
    fn fixed_xor_should_produce() {
        let xs = "1c0111001f010100061a024b53535009181c";
        let ys = "686974207468652062756c6c277320657965";
        let zs = "746865206b696420646f6e277420706c6179";
        assert_eq!(zs, super::fixed_xor_base16(&xs, &ys).unwrap());
    }
}
