use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Histogram {
    count: u32,
    frequency: BTreeMap<char, u32>,
}

impl Histogram {
    pub fn add(&mut self, key: char) {
        self.count += 1;
        *self.frequency.entry(key.to_ascii_lowercase()).or_insert(0) += 1;
    }

    pub fn score(&self) -> f64 {
        // See https://web.archive.org/web/20170918020907/http://www.data-compression.com/english.html
        self.frequency.iter().fold(0.0_f64, |acc, (&key, &count)| {
            let score = ascii_score(key as u8) * f64::from(count);
            acc + score
        }) / f64::from(self.count)
    }
}

pub fn ascii_histogram<T: ?Sized + AsRef<[u8]>>(input: &T) -> Option<Histogram> {
    let input = input.as_ref();
    if input.iter().all(|&byte| is_ascii_humanlike(byte)) {
        let mut hst = Histogram::default();
        for &byte in input.iter() {
            hst.add(byte as char);
        }
        Some(hst)
    } else {
        None
    }
}

pub fn is_ascii_humanlike(byte: u8) -> bool {
    let c = byte as char;
    c.is_ascii_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace()
}

pub fn ascii_score(byte: u8) -> f64 {
    match byte {
        b'a' => 0.08167_f64,
        b'b' => 0.01492_f64,
        b'c' => 0.02782_f64,
        b'd' => 0.04253_f64,
        b'e' => 0.12702_f64,
        b'f' => 0.02228_f64,
        b'g' => 0.02015_f64,
        b'h' => 0.06094_f64,
        b'i' => 0.06966_f64,
        b'j' => 0.00153_f64,
        b'k' => 0.00772_f64,
        b'l' => 0.04025_f64,
        b'm' => 0.02406_f64,
        b'n' => 0.06749_f64,
        b'o' => 0.07507_f64,
        b'p' => 0.01929_f64,
        b'q' => 0.00095_f64,
        b'r' => 0.05987_f64,
        b's' => 0.06327_f64,
        b't' => 0.09056_f64,
        b'u' => 0.02758_f64,
        b'v' => 0.00978_f64,
        b'w' => 0.02360_f64,
        b'x' => 0.00150_f64,
        b'y' => 0.01974_f64,
        b'z' => 0.00074_f64,
        b' ' => 0.19181_f64,
        _ => 0.0_f64,
    }
}
