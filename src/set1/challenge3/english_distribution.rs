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
            let score = match key {
                'a' => 0.08167_f64,
                'b' => 0.01492_f64,
                'c' => 0.02782_f64,
                'd' => 0.04253_f64,
                'e' => 0.12702_f64,
                'f' => 0.02228_f64,
                'g' => 0.02015_f64,
                'h' => 0.06094_f64,
                'i' => 0.06966_f64,
                'j' => 0.00153_f64,
                'k' => 0.00772_f64,
                'l' => 0.04025_f64,
                'm' => 0.02406_f64,
                'n' => 0.06749_f64,
                'o' => 0.07507_f64,
                'p' => 0.01929_f64,
                'q' => 0.00095_f64,
                'r' => 0.05987_f64,
                's' => 0.06327_f64,
                't' => 0.09056_f64,
                'u' => 0.02758_f64,
                'v' => 0.00978_f64,
                'w' => 0.02360_f64,
                'x' => 0.00150_f64,
                'y' => 0.01974_f64,
                'z' => 0.00074_f64,
                ' ' => 0.19181_f64,
                _ => 0.0_f64,
            } * f64::from(count);
            acc + score
        }) / f64::from(self.count)
    }
}

pub fn ascii_histogram<T: ?Sized + AsRef<[u8]>>(input: &T) -> Option<Histogram> {
    let input = input.as_ref();
    if input.iter().all(|&byte| (byte as char).is_ascii()) {
        let mut hst = Histogram::default();
        for &byte in input.iter() {
            hst.add(byte as char);
        }
        Some(hst)
    } else {
        None
    }
}
