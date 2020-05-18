// See: https://tools.ietf.org/html/rfc1320

pub use crate::fixed_hash::{FixedHashContext, FixedHashOutput};

#[derive(Clone)]
struct Md4Buffer([u8; 64]);

impl std::fmt::Debug for Md4Buffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (&self.0[..]).fmt(f)
    }
}

impl Default for Md4Buffer {
    fn default() -> Self {
        Self([0; 64])
    }
}

impl PartialEq for Md4Buffer {
    fn eq(&self, other: &Md4Buffer) -> bool {
        (&self.0[..]).eq(&other.0[..])
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Md4Context {
    state: [u32; 4],
    count: u64,
    buffer: Md4Buffer,
    computed: bool,
    corrupted: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Md4Error {
    InputTooLong,
    StateError,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Md4Output([u8; 16]);

impl Md4Output {
    pub fn bytes(&self) -> [u8; 16] {
        self.0
    }
}

impl FixedHashOutput for Md4Output {
    fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl FixedHashContext for Md4Context {
    type Error = Md4Error;
    type Output = Md4Output;

    fn init() -> Self {
        let mut context = Self::default();
        context.reset();
        context
    }

    fn update<T: ?Sized + AsRef<[u8]>>(&mut self, input: &T) -> Result<(), Self::Error> {
        let input = input.as_ref();
        if input.is_empty() {
            return Ok(());
        }
        if self.computed {
            return Err(Md4Error::StateError);
        }
        if self.corrupted {
            return Err(Md4Error::InputTooLong);
        }

        for &byte in input {
            // Compute number of bytes mod 64
            let index: usize = ((self.count as usize) >> 3) & 0x3F;
            // Update number of bits
            let increment: u64 = 1 << 3;
            if let Some(count) = self.count.checked_add(increment) {
                self.count = count;
            } else {
                self.corrupted = true;
                return Err(Md4Error::InputTooLong);
            }
            // Update buffer
            self.buffer.0[index] = byte;
            if index + 1 == 64 {
                self.transform()?;
            }
        }
        Ok(())
    }

    fn output(&mut self) -> Result<Self::Output, Self::Error> {
        if self.corrupted {
            return Err(Md4Error::InputTooLong);
        }
        if !self.computed {
            self.pad()?;
            // message may be sensitive, clear it out
            self.buffer.0.copy_from_slice(&[0_u8; 64]);
            // and clear count
            self.count = 0;
            self.computed = true;
        }
        let output: [u8; 16] = md4_encode(&self.state);
        Ok(Md4Output(output))
    }

    fn reset(&mut self) {
        // Load magic initialization constants.
        self.state[0] = 0x6745_2301;
        self.state[1] = 0xefcd_ab89;
        self.state[2] = 0x98ba_dcfe;
        self.state[3] = 0x1032_5476;
        self.count = 0;
        // self.message_block_index = 0;
        self.buffer.0.copy_from_slice(&[0_u8; 64]);
        self.computed = false;
        self.corrupted = false;
    }

    fn block_size() -> usize {
        64
    }

    fn hash_size() -> usize {
        16
    }
}

#[inline]
fn md4_decode(input: [u8; 64]) -> [u32; 16] {
    unsafe { std::mem::transmute(input) }
    // let mut output: [u32; 16] = [0_u32; 16];
    // let mut i = 0;
    // let mut j = 0;
    // while j < input.len() {
    //     output[i] = (input[j] as u32) | ((input[j + 1] as u32) << 8) | ((input[j + 2] as u32) << 16) | ((input[j + 3] as u32) << 24);
    //     i += 1;
    //     j += 4;
    // }
    // output
}

#[inline]
fn md4_encode(input: &[u32; 4]) -> [u8; 16] {
    let mut output: [u8; 16] = [0_u8; 16];
    let mut i = 0;
    let mut j = 0;
    while j < output.len() {
        output[j] = (input[i] & 0xff) as u8;
        output[j + 1] = ((input[i] >> 8) & 0xff) as u8;
        output[j + 2] = ((input[i] >> 16) & 0xff) as u8;
        output[j + 3] = ((input[i] >> 24) & 0xff) as u8;
        i += 1;
        j += 4;
    }
    output
}

#[allow(clippy::many_single_char_names)]
#[inline]
fn md4_rotate_left(x: u32, y: u32) -> u32 {
    x.wrapping_shl(y) | x.wrapping_shr(32 - y)
}

#[allow(clippy::many_single_char_names)]
#[inline]
fn md4_f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[allow(clippy::many_single_char_names)]
#[inline]
fn md4_g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[allow(clippy::many_single_char_names)]
#[inline]
fn md4_h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[allow(clippy::many_single_char_names)]
#[inline]
fn md4_ff(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    let temp = a.wrapping_add(md4_f(b, c, d)).wrapping_add(x);
    md4_rotate_left(temp, s)
}

#[allow(clippy::many_single_char_names)]
#[inline]
fn md4_gg(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    let temp = a
        .wrapping_add(md4_g(b, c, d))
        .wrapping_add(x)
        .wrapping_add(0x5a82_7999);
    md4_rotate_left(temp, s)
}

#[allow(clippy::many_single_char_names)]
#[inline]
fn md4_hh(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    let temp = a
        .wrapping_add(md4_h(b, c, d))
        .wrapping_add(x)
        .wrapping_add(0x6ed9_eba1);
    md4_rotate_left(temp, s)
}

impl Md4Context {
    pub fn recover(digest: [u8; 16], count: u64) -> Result<Self, &'static str> {
        use std::convert::TryInto;
        let mut state: [u32; 4] = [0_u32; 4];
        for (i, v) in state.iter_mut().enumerate() {
            *v = u32::from_le_bytes((&digest[(i * 4)..((i + 1) * 4)]).try_into().unwrap());
        }
        Md4ContextBuilder::new()
            .set_state(state)
            .set_count(count)
            .build()
    }

    pub fn get_state(&self) -> [u32; 4] {
        self.state
    }

    pub fn get_bit_size(&self) -> u64 {
        self.count
    }

    pub fn set_bit_size(&mut self, bit_size: u64) {
        self.count = bit_size;
    }

    #[allow(clippy::many_single_char_names)]
    #[allow(non_snake_case)]
    fn transform(&mut self) -> Result<(), Md4Error> {
        // Constants for MD4Transform routine.
        const S11: u32 = 3;
        const S12: u32 = 7;
        const S13: u32 = 11;
        const S14: u32 = 19;
        const S21: u32 = 3;
        const S22: u32 = 5;
        const S23: u32 = 9;
        const S24: u32 = 13;
        const S31: u32 = 3;
        const S32: u32 = 9;
        const S33: u32 = 11;
        const S34: u32 = 15;

        // Variables
        let mut a: u32 = self.state[0];
        let mut b: u32 = self.state[1];
        let mut c: u32 = self.state[2];
        let mut d: u32 = self.state[3];
        let x: [u32; 16] = md4_decode(self.buffer.0);

        // Round 1
        a = md4_ff(a, b, c, d, x[0], S11); // 1
        d = md4_ff(d, a, b, c, x[1], S12); // 2
        c = md4_ff(c, d, a, b, x[2], S13); // 3
        b = md4_ff(b, c, d, a, x[3], S14); // 4
        a = md4_ff(a, b, c, d, x[4], S11); // 5
        d = md4_ff(d, a, b, c, x[5], S12); // 6
        c = md4_ff(c, d, a, b, x[6], S13); // 7
        b = md4_ff(b, c, d, a, x[7], S14); // 8
        a = md4_ff(a, b, c, d, x[8], S11); // 9
        d = md4_ff(d, a, b, c, x[9], S12); // 10
        c = md4_ff(c, d, a, b, x[10], S13); // 11
        b = md4_ff(b, c, d, a, x[11], S14); // 12
        a = md4_ff(a, b, c, d, x[12], S11); // 13
        d = md4_ff(d, a, b, c, x[13], S12); // 14
        c = md4_ff(c, d, a, b, x[14], S13); // 15
        b = md4_ff(b, c, d, a, x[15], S14); // 16

        // Round 2
        a = md4_gg(a, b, c, d, x[0], S21); // 17
        d = md4_gg(d, a, b, c, x[4], S22); // 18
        c = md4_gg(c, d, a, b, x[8], S23); // 19
        b = md4_gg(b, c, d, a, x[12], S24); // 20
        a = md4_gg(a, b, c, d, x[1], S21); // 21
        d = md4_gg(d, a, b, c, x[5], S22); // 22
        c = md4_gg(c, d, a, b, x[9], S23); // 23
        b = md4_gg(b, c, d, a, x[13], S24); // 24
        a = md4_gg(a, b, c, d, x[2], S21); // 25
        d = md4_gg(d, a, b, c, x[6], S22); // 26
        c = md4_gg(c, d, a, b, x[10], S23); // 27
        b = md4_gg(b, c, d, a, x[14], S24); // 28
        a = md4_gg(a, b, c, d, x[3], S21); // 29
        d = md4_gg(d, a, b, c, x[7], S22); // 30
        c = md4_gg(c, d, a, b, x[11], S23); // 31
        b = md4_gg(b, c, d, a, x[15], S24); // 32

        // Round 3
        a = md4_hh(a, b, c, d, x[0], S31); // 33
        d = md4_hh(d, a, b, c, x[8], S32); // 34
        c = md4_hh(c, d, a, b, x[4], S33); // 35
        b = md4_hh(b, c, d, a, x[12], S34); // 36
        a = md4_hh(a, b, c, d, x[2], S31); // 37
        d = md4_hh(d, a, b, c, x[10], S32); // 38
        c = md4_hh(c, d, a, b, x[6], S33); // 39
        b = md4_hh(b, c, d, a, x[14], S34); // 40
        a = md4_hh(a, b, c, d, x[1], S31); // 41
        d = md4_hh(d, a, b, c, x[9], S32); // 42
        c = md4_hh(c, d, a, b, x[5], S33); // 43
        b = md4_hh(b, c, d, a, x[13], S34); // 44
        a = md4_hh(a, b, c, d, x[3], S31); // 45
        d = md4_hh(d, a, b, c, x[11], S32); // 46
        c = md4_hh(c, d, a, b, x[7], S33); // 47
        b = md4_hh(b, c, d, a, x[15], S34); // 48

        // Save state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);

        // Zeroize sensitive information.
        self.buffer.0.copy_from_slice(&[0_u8; 64]);
        Ok(())
    }

    fn pad(&mut self) -> Result<(), Md4Error> {
        const PADDING: [u8; 64] = [
            0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        // Pad out to 56 mod 64.
        let count: [u8; 8] = self.count.to_le_bytes();
        let index: usize = ((self.count as usize) >> 3) & 0x3F;
        let pad_size: usize = if index < 56 { 56 - index } else { 120 - index };
        self.update(&PADDING[0..pad_size])?;
        self.update(&count)?;
        Ok(())
    }
}

pub fn hash<T: ?Sized + AsRef<[u8]>>(input: &T) -> Md4Output {
    let mut ctx = Md4Context::init();
    ctx.update(input).unwrap();
    ctx.output().unwrap()
}

#[derive(Clone, Debug, Default)]
pub struct Md4ContextBuilder {
    state: Option<[u32; 4]>,
    count: u64,
}

impl Md4ContextBuilder {
    pub fn new() -> Self {
        Md4ContextBuilder::default()
    }

    pub fn build(&self) -> Result<Md4Context, &'static str> {
        if self.state.is_none() {
            return Err("state is required");
        }
        let mut ctx = Md4Context::default();
        ctx.state = *self.state.as_ref().unwrap();
        ctx.count = self.count;
        Ok(ctx)
    }

    pub fn set_state(&mut self, value: [u32; 4]) -> &mut Self {
        self.state = Some(value);
        self
    }

    pub fn set_count(&mut self, value: u64) -> &mut Self {
        self.count = value;
        self
    }
}

#[cfg(test)]
mod tests {
    use md4impl::{Digest, Md4};

    #[test]
    fn crate_md4_matches_extern_md4() {
        let mut input: Vec<u8> = Vec::new();
        for _ in 0..1024 {
            assert_eq!(
                Md4::digest(&input)[..],
                crate::md4::hash(&input).bytes()[..]
            );
            input.push(0x01);
        }
    }

    #[quickcheck]
    fn crate_md4_matches_extern_md4_property(input: Vec<u8>) -> bool {
        Md4::digest(&input)[..] == crate::md4::hash(&input).bytes()[..]
    }
}
