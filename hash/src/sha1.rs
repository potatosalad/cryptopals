// See: https://tools.ietf.org/html/rfc3174

pub use crate::fixed_hash::{FixedHashContext, FixedHashOutput};

#[derive(Clone)]
struct Sha1MessageBlock([u8; 64]);

impl std::fmt::Debug for Sha1MessageBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (&self.0[..]).fmt(f)
    }
}

impl Default for Sha1MessageBlock {
    fn default() -> Self {
        Self([0; 64])
    }
}

impl PartialEq for Sha1MessageBlock {
    fn eq(&self, other: &Sha1MessageBlock) -> bool {
        (&self.0[..]).eq(&other.0[..])
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sha1Context {
    intermediate_hash: [u32; 5],
    length_low: u32,
    length_high: u32,
    message_block_index: usize,
    message_block: Sha1MessageBlock,
    computed: bool,
    corrupted: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Sha1Error {
    InputTooLong,
    StateError,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sha1Output([u8; 20]);

impl Sha1Output {
    pub fn bytes(&self) -> [u8; 20] {
        self.0
    }
}

impl FixedHashOutput for Sha1Output {
    fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl FixedHashContext for Sha1Context {
    type Error = Sha1Error;
    type Output = Sha1Output;

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
            return Err(Sha1Error::StateError);
        }
        if self.corrupted {
            return Err(Sha1Error::InputTooLong);
        }
        for &byte in input {
            self.message_block.0[self.message_block_index] = byte;
            self.length_low = self.length_low.wrapping_add(8);
            if self.length_low == 0 {
                self.length_high = self.length_high.wrapping_add(1);
                if self.length_high == 0 {
                    self.corrupted = true;
                    return Err(Sha1Error::InputTooLong);
                }
            }
            self.message_block_index += 1;
            if self.message_block_index == 64 {
                self.process_message_block()?;
            }
        }
        Ok(())
    }

    fn output(&mut self) -> Result<Self::Output, Self::Error> {
        if self.corrupted {
            return Err(Sha1Error::InputTooLong);
        }
        if !self.computed {
            self.pad_message()?;
            // message may be sensitive, clear it out
            self.message_block.0.copy_from_slice(&[0_u8; 64]);
            // and clear length
            self.length_low = 0;
            self.length_high = 0;
            self.computed = true;
        }
        let mut output: [u8; 20] = [0_u8; 20];
        #[allow(clippy::needless_range_loop)]
        for i in 0..20_usize {
            output[i] = (self.intermediate_hash[i >> 2] >> (8 * (3 - (i as u32 & 0x03)))) as u8;
        }
        Ok(Sha1Output(output))
    }

    fn reset(&mut self) {
        self.intermediate_hash[0] = 0x6745_2301;
        self.intermediate_hash[1] = 0xEFCD_AB89;
        self.intermediate_hash[2] = 0x98BA_DCFE;
        self.intermediate_hash[3] = 0x1032_5476;
        self.intermediate_hash[4] = 0xC3D2_E1F0;
        self.length_low = 0;
        self.length_high = 0;
        self.message_block_index = 0;
        self.message_block.0.copy_from_slice(&[0_u8; 64]);
        self.computed = false;
        self.corrupted = false;
    }
}

#[inline]
fn sha1_circular_shift(bits: u32, word: u32) -> u32 {
    word.wrapping_shl(bits) | word.wrapping_shr(32 - bits)
}

impl Sha1Context {
    #[allow(clippy::needless_range_loop)]
    #[allow(non_snake_case)]
    fn process_message_block(&mut self) -> Result<(), Sha1Error> {
        // Constants defined in SHA-1
        const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];
        // Temporary word value
        let mut temp: u32;
        // Word sequence
        let mut W: [u32; 80] = [0; 80];
        // Word buffers
        let mut A = self.intermediate_hash[0];
        let mut B = self.intermediate_hash[1];
        let mut C = self.intermediate_hash[2];
        let mut D = self.intermediate_hash[3];
        let mut E = self.intermediate_hash[4];
        // Initialize the first 16 words in the array W
        for t in 0..16 {
            W[t] = (self.message_block.0[t * 4] as u32) << 24;
            W[t] |= (self.message_block.0[t * 4 + 1] as u32) << 16;
            W[t] |= (self.message_block.0[t * 4 + 2] as u32) << 8;
            W[t] |= self.message_block.0[t * 4 + 3] as u32;
        }
        for t in 16..80 {
            W[t] = sha1_circular_shift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
        }
        for t in 0..20 {
            temp = sha1_circular_shift(5, A)
                .wrapping_add((B & C) | ((!B) & D))
                .wrapping_add(E)
                .wrapping_add(W[t])
                .wrapping_add(K[0]);
            E = D;
            D = C;
            C = sha1_circular_shift(30, B);
            B = A;
            A = temp;
        }
        for t in 20..40 {
            temp = sha1_circular_shift(5, A)
                .wrapping_add(B ^ C ^ D)
                .wrapping_add(E)
                .wrapping_add(W[t])
                .wrapping_add(K[1]);
            E = D;
            D = C;
            C = sha1_circular_shift(30, B);
            B = A;
            A = temp;
        }
        for t in 40..60 {
            temp = sha1_circular_shift(5, A)
                .wrapping_add((B & C) | (B & D) | (C & D))
                .wrapping_add(E)
                .wrapping_add(W[t])
                .wrapping_add(K[2]);
            E = D;
            D = C;
            C = sha1_circular_shift(30, B);
            B = A;
            A = temp;
        }
        for t in 60..80 {
            temp = sha1_circular_shift(5, A)
                .wrapping_add(B ^ C ^ D)
                .wrapping_add(E)
                .wrapping_add(W[t])
                .wrapping_add(K[3]);
            E = D;
            D = C;
            C = sha1_circular_shift(30, B);
            B = A;
            A = temp;
        }
        self.intermediate_hash[0] = self.intermediate_hash[0].wrapping_add(A);
        self.intermediate_hash[1] = self.intermediate_hash[1].wrapping_add(B);
        self.intermediate_hash[2] = self.intermediate_hash[2].wrapping_add(C);
        self.intermediate_hash[3] = self.intermediate_hash[3].wrapping_add(D);
        self.intermediate_hash[4] = self.intermediate_hash[4].wrapping_add(E);
        self.message_block_index = 0;
        Ok(())
    }

    fn pad_message(&mut self) -> Result<(), Sha1Error> {
        // Check to see if the current message block is too small to hold
        // the initial padding bits and length.  If so, we will pad the
        // block, process it, and then continue padding into a second
        // block.
        if self.message_block_index > 55 {
            self.message_block.0[self.message_block_index] = 0x80;
            self.message_block_index += 1;
            while self.message_block_index < 64 {
                self.message_block.0[self.message_block_index] = 0;
                self.message_block_index += 1;
            }
            self.process_message_block()?;
            while self.message_block_index < 56 {
                self.message_block.0[self.message_block_index] = 0;
                self.message_block_index += 1;
            }
        } else {
            self.message_block.0[self.message_block_index] = 0x80;
            self.message_block_index += 1;
            while self.message_block_index < 56 {
                self.message_block.0[self.message_block_index] = 0;
                self.message_block_index += 1;
            }
        }
        // Store the message length as the last 8 octets
        self.message_block.0[56] = (self.length_high >> 24) as u8;
        self.message_block.0[57] = (self.length_high >> 16) as u8;
        self.message_block.0[58] = (self.length_high >> 8) as u8;
        self.message_block.0[59] = self.length_high as u8;
        self.message_block.0[60] = (self.length_low >> 24) as u8;
        self.message_block.0[61] = (self.length_low >> 16) as u8;
        self.message_block.0[62] = (self.length_low >> 8) as u8;
        self.message_block.0[63] = self.length_low as u8;
        self.process_message_block()
    }
}

pub fn hash<T: ?Sized + AsRef<[u8]>>(input: &T) -> Sha1Output {
    let mut ctx = Sha1Context::init();
    ctx.update(input).unwrap();
    ctx.output().unwrap()
}

#[cfg(test)]
mod tests {
    #[quickcheck]
    fn crate_sha1_matches_extern_sha1(input: Vec<u8>) -> bool {
        sha1impl::Sha1::from(input.clone()).digest().bytes()[..]
            == crate::sha1::hash(&input).bytes()[..]
    }
}
