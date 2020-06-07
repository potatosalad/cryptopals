use kex::dh::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EchoBotHandshakeRequest {
    pub(crate) p: BigUint,
    pub(crate) g: BigUint,
    pub(crate) point_a: BigUint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EchoBotHandshakeResponse {
    pub(crate) point_b: BigUint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EchoBotMessage {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) nonce: [u8; 16],
}
