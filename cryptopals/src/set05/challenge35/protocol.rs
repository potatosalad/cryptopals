pub use kex::dh::*;
pub use serde::{Deserialize, Serialize};
pub use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Serialize, Deserialize)]
pub struct EchoBotHandshakeNegotiate {
    pub(crate) p: BigUint,
    pub(crate) g: BigUint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EchoBotHandshakeAccept {}

#[derive(Debug, Serialize, Deserialize)]
pub struct EchoBotHandshakeRequest {
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

pub async fn read_once<T: serde::de::DeserializeOwned>(
    stream: &mut tokio::net::TcpStream,
) -> tokio::io::Result<T> {
    let mut buf = [0; 1024];
    let mut len = 0;

    loop {
        len += match stream.read(&mut buf[len..]).await {
            // socket closed
            Ok(n) if n == 0 => {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
            }
            Ok(n) => n,
            Err(e) => {
                eprintln!("failed to read from socket; err = {:?}", e);
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted));
            }
        };

        if let Ok(message) = serde_cbor::from_slice::<T>(&buf[0..len]) {
            return Ok(message);
        }
    }
}

pub async fn write_once<T: serde::ser::Serialize>(
    stream: &mut tokio::net::TcpStream,
    message: T,
) -> tokio::io::Result<()> {
    let message_encoded: Vec<u8> = serde_cbor::to_vec(&message).unwrap();
    stream.write_all(&message_encoded).await?;
    Ok(())
}
