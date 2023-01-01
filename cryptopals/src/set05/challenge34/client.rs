use aes::cbc::{AesCbcCipher, AesCbcIv};
use kex::dh::*;

use rand::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::protocol::*;

#[derive(Debug)]
pub struct EchoBotClient {
    stream: tokio::net::TcpStream,
    shared_key: aes::key::AesKey,
}

impl EchoBotClient {
    pub async fn connect<A: tokio::net::ToSocketAddrs>(
        secret_key: DiffieHellmanSecretKey,
        addr: A,
    ) -> tokio::io::Result<Self> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let shared_key = Self::handshake(&mut stream, secret_key).await?;
        // println!("[client] SHARED KEY = {:?}", shared_key);
        Ok(Self { stream, shared_key })
    }

    pub async fn echo(&mut self, message: &[u8]) -> tokio::io::Result<Vec<u8>> {
        let mut rng = thread_rng();
        let nonce: [u8; 16] = rng.gen();
        let iv = AesCbcIv::aes_cbc_iv(nonce);
        let cipher = AesCbcCipher::new(&self.shared_key, &iv);
        let ciphertext: Vec<u8> = cipher.encrypt(message).unwrap();
        let request = EchoBotMessage { ciphertext, nonce };
        let request_encoded = serde_cbor::to_vec(&request).unwrap();
        // println!("[client] request = {:?}", request);
        // println!("[client] request = {:?}", request_encoded);
        self.stream.write_all(&request_encoded).await?;

        let mut buf = [0; 1024];
        let mut len = 0;

        loop {
            len += match self.stream.read(&mut buf[len..]).await {
                // socket closed
                Ok(n) if n == 0 => {
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
                }
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[client] failed to read from socket; err = {:?}", e);
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted));
                }
            };

            // println!("[client] {:?} buf = {:?}", len, &buf[0..len]);

            if let Ok(response) = serde_cbor::from_slice::<EchoBotMessage>(&buf[0..len]) {
                // println!("[client] response = {:?}", response);
                // len = 0;
                let iv = AesCbcIv::aes_cbc_iv(response.nonce);
                let cipher = AesCbcCipher::new(&self.shared_key, &iv);
                let plaintext: Vec<u8> = cipher.decrypt(&response.ciphertext).unwrap();
                return Ok(plaintext);
            }
        }
    }

    async fn handshake(
        stream: &mut tokio::net::TcpStream,
        secret_key: DiffieHellmanSecretKey,
    ) -> tokio::io::Result<aes::key::AesKey> {
        let request = EchoBotHandshakeRequest {
            p: secret_key.base.p.clone(),
            g: secret_key.base.g.clone(),
            point_a: secret_key.public.clone(),
        };
        let request_encoded = serde_cbor::to_vec(&request).unwrap();
        // println!("[client] request = {:?}", request);
        // println!("[client] request = {:?}", request_encoded);
        stream.write_all(&request_encoded).await?;

        let mut buf = [0; 1024];
        let mut len = 0;

        loop {
            len += match stream.read(&mut buf[len..]).await {
                // socket closed
                Ok(n) if n == 0 => {
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
                }
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[client] failed to read from socket; err = {:?}", e);
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted));
                }
            };

            // println!("[client] {:?} buf = {:?}", len, &buf[0..len]);

            if let Ok(response) = serde_cbor::from_slice::<EchoBotHandshakeResponse>(&buf[0..len]) {
                // println!("[client] response = {:?}", response);
                // len = 0;
                let b_public_key =
                    DiffieHellmanPublicKey::new(secret_key.base.clone(), response.point_b);
                let shared_secret = secret_key.compute_shared_secret(&b_public_key).unwrap();
                let shared_key = aes::key::AesKey::try_copy_from_slice(
                    &hash::sha1::hash(&shared_secret.shared_secret.to_bytes_be()).bytes()[0..16],
                )
                .unwrap();
                return Ok(shared_key);
            }
        }
    }
}
