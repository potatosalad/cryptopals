use aes::cbc::{AesCbcCipher, AesCbcIv};
use kex::dh::*;

use rand::prelude::*;

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
        Ok(Self { stream, shared_key })
    }

    pub async fn echo(&mut self, message: &[u8]) -> tokio::io::Result<Vec<u8>> {
        let mut rng = thread_rng();
        let nonce: [u8; 16] = rng.gen();
        let iv = AesCbcIv::aes_cbc_iv(nonce);
        let cipher = AesCbcCipher::new(&self.shared_key, &iv);
        let ciphertext: Vec<u8> = cipher.encrypt(message).unwrap();
        write_once(&mut self.stream, EchoBotMessage { ciphertext, nonce }).await?;
        let response = read_once::<EchoBotMessage>(&mut self.stream).await?;
        let iv = AesCbcIv::aes_cbc_iv(response.nonce);
        let cipher = AesCbcCipher::new(&self.shared_key, &iv);
        let plaintext: Vec<u8> = cipher.decrypt(&response.ciphertext).unwrap();
        Ok(plaintext)
    }

    async fn handshake(
        stream: &mut tokio::net::TcpStream,
        secret_key: DiffieHellmanSecretKey,
    ) -> tokio::io::Result<aes::key::AesKey> {
        write_once(
            stream,
            EchoBotHandshakeNegotiate {
                p: secret_key.base.p.clone(),
                g: secret_key.base.g.clone(),
            },
        )
        .await?;
        read_once::<EchoBotHandshakeAccept>(stream).await?;
        write_once(
            stream,
            EchoBotHandshakeRequest {
                point_a: secret_key.public.clone(),
            },
        )
        .await?;
        let response = read_once::<EchoBotHandshakeResponse>(stream).await?;
        let b_public_key = DiffieHellmanPublicKey::new(secret_key.base.clone(), response.point_b);
        let shared_secret = secret_key.compute_shared_secret(&b_public_key).unwrap();
        // println!("[client] secret_key = {:?}", secret_key);
        // println!("[client] b_public_key = {:?}", b_public_key);
        // println!(
        //     "[client] shared_secret.to_bytes_be() = {:?}",
        //     shared_secret.shared_secret.to_bytes_be()
        // );
        let shared_key = aes::key::AesKey::try_copy_from_slice(
            &hash::sha1::hash(&shared_secret.shared_secret.to_bytes_be()).bytes()[0..16],
        )
        .unwrap();
        Ok(shared_key)
    }
}
