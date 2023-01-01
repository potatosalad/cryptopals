use aes::cbc::{AesCbcCipher, AesCbcIv};
use kex::dh::*;

use rand::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::protocol::*;

#[derive(Debug)]
pub struct EchoBotRuntime {
    join_handle: tokio::task::JoinHandle<()>,
    terminator: tokio::sync::oneshot::Sender<()>,
}

#[derive(Debug)]
pub struct EchoBotServer {
    address: std::net::SocketAddr,
    runtime: Option<EchoBotRuntime>,
}

impl EchoBotServer {
    pub async fn start() -> tokio::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let join_handle = tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    loop {
                        match listener.accept().await {
                            Ok((stream, _)) => {
                                // println!("[server] new client: {:?}", stream);
                                tokio::spawn(async {
                                    Self::init(stream).await;
                                });
                            }
                            Err(e) => {
                                eprintln!("connection failed: {:?}", e);
                            }
                        }
                    }
                } => {}
                _ = rx => {}
            }
        });
        Ok(Self {
            address: addr,
            runtime: Some(EchoBotRuntime {
                join_handle,
                terminator: tx,
            }),
        })
    }

    pub async fn stop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.terminator.send(()).unwrap();
            rt.join_handle.await.unwrap();
        }
    }

    pub fn get_port(&self) -> u16 {
        self.address.port()
    }

    async fn init(stream: tokio::net::TcpStream) {
        let mut stream = stream;

        let shared_key = Self::handshake_loop(&mut stream).await.unwrap();
        // println!("[server] SHARED KEY = {:?}", shared_key);
        Self::message_loop(&mut stream, shared_key).await;
    }

    async fn handshake_loop(stream: &mut tokio::net::TcpStream) -> Option<aes::key::AesKey> {
        let mut buf = [0; 1024];
        let mut len = 0;

        loop {
            len += match stream.read(&mut buf[len..]).await {
                // socket closed
                Ok(n) if n == 0 => return None,
                Ok(n) => n,
                Err(e) => {
                    eprintln!("failed to read from socket; err = {:?}", e);
                    return None;
                }
            };

            // println!("[server] {:?} buf = {:?}", len, &buf[0..len]);

            if let Ok(request) = serde_cbor::from_slice::<EchoBotHandshakeRequest>(&buf[0..len]) {
                // println!("[server] request = {:?}", request);
                // len = 0;
                let base = DiffieHellmanBase::new(request.p, request.g);
                let a_public_key = DiffieHellmanPublicKey::new(base.clone(), request.point_a);
                let b_secret_key = base.gen_secret_key();
                let b_public_key = b_secret_key.to_public_key();
                let response = EchoBotHandshakeResponse {
                    point_b: b_public_key.public.clone(),
                };
                let response_encoded = serde_cbor::to_vec(&response).unwrap();
                // println!("[server] response = {:?}", response);
                // println!("[server] response = {:?}", response_encoded);
                if let Err(e) = stream.write_all(&response_encoded).await {
                    eprintln!("failed to write to socket; err = {:?}", e);
                    return None;
                }
                let b_shared_secret = b_secret_key.compute_shared_secret(&a_public_key).unwrap();
                let shared_key = aes::key::AesKey::try_copy_from_slice(
                    &hash::sha1::hash(&b_shared_secret.shared_secret.to_bytes_be()).bytes()[0..16],
                )
                .unwrap();
                return Some(shared_key);
            }
        }
    }

    async fn message_loop(stream: &mut tokio::net::TcpStream, shared_key: aes::key::AesKey) {
        let mut buf = [0; 1024];
        let mut len = 0;

        loop {
            len += match stream.read(&mut buf[len..]).await {
                // socket closed
                Ok(n) if n == 0 => return,
                Ok(n) => n,
                Err(e) => {
                    eprintln!("failed to read from socket; err = {:?}", e);
                    return;
                }
            };

            // println!("[server] {:?} buf = {:?}", len, &buf[0..len]);

            if let Ok(request) = serde_cbor::from_slice::<EchoBotMessage>(&buf[0..len]) {
                // println!("[server] request = {:?}", request);
                len = 0;
                let iv = AesCbcIv::aes_cbc_iv(request.nonce);
                let cipher = AesCbcCipher::new(&shared_key, &iv);
                let plaintext: Vec<u8> = cipher.decrypt(&request.ciphertext).unwrap();
                // println!("[server] plaintext = {:?}", plaintext);
                // let mut rng = thread_rng();
                // let nonce: [u8; 16] = rng.gen();
                let nonce: [u8; 16] = thread_rng().gen();
                let iv = AesCbcIv::aes_cbc_iv(nonce);
                let cipher = AesCbcCipher::new(&shared_key, &iv);
                let ciphertext: Vec<u8> = cipher.encrypt(&plaintext).unwrap();
                let response = EchoBotMessage { ciphertext, nonce };
                let response_encoded = serde_cbor::to_vec(&response).unwrap();
                // println!("[server] response = {:?}", response);
                // println!("[server] response = {:?}", response_encoded);
                if let Err(e) = stream.write_all(&response_encoded).await {
                    eprintln!("failed to write to socket; err = {:?}", e);
                    return;
                }
            }
        }
    }
}

impl Drop for EchoBotServer {
    fn drop(&mut self) {
        futures::executor::block_on(self.stop());
    }
}
