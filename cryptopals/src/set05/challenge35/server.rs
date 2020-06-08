use aes::cbc::{AesCbcCipher, AesCbcIv};
use kex::dh::*;

use futures::stream::StreamExt;
use rand::prelude::*;
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

#[derive(Debug)]
struct EchoBotStateInit {
    stream: tokio::net::TcpStream,
}

#[derive(Debug)]
struct EchoBotStateAcknowledged {
    stream: tokio::net::TcpStream,
    base: DiffieHellmanBase,
}

#[derive(Debug)]
struct EchoBotStateReady {
    stream: tokio::net::TcpStream,
    shared_key: aes::key::AesKey,
}

impl EchoBotStateInit {
    fn new(stream: tokio::net::TcpStream) -> Self {
        Self { stream }
    }

    async fn run(mut self) -> tokio::io::Result<()> {
        let request = read_once::<EchoBotHandshakeNegotiate>(&mut self.stream).await?;
        let base = DiffieHellmanBase::new(request.p, request.g);
        write_once(&mut self.stream, EchoBotHandshakeAccept {}).await?;
        EchoBotStateAcknowledged::new(self, base).run().await
    }
}

impl EchoBotStateAcknowledged {
    fn new(state: EchoBotStateInit, base: DiffieHellmanBase) -> Self {
        Self {
            stream: state.stream,
            base,
        }
    }

    async fn run(mut self) -> tokio::io::Result<()> {
        let request = read_once::<EchoBotHandshakeRequest>(&mut self.stream).await?;
        let a_public_key = DiffieHellmanPublicKey::new(self.base.clone(), request.point_a);
        let b_secret_key = self.base.gen_secret_key();
        let b_public_key = b_secret_key.to_public_key();
        let b_shared_secret = b_secret_key.compute_shared_secret(&a_public_key).unwrap();
        // println!(
        //     "[server] shared_secret.to_bytes_be() = {:?}",
        //     b_shared_secret.shared_secret.to_bytes_be()
        // );
        let shared_key = aes::key::AesKey::try_copy_from_slice(
            &hash::sha1::hash(&b_shared_secret.shared_secret.to_bytes_be()).bytes()[0..16],
        )
        .unwrap();
        write_once(
            &mut self.stream,
            EchoBotHandshakeResponse {
                point_b: b_public_key.public.clone(),
            },
        )
        .await?;
        EchoBotStateReady::new(self, shared_key).run().await
    }
}

impl EchoBotStateReady {
    fn new(state: EchoBotStateAcknowledged, shared_key: aes::key::AesKey) -> Self {
        Self {
            stream: state.stream,
            shared_key,
        }
    }

    async fn run(mut self) -> tokio::io::Result<()> {
        loop {
            let request = read_once::<EchoBotMessage>(&mut self.stream).await?;
            let iv = AesCbcIv::aes_cbc_iv(request.nonce);
            let cipher = AesCbcCipher::new(&self.shared_key, &iv);
            let plaintext: Vec<u8> = cipher.decrypt(&request.ciphertext).unwrap();
            let nonce: [u8; 16] = thread_rng().gen();
            let iv = AesCbcIv::aes_cbc_iv(nonce);
            let cipher = AesCbcCipher::new(&self.shared_key, &iv);
            let ciphertext: Vec<u8> = cipher.encrypt(&plaintext).unwrap();
            write_once(&mut self.stream, EchoBotMessage { ciphertext, nonce }).await?;
        }
    }
}

impl EchoBotServer {
    pub async fn start() -> tokio::io::Result<Self> {
        let mut listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let join_handle = tokio::spawn(async move {
            let mut incoming = listener.incoming().take_until(rx);
            while let Some(stream) = incoming.next().await {
                match stream {
                    Ok(stream) => {
                        // println!("[server] new client: {:?}", stream);
                        tokio::spawn(async {
                            EchoBotStateInit::new(stream).run().await.unwrap();
                        });
                    }
                    Err(e) => {
                        eprintln!("connection failed: {:?}", e);
                    }
                }
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
}

impl Drop for EchoBotServer {
    fn drop(&mut self) {
        futures::executor::block_on(self.stop());
    }
}
