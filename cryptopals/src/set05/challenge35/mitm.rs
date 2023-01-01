use aes::cbc::{AesCbcCipher, AesCbcIv};
use kex::dh::*;

use tokio::net::TcpListener;

use super::protocol::*;

use std::sync::Arc;
use tokio::sync::RwLock;

pub type ManInTheMiddlePairs = Arc<RwLock<Vec<(Vec<u8>, Vec<u8>)>>>;

#[derive(Clone, Copy, Debug)]
pub enum ManInTheMiddleKind {
    GroupEqualsOne,
    GroupEqualsPrime,
    GroupEqualsPrimeMinusOne,
}

#[derive(Debug)]
pub struct ManInTheMiddleRuntime {
    join_handle: tokio::task::JoinHandle<()>,
    terminator: tokio::sync::oneshot::Sender<()>,
}

#[derive(Debug)]
pub struct ManInTheMiddleServer {
    address: std::net::SocketAddr,
    runtime: Option<ManInTheMiddleRuntime>,
    messages: ManInTheMiddlePairs,
}

#[derive(Debug)]
struct ManInTheMiddleInit {
    kind: ManInTheMiddleKind,
    messages: ManInTheMiddlePairs,
    client_stream: tokio::net::TcpStream,
    server_stream: tokio::net::TcpStream,
}

#[derive(Debug)]
struct ManInTheMiddleAcknowledged {
    kind: ManInTheMiddleKind,
    messages: ManInTheMiddlePairs,
    client_stream: tokio::net::TcpStream,
    server_stream: tokio::net::TcpStream,
    base: DiffieHellmanBase,
}

#[derive(Debug)]
struct ManInTheMiddleReady {
    kind: ManInTheMiddleKind,
    messages: ManInTheMiddlePairs,
    client_stream: tokio::net::TcpStream,
    server_stream: tokio::net::TcpStream,
    shared_key: aes::key::AesKey,
}

impl ManInTheMiddleInit {
    fn new(
        kind: ManInTheMiddleKind,
        messages: ManInTheMiddlePairs,
        client_stream: tokio::net::TcpStream,
        server_stream: tokio::net::TcpStream,
    ) -> Self {
        Self {
            kind,
            messages,
            client_stream,
            server_stream,
        }
    }

    async fn run(mut self) -> tokio::io::Result<()> {
        use num_traits::CheckedSub;
        let request = read_once::<EchoBotHandshakeNegotiate>(&mut self.client_stream).await?;
        let base = match self.kind {
            ManInTheMiddleKind::GroupEqualsOne => {
                DiffieHellmanBase::new(request.p, BigUint::from_str_radix("1", 10).unwrap())
            }
            ManInTheMiddleKind::GroupEqualsPrime => {
                DiffieHellmanBase::new(request.p.clone(), request.p)
            }
            ManInTheMiddleKind::GroupEqualsPrimeMinusOne => DiffieHellmanBase::new(
                request.p.clone(),
                request
                    .p
                    .checked_sub(&BigUint::from_str_radix("1", 10).unwrap())
                    .unwrap(),
            ),
        };
        write_once(
            &mut self.server_stream,
            EchoBotHandshakeNegotiate {
                p: base.p.clone(),
                g: base.g.clone(),
            },
        )
        .await?;
        let response = read_once::<EchoBotHandshakeAccept>(&mut self.server_stream).await?;
        write_once(&mut self.client_stream, response).await?;
        ManInTheMiddleAcknowledged::new(self, base).run().await
    }
}

impl ManInTheMiddleAcknowledged {
    fn new(state: ManInTheMiddleInit, base: DiffieHellmanBase) -> Self {
        Self {
            kind: state.kind,
            messages: state.messages,
            client_stream: state.client_stream,
            server_stream: state.server_stream,
            base,
        }
    }

    async fn run(mut self) -> tokio::io::Result<()> {
        let _request = read_once::<EchoBotHandshakeRequest>(&mut self.client_stream).await?;
        // let a_public_key = DiffieHellmanPublicKey::new(self.base.clone(), request.point_a);
        let shared_secret = match self.kind {
            ManInTheMiddleKind::GroupEqualsOne => BigUint::from_str_radix("0", 10).unwrap(),
            ManInTheMiddleKind::GroupEqualsPrime => BigUint::from_str_radix("0", 10).unwrap(),
            ManInTheMiddleKind::GroupEqualsPrimeMinusOne => {
                BigUint::from_str_radix("0", 10).unwrap()
            }
        };
        // println!(
        //     "[mitm] shared_secret.to_bytes_be() = {:?}",
        //     shared_secret.to_bytes_be()
        // );
        let shared_key = aes::key::AesKey::try_copy_from_slice(
            &hash::sha1::hash(&shared_secret.to_bytes_be()).bytes()[0..16],
        )
        .unwrap();
        write_once(
            &mut self.server_stream,
            EchoBotHandshakeRequest {
                point_a: self.base.p.clone(),
            },
        )
        .await?;
        let _response = read_once::<EchoBotHandshakeResponse>(&mut self.server_stream).await?;
        // let b_public_key = DiffieHellmanPublicKey::new(self.base.clone(), response.point_b);
        // println!("[miitm] b_public_key = {:?}", b_public_key);
        write_once(
            &mut self.client_stream,
            EchoBotHandshakeResponse {
                point_b: self.base.p.clone(),
            },
        )
        .await?;
        ManInTheMiddleReady::new(self, shared_key).run().await
    }
}

impl ManInTheMiddleReady {
    fn new(state: ManInTheMiddleAcknowledged, shared_key: aes::key::AesKey) -> Self {
        Self {
            kind: state.kind,
            messages: state.messages,
            client_stream: state.client_stream,
            server_stream: state.server_stream,
            shared_key,
        }
    }

    async fn run(mut self) -> tokio::io::Result<()> {
        loop {
            let request = read_once::<EchoBotMessage>(&mut self.client_stream).await?;
            let iv = AesCbcIv::aes_cbc_iv(request.nonce);
            let cipher = AesCbcCipher::new(&self.shared_key, &iv);
            let client_plaintext: Vec<u8> = cipher.decrypt(&request.ciphertext).unwrap();
            write_once(&mut self.server_stream, request).await?;
            let response = read_once::<EchoBotMessage>(&mut self.server_stream).await?;
            let iv = AesCbcIv::aes_cbc_iv(response.nonce);
            let cipher = AesCbcCipher::new(&self.shared_key, &iv);
            let server_plaintext: Vec<u8> = cipher.decrypt(&response.ciphertext).unwrap();
            let mut msgs = self.messages.write().await;
            msgs.push((client_plaintext, server_plaintext));
            write_once(&mut self.client_stream, response).await?;
        }
    }
}

impl ManInTheMiddleServer {
    pub async fn start<A: tokio::net::ToSocketAddrs>(
        kind: ManInTheMiddleKind,
        server_addr: A,
    ) -> tokio::io::Result<Self> {
        let messages: ManInTheMiddlePairs = Arc::new(RwLock::new(Vec::new()));
        let msgs = messages.clone();
        let server_addr = tokio::net::lookup_host(server_addr).await?.next().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let join_handle = tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    loop {
                        match listener.accept().await {
                            Ok((client_stream, _)) => {
                                // println!("[server] new client: {:?}", client_stream);
                                let messages = messages.clone();
                                tokio::spawn(async move {
                                    let server_stream =
                                        tokio::net::TcpStream::connect(server_addr).await.unwrap();
                                    ManInTheMiddleInit::new(kind, messages, client_stream, server_stream)
                                        .run()
                                        .await
                                        .unwrap();
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
            runtime: Some(ManInTheMiddleRuntime {
                join_handle,
                terminator: tx,
            }),
            messages: msgs,
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

    pub async fn get_captured_pairs(&self) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> {
        let msgs = self.messages.read().await;
        msgs.clone().into_iter()
    }
}

impl Drop for ManInTheMiddleServer {
    fn drop(&mut self) {
        futures::executor::block_on(self.stop());
    }
}
