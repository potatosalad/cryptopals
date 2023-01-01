pub use aes::cbc::{AesCbcCipher, AesCbcIv};
pub use kex::dh::*;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use std::sync::Arc;
use tokio::sync::RwLock;

pub mod client;
pub mod protocol;
pub mod server;

pub type ManInTheMiddlePairs = Arc<RwLock<Vec<(Vec<u8>, Vec<u8>)>>>;

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

impl ManInTheMiddleServer {
    pub async fn start<A: tokio::net::ToSocketAddrs>(server_addr: A) -> tokio::io::Result<Self> {
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
                                // println!("[mitm] new client: {:?}", client_stream);
                                let messages = messages.clone();
                                tokio::spawn(async move {
                                    let server_stream =
                                        tokio::net::TcpStream::connect(server_addr).await.unwrap();
                                    Self::init(messages, client_stream, server_stream)
                                        .await
                                        .unwrap();
                                });
                            }
                            Err(e) => {
                                eprintln!("[mitm] connection failed: {:?}", e);
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

    async fn init(
        messages: ManInTheMiddlePairs,
        client_stream: tokio::net::TcpStream,
        server_stream: tokio::net::TcpStream,
    ) -> tokio::io::Result<()> {
        let mut client_stream = client_stream;
        let mut server_stream = server_stream;

        let shared_key = Self::handshake_attack(&mut client_stream, &mut server_stream).await?;
        Self::message_loop(messages, &mut client_stream, &mut server_stream, shared_key).await?;
        Ok(())
    }

    async fn handshake_attack(
        client_stream: &mut tokio::net::TcpStream,
        server_stream: &mut tokio::net::TcpStream,
    ) -> tokio::io::Result<aes::key::AesKey> {
        let mut buf = [0; 1024];
        let mut len = 0;

        loop {
            len += match client_stream.read(&mut buf[len..]).await {
                // socket closed
                Ok(n) if n == 0 => {
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
                }
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[mitm] failed to read from socket; err = {:?}", e);
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted));
                }
            };

            // println!("[mitm] {:?} buf = {:?}", len, &buf[0..len]);

            if let Ok(client_request) =
                serde_cbor::from_slice::<protocol::EchoBotHandshakeRequest>(&buf[0..len])
            {
                // println!("[mitm] client_request = {:?}", client_request);
                let base = DiffieHellmanBase::new(client_request.p, client_request.g);
                let shared_key = Self::handshake_attack_server(server_stream, &base).await?;
                let fake_response = protocol::EchoBotHandshakeResponse {
                    point_b: base.p.clone(),
                };
                let fake_response_encoded = serde_cbor::to_vec(&fake_response).unwrap();
                // println!("[mitm] fake_response = {:?}", fake_response);
                // println!("[mitm] fake_response = {:?}", fake_response_encoded);
                client_stream.write_all(&fake_response_encoded).await?;
                return Ok(shared_key);
            }
        }
    }

    async fn handshake_attack_server(
        server_stream: &mut tokio::net::TcpStream,
        base: &DiffieHellmanBase,
    ) -> tokio::io::Result<aes::key::AesKey> {
        let fake_request = protocol::EchoBotHandshakeRequest {
            p: base.p.clone(),
            g: base.g.clone(),
            point_a: base.p.clone(),
        };
        let fake_request_encoded = serde_cbor::to_vec(&fake_request).unwrap();
        server_stream.write_all(&fake_request_encoded).await?;

        let mut buf = [0; 1024];
        let mut len = 0;

        loop {
            len += match server_stream.read(&mut buf[len..]).await {
                // socket closed
                Ok(n) if n == 0 => {
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
                }
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[mitm] failed to read from socket; err = {:?}", e);
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted));
                }
            };

            // println!("[mitm] {:?} buf = {:?}", len, &buf[0..len]);

            if let Ok(_response) =
                serde_cbor::from_slice::<protocol::EchoBotHandshakeResponse>(&buf[0..len])
            {
                // println!("[mitm] response = {:?}", response);
                let shared_secret = DiffieHellmanSharedSecret::new(
                    base.clone(),
                    BigUint::from_str_radix("0", 10).unwrap(),
                );
                let shared_key = aes::key::AesKey::try_copy_from_slice(
                    &hash::sha1::hash(&shared_secret.shared_secret.to_bytes_be()).bytes()[0..16],
                )
                .unwrap();
                return Ok(shared_key);
            }
        }
    }

    async fn message_loop(
        messages: ManInTheMiddlePairs,
        client_stream: &mut tokio::net::TcpStream,
        server_stream: &mut tokio::net::TcpStream,
        shared_key: aes::key::AesKey,
    ) -> tokio::io::Result<()> {
        let mut buf = [0; 1024];
        let mut len = 0;

        loop {
            len += match client_stream.read(&mut buf[len..]).await {
                // socket closed
                Ok(n) if n == 0 => {
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
                }
                Ok(n) => n,
                Err(e) => {
                    eprintln!("failed to read from socket; err = {:?}", e);
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted));
                }
            };

            // println!("[mitm] {:?} buf = {:?}", len, &buf[0..len]);

            if let Ok(client_request) =
                serde_cbor::from_slice::<protocol::EchoBotMessage>(&buf[0..len])
            {
                // println!("[mitm] client_request = {:?}", client_request);
                // len = 0;
                let iv = AesCbcIv::aes_cbc_iv(client_request.nonce);
                let cipher = AesCbcCipher::new(&shared_key, &iv);
                let client_plaintext: Vec<u8> = cipher.decrypt(&client_request.ciphertext).unwrap();
                // println!("[mitm] client plaintext = {:?}", client_plaintext);
                server_stream.write_all(&buf[0..len]).await?;
                len = 0;
                loop {
                    len += match server_stream.read(&mut buf[len..]).await {
                        // socket closed
                        Ok(n) if n == 0 => {
                            return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
                        }
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("failed to read from socket; err = {:?}", e);
                            return Err(std::io::Error::from(
                                std::io::ErrorKind::ConnectionAborted,
                            ));
                        }
                    };

                    if let Ok(server_response) =
                        serde_cbor::from_slice::<protocol::EchoBotMessage>(&buf[0..len])
                    {
                        // println!("[mitm] server_response = {:?}", server_response);
                        // len = 0;
                        let iv = AesCbcIv::aes_cbc_iv(server_response.nonce);
                        let cipher = AesCbcCipher::new(&shared_key, &iv);
                        let server_plaintext: Vec<u8> =
                            cipher.decrypt(&server_response.ciphertext).unwrap();
                        // println!("[mitm] server plaintext = {:?}", server_plaintext);
                        client_stream.write_all(&buf[0..len]).await?;
                        let mut msgs = messages.write().await;
                        msgs.push((client_plaintext, server_plaintext));
                        len = 0;
                        break;
                    }
                }
            }
        }
    }
}

impl Drop for ManInTheMiddleServer {
    fn drop(&mut self) {
        futures::executor::block_on(self.stop());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[tokio::test]
    async fn implement_a_mitm_key_fixing_attack_on_diffie_hellman_with_parameter_injection() {
        let base = DiffieHellmanBase::new(
            BigUint::from_str_radix("37", 10).unwrap(),
            BigUint::from_str_radix("5", 10).unwrap(),
        );
        // let base = DiffieHellmanBase::new(
        //     BigUint::from_str_radix(
        //         "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        //          e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        //          3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        //          6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        //          24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        //          c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        //          bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        //          fffffffffffff",
        //         16,
        //     )
        //     .unwrap(),
        //     BigUint::from_str_radix("2", 16).unwrap(),
        // );
        let secret_key = base.gen_secret_key();
        let mut real_server = server::EchoBotServer::start().await.unwrap();
        let mut mitm_server =
            ManInTheMiddleServer::start(format!("127.0.0.1:{}", real_server.get_port()))
                .await
                .unwrap();
        let mut client = client::EchoBotClient::connect(
            secret_key,
            format!("127.0.0.1:{}", mitm_server.get_port()),
        )
        .await
        .unwrap();
        let mut request: Vec<u8> = vec![0; 64];
        thread_rng().fill_bytes(&mut request[..]);
        let response: Vec<u8> = client.echo(&request).await.unwrap();
        assert_eq!(request, response);
        let captured_request: Vec<u8>;
        let captured_response: Vec<u8>;
        {
            let msgs = mitm_server.messages.read().await;
            captured_request = (*msgs)[0].0.clone();
            captured_response = (*msgs)[0].1.clone();
        }
        assert_eq!(captured_request, request);
        assert_eq!(captured_response, response);
        mitm_server.stop().await;
        real_server.stop().await;
    }
}
