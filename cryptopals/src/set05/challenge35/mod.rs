pub use aes::cbc::{AesCbcCipher, AesCbcIv};
pub use kex::dh::*;

pub mod client;
pub mod mitm;
pub mod protocol;
pub mod server;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[tokio::test]
    async fn implement_dh_with_negotiated_groups_group_equals_one() {
        implement_dh_with_negotiated_groups(mitm::ManInTheMiddleKind::GroupEqualsOne).await;
    }

    #[tokio::test]
    async fn implement_dh_with_negotiated_groups_group_equals_prime() {
        implement_dh_with_negotiated_groups(mitm::ManInTheMiddleKind::GroupEqualsPrime).await;
    }

    #[tokio::test]
    async fn implement_dh_with_negotiated_groups_group_equals_prime_minus_one() {
        implement_dh_with_negotiated_groups(mitm::ManInTheMiddleKind::GroupEqualsPrimeMinusOne)
            .await;
    }

    async fn implement_dh_with_negotiated_groups(kind: mitm::ManInTheMiddleKind) {
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
        let mut mitm_server = mitm::ManInTheMiddleServer::start(
            kind,
            format!("127.0.0.1:{}", real_server.get_port()),
        )
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
        let (captured_request, captured_response) =
            mitm_server.get_captured_pairs().await.next().unwrap();
        mitm_server.stop().await;
        real_server.stop().await;
        assert_eq!(request, response);
        assert_eq!(captured_request, request);
        assert_eq!(captured_response, response);
    }
}
