pub use crate::set04::challenge31::*;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[ignore]
    #[tokio::test]
    async fn break_hmac_sha1_with_a_slightly_less_artificial_timing_leak() {
        let rng = thread_rng();
        let key: Vec<u8> = rng
            .clone()
            .sample_iter(rand::distributions::Standard)
            .take(20)
            .collect();
        let file: String = rng
            .sample_iter(rand::distributions::Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();
        let hmac_length = 20;
        let rounds = 3;
        let delay = std::time::Duration::from_millis(1);
        let mut server = ArtificialTimingLeakServer::start(&key, hmac_length, Some(delay));
        let mut oracle = ArtificialTimingLeakOracle::new(&server, &file);
        let signature = oracle.forge(hmac_length, rounds).await.unwrap();
        assert!(oracle.check(&signature).await.unwrap());
        server.stop();
    }
}
