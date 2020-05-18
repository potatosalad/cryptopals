use async_trait::async_trait;
use hash::fixed_hash::{FixedHashContext, FixedHashOutput};
use mac::hmac::HmacSha1Context;
pub use oracles::timing_leak_oracle::{TimingLeakOracle, TimingLeakResult};
use warp::Filter;

pub async fn insecure_compare<A: ?Sized + AsRef<[u8]>, B: ?Sized + AsRef<[u8]>>(
    a: &A,
    b: &B,
    delay: Option<std::time::Duration>,
) -> bool {
    let a = a.as_ref();
    let b = b.as_ref();
    if a.len() != b.len() {
        false
    } else {
        for i in 0..a.len() {
            if a[i] != b[i] {
                return false;
            }
            if let Some(delay) = delay {
                tokio::time::delay_for(delay).await;
            }
        }
        true
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct ArtificialTimingLeakParams {
    pub file: String,
    pub signature: String,
}

#[derive(Clone)]
pub struct ArtificialTimingContext {
    hmac_context: HmacSha1Context,
    hmac_length: usize,
    delay: Option<std::time::Duration>,
}

#[derive(Debug)]
pub struct ArtificialTimingRuntime {
    join_handle: std::thread::JoinHandle<()>,
    terminator: tokio::sync::oneshot::Sender<()>,
}

#[derive(Debug)]
pub struct ArtificialTimingLeakServer {
    address: std::net::SocketAddr,
    runtime: Option<ArtificialTimingRuntime>,
}

impl ArtificialTimingLeakServer {
    pub fn start<K: ?Sized + AsRef<[u8]>>(
        key: &K,
        hmac_length: usize,
        delay: Option<std::time::Duration>,
    ) -> Self {
        let hmac_context = HmacSha1Context::new(key).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let routes = warp::get()
            .and(warp::path("test"))
            .and(warp::query())
            .and(Self::with_context(hmac_context, hmac_length, delay))
            .and_then(Self::handle);
        let (addr, server) =
            warp::serve(routes).bind_with_graceful_shutdown(([0, 0, 0, 0], 0), async {
                rx.await.ok();
            });
        let join_handle = std::thread::spawn(move || {
            let mut rt = tokio::runtime::Builder::new()
                .threaded_scheduler()
                .core_threads(1)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(server);
        });
        Self {
            address: addr,
            runtime: Some(ArtificialTimingRuntime {
                join_handle,
                terminator: tx,
            }),
        }
    }

    pub fn stop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.terminator.send(()).unwrap();
            rt.join_handle.join().unwrap();
        }
    }

    pub fn get_port(&self) -> u16 {
        self.address.port()
    }

    fn with_context(
        hmac_context: HmacSha1Context,
        hmac_length: usize,
        delay: Option<std::time::Duration>,
    ) -> impl Filter<Extract = (ArtificialTimingContext,), Error = std::convert::Infallible> + Clone
    {
        let context = ArtificialTimingContext {
            hmac_context,
            hmac_length,
            delay,
        };
        warp::any().map(move || context.clone())
    }

    async fn handle(
        params: ArtificialTimingLeakParams,
        context: ArtificialTimingContext,
    ) -> Result<impl warp::Reply, std::convert::Infallible> {
        let mut hmac_context = context.hmac_context;
        hmac_context.update(&params.file).unwrap();
        let mut challenge = hmac_context.output().unwrap().to_hex();
        challenge.truncate(context.hmac_length * 2);
        if insecure_compare(&params.signature, &challenge, context.delay).await {
            Ok(warp::http::StatusCode::OK)
        } else {
            Ok(warp::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

impl Drop for ArtificialTimingLeakServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Debug)]
pub struct ArtificialTimingLeakOracle {
    client: reqwest::Client,
    endpoint: reqwest::Url,
}

impl ArtificialTimingLeakOracle {
    pub fn new(server: &ArtificialTimingLeakServer, file: &str) -> Self {
        let mut endpoint = reqwest::Url::parse("http://127.0.0.1/test").unwrap();
        endpoint.set_port(Some(server.get_port())).unwrap();
        endpoint.query_pairs_mut().append_pair("file", file);
        let client = reqwest::Client::new();
        Self { client, endpoint }
    }
}

#[async_trait]
impl TimingLeakOracle for ArtificialTimingLeakOracle {
    async fn check<T: ?Sized + AsRef<[u8]> + Sync>(&mut self, input: &T) -> TimingLeakResult<bool> {
        let signature = hex::encode(input);
        let mut endpoint = self.endpoint.clone();
        endpoint
            .query_pairs_mut()
            .append_pair("signature", &signature);

        let response = self.client.get(endpoint).send().await?;
        Ok(response.status() == 200)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[ignore]
    #[tokio::test]
    async fn implement_and_break_hmac_sha1_with_an_artificial_timing_leak() {
        let rng = thread_rng();
        let key: Vec<u8> = rng
            .sample_iter(rand::distributions::Standard)
            .take(20)
            .collect();
        let file: String = rng
            .sample_iter(rand::distributions::Alphanumeric)
            .take(20)
            .collect();
        let hmac_length = 20;
        let rounds = 3;
        let delay = std::time::Duration::from_millis(50);
        let mut server = ArtificialTimingLeakServer::start(&key, hmac_length, Some(delay));
        let mut oracle = ArtificialTimingLeakOracle::new(&server, &file);
        let signature = oracle.forge(hmac_length, rounds).await.unwrap();
        assert!(oracle.check(&signature).await.unwrap());
        server.stop();
    }
}
