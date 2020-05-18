use async_trait::async_trait;

pub type TimingLeakResult<T> =
    std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[async_trait]
pub trait TimingLeakOracle: Clone + std::fmt::Debug + Send + Sync {
    async fn check<T: ?Sized + AsRef<[u8]> + Send + Sync>(
        &mut self,
        input: &T,
    ) -> TimingLeakResult<bool>;

    async fn forge(&self, input_length: usize, rounds: usize) -> TimingLeakResult<Vec<u8>> {
        let mut forgery = TimingLeakForgery::new(self.clone(), input_length, rounds);
        let mut input: Vec<u8> = Vec::with_capacity(input_length);
        while let Some(candidate) = forgery.stream_guess_next().await? {
            input.push(candidate);
        }
        Ok(input)
    }
}

#[derive(Clone, Debug)]
pub struct TimingLeakForgery<O> {
    oracle: O,
    input: Vec<u8>,
    input_offset: usize,
    input_length: usize,
    rounds: usize,
}

impl<O: TimingLeakOracle> TimingLeakForgery<O> {
    pub fn new(oracle: O, input_length: usize, rounds: usize) -> Self {
        Self {
            oracle,
            input: vec![0; input_length],
            input_offset: 0,
            input_length,
            rounds,
        }
    }

    pub async fn stream_guess_next(&mut self) -> TimingLeakResult<Option<u8>> {
        fn t_statistic(n: f32, (mu_u, sd_u): (f32, f32), (mu_v, sd_v): (f32, f32)) -> f32 {
            let m = n;
            let var = (sd_u + sd_v) / (n + m - 2_f32);
            (n * m / (n + m)).sqrt() * (mu_u - mu_v) / var.sqrt()
        }
        if self.input_offset < self.input_length {
            let mut best_candidate: u8 = 0_u8;
            let mut best_stat: (f32, f32) = (0_f32, 0_f32);
            for candidate in 0_u8..=255_u8 {
                self.input[self.input_offset] = candidate;
                let stat = self.measure_timing_performance().await?;
                let t = t_statistic(self.rounds as f32, best_stat, stat);
                if t < -2_f32 {
                    best_candidate = candidate;
                    best_stat = stat;
                }
            }
            self.input[self.input_offset] = best_candidate;
            self.input_offset += 1;
            Ok(Some(best_candidate))
        } else {
            Ok(None)
        }
    }

    async fn measure_timing_performance(&mut self) -> TimingLeakResult<(f32, f32)> {
        fn mean(u: &[f32]) -> f32 {
            let n = u.len() as f32;
            u.iter().fold(0f32, |a, b| a + b) / n
        }
        fn squared_deviation(u: &[f32], mu: f32) -> f32 {
            u.iter().fold(0f32, |a, b| a + (b - mu).powi(2))
        }
        let mut measurements: Vec<f32> = Vec::with_capacity(self.rounds);
        loop {
            let now = std::time::Instant::now();
            self.oracle.check(self.input.as_slice()).await?;
            let elapsed_time = now.elapsed();
            let elapsed_micros = (elapsed_time.as_secs() as f32) * 1_000_000.0
                + (elapsed_time.subsec_nanos() as f32) / 1_000.0;
            measurements.push(elapsed_micros);
            if measurements.len() >= self.rounds {
                break;
            }
        }
        let mu = mean(&measurements);
        let sd = squared_deviation(&measurements, mu);
        Ok((mu, sd))
    }
}
