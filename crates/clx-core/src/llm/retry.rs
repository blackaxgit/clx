//! Generic retry-with-backoff for transient HTTP failures.
//! Used by every LLM backend so retry semantics are identical.

use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub backoff_factor: f64,
    pub max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(250),
            backoff_factor: 2.0,
            max_delay: Duration::from_secs(10),
        }
    }
}

pub async fn with_backoff<T, E, F, Fut>(
    cfg: RetryConfig,
    mut op: F,
    is_transient: impl Fn(&E) -> bool,
    retry_after: impl Fn(&E) -> Option<Duration>,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut delay = cfg.base_delay;
    let mut attempt = 0u32;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < cfg.max_retries && is_transient(&e) => {
                let wait = retry_after(&e).unwrap_or(delay).min(cfg.max_delay);
                tokio::time::sleep(wait).await;
                delay = (delay.mul_f64(cfg.backoff_factor)).min(cfg.max_delay);
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}
