//! Generic retry-with-backoff for transient HTTP failures.
//! Used by every LLM backend so retry semantics are identical.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
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

#[cfg(test)]
#[allow(clippy::ignored_unit_patterns)] // closures take &() (the test error type); |_| is clearest
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Fixed config with deterministic backoff. `tokio::time::pause`
    /// (`start_paused`) makes the `sleep` calls advance virtual time
    /// instantly so the tests run without real wall-clock delays and stay
    /// hermetic.
    fn cfg(max_retries: u32) -> RetryConfig {
        RetryConfig {
            max_retries,
            base_delay: Duration::from_millis(100),
            backoff_factor: 2.0,
            max_delay: Duration::from_secs(10),
        }
    }

    // Branch: Ok(v) on first attempt -> never retries, op called exactly once.
    // Kills a mutant that always enters the retry arm or starts `attempt` at 1.
    #[tokio::test(start_paused = true)]
    async fn returns_immediately_on_first_success() {
        let calls = Cell::new(0u32);
        let r: Result<&str, ()> = with_backoff(
            cfg(3),
            || {
                calls.set(calls.get() + 1);
                async { Ok("ok") }
            },
            |_| true,
            |_| None,
        )
        .await;
        assert_eq!(r, Ok("ok"));
        assert_eq!(calls.get(), 1, "success must not trigger any retry");
    }

    // Branch: transient error retried until it eventually succeeds.
    // Kills a mutant that returns Err on the first transient failure
    // (i.e. drops the `attempt < max_retries && is_transient` guard arm).
    #[tokio::test(start_paused = true)]
    async fn retries_transient_then_succeeds() {
        let calls = Cell::new(0u32);
        let r: Result<u32, &str> = with_backoff(
            cfg(3),
            || {
                let n = calls.get() + 1;
                calls.set(n);
                async move { if n < 3 { Err("transient") } else { Ok(n) } }
            },
            |_| true,
            |_| None,
        )
        .await;
        assert_eq!(r, Ok(3));
        assert_eq!(
            calls.get(),
            3,
            "should retry twice then succeed on 3rd call"
        );
    }

    // Branch: non-transient error returns immediately (is_transient == false).
    // Kills a mutant that treats every error as transient.
    #[tokio::test(start_paused = true)]
    async fn terminal_error_is_not_retried() {
        let calls = Cell::new(0u32);
        let r: Result<(), &str> = with_backoff(
            cfg(5),
            || {
                calls.set(calls.get() + 1);
                async { Err("fatal") }
            },
            |_| false, // never transient
            |_| None,
        )
        .await;
        assert_eq!(r, Err("fatal"));
        assert_eq!(calls.get(), 1, "non-transient error must not be retried");
    }

    // Branch: transient error that never recovers is retried exactly
    // `max_retries` times then surfaces the final error.
    // Kills a mutant that retries forever (drops `attempt < max_retries`)
    // or one that uses `<=` (off-by-one => one extra call).
    #[tokio::test(start_paused = true)]
    async fn exhausts_max_retries_then_returns_last_error() {
        let calls = Cell::new(0u32);
        let r: Result<(), &str> = with_backoff(
            cfg(2),
            || {
                calls.set(calls.get() + 1);
                async { Err("still-transient") }
            },
            |_| true,
            |_| None,
        )
        .await;
        assert_eq!(r, Err("still-transient"));
        // 1 initial attempt + 2 retries = 3 total calls.
        assert_eq!(
            calls.get(),
            3,
            "max_retries=2 means exactly 3 total attempts"
        );
    }

    // Branch: max_retries == 0 -> a transient error is returned without any
    // retry. Kills a mutant that retries at least once regardless of config.
    #[tokio::test(start_paused = true)]
    async fn zero_max_retries_never_retries() {
        let calls = Cell::new(0u32);
        let r: Result<(), &str> = with_backoff(
            cfg(0),
            || {
                calls.set(calls.get() + 1);
                async { Err("transient") }
            },
            |_| true,
            |_| None,
        )
        .await;
        assert_eq!(r, Err("transient"));
        assert_eq!(calls.get(), 1, "max_retries=0 must mean a single attempt");
    }

    // Branch: `retry_after` override is honored over the computed backoff and
    // is capped at `max_delay`. Asserts elapsed virtual time equals the capped
    // value rather than the exponential schedule.
    // Kills a mutant that ignores `retry_after` (would wait base_delay=100ms)
    // or one that drops the `.min(cfg.max_delay)` cap.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::duration_suboptimal_units)]
    async fn retry_after_override_is_capped_at_max_delay() {
        let calls = Cell::new(0u32);
        let start = tokio::time::Instant::now();
        // retry_after asks for 60s but max_delay is 10s -> must wait 10s.
        let r: Result<u32, &str> = with_backoff(
            cfg(1),
            || {
                let n = calls.get() + 1;
                calls.set(n);
                async move { if n == 1 { Err("transient") } else { Ok(n) } }
            },
            |_| true,
            |_| Some(Duration::from_secs(60)),
        )
        .await;
        assert_eq!(r, Ok(2));
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(10),
            "retry_after must be capped at max_delay (10s), not base_delay or raw 60s"
        );
    }

    // Branch: with no retry_after, the backoff wait equals base_delay on the
    // first retry. Kills a mutant that skips the sleep entirely (waited == 0)
    // or starts from a different base.
    #[tokio::test(start_paused = true)]
    async fn first_backoff_wait_uses_base_delay() {
        let calls = Cell::new(0u32);
        let start = tokio::time::Instant::now();
        let r: Result<u32, &str> = with_backoff(
            cfg(1),
            || {
                let n = calls.get() + 1;
                calls.set(n);
                async move { if n == 1 { Err("transient") } else { Ok(n) } }
            },
            |_| true,
            |_| None,
        )
        .await;
        assert_eq!(r, Ok(2));
        assert_eq!(
            start.elapsed(),
            Duration::from_millis(100),
            "first retry must wait exactly base_delay (100ms)"
        );
    }

    // Default config sanity: documents the production retry budget so a
    // mutant that flips a default (e.g. max_retries 3 -> 0) is caught.
    #[test]
    fn default_config_matches_documented_budget() {
        let d = RetryConfig::default();
        assert_eq!(d.max_retries, 3);
        assert_eq!(d.base_delay, Duration::from_millis(250));
        assert!((d.backoff_factor - 2.0).abs() < f64::EPSILON);
        assert_eq!(d.max_delay, Duration::from_secs(10));
    }
}
