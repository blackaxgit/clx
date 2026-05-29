//! Rate limiter for LLM validation calls.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Rate limiter for LLM validation calls
#[derive(Debug)]
pub struct RateLimiter {
    window_start: Mutex<Instant>,
    request_count: AtomicU64,
    max_per_minute: u64,
}

impl RateLimiter {
    pub fn new(max_per_minute: u64) -> Self {
        Self {
            window_start: Mutex::new(Instant::now()),
            request_count: AtomicU64::new(0),
            max_per_minute,
        }
    }

    pub fn check(&self) -> bool {
        if let Ok(mut start) = self.window_start.lock() {
            let now = Instant::now();
            if now.duration_since(*start) > Duration::from_mins(1) {
                *start = now;
                self.request_count.store(0, Ordering::Relaxed);
            }
        }
        self.request_count.fetch_add(1, Ordering::Relaxed) < self.max_per_minute
    }

    /// Test-only: rewind the window start by `secs` seconds so the
    /// minute-boundary reset branch in [`Self::check`] can be exercised
    /// deterministically without sleeping for a real minute. Does not touch
    /// the request counter.
    #[cfg(test)]
    pub(crate) fn rewind_window(&self, secs: u64) {
        if let Ok(mut start) = self.window_start.lock() {
            *start -= Duration::from_secs(secs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    // Branch: when the window is older than 1 minute, `check` resets the
    // counter so requests are allowed again. Kills a mutant that drops the
    // reset (the limiter would stay saturated forever) or flips the `>`
    // comparison so the window never rolls over.
    #[test]
    fn window_reset_after_one_minute_reallows_requests() {
        let limiter = RateLimiter::new(2);

        // Saturate the window: 2 allowed, 3rd denied.
        assert!(limiter.check());
        assert!(limiter.check());
        assert!(!limiter.check(), "3rd request in the window must be denied");

        // Simulate the window aging past the 1-minute boundary.
        limiter.rewind_window(61);

        // The next check must observe the rollover, reset the counter, and
        // allow the request again.
        assert!(
            limiter.check(),
            "after the window rolls over, requests must be allowed again"
        );
    }

    // Branch: a window that is NOT yet a minute old must NOT reset.
    // Kills a mutant that resets unconditionally (would never rate-limit) and,
    // via the 59s case, any mutant that LOWERS the threshold (e.g. `> 30s`,
    // `> 45s`): at 59s+epsilon the production `> 60s` must still not reset.
    //
    // Equivalent-mutant note: the exact `> 60s` vs `>= 60s` off-by-one is NOT
    // killable by a wall-clock test - `rewind_window(60)` yields 60s+epsilon
    // from real `Instant` arithmetic, which resets under BOTH operators, and
    // exactly 60.000000s with zero epsilon is unobservable. Killing it would
    // need an injected clock; that seam is not worth adding for a rate limiter.
    #[test]
    fn window_does_not_reset_within_the_minute() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.check());
        assert!(limiter.check());

        // 30s in: well under the threshold.
        limiter.rewind_window(30);
        assert!(!limiter.check(), "30s in, the limiter must stay saturated");

        // 59s in: just under the 60s boundary. Deterministic (59s+epsilon < 60s)
        // and kills any threshold-lowered mutant.
        limiter.rewind_window(29); // total ~59s
        assert!(
            !limiter.check(),
            "59s in, still within the minute - must not reset"
        );
    }
}
