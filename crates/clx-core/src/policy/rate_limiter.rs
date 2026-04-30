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
}
