use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Adaptive rate limiter that slows down on 429/403 responses.
pub struct AdaptiveRateLimiter {
    current_delay_ms: AtomicU64,
    max_delay_ms: u64,
    min_delay_ms: u64,
    backoff_factor: f64,
    last_backoff: std::sync::Mutex<Option<Instant>>,
}

impl AdaptiveRateLimiter {
    pub fn new() -> Self {
        Self {
            current_delay_ms: AtomicU64::new(200),
            max_delay_ms: 30_000,  // 30 seconds max
            min_delay_ms: 50,      // 50ms minimum
            backoff_factor: 2.0,
            last_backoff: std::sync::Mutex::new(None),
        }
    }

    pub fn new_with(min_ms: u64, max_ms: u64) -> Self {
        Self {
            current_delay_ms: AtomicU64::new(min_ms),
            max_delay_ms: max_ms,
            min_delay_ms: min_ms,
            backoff_factor: 2.0,
            last_backoff: std::sync::Mutex::new(None),
        }
    }

    /// Report a successful request — gradually reduce delay.
    pub fn report_success(&self) {
        let current = self.current_delay_ms.load(Ordering::Relaxed);
        if current > self.min_delay_ms {
            let new = (current as f64 * 0.9).max(self.min_delay_ms as f64) as u64;
            self.current_delay_ms.store(new, Ordering::Relaxed);
        }
    }

    /// Report a rate-limited response — apply exponential backoff.
    pub fn report_rate_limited(&self) {
        let current = self.current_delay_ms.load(Ordering::Relaxed);
        let new = ((current as f64 * self.backoff_factor) as u64).min(self.max_delay_ms);
        self.current_delay_ms.store(new, Ordering::Relaxed);
        if let Ok(mut last) = self.last_backoff.lock() {
            *last = Some(Instant::now());
        }
    }

    /// Get current delay in milliseconds.
    pub fn delay_ms(&self) -> u64 {
        self.current_delay_ms.load(Ordering::Relaxed)
    }

    /// Check if we should wait before the next request.
    pub async fn wait_if_needed(&self) {
        let delay = self.delay_ms();
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }

    /// Reset to minimum delay.
    pub fn reset(&self) {
        self.current_delay_ms.store(self.min_delay_ms, Ordering::Relaxed);
    }

    /// Time since last backoff.
    pub fn time_since_backoff(&self) -> Option<Duration> {
        self.last_backoff.lock().ok().and_then(|lock| lock.map(|i| i.elapsed()))
    }
}

impl Default for AdaptiveRateLimiter { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_delay() {
        let limiter = AdaptiveRateLimiter::new();
        assert_eq!(limiter.delay_ms(), 200);
    }

    #[test]
    fn test_backoff_increases() {
        let limiter = AdaptiveRateLimiter::new();
        limiter.report_rate_limited();
        assert!(limiter.delay_ms() > 200);
    }

    #[test]
    fn test_success_decreases() {
        let limiter = AdaptiveRateLimiter::new();
        limiter.report_rate_limited();
        let after_backoff = limiter.delay_ms();
        limiter.report_success();
        assert!(limiter.delay_ms() < after_backoff);
    }

    #[test]
    fn test_reset() {
        let limiter = AdaptiveRateLimiter::new();
        limiter.report_rate_limited();
        limiter.reset();
        assert_eq!(limiter.delay_ms(), 50);
    }
}
