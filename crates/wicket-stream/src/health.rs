//! Passive health tracking for stream proxy backends.
//!
//! Tracks connect outcomes per backend using lock-free atomics.
//! No active probes — state is updated from real connection attempts.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Per-backend health state, lock-free.
#[derive(Debug)]
pub struct BackendHealth {
    label: String,
    healthy: AtomicBool,
    /// Unix timestamp (millis) when marked unhealthy. 0 = never.
    unhealthy_since: AtomicU64,
    /// Consecutive failure count.
    consecutive_failures: AtomicU64,
}

impl BackendHealth {
    /// Create a new health tracker for the given backend label.
    ///
    /// Starts in a healthy state with zero consecutive failures.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            healthy: AtomicBool::new(true),
            unhealthy_since: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
        }
    }

    /// Return the backend label being tracked.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return whether the backend is currently considered healthy.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Check if enough time has passed for this backend to be retried.
    pub fn is_eligible(&self, cooldown: Duration) -> bool {
        if self.is_healthy() {
            return true;
        }
        let since = self.unhealthy_since.load(Ordering::Acquire);
        if since == 0 {
            return true;
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now_ms.saturating_sub(since) >= cooldown.as_millis() as u64
    }

    /// Record a successful connect — mark healthy, reset failure count.
    pub fn record_success(&self) {
        let was_healthy = self.healthy.swap(true, Ordering::Release);
        self.consecutive_failures.store(0, Ordering::Release);
        self.unhealthy_since.store(0, Ordering::Release);
        if !was_healthy {
            tracing::info!(
                backend = %self.label,
                "Backend recovered"
            );
        }
    }

    /// Record a failed connect — mark unhealthy, bump failure count.
    pub fn record_failure(&self) {
        let was_healthy = self.healthy.swap(false, Ordering::Release);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        if was_healthy {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            self.unhealthy_since.store(now_ms, Ordering::Release);
            tracing::warn!(
                backend = %self.label,
                "Backend marked unhealthy"
            );
        }
    }

    /// Return the number of consecutive connection failures since last success.
    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(port: u16) -> String {
        format!("127.0.0.1:{port}")
    }

    #[test]
    fn test_new_backend_starts_healthy() {
        let h = BackendHealth::new(backend(8080));
        assert!(h.is_healthy());
        assert_eq!(h.consecutive_failures(), 0);
    }

    #[test]
    fn test_record_failure_marks_unhealthy() {
        let h = BackendHealth::new(backend(8080));
        h.record_failure();
        assert!(!h.is_healthy());
        assert_eq!(h.consecutive_failures(), 1);
    }

    #[test]
    fn test_record_failure_increments_consecutive() {
        let h = BackendHealth::new(backend(8080));
        h.record_failure();
        h.record_failure();
        h.record_failure();
        assert_eq!(h.consecutive_failures(), 3);
    }

    #[test]
    fn test_record_success_recovers() {
        let h = BackendHealth::new(backend(8080));
        h.record_failure();
        h.record_failure();
        assert!(!h.is_healthy());
        h.record_success();
        assert!(h.is_healthy());
        assert_eq!(h.consecutive_failures(), 0);
    }

    #[test]
    fn test_is_eligible_healthy_always_true() {
        let h = BackendHealth::new(backend(8080));
        assert!(h.is_eligible(Duration::from_secs(30)));
        assert!(h.is_eligible(Duration::from_secs(0)));
    }

    #[test]
    fn test_is_eligible_false_during_cooldown() {
        let h = BackendHealth::new(backend(8080));
        h.record_failure();
        // Cooldown of 1 hour — should not be eligible yet
        assert!(!h.is_eligible(Duration::from_secs(3600)));
    }

    #[test]
    fn test_is_eligible_true_after_cooldown() {
        let h = BackendHealth::new(backend(8080));
        h.record_failure();
        // Cooldown of zero — immediately eligible
        assert!(h.is_eligible(Duration::from_secs(0)));
    }

    #[test]
    fn test_is_eligible_zero_unhealthy_since() {
        // If unhealthy_since is 0 (never set), eligible regardless
        let h = BackendHealth::new(backend(8080));
        h.healthy.store(false, Ordering::Release);
        // unhealthy_since stays 0
        assert!(h.is_eligible(Duration::from_secs(3600)));
    }

    #[test]
    fn test_label_returns_backend_label() {
        let label = backend(9090);
        let h = BackendHealth::new(label.clone());
        assert_eq!(h.label(), label);
    }

    #[test]
    fn test_consecutive_failures_resets_on_success() {
        let h = BackendHealth::new(backend(8080));
        for _ in 0..5 {
            h.record_failure();
        }
        assert_eq!(h.consecutive_failures(), 5);
        h.record_success();
        assert_eq!(h.consecutive_failures(), 0);
    }
}
