//! Per-sender reply rate limiting (Jas's item 5). Since mimi-bot makes no membership-grant
//! decision, message/reply volume is the only rate limit that matters (see the plan's own
//! rate-limiting section) - this is a resource-exhaustion guard, not a trust boundary. A fixed
//! window counter per sender identity, checked before mimi-bot spends CPU/openmls cycles building
//! and submitting a reply.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    windows: HashMap<Vec<u8>, (Instant, u32)>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            windows: HashMap::new(),
        }
    }

    /// Returns true if `sender` may get a reply right now, and records the attempt either way
    /// (a throttled burst still counts, so a sender who floods past the cap cannot reset the
    /// window early by spacing requests just inside it).
    pub fn allow(&mut self, sender: &[u8]) -> bool {
        let now = Instant::now();
        let entry = self.windows.entry(sender.to_vec()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max_per_window
    }

    /// Drop windows that closed a while ago, so a long-lived process doesn't accumulate one entry
    /// per distinct sender forever (a bounded resource guard, same spirit as the room cap).
    pub fn sweep_expired(&mut self, older_than: Duration) {
        let now = Instant::now();
        self.windows
            .retain(|_, (started, _)| now.duration_since(*started) < older_than);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_cap_then_throttles() {
        let mut rl = RateLimiter::new(3, Duration::from_secs(60));
        let sender = b"alice".as_slice();
        assert!(rl.allow(sender));
        assert!(rl.allow(sender));
        assert!(rl.allow(sender));
        assert!(
            !rl.allow(sender),
            "4th reply within the window must be throttled"
        );
        assert!(!rl.allow(sender), "still throttled, not silently reset");
    }

    #[test]
    fn separate_senders_have_independent_windows() {
        let mut rl = RateLimiter::new(1, Duration::from_secs(60));
        assert!(rl.allow(b"alice"));
        assert!(
            rl.allow(b"bob"),
            "bob's own window is independent of alice's"
        );
        assert!(!rl.allow(b"alice"));
    }

    #[test]
    fn window_resets_after_it_elapses() {
        let mut rl = RateLimiter::new(1, Duration::from_millis(20));
        let sender = b"alice".as_slice();
        assert!(rl.allow(sender));
        assert!(!rl.allow(sender));
        std::thread::sleep(Duration::from_millis(30));
        assert!(rl.allow(sender), "a new window must allow again");
    }

    #[test]
    fn sweep_expired_drops_old_windows_but_keeps_recent_ones() {
        let mut rl = RateLimiter::new(1, Duration::from_secs(60));
        rl.allow(b"alice");
        rl.sweep_expired(Duration::from_millis(0));
        assert!(
            rl.windows.is_empty(),
            "immediately-expired window must be swept"
        );

        let mut rl2 = RateLimiter::new(1, Duration::from_secs(60));
        rl2.allow(b"alice");
        rl2.sweep_expired(Duration::from_secs(3600));
        assert_eq!(
            rl2.windows.len(),
            1,
            "a fresh window must not be swept early"
        );
    }
}
