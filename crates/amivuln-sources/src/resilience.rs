// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Retry delays, a per-endpoint circuit breaker and a per-host rate limiter.
//!
//! These are pure state machines driven by an explicit clock (`Instant`
//! arguments), so tests control time and nothing here sleeps. The HTTP client
//! owns the sleeping.

use core::time::Duration;
use std::collections::HashMap;
use std::time::Instant;

/// How hard to try one endpoint before giving up on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Extra attempts after the first one.
    pub retries: u32,
    /// Delay before the first retry; doubles for every later one.
    pub base: Duration,
    /// Longest wait accepted between attempts. A `Retry-After` above this makes
    /// the endpoint count as failed instead of stalling the run.
    pub max_wait: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            retries: 2,
            base: Duration::from_millis(250),
            max_wait: Duration::from_secs(5),
        }
    }
}

/// What to do after a failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Wait, then try again.
    Wait(Duration),
    /// Stop retrying this endpoint.
    GiveUp,
}

impl RetryPolicy {
    /// Decides what follows the failed attempt number `attempt` (0 for the
    /// first). `retry_after` is the server's `Retry-After` in seconds and
    /// `jitter` a value in `0..=1000` (per mille of the delay to subtract),
    /// which spreads clients that failed together.
    #[must_use]
    pub fn next(&self, attempt: u32, retry_after: Option<u64>, jitter: u64) -> Next {
        if attempt >= self.retries {
            return Next::GiveUp;
        }
        if let Some(secs) = retry_after {
            let wait = Duration::from_secs(secs);
            // The server asked for a pause; honor it, but never longer than
            // the budget, and never shorter than it asked.
            return if wait > self.max_wait {
                Next::GiveUp
            } else {
                Next::Wait(wait)
            };
        }
        let shift = attempt.min(16);
        let exponential = self
            .base
            .checked_mul(1u32 << shift)
            .unwrap_or(self.max_wait)
            .min(self.max_wait);
        // Subtract up to half the delay: the result stays in [delay/2, delay].
        let millis = u64::try_from(exponential.as_millis()).unwrap_or(u64::MAX);
        let cut = millis / 2 * jitter.min(1000) / 1000;
        Next::Wait(exponential.saturating_sub(Duration::from_millis(cut)))
    }
}

/// Circuit breaker thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerPolicy {
    /// Consecutive failures that open the circuit.
    pub threshold: u32,
    /// How long an open circuit refuses requests before one trial is allowed.
    pub cooldown: Duration,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        Self {
            threshold: 3,
            cooldown: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Circuit {
    Closed { failures: u32 },
    Open { until: Instant },
    HalfOpen,
}

/// One breaker per endpoint (host), keyed by name.
#[derive(Debug, Default)]
pub struct Breakers {
    policy: BreakerPolicy,
    circuits: HashMap<String, Circuit>,
}

impl Breakers {
    /// Creates breakers with the given thresholds.
    #[must_use]
    pub fn new(policy: BreakerPolicy) -> Self {
        Self {
            policy,
            circuits: HashMap::new(),
        }
    }

    /// True when a request to `endpoint` may go out at `now`. An open circuit
    /// whose cooldown ended lets exactly one trial request through.
    pub fn allow(&mut self, endpoint: &str, now: Instant) -> bool {
        match self.circuits.get(endpoint).copied() {
            None | Some(Circuit::Closed { .. }) => true,
            Some(Circuit::Open { until }) if now >= until => {
                self.circuits.insert(endpoint.to_owned(), Circuit::HalfOpen);
                true
            }
            // Open before the cooldown ends, or a trial already in flight.
            Some(Circuit::Open { .. } | Circuit::HalfOpen) => false,
        }
    }

    /// Records an answer from `endpoint`: the circuit closes.
    pub fn success(&mut self, endpoint: &str) {
        self.circuits.remove(endpoint);
    }

    /// Records a failure of `endpoint` at `now`.
    pub fn failure(&mut self, endpoint: &str, now: Instant) {
        let next = match self.circuits.get(endpoint).copied() {
            Some(Circuit::HalfOpen) => Circuit::Open {
                until: now + self.policy.cooldown,
            },
            Some(Circuit::Closed { failures }) if failures + 1 >= self.policy.threshold => {
                Circuit::Open {
                    until: now + self.policy.cooldown,
                }
            }
            Some(Circuit::Closed { failures }) => Circuit::Closed {
                failures: failures + 1,
            },
            Some(open @ Circuit::Open { .. }) => open,
            None if self.policy.threshold <= 1 => Circuit::Open {
                until: now + self.policy.cooldown,
            },
            None => Circuit::Closed { failures: 1 },
        };
        self.circuits.insert(endpoint.to_owned(), next);
    }

    /// True when the circuit of `endpoint` is open or half-open.
    #[must_use]
    pub fn is_tripped(&self, endpoint: &str) -> bool {
        matches!(
            self.circuits.get(endpoint),
            Some(Circuit::Open { .. } | Circuit::HalfOpen)
        )
    }
}

/// Keeps at least `min_interval` between requests to one host.
#[derive(Debug, Default)]
pub struct Limiter {
    min_interval: Option<Duration>,
    last: HashMap<String, Instant>,
}

impl Limiter {
    /// Creates a limiter; `None` disables it.
    #[must_use]
    pub fn new(min_interval: Option<Duration>) -> Self {
        Self {
            min_interval,
            last: HashMap::new(),
        }
    }

    /// Reserves the next slot for `host` and returns how long the caller must
    /// wait before sending. Slots are handed out in order, so concurrent
    /// callers queue instead of bunching up.
    pub fn reserve(&mut self, host: &str, now: Instant) -> Duration {
        let Some(interval) = self.min_interval else {
            return Duration::ZERO;
        };
        let slot = match self.last.get(host) {
            Some(previous) => (*previous + interval).max(now),
            None => now,
        };
        self.last.insert(host.to_owned(), slot);
        slot.saturating_duration_since(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let p = RetryPolicy {
            retries: 6,
            base: ms(100),
            max_wait: ms(1000),
        };
        // No jitter: the full delay.
        let waits: Vec<Next> = (0..6).map(|a| p.next(a, None, 0)).collect();
        assert_eq!(
            waits,
            [
                Next::Wait(ms(100)),
                Next::Wait(ms(200)),
                Next::Wait(ms(400)),
                Next::Wait(ms(800)),
                Next::Wait(ms(1000)),
                Next::Wait(ms(1000)),
            ]
        );
        assert_eq!(p.next(6, None, 0), Next::GiveUp);
    }

    #[test]
    fn jitter_stays_between_half_and_full_delay() {
        let p = RetryPolicy {
            retries: 3,
            base: ms(400),
            max_wait: ms(5000),
        };
        for jitter in [0, 1, 250, 500, 999, 1000, 5000] {
            let Next::Wait(d) = p.next(0, None, jitter) else {
                return;
            };
            assert!(d >= ms(200) && d <= ms(400), "{jitter}: {d:?}");
        }
    }

    #[test]
    fn retry_after_is_honored_within_the_budget_and_ends_retries_beyond_it() {
        let p = RetryPolicy {
            retries: 3,
            base: ms(100),
            max_wait: Duration::from_secs(5),
        };
        assert_eq!(p.next(0, Some(2), 1000), Next::Wait(Duration::from_secs(2)));
        assert_eq!(p.next(0, Some(0), 0), Next::Wait(Duration::ZERO));
        assert_eq!(p.next(0, Some(600), 0), Next::GiveUp);
        // Out of attempts wins over a polite Retry-After.
        assert_eq!(p.next(3, Some(1), 0), Next::GiveUp);
    }

    #[test]
    fn no_retries_means_give_up_at_once() {
        let p = RetryPolicy {
            retries: 0,
            ..RetryPolicy::default()
        };
        assert_eq!(p.next(0, None, 0), Next::GiveUp);
    }

    #[test]
    fn breaker_opens_after_the_threshold_and_half_opens_after_the_cooldown() {
        let t0 = Instant::now();
        let mut b = Breakers::new(BreakerPolicy {
            threshold: 3,
            cooldown: Duration::from_secs(30),
        });
        assert!(b.allow("a", t0));
        b.failure("a", t0);
        b.failure("a", t0);
        assert!(b.allow("a", t0), "two failures keep it closed");
        b.failure("a", t0);
        assert!(b.is_tripped("a"));
        assert!(!b.allow("a", t0 + Duration::from_secs(29)), "open");
        // After the cooldown exactly one trial passes.
        assert!(b.allow("a", t0 + Duration::from_secs(30)));
        assert!(
            !b.allow("a", t0 + Duration::from_secs(30)),
            "trial in flight"
        );
        // A failed trial reopens for another cooldown.
        b.failure("a", t0 + Duration::from_secs(31));
        assert!(!b.allow("a", t0 + Duration::from_secs(60)));
        assert!(b.allow("a", t0 + Duration::from_secs(61)));
        // A successful trial closes it for good.
        b.success("a");
        assert!(!b.is_tripped("a"));
        assert!(b.allow("a", t0 + Duration::from_secs(62)));
    }

    #[test]
    fn a_success_resets_the_failure_count_and_endpoints_are_independent() {
        let t0 = Instant::now();
        let mut b = Breakers::new(BreakerPolicy {
            threshold: 2,
            cooldown: Duration::from_secs(10),
        });
        b.failure("a", t0);
        b.success("a");
        b.failure("a", t0);
        assert!(!b.is_tripped("a"), "the earlier failure was forgotten");
        b.failure("b", t0);
        b.failure("b", t0);
        assert!(b.is_tripped("b"));
        assert!(!b.is_tripped("a"));
        assert!(b.allow("a", t0));
    }

    #[test]
    fn a_threshold_of_one_opens_on_the_first_failure() {
        let t0 = Instant::now();
        let mut b = Breakers::new(BreakerPolicy {
            threshold: 1,
            cooldown: Duration::from_secs(5),
        });
        b.failure("a", t0);
        assert!(b.is_tripped("a"));
    }

    #[test]
    fn the_limiter_spaces_requests_per_host() {
        let t0 = Instant::now();
        let mut l = Limiter::new(Some(ms(200)));
        assert_eq!(l.reserve("h", t0), Duration::ZERO);
        assert_eq!(l.reserve("h", t0), ms(200));
        assert_eq!(l.reserve("h", t0), ms(400));
        // Another host is unaffected.
        assert_eq!(l.reserve("other", t0), Duration::ZERO);
        // Time passing frees the queue.
        assert_eq!(l.reserve("h", t0 + ms(1000)), Duration::ZERO);
        // Disabled limiter never waits.
        let mut off = Limiter::new(None);
        assert_eq!(off.reserve("h", t0), Duration::ZERO);
        assert_eq!(off.reserve("h", t0), Duration::ZERO);
    }
}
