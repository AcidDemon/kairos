//! Per-source-IP knock state machine.
//!
//! See the module-level state transition diagram. The only change from the
//! previous version is that replay prevention is now delegated to
//! [`crate::store::ReplayStore`] rather than an in-process `HashMap`, so
//! used `(user, window)` pairs survive daemon restarts.

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use kairos_core::derive_sequence;
use tracing::{debug, info, warn};

use crate::config::{Config, User};
use crate::store::ReplayStore;

const PARTIAL_TIMEOUT_SECS: u64 = 10;

/// Maximum number of source IPs tracked simultaneously in the state map.
const MAX_TRACKED_IPS: usize = 10_000;

/// How often (in packets) to sweep expired entries from the state map.
const SWEEP_INTERVAL: u64 = 256;

/// Maximum first-knock attempts per source IP per rate-limit window.
const RATE_LIMIT_MAX: u32 = 10;

/// Duration of the rate-limit window.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

// ── Internal progress state ───────────────────────────────────────────────────

#[derive(Debug)]
struct KnockProgress {
    user_name:  String,
    window:     u64,
    sequence:   Vec<u16>,
    next_index: usize,
    last_knock: Instant,
}

impl KnockProgress {
    fn new(user_name: String, window: u64, sequence: Vec<u16>) -> Self {
        KnockProgress {
            user_name,
            window,
            sequence,
            next_index: 1,
            last_knock: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.last_knock.elapsed() > Duration::from_secs(PARTIAL_TIMEOUT_SECS)
    }
}

// ── Pre-computed first-knock lookup table ─────────────────────────────────────

struct FirstKnockCandidate {
    user_index: usize,
    window:     u64,
    sequence:   Vec<u16>,
}

struct FirstKnockTable {
    table:            HashMap<u16, Vec<FirstKnockCandidate>>,
    built_for_windows: Vec<u64>,
}

impl FirstKnockTable {
    fn build(users: &[User], valid_windows: &[u64], knock_count: usize) -> Self {
        let mut table: HashMap<u16, Vec<FirstKnockCandidate>> = HashMap::new();
        for (user_index, user) in users.iter().enumerate() {
            for &window in valid_windows {
                let seq = derive_sequence(user.secret.as_bytes(), window, knock_count);
                let first_port = seq[0];
                table.entry(first_port).or_default().push(FirstKnockCandidate {
                    user_index,
                    window,
                    sequence: seq,
                });
            }
        }
        FirstKnockTable {
            table,
            built_for_windows: valid_windows.to_vec(),
        }
    }

    fn is_stale(&self, valid_windows: &[u64]) -> bool {
        self.built_for_windows != valid_windows
    }

    fn lookup(&self, port: u16) -> Option<&[FirstKnockCandidate]> {
        self.table.get(&port).map(|v| v.as_slice())
    }
}

// ── Public result type ────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum KnockResult {
    Partial  { user: String, progress: usize, total: usize },
    Complete { user: String },
    Mismatch,
    Unrelated,
}

// ── Metrics ──────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct KnockMetrics {
    pub auth_success:   u64,
    pub replay_blocked: u64,
    pub rate_limited:   u64,
    pub mismatches:     u64,
}

// ── Tracker ───────────────────────────────────────────────────────────────────

pub struct KnockTracker {
    state:       HashMap<IpAddr, KnockProgress>,
    /// Monotonic packet counter used to trigger periodic sweeps.
    pkt_counter: u64,
    /// Per-IP rate limiter: (attempt count, window start).
    rate_limits: HashMap<IpAddr, (u32, Instant)>,
    /// Pre-computed first-knock lookup table (rebuilt on window transitions).
    first_knock_table: Option<FirstKnockTable>,
    /// Cumulative metrics.
    metrics: KnockMetrics,
}

impl KnockTracker {
    pub fn new() -> Self {
        KnockTracker {
            state:             HashMap::new(),
            pkt_counter:       0,
            rate_limits:       HashMap::new(),
            first_knock_table: None,
            metrics:           KnockMetrics::default(),
        }
    }

    pub fn metrics(&self) -> &KnockMetrics {
        &self.metrics
    }

    /// Process an incoming UDP packet.
    ///
    /// `valid_windows` comes from [`kairos_core::windows_with_skew`] at call
    /// time.  `store` is borrowed mutably so successful completions can be
    /// recorded immediately.
    pub fn process(
        &mut self,
        src:           IpAddr,
        port:          u16,
        valid_windows: &[u64],
        config:        &Config,
        store:         &mut ReplayStore,
    ) -> KnockResult {
        // ── Periodic sweep of expired entries ────────────────────────────
        self.pkt_counter += 1;
        if self.pkt_counter % SWEEP_INTERVAL == 0 {
            self.state.retain(|_, p| !p.is_expired());

            // If still at capacity after sweep, evict the oldest entry.
            if self.state.len() >= MAX_TRACKED_IPS {
                if let Some(oldest_ip) = self
                    .state
                    .iter()
                    .min_by_key(|(_, p)| p.last_knock)
                    .map(|(ip, _)| *ip)
                {
                    debug!(%oldest_ip, "evicting oldest tracked IP (at capacity)");
                    self.state.remove(&oldest_ip);
                }
            }

            // Also sweep stale rate-limit entries.
            self.rate_limits
                .retain(|_, (_, start)| start.elapsed() < RATE_LIMIT_WINDOW);
        }

        // Lazy expiry of stale partial sequences.
        if self.state.get(&src).map(|p| p.is_expired()).unwrap_or(false) {
            debug!(%src, "expiring stale partial sequence");
            self.state.remove(&src);
        }

        // ── Continue an in-progress sequence ─────────────────────────────
        if let Some(progress) = self.state.get_mut(&src) {
            let expected = progress.sequence[progress.next_index];

            if port == expected {
                progress.next_index += 1;
                progress.last_knock = Instant::now();
                let total = progress.sequence.len();

                if progress.next_index == total {
                    let user   = progress.user_name.clone();
                    let window = progress.window;
                    self.state.remove(&src);

                    // Replay check — consult the persistent store.
                    // Fail-closed: on DB error, deny the knock.
                    match store.is_used(&user, window) {
                        Ok(true) => {
                            warn!(%src, %user, window, "replay detected — ignoring");
                            self.metrics.replay_blocked += 1;
                            return KnockResult::Mismatch;
                        }
                        Err(e) => {
                            warn!(%src, %user, "replay store error (fail-closed): {e}");
                            self.metrics.replay_blocked += 1;
                            return KnockResult::Mismatch;
                        }
                        Ok(false) => {}
                    }

                    if let Err(e) = store.mark_used(&user, window) {
                        warn!(%src, %user, "failed to record used window: {e}");
                        // Non-fatal: we still open the firewall for this
                        // successful knock; the worst case is one extra open
                        // if the daemon immediately restarts.
                    }

                    info!(%src, %user, window, "knock sequence COMPLETE");
                    self.metrics.auth_success += 1;
                    return KnockResult::Complete { user };
                }

                let n    = progress.next_index;
                let user = progress.user_name.clone();
                debug!(%src, %user, "knock {n}/{total}");
                return KnockResult::Partial { user, progress: n, total };
            }

            // Wrong port — reset and fall through to retry as a first knock.
            debug!(%src, "mismatch (expected {expected}, got {port}), resetting");
            self.state.remove(&src);
            self.metrics.mismatches += 1;
        }

        // ── Rebuild first-knock table if stale or absent ─────────────────
        let need_rebuild = self
            .first_knock_table
            .as_ref()
            .map(|t| t.is_stale(valid_windows))
            .unwrap_or(true);

        if need_rebuild {
            self.first_knock_table = Some(FirstKnockTable::build(
                &config.users,
                valid_windows,
                config.knock_count,
            ));
        }

        // ── Try as the first knock of a new sequence (O(1) lookup) ───────
        let candidate = self
            .first_knock_table
            .as_ref()
            .and_then(|t| t.lookup(port))
            .and_then(|candidates| candidates.first())
            .map(|c| (c.user_index, c.window, c.sequence.clone()));

        if let Some((user_index, window, seq)) = candidate {
            let user = &config.users[user_index];

            // ── Rate limit first-knock attempts per source IP ────────────
            if self.is_rate_limited(src) {
                self.metrics.rate_limited += 1;
                return KnockResult::Unrelated;
            }

            debug!(%src, user=%user.name, "first knock matched (port {port})");
            let name = user.name.clone();

            if seq.len() == 1 {
                // Fail-closed: on DB error, deny the knock.
                match store.is_used(&name, window) {
                    Ok(true) => {
                        warn!(%src, user=%name, "replay detected on single-knock sequence");
                        self.metrics.replay_blocked += 1;
                        return KnockResult::Mismatch;
                    }
                    Err(e) => {
                        warn!(%src, user=%name, "replay store error (fail-closed): {e}");
                        self.metrics.replay_blocked += 1;
                        return KnockResult::Mismatch;
                    }
                    Ok(false) => {}
                }
                let _ = store.mark_used(&name, window);
                info!(%src, user=%name, "knock sequence COMPLETE (single knock)");
                self.metrics.auth_success += 1;
                return KnockResult::Complete { user: name };
            }

            // Enforce capacity before inserting.
            if self.state.len() >= MAX_TRACKED_IPS {
                if let Some(oldest_ip) = self
                    .state
                    .iter()
                    .min_by_key(|(_, p)| p.last_knock)
                    .map(|(ip, _)| *ip)
                {
                    debug!(%oldest_ip, "evicting oldest tracked IP (at capacity)");
                    self.state.remove(&oldest_ip);
                }
            }

            self.state.insert(src, KnockProgress::new(name.clone(), window, seq));
            return KnockResult::Partial {
                user:     name,
                progress: 1,
                total:    config.knock_count,
            };
        }

        KnockResult::Unrelated
    }

    /// Check and update the per-IP rate limiter.  Returns `true` if the
    /// source has exceeded `RATE_LIMIT_MAX` first-knock attempts within the
    /// current `RATE_LIMIT_WINDOW`.
    fn is_rate_limited(&mut self, src: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.rate_limits.entry(src).or_insert((0, now));

        // Reset the window if it has elapsed.
        if now.duration_since(entry.1) >= RATE_LIMIT_WINDOW {
            *entry = (0, now);
        }

        entry.0 += 1;
        if entry.0 > RATE_LIMIT_MAX {
            warn!(%src, "rate limit exceeded ({RATE_LIMIT_MAX} first-knocks / {}s)", RATE_LIMIT_WINDOW.as_secs());
            return true;
        }
        false
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::User, store::ReplayStore};
    use kairos_core::SecretKey;

    fn make_config(secret: &[u8], count: usize) -> Config {
        Config {
            window_secs: 30,
            knock_count: count,
            skew:        1,
            open_secs:   60,
            interface:   "eth0".into(),
            ssh_port:    22,
            log_filter:  "info".into(),
            replay_db:   None,
            users: vec![User {
                name:   "alice".into(),
                secret: SecretKey::from_bytes(secret.to_vec()),
            }],
        }
    }

    fn src() -> IpAddr { "10.0.0.1".parse().unwrap() }

    #[test]
    fn full_sequence_yields_complete() {
        let secret = b"test-secret-kairos";
        let window = 42u64;
        let count  = 4;
        let config = make_config(secret, count);
        let seq    = derive_sequence(secret, window, count);
        let windows = vec![window];
        let mut tracker = KnockTracker::new();
        let mut store   = ReplayStore::in_memory(30);

        for (i, &port) in seq.iter().enumerate() {
            let result = tracker.process(src(), port, &windows, &config, &mut store);
            if i < count - 1 {
                assert!(matches!(result, KnockResult::Partial { .. }));
            } else {
                assert_eq!(result, KnockResult::Complete { user: "alice".into() });
            }
        }
    }

    #[test]
    fn wrong_port_resets_state() {
        let secret  = b"reset-test";
        let window  = 10u64;
        let count   = 4;
        let config  = make_config(secret, count);
        let seq     = derive_sequence(secret, window, count);
        let windows = vec![window];
        let mut tracker = KnockTracker::new();
        let mut store   = ReplayStore::in_memory(30);

        tracker.process(src(), seq[0], &windows, &config, &mut store);
        let result = tracker.process(src(), 9999, &windows, &config, &mut store);
        assert_eq!(result, KnockResult::Unrelated);
        assert!(tracker.state.get(&src()).is_none());
    }

    #[test]
    fn replay_is_rejected() {
        let secret  = b"replay-test";
        let window  = 77u64;
        let count   = 4;
        let config  = make_config(secret, count);
        let seq     = derive_sequence(secret, window, count);
        let windows = vec![window];
        let mut tracker = KnockTracker::new();
        let mut store   = ReplayStore::in_memory(30);

        for &port in &seq {
            tracker.process(src(), port, &windows, &config, &mut store);
        }

        // Attempt replay from a different source IP.
        let src2: IpAddr = "10.0.0.2".parse().unwrap();
        for (i, &port) in seq.iter().enumerate() {
            let result = tracker.process(src2, port, &windows, &config, &mut store);
            if i == count - 1 {
                assert_eq!(result, KnockResult::Mismatch, "replay must be rejected");
            }
        }
    }
}
