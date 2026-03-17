//! Persistent replay-prevention store backed by SQLite.
//!
//! Replay prevention requires tracking `(user, window)` pairs that have
//! already triggered a successful knock.  Storing this in memory alone means
//! the protection vanishes on daemon restart — an attacker who captures a
//! valid sequence and kills the daemon could replay it.
//!
//! This module provides [`ReplayStore`], a thin wrapper around a SQLite
//! database that persists used windows across restarts.  The database file
//! is owned by root with mode 600 and contains no secret material — only
//! username strings and window counter integers.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE used_windows (
//!     user    TEXT    NOT NULL,
//!     window  INTEGER NOT NULL,
//!     used_at INTEGER NOT NULL,  -- Unix timestamp
//!     PRIMARY KEY (user, window)
//! );
//! ```
//!
//! Old entries are pruned eagerly: any window older than
//! `3 * window_secs` seconds is deleted on every [`ReplayStore::mark_used`]
//! call, bounding the table size even on long-running servers.
//!
//! # In-memory fallback
//!
//! When `replay_db` is `None` in the config the store operates in
//! memory-only mode (identical behaviour to the previous `HashMap` in
//! `KnockTracker`).  This preserves backward compatibility.

use std::{
    collections::HashMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use tracing::{debug, info};

// ── Store ─────────────────────────────────────────────────────────────────────

/// Backing storage for used `(user, window)` pairs.
enum Backend {
    /// Persistent SQLite database.
    Sqlite(Connection),
    /// In-memory fallback when no DB path is configured.
    /// Value is the Unix timestamp when the entry was recorded.
    Memory(HashMap<(String, u64), u64>),
}

pub struct ReplayStore {
    backend:     Backend,
    window_secs: u64,
}

impl ReplayStore {
    /// Open (or create) a persistent store at `db_path`.
    pub fn open(db_path: &Path, window_secs: u64) -> Result<Self> {
        // Ensure the parent directory exists.
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating DB directory: {}", parent.display()))?;
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("opening replay DB: {}", db_path.display()))?;

        // Restrict file permissions to root-only (600).
        // This is best-effort; the file may already exist with correct perms.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(db_path)?;
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(db_path, perms).ok();
        }

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous  = NORMAL;
             CREATE TABLE IF NOT EXISTS used_windows (
                 user    TEXT    NOT NULL,
                 window  INTEGER NOT NULL,
                 used_at INTEGER NOT NULL,
                 PRIMARY KEY (user, window)
             );",
        )
        .context("initialising replay DB schema")?;

        info!(path = %db_path.display(), "replay store opened");
        Ok(Self { backend: Backend::Sqlite(conn), window_secs })
    }

    /// Create an ephemeral in-memory store (no persistence).
    pub fn in_memory(window_secs: u64) -> Self {
        Self {
            backend: Backend::Memory(HashMap::new()),
            window_secs,
        }
    }

    /// Returns `true` if `(user, window)` has already been used.
    ///
    /// Returns an error on SQLite failures so the caller can fail-closed
    /// rather than silently allowing a replay.
    pub fn is_used(&self, user: &str, window: u64) -> Result<bool> {
        match &self.backend {
            Backend::Memory(map) => Ok(map.contains_key(&(user.to_owned(), window))),
            Backend::Sqlite(conn) => {
                let found: Option<u64> = conn
                    .query_row(
                        "SELECT window FROM used_windows WHERE user = ?1 AND window = ?2",
                        params![user, window as i64],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("querying replay store")?;
                Ok(found.is_some())
            }
        }
    }

    /// Mark `(user, window)` as used and prune old entries.
    pub fn mark_used(&mut self, user: &str, window: u64) -> Result<()> {
        let now = unix_now();
        // Entries older than 3 windows are irrelevant for replay prevention.
        let cutoff = now.saturating_sub(self.window_secs * 3);

        match &mut self.backend {
            Backend::Memory(map) => {
                map.insert((user.to_owned(), window), now);
                // Prune entries older than 3 * window_secs, same as SQLite.
                let before = map.len();
                map.retain(|_, ts| *ts >= cutoff);
                let pruned = before - map.len();
                if pruned > 0 {
                    debug!(pruned, "pruned expired in-memory replay entries");
                }
            }
            Backend::Sqlite(conn) => {
                conn.execute(
                    "INSERT OR IGNORE INTO used_windows (user, window, used_at)
                     VALUES (?1, ?2, ?3)",
                    params![user, window as i64, now as i64],
                )
                .context("marking window as used")?;

                let pruned = conn
                    .execute(
                        "DELETE FROM used_windows WHERE used_at < ?1",
                        params![cutoff as i64],
                    )
                    .context("pruning old replay entries")?;

                if pruned > 0 {
                    debug!(pruned, "pruned expired replay entries");
                }
            }
        }
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_basic() {
        let mut store = ReplayStore::in_memory(30);
        assert!(!store.is_used("alice", 100).unwrap());
        store.mark_used("alice", 100).unwrap();
        assert!(store.is_used("alice", 100).unwrap());
        assert!(!store.is_used("alice", 101).unwrap());
        assert!(!store.is_used("bob", 100).unwrap());
    }

    #[test]
    fn sqlite_store_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db  = dir.path().join("replay.db");

        {
            let mut store = ReplayStore::open(&db, 30).unwrap();
            store.mark_used("alice", 42).unwrap();
        }

        // Reopen a new connection — entry must still be there.
        let store = ReplayStore::open(&db, 30).unwrap();
        assert!(store.is_used("alice", 42).unwrap());
        assert!(!store.is_used("alice", 43).unwrap());
    }

    #[test]
    fn different_users_are_independent() {
        let mut store = ReplayStore::in_memory(30);
        store.mark_used("alice", 99).unwrap();
        assert!(!store.is_used("bob", 99).unwrap());
    }
}
