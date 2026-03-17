//! Configuration file parsing for `kairosd`.
//!
//! # Secret sources (mutually exclusive per user)
//!
//! | Field              | Description |
//! |--------------------|-------------|
//! | `secret`           | Inline hex string or passphrase |
//! | `secret_file`      | Path to a file containing the secret |
//! | `secret_credential`| systemd credential name, loaded from `/run/credentials/kairosd.service/<name>` |
//!
//! `secret_credential` is the recommended option on NixOS when combined with
//! `systemd-creds` and TPM2 binding — the credential is encrypted at rest
//! with a machine-specific key and decrypted into a `tmpfs` mount at service
//! start, never touching the filesystem as plaintext.
//!
//! # Memory security
//!
//! All loaded secrets are held in [`kairos_core::SecretKey`] which
//! implements [`zeroize::ZeroizeOnDrop`].  After parsing, the daemon calls
//! [`Config::mlock_secrets`] to pin the secret pages into RAM, preventing
//! them from being swapped to disk.
//!
//! # Example config
//!
//! ```toml
//! interface   = "eth0"
//! window_secs = 30
//! knock_count = 4
//! skew        = 1
//! open_secs   = 60
//! ssh_port    = 22
//! log_filter  = "info"
//! replay_db   = "/var/lib/kairosd/replay.db"
//!
//! [[users]]
//! name              = "alice"
//! secret_credential = "alice-key"   # /run/credentials/kairosd.service/alice-key
//!
//! [[users]]
//! name        = "bob"
//! secret_file = "/run/secrets/kairos/bob"
//!
//! [[users]]
//! name   = "ci-runner"
//! secret = "hunter2"
//! ```

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use kairos_core::{decode_secret, SecretKey};
use serde::Deserialize;
use zeroize::Zeroizing;

// ── Constants ──────────────────────────────────────────────────────────────

/// Base path where systemd places decrypted credentials for a service.
const SYSTEMD_CREDENTIALS_DIR: &str = "/run/credentials/kairosd.service";

// ── Raw (serde) types ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RawConfig {
    #[serde(default = "default_window")]
    pub window_secs: u64,
    #[serde(default = "default_count")]
    pub knock_count: usize,
    #[serde(default = "default_skew")]
    pub skew: u64,
    #[serde(default = "default_open_secs")]
    pub open_secs: u64,
    pub interface: String,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default = "default_log")]
    pub log_filter: String,
    /// Path to the SQLite replay-prevention database.
    /// Created on first run if it does not exist.
    pub replay_db: Option<PathBuf>,
    pub users: Vec<RawUser>,
}

#[derive(Debug, Deserialize)]
pub struct RawUser {
    pub name: String,
    /// Inline hex string or passphrase.
    pub secret: Option<String>,
    /// Path to a file whose contents are the secret.
    pub secret_file: Option<String>,
    /// systemd credential name (file under SYSTEMD_CREDENTIALS_DIR).
    pub secret_credential: Option<String>,
}

fn default_window()    -> u64    { 30 }
fn default_count()     -> usize  { 4 }
fn default_skew()      -> u64    { 1 }
fn default_open_secs() -> u64    { 60 }
fn default_ssh_port()  -> u16    { 22 }
fn default_log()       -> String { "info".into() }

// ── Validated runtime types ────────────────────────────────────────────────

#[derive(Debug)]
pub struct Config {
    pub window_secs: u64,
    pub knock_count: usize,
    pub skew: u64,
    pub open_secs: u64,
    pub interface: String,
    #[allow(dead_code)] // parsed from config; used by the NixOS module, not the daemon directly
    pub ssh_port: u16,
    pub log_filter: String,
    /// None → replay state is in-memory only (lost on restart).
    pub replay_db: Option<PathBuf>,
    pub users: Vec<User>,
}

pub struct User {
    pub name: String,
    /// Zeroizes on drop.
    pub secret: SecretKey,
}

// Manual Debug to avoid leaking secret bytes via derived impl.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("name", &self.name)
            .field("secret", &self.secret)
            .finish()
    }
}

// ── Loading ────────────────────────────────────────────────────────────────

impl Config {
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config: {}", path.display()))?;
        let raw: RawConfig = toml::from_str(&text).context("parsing config TOML")?;
        let cfg = Self::from_raw(raw)?;
        cfg.mlock_secrets();
        Ok(cfg)
    }

    fn from_raw(raw: RawConfig) -> Result<Self> {
        anyhow::ensure!(raw.window_secs > 0, "window_secs must be positive");
        anyhow::ensure!(raw.knock_count >= 2, "knock_count must be at least 2");
        anyhow::ensure!(
            raw.knock_count <= kairos_core::MAX_KNOCK_COUNT,
            "knock_count exceeds MAX_KNOCK_COUNT ({})",
            kairos_core::MAX_KNOCK_COUNT
        );
        anyhow::ensure!(!raw.users.is_empty(), "no users defined in config");

        // Check for duplicate user names.
        let mut seen_names = HashSet::new();
        for u in &raw.users {
            anyhow::ensure!(
                seen_names.insert(&u.name),
                "duplicate user name '{}'",
                u.name
            );
        }

        let users = raw
            .users
            .into_iter()
            .map(resolve_user)
            .collect::<Result<Vec<_>>>()?;

        Ok(Config {
            window_secs: raw.window_secs,
            knock_count: raw.knock_count,
            skew: raw.skew,
            open_secs: raw.open_secs,
            interface: raw.interface,
            ssh_port: raw.ssh_port,
            log_filter: raw.log_filter,
            replay_db: raw.replay_db,
            users,
        })
    }

    /// Lock all secret key pages into RAM using `mlock(2)`.
    ///
    /// This prevents the OS from swapping secret bytes to disk under memory
    /// pressure.  Requires `CAP_IPC_LOCK` or sufficient `RLIMIT_MEMLOCK`.
    /// Failure is logged as a warning rather than a fatal error so the daemon
    /// still starts in constrained environments (e.g. containers without the
    /// capability).
    pub fn mlock_secrets(&self) {
        for user in &self.users {
            let bytes = user.secret.as_bytes();
            let ptr   = bytes.as_ptr() as *mut libc::c_void;
            let len   = bytes.len();
            // SAFETY: ptr and len come directly from a valid slice.
            let rc = unsafe { libc::mlock(ptr, len) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!(
                    user = %user.name,
                    "mlock failed (secret may be swappable): {err}"
                );
            }
        }
    }
}

// ── Secret resolution ──────────────────────────────────────────────────────

fn resolve_user(raw: RawUser) -> Result<User> {
    let raw_bytes: Vec<u8> = match (raw.secret, raw.secret_file, raw.secret_credential) {
        // ── Exactly one source ───────────────────────────────────────────
        (Some(inline), None, None) => {
            decode_secret(&inline)
                .with_context(|| format!("user '{}': decoding inline secret", raw.name))?
        }

        (None, Some(file_path), None) => {
            let contents = Zeroizing::new(
                fs::read_to_string(&file_path)
                    .with_context(|| {
                        format!("user '{}': reading secret_file '{file_path}'", raw.name)
                    })?,
            );
            decode_secret(&contents)
                .with_context(|| format!("user '{}': decoding secret_file", raw.name))?
        }

        (None, None, Some(cred_name)) => {
            // systemd places credentials at a well-known path derived from
            // the service name.  The directory is a read-only tmpfs, so the
            // contents are never written to persistent storage.
            let cred_path = PathBuf::from(SYSTEMD_CREDENTIALS_DIR).join(&cred_name);
            let contents = Zeroizing::new(
                fs::read_to_string(&cred_path).with_context(|| {
                    format!(
                        "user '{}': reading systemd credential '{}' from '{}'",
                        raw.name,
                        cred_name,
                        cred_path.display()
                    )
                })?,
            );
            decode_secret(&contents)
                .with_context(|| format!("user '{}': decoding credential", raw.name))?
        }

        // ── Ambiguous or missing ─────────────────────────────────────────
        (None, None, None) => {
            anyhow::bail!(
                "user '{}': one of 'secret', 'secret_file', or \
                 'secret_credential' is required",
                raw.name
            )
        }
        _ => {
            anyhow::bail!(
                "user '{}': only one of 'secret', 'secret_file', or \
                 'secret_credential' may be set",
                raw.name
            )
        }
    };

    // Secret length validation.
    anyhow::ensure!(
        raw_bytes.len() >= 8,
        "user '{}': secret is only {} bytes (minimum 8)",
        raw.name,
        raw_bytes.len()
    );
    if raw_bytes.len() < 16 {
        tracing::warn!(
            user = %raw.name,
            len  = raw_bytes.len(),
            "secret is shorter than recommended minimum of 16 bytes"
        );
    }

    Ok(User {
        name: raw.name,
        secret: SecretKey::from_bytes(raw_bytes),
    })
}
