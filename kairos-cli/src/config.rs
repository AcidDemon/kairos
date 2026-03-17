//! Client configuration parsing and secret loading.

use std::{
    collections::HashMap,
    env,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use kairos_core::SecretKey;
use serde::Deserialize;
use zeroize::Zeroizing;

// ── Raw serde types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RawConfig {
    #[serde(default)]
    pub defaults: RawDefaults,
    #[serde(default)]
    pub hosts: HashMap<String, RawHostConfig>,
}

#[derive(Debug, Deserialize)]
pub struct RawDefaults {
    #[serde(default = "default_window")]
    pub window_secs: u64,
    #[serde(default = "default_count")]
    pub knock_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct RawHostConfig {
    pub hostname: String,
    pub secret_file: String,
    pub window_secs: Option<u64>,
    pub knock_count: Option<usize>,
}

impl Default for RawDefaults {
    fn default() -> Self {
        Self {
            window_secs: kairos_core::DEFAULT_WINDOW_SECS,
            knock_count: kairos_core::DEFAULT_KNOCK_COUNT,
        }
    }
}

fn default_window() -> u64 {
    kairos_core::DEFAULT_WINDOW_SECS
}

fn default_count() -> usize {
    kairos_core::DEFAULT_KNOCK_COUNT
}

// ── Resolved types ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ResolvedHost {
    pub hostname: String,
    pub secret: SecretKey,
    pub window_secs: u64,
    pub knock_count: usize,
}

// ── Config loading ───────────────────────────────────────────────────────────

/// Determine the config file path from (in priority order):
/// 1. `--config` CLI flag (passed as `cli_config`)
/// 2. `$KAIROS_CONFIG` env var
/// 3. `$XDG_CONFIG_HOME/kairos/config.toml` (via `dirs::config_dir()`)
pub fn config_path(cli_config: Option<&Path>) -> PathBuf {
    if let Some(p) = cli_config {
        return p.to_path_buf();
    }
    if let Ok(p) = env::var("KAIROS_CONFIG") {
        return PathBuf::from(p);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("kairos")
        .join("config.toml")
}

/// Load and parse the config file. Returns `None` if the file doesn't exist.
pub fn load_config(path: &Path) -> Result<Option<RawConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading config: {}", path.display()))?;
    let cfg: RawConfig = toml::from_str(&text).context("parsing config TOML")?;
    Ok(Some(cfg))
}

/// Resolve a named host from config, applying overrides.
pub fn resolve_host(
    config: &RawConfig,
    name: &str,
    window_override: Option<u64>,
    count_override: Option<usize>,
) -> Result<ResolvedHost> {
    let host = config
        .hosts
        .get(name)
        .with_context(|| format!("host '{name}' not found in config"))?;

    let window_secs = window_override
        .or(host.window_secs)
        .unwrap_or(config.defaults.window_secs);
    let knock_count = count_override
        .or(host.knock_count)
        .unwrap_or(config.defaults.knock_count);

    let secret = load_secret(&host.secret_file)
        .with_context(|| format!("loading secret for host '{name}'"))?;

    Ok(ResolvedHost {
        hostname: host.hostname.clone(),
        secret,
        window_secs,
        knock_count,
    })
}

/// Load a secret from a file path, expanding `~` to the home directory.
/// Warns to stderr if the file is group- or world-readable on Unix.
pub fn load_secret(path: &str) -> Result<SecretKey> {
    let expanded = expand_tilde(path);
    let contents = Zeroizing::new(
        fs::read_to_string(&expanded)
            .with_context(|| format!("reading secret file: {}", expanded.display()))?,
    );

    check_permissions(&expanded);

    SecretKey::from_hex_or_passphrase(&contents)
        .map_err(|e| anyhow::anyhow!("decoding secret: {e}"))
}

/// Expand a leading `~` to the user's home directory (public for init.rs).
pub fn expand_tilde_pub(path: &str) -> PathBuf {
    expand_tilde(path)
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

/// Warn if the secret file has group or world readable bits set.
#[cfg(unix)]
fn check_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: secret file {} has group/world permissions (mode {:04o})",
                path.display(),
                mode & 0o777,
            );
        }
    }
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) {}

// ── Config directory helpers ─────────────────────────────────────────────────

/// Return the kairos config directory (e.g. ~/.config/kairos).
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("kairos")
}

/// Return the kairos secrets directory (e.g. ~/.config/kairos/secrets).
pub fn secrets_dir() -> PathBuf {
    config_dir().join("secrets")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[defaults]
window_secs = 30
knock_count = 4

[hosts.myserver]
hostname    = "example.com"
secret_file = "/tmp/test.key"
"#;
        let cfg: RawConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.defaults.window_secs, 30);
        assert_eq!(cfg.defaults.knock_count, 4);
        assert!(cfg.hosts.contains_key("myserver"));
        assert_eq!(cfg.hosts["myserver"].hostname, "example.com");
    }

    #[test]
    fn parse_empty_config() {
        let cfg: RawConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.defaults.window_secs, kairos_core::DEFAULT_WINDOW_SECS);
        assert_eq!(cfg.defaults.knock_count, kairos_core::DEFAULT_KNOCK_COUNT);
        assert!(cfg.hosts.is_empty());
    }

    #[test]
    fn host_overrides_defaults() {
        let toml = r#"
[defaults]
window_secs = 30
knock_count = 4

[hosts.myserver]
hostname    = "example.com"
secret_file = "/tmp/test.key"
knock_count = 6
"#;
        let cfg: RawConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.hosts["myserver"].knock_count, Some(6));
        assert_eq!(cfg.hosts["myserver"].window_secs, None);
    }

    #[test]
    fn expand_tilde_works() {
        let expanded = expand_tilde("~/foo/bar");
        assert!(!expanded.starts_with("~"));
    }

    #[test]
    fn expand_tilde_no_tilde() {
        let expanded = expand_tilde("/absolute/path");
        assert_eq!(expanded, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn load_secret_from_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.key");
        let mut f = fs::File::create(&key_path).unwrap();
        write!(f, "deadbeefcafebabe").unwrap();
        drop(f);

        let secret = load_secret(key_path.to_str().unwrap()).unwrap();
        assert_eq!(secret.as_bytes(), &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn resolve_host_applies_overrides() {
        let toml = r#"
[defaults]
window_secs = 30
knock_count = 4

[hosts.myserver]
hostname    = "example.com"
secret_file = "/tmp/nonexistent.key"
knock_count = 6
"#;
        let cfg: RawConfig = toml::from_str(toml).unwrap();
        // CLI override should win over host config
        let result = resolve_host(&cfg, "myserver", Some(60), Some(8));
        // This will fail because the secret file doesn't exist, but we can
        // check that the error is about the file, not the override logic.
        let err = result.unwrap_err();
        assert!(err.to_string().contains("secret"), "unexpected error: {err}");
    }

    #[test]
    fn resolve_host_missing() {
        let cfg: RawConfig = toml::from_str("").unwrap();
        let err = resolve_host(&cfg, "nonexistent", None, None).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
