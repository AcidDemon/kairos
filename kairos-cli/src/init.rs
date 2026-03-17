//! Onboarding helpers: `kairos init` and `kairos add`.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use anyhow::{Context, Result};

use crate::config::{self, load_config};

/// Generate a new secret and configure a host.
pub fn init_host(
    name: &str,
    hostname: &str,
    knock_count: usize,
    window_secs: u64,
    config_path: &Path,
) -> Result<()> {
    check_host_not_exists(name, config_path)?;

    let secret_hex = generate_secret()?;
    let secret_path = config::secrets_dir().join(format!("{name}.key"));

    write_secret_file(&secret_path, &secret_hex)?;
    append_host_config(name, hostname, &secret_path, knock_count, window_secs, config_path)?;

    let secret_display = secret_path.display();
    let config_display = config_path.display();

    eprintln!("Secret saved to {secret_display}");
    eprintln!("Host added to {config_display}");
    eprintln!();
    eprintln!("--- Server setup ---");
    eprintln!("Copy the secret to the server and add to kairosd config:");
    eprintln!();
    eprintln!("  [[users]]");
    eprintln!("  name        = \"{name}\"");
    eprintln!("  secret_file = \"/path/to/{name}.key\"");
    eprintln!();
    eprintln!("Secret (hex):");
    eprintln!("  {secret_hex}");
    eprintln!();
    print_ssh_snippet(name, hostname);

    Ok(())
}

/// Import an existing secret file and configure a host.
pub fn add_host(
    name: &str,
    hostname: &str,
    source_secret: &str,
    knock_count: usize,
    window_secs: u64,
    config_path: &Path,
) -> Result<()> {
    check_host_not_exists(name, config_path)?;

    let source = config::expand_tilde_pub(source_secret);
    let contents = fs::read_to_string(&source)
        .with_context(|| format!("reading secret file: {}", source.display()))?;
    let trimmed = contents.trim();

    let secret_path = config::secrets_dir().join(format!("{name}.key"));
    write_secret_file(&secret_path, trimmed)?;
    append_host_config(name, hostname, &secret_path, knock_count, window_secs, config_path)?;

    let secret_display = secret_path.display();
    let config_display = config_path.display();

    eprintln!("Secret copied to {secret_display}");
    eprintln!("Host added to {config_display}");
    eprintln!();
    print_ssh_snippet(name, hostname);

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Generate 32 random bytes and return as a hex string.
fn generate_secret() -> Result<String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("generating random secret: {e}"))?;
    Ok(hex::encode(buf))
}

/// Write secret to file with mode 0600, creating parent directories.
fn write_secret_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory: {}", parent.display()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating secret file: {}", path.display()))?;
        f.write_all(contents.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("creating secret file: {}", path.display()))?;
        f.write_all(contents.as_bytes())?;
    }

    Ok(())
}

/// Append a host entry to the config file, creating it if it doesn't exist.
fn append_host_config(
    name: &str,
    hostname: &str,
    secret_path: &Path,
    knock_count: usize,
    window_secs: u64,
    config_path: &Path,
) -> Result<()> {
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating config directory: {}", parent.display()))?;
    }

    // Build the TOML snippet to append.
    let secret_display = secret_path.display();
    let mut snippet = format!(
        "\n[hosts.{name}]\nhostname    = \"{hostname}\"\nsecret_file = \"{secret_display}\"\n"
    );

    // Only write non-default values.
    if knock_count != kairos_core::DEFAULT_KNOCK_COUNT {
        snippet.push_str(&format!("knock_count = {knock_count}\n"));
    }
    if window_secs != kairos_core::DEFAULT_WINDOW_SECS {
        snippet.push_str(&format!("window_secs = {window_secs}\n"));
    }

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(config_path)
        .with_context(|| format!("opening config file: {}", config_path.display()))?;
    f.write_all(snippet.as_bytes())?;

    Ok(())
}

/// Check that a host name doesn't already exist in config.
fn check_host_not_exists(name: &str, config_path: &Path) -> Result<()> {
    if let Some(cfg) = load_config(config_path)? {
        anyhow::ensure!(
            !cfg.hosts.contains_key(name),
            "host '{name}' already exists in config"
        );
    }
    Ok(())
}

fn print_ssh_snippet(name: &str, hostname: &str) {
    eprintln!("--- SSH config ---");
    eprintln!("Add to ~/.ssh/config:");
    eprintln!();
    eprintln!("  Match host {name} exec \"kairos knock {name}\"");
    eprintln!("      Hostname {hostname}");
}
