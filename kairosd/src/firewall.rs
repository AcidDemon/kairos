//! Firewall integration — opens and closes the SSH port for a source IP.
//!
//! Supports both IPv4 and IPv6 by targeting the appropriate nftables set.
//! See `contrib/kairos.nft` and `nix/module.nix` for the expected set names.

use std::{net::IpAddr, process::Command, time::Duration};

use anyhow::{Context, Result};
use tracing::{info, warn};

const NFT_TABLE: &str = "inet kairos";
const NFT_SET_V4: &str = "kairos_allowed_v4";
const NFT_SET_V6: &str = "kairos_allowed_v6";

/// Open the SSH port for `ip` for up to `duration`.
///
/// Selects the correct set based on address family.  Idempotent — adding an
/// IP that is already in the set refreshes its timeout under nftables semantics.
pub fn open(ip: IpAddr, duration: Duration) -> Result<()> {
    let set  = set_for(&ip);
    let secs = duration.as_secs();
    nft(&format!("add element {NFT_TABLE} {set} {{ {ip} timeout {secs}s }}"))
        .with_context(|| format!("nft: opening firewall for {ip}"))?;
    info!(%ip, secs, "firewall opened");
    Ok(())
}

/// Remove the firewall opening for `ip` ahead of its timeout.
#[allow(dead_code)] // retained for future active-expiry support
pub fn close(ip: IpAddr) -> Result<()> {
    let set = set_for(&ip);
    match nft(&format!("delete element {NFT_TABLE} {set} {{ {ip} }}")) {
        Ok(()) => {
            info!(%ip, "firewall closed");
            Ok(())
        }
        Err(e) => {
            warn!(%ip, "firewall close (element may already be gone): {e}");
            Ok(())
        }
    }
}

fn set_for(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => NFT_SET_V4,
        IpAddr::V6(_) => NFT_SET_V6,
    }
}

fn nft(rule: &str) -> Result<()> {
    let output = Command::new("nft")
        .arg(rule)
        .output()
        .context("spawning nft")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft exited {}: {stderr}", output.status);
    }
    Ok(())
}
