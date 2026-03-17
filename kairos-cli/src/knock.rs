//! UDP knock sender.

use std::net::{IpAddr, ToSocketAddrs, UdpSocket};

use anyhow::{Context, Result};
use kairos_core::{current_window, derive_sequence, SecretKey};

/// Send a knock sequence to the given hostname.
///
/// Resolves the hostname to an IP address, derives the current port sequence,
/// and sends a single-byte UDP packet to each port. Returns immediately after
/// sending all packets — no inter-packet delay is needed.
pub fn send_knock(
    hostname: &str,
    secret: &SecretKey,
    window_secs: u64,
    knock_count: usize,
) -> Result<()> {
    let addr = resolve(hostname)?;
    let window = current_window(window_secs);
    let ports = derive_sequence(secret.as_bytes(), window, knock_count);

    let socket = match addr {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0"),
        IpAddr::V6(_) => UdpSocket::bind("[::]:0"),
    }
    .context("binding UDP socket")?;

    for port in &ports {
        socket
            .send_to(&[0u8; 1], (addr, *port))
            .with_context(|| format!("sending knock to {addr}:{port}"))?;
    }

    Ok(())
}

/// Resolve a hostname to the first IP address returned by DNS.
fn resolve(hostname: &str) -> Result<IpAddr> {
    // Try parsing as a raw IP address first.
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(ip);
    }

    let addr = (hostname, 0u16)
        .to_socket_addrs()
        .with_context(|| format!("resolving hostname '{hostname}'"))?
        .next()
        .with_context(|| format!("no addresses found for '{hostname}'"))?;

    Ok(addr.ip())
}
