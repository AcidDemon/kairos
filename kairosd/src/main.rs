//! `kairosd` — TOTP-derived port-knocking daemon.

mod config;
mod firewall;
mod knock;
mod store;

use std::{
    net::IpAddr,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use kairos_core::windows_with_skew;
use pcap::{Capture, Device};
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    udp::UdpPacket,
    Packet,
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use config::Config;
use knock::{KnockResult, KnockTracker};
use store::ReplayStore;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "kairosd", about = "TOTP-derived port-knocking daemon")]
struct Args {
    #[arg(
        short, long,
        env = "KAIROSD_CONFIG",
        default_value = "/etc/kairosd/config.toml",
        value_name = "PATH"
    )]
    config: PathBuf,

    /// List available capture interfaces and exit.
    #[arg(long)]
    list_interfaces: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_interfaces {
        for dev in Device::list().context("listing pcap devices")? {
            println!("{}", dev.name);
        }
        return Ok(());
    }

    let config = Config::from_file(&args.config)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.log_filter)),
        )
        .init();

    info!(
        interface   = %config.interface,
        users       = config.users.len(),
        window_secs = config.window_secs,
        knock_count = config.knock_count,
        replay_db   = ?config.replay_db,
        "kairosd starting"
    );

    // Open the replay store — persistent if a path is configured, otherwise
    // in-memory (state lost on restart, but still functional).
    let mut store = match &config.replay_db {
        Some(path) => ReplayStore::open(path, config.window_secs)?,
        None => {
            tracing::warn!(
                "no replay_db configured — replay protection is in-memory only \
                 and will not survive restarts"
            );
            ReplayStore::in_memory(config.window_secs)
        }
    };

    run(&config, &mut store)
}

// ── Capture loop ──────────────────────────────────────────────────────────────

fn run(config: &Config, store: &mut ReplayStore) -> Result<()> {
    // ── Signal handling ──────────────────────────────────────────────────
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))
        .context("registering SIGTERM handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))
        .context("registering SIGINT handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&reload))
        .context("registering SIGHUP handler")?;

    // ── Packet capture setup ─────────────────────────────────────────────
    let mut cap = Capture::from_device(config.interface.as_str())
        .context("opening capture device")?
        .promisc(true)
        .snaplen(128)
        .timeout(1000)
        .open()
        .context("activating pcap capture")?;

    cap.filter("udp dst portrange 1024-65535", true)
        .context("setting BPF filter")?;

    // ── Notify systemd we are ready ──────────────────────────────────────
    if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        warn!("sd_notify READY failed: {e}");
    }

    let mut tracker = KnockTracker::new();
    let mut pkt_count: u64 = 0;
    let mut mismatch_count: u64 = 0;
    let mut mismatch_window_start = Instant::now();
    info!("listening for knock packets");

    loop {
        // Check for graceful shutdown signal.
        if shutdown.load(Ordering::Relaxed) {
            let m = tracker.metrics();
            info!(
                auth     = m.auth_success,
                replays  = m.replay_blocked,
                rate_limited = m.rate_limited,
                mismatches   = m.mismatches,
                packets  = pkt_count,
                "shutting down — final metrics"
            );
            if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]) {
                warn!("sd_notify STOPPING failed: {e}");
            }
            return Ok(());
        }

        // Check for reload signal (placeholder).
        if reload.swap(false, Ordering::Relaxed) {
            warn!("SIGHUP received — config reload not yet implemented");
        }

        match cap.next_packet() {
            Ok(packet) => {
                if let Some((src_ip, dst_port)) = parse_udp(packet.data) {
                    pkt_count += 1;
                    handle_packet(
                        &mut tracker, src_ip, dst_port, config, store,
                        &mut mismatch_count, &mut mismatch_window_start,
                    );

                    if pkt_count % 10_000 == 0 {
                        let m = tracker.metrics();
                        info!(
                            auth     = m.auth_success,
                            replays  = m.replay_blocked,
                            rate_limited = m.rate_limited,
                            mismatches   = m.mismatches,
                            packets  = pkt_count,
                            "metrics snapshot"
                        );
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                error!("pcap error: {e}");
                return Err(e.into());
            }
        }
    }
}

fn handle_packet(
    tracker:              &mut KnockTracker,
    src:                  IpAddr,
    dst_port:             u16,
    config:               &Config,
    store:                &mut ReplayStore,
    mismatch_count:       &mut u64,
    mismatch_window_start: &mut Instant,
) {
    let windows: Vec<u64> = windows_with_skew(config.window_secs, config.skew).collect();

    match tracker.process(src, dst_port, &windows, config, store) {
        KnockResult::Partial { user, progress, total } => {
            debug!(%src, %user, "{progress}/{total}");
        }
        KnockResult::Complete { user } => {
            info!(%src, %user, "authenticated — opening firewall");
            if let Err(e) = firewall::open(src, Duration::from_secs(config.open_secs)) {
                error!(%src, "failed to open firewall: {e}");
            }
        }
        KnockResult::Mismatch => {
            debug!(%src, "knock mismatch");
            *mismatch_count += 1;
            if *mismatch_count % 100 == 0 {
                let elapsed = mismatch_window_start.elapsed().as_secs();
                warn!(
                    "100 failed knock attempts in last {elapsed}s"
                );
                *mismatch_window_start = Instant::now();
            }
        }
        KnockResult::Unrelated => {}
    }
}

// ── Packet parsing ────────────────────────────────────────────────────────────

fn parse_udp(data: &[u8]) -> Option<(IpAddr, u16)> {
    let eth = EthernetPacket::new(data)?;
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ip = Ipv4Packet::new(eth.payload())?;
            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                return None;
            }
            let udp = UdpPacket::new(ip.payload())?;
            Some((IpAddr::V4(ip.get_source()), udp.get_destination()))
        }
        EtherTypes::Ipv6 => {
            let ip = Ipv6Packet::new(eth.payload())?;
            if ip.get_next_header() != IpNextHeaderProtocols::Udp {
                return None;
            }
            let udp = UdpPacket::new(ip.payload())?;
            Some((IpAddr::V6(ip.get_source()), udp.get_destination()))
        }
        _ => None,
    }
}
