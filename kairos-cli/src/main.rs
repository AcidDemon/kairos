//! `kairos` — TOTP-derived port-knocking client.

mod config;
mod init;
mod knock;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "kairos", about = "TOTP-derived port-knocking client")]
struct Cli {
    /// Path to config file.
    #[arg(
        short, long,
        env = "KAIROS_CONFIG",
        value_name = "PATH",
        global = true,
    )]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Send a knock sequence for a configured host.
    Knock(KnockArgs),
    /// Generate a new secret and configure a host.
    Init(InitArgs),
    /// Import an existing secret and configure a host.
    Add(AddArgs),
}

#[derive(clap::Args, Debug)]
struct KnockArgs {
    /// Host name from config, or arbitrary hostname with --host.
    host: Option<String>,

    /// Hostname/IP to knock (bare mode, no config needed).
    #[arg(long, value_name = "ADDR")]
    host_addr: Option<String>,

    /// Path to secret file (bare mode).
    #[arg(long, value_name = "PATH")]
    secret_file: Option<String>,

    /// Override the time window in seconds.
    #[arg(long)]
    window_secs: Option<u64>,

    /// Override the knock count.
    #[arg(long)]
    knock_count: Option<usize>,
}

#[derive(clap::Args, Debug)]
struct InitArgs {
    /// Name for this host in config.
    name: String,

    /// Hostname or IP of the server.
    hostname: String,

    /// Number of ports in the knock sequence.
    #[arg(long, default_value_t = kairos_core::DEFAULT_KNOCK_COUNT)]
    knock_count: usize,

    /// Time window in seconds.
    #[arg(long, default_value_t = kairos_core::DEFAULT_WINDOW_SECS)]
    window_secs: u64,
}

#[derive(clap::Args, Debug)]
struct AddArgs {
    /// Name for this host in config.
    name: String,

    /// Hostname or IP of the server.
    hostname: String,

    /// Path to existing secret file to import.
    #[arg(long, value_name = "PATH")]
    secret_file: String,

    /// Number of ports in the knock sequence.
    #[arg(long, default_value_t = kairos_core::DEFAULT_KNOCK_COUNT)]
    knock_count: usize,

    /// Time window in seconds.
    #[arg(long, default_value_t = kairos_core::DEFAULT_WINDOW_SECS)]
    window_secs: u64,
}

// ── Entry point ──────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let cfg_path = config::config_path(cli.config.as_deref());

    match cli.command {
        Command::Knock(args) => cmd_knock(args, &cfg_path),
        Command::Init(args) => cmd_init(args, &cfg_path),
        Command::Add(args) => cmd_add(args, &cfg_path),
    }
}

// ── Subcommands ──────────────────────────────────────────────────────────────

fn cmd_knock(args: KnockArgs, cfg_path: &std::path::Path) -> Result<()> {
    match (&args.host, &args.host_addr, &args.secret_file) {
        // Config mode: kairos knock <HOST>
        (Some(name), None, None) => {
            let cfg = config::load_config(cfg_path)?
                .ok_or_else(|| anyhow::anyhow!(
                    "config file not found: {}\nUse 'kairos init' to create one, or use bare mode with --host-addr and --secret-file.",
                    cfg_path.display()
                ))?;
            let resolved = config::resolve_host(
                &cfg,
                name,
                args.window_secs,
                args.knock_count,
            )?;
            knock::send_knock(
                &resolved.hostname,
                &resolved.secret,
                resolved.window_secs,
                resolved.knock_count,
            )
        }
        // Bare mode: kairos knock --host-addr <ADDR> --secret-file <PATH>
        (None, Some(addr), Some(secret_path)) => {
            let secret = config::load_secret(secret_path)?;
            let window_secs = args.window_secs.unwrap_or(kairos_core::DEFAULT_WINDOW_SECS);
            let knock_count = args.knock_count.unwrap_or(kairos_core::DEFAULT_KNOCK_COUNT);
            knock::send_knock(addr, &secret, window_secs, knock_count)
        }
        _ => {
            anyhow::bail!(
                "usage: kairos knock <HOST>  or  kairos knock --host-addr <ADDR> --secret-file <PATH>"
            );
        }
    }
}

fn cmd_init(args: InitArgs, cfg_path: &std::path::Path) -> Result<()> {
    init::init_host(
        &args.name,
        &args.hostname,
        args.knock_count,
        args.window_secs,
        cfg_path,
    )
}

fn cmd_add(args: AddArgs, cfg_path: &std::path::Path) -> Result<()> {
    init::add_host(
        &args.name,
        &args.hostname,
        &args.secret_file,
        args.knock_count,
        args.window_secs,
        cfg_path,
    )
}
