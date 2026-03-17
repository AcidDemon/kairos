# Kairos

TOTP-derived port knocking for Linux.

Kairos hides services (typically SSH) behind a time-based knock sequence that changes every 30 seconds. A client and server share a secret; the client derives the current sequence of UDP ports with HMAC-SHA256 and sends packets to each one in order. The daemon watches the wire with libpcap and, on a valid sequence, adds the source IP to an nftables set for a configurable duration. No listening sockets, no static ports, no permanent firewall holes.

## How it works

```
secret + floor(time / 30)
        |
        v
  HMAC-SHA256
        |
        v
  4 UDP ports (1024-65535)

Client sends UDP to each port in order.
Daemon sees the sequence via BPF → opens SSH for that IP.
```

1. Both sides compute `HMAC-SHA256(secret, window)` where `window = unix_time / window_secs`.
2. The first `knock_count` pairs of bytes from the digest are mapped to ports in the unprivileged range (1024-65535).
3. The client sends a UDP packet to each port in sequence.
4. The daemon (`kairosd`) captures UDP traffic with a BPF filter and matches incoming packets against the expected sequence for each configured user, tolerating clock skew of +/-1 window by default.
5. On a complete match, the source IP is added to an nftables set with a timeout, granting temporary access to the protected port.

Replay prevention is handled by a persistent SQLite database that records used `(user, window)` pairs across restarts.

## Components

| Crate | Description |
|-------|-------------|
| `kairos-core` | Pure-computation library: HMAC-SHA256 sequence derivation, time-window helpers. Shared by client and daemon. |
| `kairos` | Client CLI: sends knock sequences, integrates with SSH via `Match exec`, manages host configs and secrets. |
| `kairosd` | Daemon: libpcap capture, knock state machine, nftables integration, replay prevention, systemd notify support. |

## Quick start

```sh
# 1. Generate a secret and configure a host
kairos init myserver example.com

# 2. Copy the printed secret to the server's kairosd config

# 3. Add to ~/.ssh/config for transparent SSH integration
#    Match host myserver exec "kairos knock myserver"
#        Hostname example.com
#        User alice

# 4. SSH as usual — knock is sent automatically
ssh myserver
```

The `Match exec` directive runs `kairos knock` before each connection. If the knock succeeds (exit 0), SSH proceeds. This works with `scp`, `rsync`, `git+ssh`, and `ProxyJump`.

## Client configuration

`kairos` reads `~/.config/kairos/config.toml` (override with `--config` or `$KAIROS_CONFIG`).

```toml
[defaults]
window_secs = 30
knock_count = 4

[hosts.myserver]
hostname    = "example.com"
secret_file = "~/.config/kairos/secrets/myserver.key"

[hosts.staging]
hostname    = "staging.example.com"
secret_file = "~/.config/kairos/secrets/staging.key"
knock_count = 6
```

Subcommands:

| Command | Description |
|---------|-------------|
| `kairos knock <HOST>` | Send knock for a configured host |
| `kairos knock --host-addr <ADDR> --secret-file <PATH>` | Bare mode (no config needed) |
| `kairos init <NAME> <HOSTNAME>` | Generate secret, write config, print setup instructions |
| `kairos add <NAME> <HOSTNAME> --secret-file <PATH>` | Import existing secret and configure host |

## Security properties

- Secrets are held in [`zeroize`](https://docs.rs/zeroize)-backed memory that is overwritten on drop.
- `mlock(2)` pins secret pages in RAM to prevent swap.
- Supports `systemd-creds` with TPM2 binding so secrets are encrypted at rest and never touch disk as plaintext.
- Runs as a dedicated unprivileged user with only `CAP_NET_RAW`, `CAP_NET_ADMIN`, and `CAP_IPC_LOCK`.
- Hardened systemd unit: `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, restricted syscalls, etc.
- Per-IP rate limiting on first-knock attempts.
- Fail-closed: replay store errors deny the knock rather than allowing it through.

## Installation

### NixOS (recommended)

Add the flake as an input and import the module:

```nix
# flake.nix
{
  inputs.kairos.url = "github:yourorg/kairos";

  outputs = { self, nixpkgs, kairos, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        kairos.nixosModules.kairosd
        {
          networking.nftables.enable = true;

          services.kairosd = {
            enable    = true;
            package   = kairos.packages.x86_64-linux.kairosd;
            interface = "eth0";

            users = [
              {
                name             = "alice";
                secretCredential = "alice-key";  # see below
              }
            ];
          };

          # Encrypted credential (provision with systemd-creds encrypt)
          systemd.services.kairosd.serviceConfig.LoadCredentialEncrypted = [
            "alice-key:/etc/kairosd/credentials/alice-key.cred"
          ];
        }
      ];
    };
  };
}
```

Provision an encrypted credential:

```sh
echo -n 'my-shared-secret' | systemd-creds encrypt --name=alice-key - alice-key.cred
sudo cp alice-key.cred /etc/kairosd/credentials/
```

The module creates the `kairosd` system user, the nftables table/sets, and the systemd service automatically.

### From source with Cargo

Requires libpcap headers and a Rust toolchain (stable).

```sh
# Build
cargo build --release

# The daemon binary is at target/release/kairosd
# Install it somewhere on PATH
sudo install -m 755 target/release/kairosd /usr/local/bin/
```

### Nix dev shell

```sh
nix develop
cargo build
```

The dev shell provides the Rust toolchain, libpcap, nftables CLI, and cargo-watch.

## Configuration

`kairosd` reads a TOML config file (default: `/etc/kairosd/config.toml`).

```toml
interface   = "eth0"
window_secs = 30
knock_count = 4
skew        = 1
open_secs   = 60
ssh_port    = 22
log_filter  = "info"
replay_db   = "/var/lib/kairosd/replay.db"

[[users]]
name              = "alice"
secret_credential = "alice-key"

[[users]]
name        = "bob"
secret_file = "/run/secrets/kairos/bob"

[[users]]
name   = "ci-runner"
secret = "68756e74657232"
```

Each user needs exactly one secret source:

| Field | Description |
|-------|-------------|
| `secret` | Inline hex string or passphrase. Ends up in the Nix store if used with the NixOS module — only for testing. |
| `secret_file` | Path to a file containing the secret. Works with agenix, sops-nix, etc. |
| `secret_credential` | systemd credential name. Decrypted at service start from `/run/credentials/kairosd.service/<name>`. Recommended for production. |

## Running

```sh
# With the NixOS module, the service starts automatically.
# Manual invocation:
sudo kairosd --config /etc/kairosd/config.toml

# List available capture interfaces:
kairosd --list-interfaces
```

The daemon sends `sd_notify(READY)` once the capture loop is running, so the systemd unit is `Type=notify`.

## Testing

```sh
# Core library tests (no special dependencies)
cargo test -p kairos-core

# Client tests
cargo test -p kairos

# Daemon tests (requires libpcap headers for linking)
cargo test -p kairosd

# NixOS VM integration test
nix flake check
```

## License

MIT
