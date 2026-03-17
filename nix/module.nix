# nix/module.nix — NixOS module for kairosd
#
# Changes from v1:
#   - IPv6: dual nftables sets (ipv4_addr + ipv6_addr) with a shared chain
#   - Secret sources: secret / secret_file / secret_credential (systemd)
#   - replay_db: defaults to /var/lib/kairosd/replay.db
#   - StateDirectory: systemd creates and owns /var/lib/kairosd
#   - Dedicated kairosd system user (no longer runs as root)
#   - Config generated via pkgs.formats.toml
#   - Operators wire LoadCredentialEncrypted themselves for secret_credential
{ config, lib, pkgs, ... }:

let
  cfg = config.services.kairosd;

  # ── User submodule ──────────────────────────────────────────────────────────
  userOpts = { name, ... }: {
    options = {
      name = lib.mkOption {
        type    = lib.types.str;
        default = name;
        description = "Username, must be unique.";
      };

      secret = lib.mkOption {
        type    = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Inline secret: lowercase hex string or plain passphrase.
          Stored in the Nix store — only use for non-sensitive testing.
        '';
      };

      secretFile = lib.mkOption {
        type    = lib.types.nullOr lib.types.path;
        default = null;
        description = ''
          Path to a file containing the secret (hex or passphrase).
          Compatible with agenix, sops-nix, and any tool that writes to
          /run/secrets at boot.  Never enters the Nix store.
        '';
        example = "/run/secrets/kairos/alice";
      };

      secretCredential = lib.mkOption {
        type    = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          systemd credential name.  The credential is encrypted at rest with
          a machine-specific key (optionally TPM2-bound via systemd-creds) and
          decrypted into /run/credentials/kairosd.service/<name> at service
          start.

          Provision with:
            systemd-creds encrypt --name=alice-key secret.hex alice-key.cred

          Reference the encrypted file in your NixOS config:
            systemd.services.kairosd.serviceConfig.LoadCredentialEncrypted =
              [ "alice-key:/etc/kairosd/credentials/alice-key.cred" ];
        '';
        example = "alice-key";
      };
    };
  };

  # ── Validation helper ───────────────────────────────────────────────────────
  exactlyOneSecret = u:
    let
      set = lib.filter (x: x != null) [u.secret u.secretFile u.secretCredential];
    in builtins.length set == 1;

  # ── Config file generation (idiomatic pkgs.formats.toml) ───────────────────
  tomlFormat = pkgs.formats.toml {};

  configFile = tomlFormat.generate "kairosd.toml" {
    interface   = cfg.interface;
    window_secs = cfg.windowSecs;
    knock_count = cfg.knockCount;
    skew        = cfg.skew;
    open_secs   = cfg.openSecs;
    ssh_port    = cfg.sshPort;
    log_filter  = cfg.logFilter;
    replay_db   = "/var/lib/kairosd/replay.db";
    users       = builtins.map (u: {
      name = u.name;
    } // (if u.secret != null then { secret = u.secret; }
       else if u.secretFile != null then { secret_file = toString u.secretFile; }
       else { secret_credential = u.secretCredential; }
    )) cfg.users;
  };

  # Users with inline secrets — triggers a warning.
  usersWithInlineSecrets = lib.filter (u: u.secret != null) cfg.users;

in {
  # ── Options ─────────────────────────────────────────────────────────────────
  options.services.kairosd = {
    enable = lib.mkEnableOption "kairosd TOTP-derived port-knocking daemon";

    package = lib.mkOption {
      type        = lib.types.package;
      description = "The kairosd package.";
    };

    interface = lib.mkOption {
      type        = lib.types.str;
      description = "Network interface to capture knock packets on.";
      example     = "eth0";
    };

    windowSecs = lib.mkOption {
      type    = lib.types.ints.positive;
      default = 30;
      description = "TOTP time-window size in seconds. Must match clients.";
    };

    knockCount = lib.mkOption {
      type    = lib.types.ints.between 2 16;
      default = 4;
      description = "Ports per knock sequence (2–16).";
    };

    skew = lib.mkOption {
      type    = lib.types.ints.unsigned;
      default = 1;
      description = "Clock-skew tolerance in windows (RFC 6238 §5.2).";
    };

    openSecs = lib.mkOption {
      type    = lib.types.ints.positive;
      default = 60;
      description = "Seconds to keep SSH port open after a valid knock.";
    };

    sshPort = lib.mkOption {
      type    = lib.types.port;
      default = 22;
      description = "TCP port to unlock after a successful knock sequence.";
    };

    logFilter = lib.mkOption {
      type    = lib.types.str;
      default = "info";
      description = "tracing env-filter string (overridden by RUST_LOG).";
    };

    users = lib.mkOption {
      type        = lib.types.listOf (lib.types.submodule userOpts);
      default     = [];
      description = "Users with their knock secrets.";
    };

    openFirewall = lib.mkOption {
      type    = lib.types.bool;
      default = true;
      description = ''
        Add nftables sets and chain for kairosd.  Requires
        networking.nftables.enable = true.  Disable to manage firewall rules
        yourself using contrib/kairos.nft as a reference.
      '';
    };
  };

  # ── Implementation ───────────────────────────────────────────────────────────
  config = lib.mkIf cfg.enable {

    warnings = lib.optional (usersWithInlineSecrets != [])
      ("services.kairosd: the following users have inline 'secret' values which "
      + "will be stored world-readable in the Nix store: "
      + lib.concatMapStringsSep ", " (u: u.name) usersWithInlineSecrets
      + ". Use 'secretFile' or 'secretCredential' for production deployments.");

    assertions =
      [
        {
          assertion = cfg.users != [];
          message   = "services.kairosd.users must not be empty.";
        }
        {
          assertion = config.networking.nftables.enable || !cfg.openFirewall;
          message   = "services.kairosd.openFirewall requires networking.nftables.enable = true.";
        }
      ]
      # Per-user: exactly one secret source.
      ++ builtins.map (u: {
        assertion = exactlyOneSecret u;
        message   = "services.kairosd user '${u.name}': exactly one of "
                  + "'secret', 'secretFile', or 'secretCredential' must be set.";
      }) cfg.users;

    # ── Dedicated service user ──────────────────────────────────────────────
    users.users.kairosd = {
      isSystemUser = true;
      group        = "kairosd";
      description  = "kairosd port-knocking daemon";
    };
    users.groups.kairosd = {};

    # ── nftables ─────────────────────────────────────────────────────────────
    #
    # Dual sets cover IPv4 and IPv6.  A single chain at priority filter-1
    # (runs before the default filter chain) accepts SSH from either set.
    # Entries carry per-element timeouts so they expire automatically.
    networking.nftables.tables = lib.mkIf cfg.openFirewall {
      "kairos" = {
        family  = "inet";
        content = ''
          # IPv4 source addresses authenticated by kairosd.
          set kairos_allowed_v4 {
            type  ipv4_addr
            flags timeout, interval
          }

          # IPv6 source addresses authenticated by kairosd.
          set kairos_allowed_v6 {
            type  ipv6_addr
            flags timeout, interval
          }

          # High-priority chain so the allow rules run before the default
          # policy drop in the user's main input chain.
          chain kairos_input {
            type filter hook input priority filter - 1;
            ip  saddr @kairos_allowed_v4 tcp dport ${toString cfg.sshPort} accept
            ip6 saddr @kairos_allowed_v6 tcp dport ${toString cfg.sshPort} accept
          }
        '';
      };
    };

    # ── systemd service ───────────────────────────────────────────────────────
    systemd.services.kairosd = {
      description = "kairosd TOTP-derived port-knocking daemon";
      after       = [ "network.target" "nftables.service" ];
      wants       = [ "nftables.service" ];
      wantedBy    = [ "multi-user.target" ];

      serviceConfig = {
        Type      = "notify";
        ExecStart = "${cfg.package}/bin/kairosd --config ${configFile}";
        Restart   = "on-failure";
        RestartSec = "5s";

        # /var/lib/kairosd is created and owned by the service automatically.
        StateDirectory     = "kairosd";
        StateDirectoryMode = "0700";

        # Run as a dedicated unprivileged user with only the caps it needs.
        User  = "kairosd";
        Group = "kairosd";
        AmbientCapabilities   = [ "CAP_NET_RAW" "CAP_NET_ADMIN" "CAP_IPC_LOCK" ];
        CapabilityBoundingSet = [ "CAP_NET_RAW" "CAP_NET_ADMIN" "CAP_IPC_LOCK" ];

        # NOTE: Users that set `secretCredential` must add their own
        # `LoadCredentialEncrypted` entries to this service.  See the
        # secretCredential option docs and nixos-host.nix for an example:
        #
        #   systemd.services.kairosd.serviceConfig.LoadCredentialEncrypted = [
        #     "bob-key:/etc/kairosd/credentials/bob-key.cred"
        #   ];

        # Hardening
        NoNewPrivileges         = true;
        ProtectSystem           = "strict";
        ProtectHome             = true;
        PrivateTmp              = true;
        PrivateDevices          = false;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_NETLINK" "AF_PACKET" ];
        SystemCallFilter        = "@system-service";
        LockPersonality         = true;
        MemoryDenyWriteExecute  = true;
        ProtectKernelTunables   = true;
        ProtectKernelModules    = true;
        ProtectKernelLogs       = true;
        ProtectControlGroups    = true;
        ProtectClock            = true;
        RestrictNamespaces      = true;
        RestrictRealtime        = true;
        RestrictSUIDSGID        = true;
        RemoveIPC               = true;
        SystemCallArchitectures = "native";

        Environment = [ "RUST_LOG=${cfg.logFilter}" ];
      };
    };
  };
}
