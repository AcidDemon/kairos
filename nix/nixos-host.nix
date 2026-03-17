# example/nixos-host.nix
#
# Illustrative NixOS configuration showing the three secret strategies.
#
# Flake snippet:
#   inputs.kairos.url = "github:yourorg/kairos";
#   nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
#     modules = [ kairos.nixosModules.kairosd ./nixos-host.nix ];
#   };

{ config, pkgs, ... }:

{
  # ── Network ──────────────────────────────────────────────────────────────
  networking.nftables.enable = true;
  # SSH is blocked by default — kairosd inserts per-IP allow rules.
  networking.firewall.allowedTCPPorts = [];

  # ── Secrets — three approaches, pick one per user ────────────────────────

  # 1. agenix / sops-nix → secret_file
  age.secrets."kairos-alice" = {
    file  = ./secrets/kairos-alice.age;
    owner = "root";
    mode  = "0400";
  };

  # 2. systemd-creds (TPM2-bound) → secret_credential
  #    Encrypt once with:
  #      systemd-creds encrypt --name=bob-key --with-key=tpm2 secret.hex \
  #        /etc/kairosd/credentials/bob-key.cred
  #    Then reference the encrypted file via LoadCredentialEncrypted below.
  systemd.services.kairosd.serviceConfig.LoadCredentialEncrypted = [
    "bob-key:/etc/kairosd/credentials/bob-key.cred"
  ];

  # ── kairosd ──────────────────────────────────────────────────────────────
  services.kairosd = {
    enable  = true;
    # Use the kairosd package from the kairos flake:
    #   package = inputs.kairos.packages.${pkgs.system}.kairosd;
    package = pkgs.kairosd;  # assumes overlay or specialArgs

    interface  = "eth0";
    windowSecs = 30;
    knockCount = 4;
    skew       = 1;
    openSecs   = 60;
    sshPort    = 22;
    logFilter  = "info";
    openFirewall = true;   # manages the inet kairos nftables table

    users = [
      # Strategy 1: agenix-managed file
      {
        name       = "alice";
        secretFile = config.age.secrets."kairos-alice".path;
      }

      # Strategy 2: TPM2-encrypted systemd credential
      {
        name             = "bob";
        secretCredential = "bob-key";
      }

      # Strategy 3: inline (only for non-sensitive testing / CI)
      {
        name   = "ci-runner";
        secret = "replace-me-with-openssl-rand-hex-32";
      }
    ];
  };

  # ── SSH hardening ─────────────────────────────────────────────────────────
  services.openssh = {
    enable = true;
    ports  = [ 22 ];
    settings = {
      PasswordAuthentication = false;
      PermitRootLogin        = "no";
      ClientAliveInterval    = 120;
      ClientAliveCountMax    = 2;
    };
  };
}
