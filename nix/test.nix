# nix/test.nix — NixOS VM integration test for kairosd
{ pkgs, kairosdModule, kairosdPackage, kairosPackage }:

pkgs.nixosTest {
  name = "kairosd-integration";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ kairosdModule ];

    networking.nftables.enable = true;

    services.kairosd = {
      enable      = true;
      package     = kairosdPackage;
      interface   = "eth0";
      knock_count = 4;
      window_secs = 30;
      skew        = 1;
      open_secs   = 60;
      replay_db   = "/var/lib/kairosd/replay.db";
      users = [
        {
          name   = "testuser";
          secret = "dGVzdC1zZWNyZXQta2Fpcm9z";   # base64 "test-secret-kairos"
        }
      ];
    };

    environment.systemPackages = [ kairosPackage ];
  };

  testScript = ''
    machine.wait_for_unit("kairosd.service")

    # Service must be running as the dedicated user, not root.
    machine.succeed("systemctl show -p MainPID kairosd.service | grep -qE 'MainPID=[1-9]'")
    pid = machine.succeed("systemctl show -p MainPID --value kairosd.service").strip()
    user = machine.succeed(f"ps -o user= -p {pid}").strip()
    assert user == "kairosd", f"expected kairosd user, got {user}"

    # systemd must report Type=notify.
    svc_type = machine.succeed(
        "systemctl show -p Type --value kairosd.service"
    ).strip()
    assert svc_type == "notify", f"expected notify type, got {svc_type}"

    # nftables table and sets must exist.
    machine.succeed("nft list table inet kairosd")

    # Replay database must have been created.
    machine.succeed("test -f /var/lib/kairosd/replay.db")

    # ── Client knock test ───────────────────────────────────────────────
    # Write the matching secret to a file.
    machine.succeed("mkdir -p /tmp/kairos-test")
    machine.succeed("echo -n 'dGVzdC1zZWNyZXQta2Fpcm9z' > /tmp/kairos-test/secret.key")

    # Write a client config.
    machine.succeed("""
        cat > /tmp/kairos-test/config.toml << 'EOF'
    [hosts.testhost]
    hostname    = "127.0.0.1"
    secret_file = "/tmp/kairos-test/secret.key"
    EOF
    """)

    # Send the knock sequence using the client.
    machine.succeed("kairos --config /tmp/kairos-test/config.toml knock testhost")

    # Verify the source IP was added to the nftables set.
    machine.succeed("nft list set inet kairosd kairos_allowed_v4 | grep -q '127.0.0.1'")
  '';
}
