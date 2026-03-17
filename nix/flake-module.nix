# nix/flake-module.nix
#
# flake-parts module that wires together:
#   - per-system packages (kairos, kairosd)
#   - a development shell
#   - the system-agnostic nixosModules export
{ inputs, ... }: {

  perSystem = { system, pkgs, lib, ... }: let
    rustPkgs = import inputs.nixpkgs {
      inherit system;
      overlays = [ inputs.rust-overlay.overlays.default ];
    };

    # Pin to the stable toolchain declared in rust-toolchain.toml if present,
    # otherwise fall back to the latest stable.
    rustToolchain = rustPkgs.rust-bin.stable.latest.default;

    rustPlatform = rustPkgs.makeRustPlatform {
      cargo = rustToolchain;
      rustc = rustToolchain;
    };

    # Read the version from the workspace manifest to keep it as a single
    # source of truth.
    workspaceVersion =
      (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package.version;

    # Common arguments shared between both derivations.
    commonArgs = {
      version = workspaceVersion;
      src     = lib.cleanSource ../.;

      # Cargo.lock must be present and committed for reproducible builds.
      cargoLock.lockFile = ../Cargo.lock;

      # Native build inputs needed by transitive C dependencies.
      nativeBuildInputs = with pkgs; [ pkg-config ];
      buildInputs       = with pkgs; [ libpcap ];
    };

    # Client knock binary.
    kairos = rustPlatform.buildRustPackage (commonArgs // {
      pname        = "kairos";
      cargoBuildFlags = [ "--bin" "kairos" ];

      meta = with lib; {
        description   = "TOTP-derived port-knocking client";
        license       = licenses.mit;
        maintainers   = [];
        platforms     = platforms.linux;
      };
    });

    # Server daemon.
    kairosd = rustPlatform.buildRustPackage (commonArgs // {
      pname        = "kairosd";
      cargoBuildFlags = [ "--bin" "kairosd" ];

      meta = with lib; {
        description   = "TOTP-derived port-knocking daemon";
        license       = licenses.mit;
        maintainers   = [];
        platforms     = platforms.linux;
        # Remind packagers this needs CAP_NET_RAW + CAP_NET_ADMIN at runtime.
        mainProgram   = "kairosd";
      };
    });
  in {
    # ── Packages ───────────────────────────────────────────────────────────
    packages = {
      inherit kairos kairosd;

      default = pkgs.symlinkJoin {
        name  = "kairos-suite";
        paths = [ kairos kairosd ];
      };
    };

    # ── Integration test ─────────────────────────────────────────────────
    checks.integration = import ./test.nix {
      inherit pkgs;
      kairosdModule  = ./module.nix;
      kairosdPackage = kairosd;
      kairosPackage  = kairos;
    };

    # ── Dev shell ──────────────────────────────────────────────────────────
    devShells.default = pkgs.mkShell {
      name = "kairos-dev";

      packages = with pkgs; [
        rustToolchain
        pkg-config
        libpcap
        nftables   # `nft` CLI for manual testing
        cargo-watch
        cargo-nextest
      ];

      # Make libpcap findable by the build script.
      PKG_CONFIG_PATH = "${pkgs.libpcap}/lib/pkgconfig";

      shellHook = ''
        echo "kairos dev shell — cargo $(cargo --version)"
      '';
    };
  };

  # ── NixOS module (system-agnostic) ──────────────────────────────────────
  flake.nixosModules = {
    kairosd        = import ./module.nix;
    default        = import ./module.nix;
  };
}
