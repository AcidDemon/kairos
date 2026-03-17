#!/usr/bin/env bash
# contrib/provision-user.sh
#
# Generates a kairos secret for a new user, places it in the right location
# on the client, and prints the hex string to add to the server config.
#
# Usage:
#   ./provision-user.sh alice
#   ./provision-user.sh alice --output /path/to/secret  # custom path

set -euo pipefail

PROGNAME=$(basename "$0")
usage() { echo "usage: $PROGNAME <username> [--output <path>]" >&2; exit 1; }

[[ $# -lt 1 ]] && usage
USERNAME="$1"; shift

OUTPUT="${HOME}/.config/kairos/secret"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT="$2"; shift 2 ;;
    *) usage ;;
  esac
done

# ── Generate ────────────────────────────────────────────────────────────────
SECRET_HEX=$(openssl rand -hex 32)

# ── Write client secret file ────────────────────────────────────────────────
mkdir -p "$(dirname "$OUTPUT")"
# Write with mode 600 in a single operation to avoid a race window.
(umask 177; printf '%s\n' "$SECRET_HEX" > "$OUTPUT")
echo "wrote secret to: $OUTPUT  (mode 600)"

# ── Server-side instructions ────────────────────────────────────────────────
cat <<EOF

Add the following to your kairosd config (or NixOS module):

  [[users]]
  name   = "${USERNAME}"
  secret = "${SECRET_HEX}"

  # Or with secret_file (NixOS / agenix):
  # echo "${SECRET_HEX}" | agenix encrypt -i ~/.ssh/id_ed25519 > secrets/kairos-${USERNAME}.age

The client will read the secret from:
  ${OUTPUT}

Test with:
  kairos --dry-run <host>
EOF
