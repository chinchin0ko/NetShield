#!/usr/bin/env bash
# The network namespace and its test-only interface disappear when this exits.
set -euo pipefail
cd "$(dirname "$0")/.."
for command in unshare ip wg python; do
  command -v "$command" >/dev/null || { echo "Falta $command" >&2; exit 1; }
done
exec unshare --user --map-root-user --net bash -c '
  set -euo pipefail
  ip link add wg-lab0 type wireguard
  NETSHIELD_WG_LAB=1 python -m pytest -q tests/integration/test_wireguard_lab.py
'
