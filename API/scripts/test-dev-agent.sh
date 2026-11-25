#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
for command in unshare ip wg python; do command -v "$command" >/dev/null || { echo "Falta $command" >&2; exit 1; }; done
exec unshare --user --map-root-user --net env NETSHIELD_AGENT_LAB=1 python -m pytest -q tests/integration/test_dev_agent.py
