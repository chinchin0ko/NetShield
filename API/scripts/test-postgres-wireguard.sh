#!/usr/bin/env bash
# Needs a running disposable PostgreSQL lab; no production credentials.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${NETSHIELD_TEST_DSN:?Set NETSHIELD_TEST_DSN for the disposable netshield_lab database}"
for command in python unshare ip wg socat; do command -v "$command" >/dev/null || { echo "Falta $command" >&2; exit 1; }; done
read -r host port < <(python - <<'PY'
import os
from psycopg.conninfo import conninfo_to_dict
p = conninfo_to_dict(os.environ['NETSHIELD_TEST_DSN'])
if p.get('hostaddr', p.get('host')) != '127.0.0.1' or p.get('dbname') != 'netshield_lab':
    raise SystemExit('Expected a localhost netshield_lab database')
print('127.0.0.1', p.get('port', '5432'))
PY
)
workdir=$(mktemp -d)
relay_pid=''
cleanup() {
  [[ -z "$relay_pid" ]] || kill "$relay_pid" 2>/dev/null || true
  python -c 'import shutil, sys; shutil.rmtree(sys.argv[1])' "$workdir"
}
trap cleanup EXIT
socat UNIX-LISTEN:"$workdir/relay.sock",fork TCP:"$host":"$port" & relay_pid=$!
export NETSHIELD_RELAY_SOCKET="$workdir/relay.sock"
export NETSHIELD_TEST_DSN="$(python - <<'PY'
import os
from psycopg.conninfo import make_conninfo
print(make_conninfo(os.environ['NETSHIELD_TEST_DSN'], port='15435'))
PY
)"
for i in {1..20}; do [[ -S "$NETSHIELD_RELAY_SOCKET" ]] && break; sleep 0.1; done
unshare --user --map-root-user --net bash -c '
set -euo pipefail
ip link set lo up
ip link add wg-lab0 type wireguard
socat TCP-LISTEN:15435,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:"$NETSHIELD_RELAY_SOCKET" & relay=$!
trap "kill $relay 2>/dev/null || true" EXIT
sleep 1
NETSHIELD_WG_LAB=1 python -m pytest -q tests/integration/test_postgres_wireguard.py
'
