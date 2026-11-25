#!/usr/bin/env bash
# Simulación de backend; no conecta ni modifica una VPN.
set -euo pipefail
key=${NETSHIELD_SSH_KEY:-"$HOME/Projects/SSH/UPVPN/ssh-key-2026-09-17.key"}
jump=${NETSHIELD_SSH_JUMP:-ubuntu@140.84.183.78}
target=${NETSHIELD_SSH_API:-ubuntu@10.0.0.250}
[[ -f "$key" ]] || { printf 'No se encontró la clave SSH. Configure NETSHIELD_SSH_KEY.\n' >&2; exit 1; }
printf '\nNetShield · Simulación de conexión\n'
printf 'API y PostgreSQL de pruebas en OCI; WireGuard simulado.\n\n'
ssh -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes \
  -o "ProxyCommand=ssh -i '$key' -o IdentitiesOnly=yes -o BatchMode=yes -W %h:%p '$jump'" \
  "$target" 'bash -s' <<'REMOTE'
set -euo pipefail
cd "$HOME/netshield-lab/API"
export PGPASSWORD="$(cat "$HOME/netshield-lab/db-password")"
export NETSHIELD_TEST_DSN="host=10.0.0.176 port=5432 dbname=netshield_lab user=netshield_lab sslmode=verify-full sslrootcert=$HOME/netshield-lab/postgres.crt connect_timeout=5"
printf 'Probando autenticación, dispositivo, asignación y revocación...\n'
"$HOME/netshield-lab/venv/bin/python" -m pytest -q --disable-warnings tests/integration/test_postgres_api.py tests/integration/test_postgres_connections.py
printf '\nSimulación completada. No se estableció una VPN ni se cambió el tráfico de este equipo.\n'
REMOTE
