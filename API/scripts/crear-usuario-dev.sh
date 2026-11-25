#!/usr/bin/env bash
# Administrative development tool; passwords are entered interactively on the API host.
set -euo pipefail
key=${NETSHIELD_SSH_KEY:-"$HOME/Projects/SSH/UPVPN/ssh-key-2026-09-17.key"}
jump=${NETSHIELD_SSH_JUMP:-ubuntu@140.84.183.78}
target=${NETSHIELD_SSH_API:-ubuntu@10.0.0.250}
[[ -t 0 && -t 1 ]] || { echo 'Ejecuta este comando desde una terminal interactiva.' >&2; exit 1; }
[[ -f "$key" ]] || { echo 'No se encontró la clave administrativa de desarrollo.' >&2; exit 1; }
exec ssh -tt -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes \
  -o "ProxyCommand=ssh -i '$key' -o IdentitiesOnly=yes -o BatchMode=yes -W %h:%p '$jump'" \
  "$target" 'sudo systemd-run --quiet --wait --pty --collect -p User=netshield-api -p Group=netshield-api -p WorkingDirectory=/opt/netshield-api-dev/API -p EnvironmentFile=/etc/netshield-api-dev/app.env /opt/netshield-api-dev/venv/bin/python -m app.create_user'
