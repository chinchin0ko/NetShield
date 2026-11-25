#!/usr/bin/env bash
# Connect this computer to the private development API using SSH only.
set -euo pipefail
key=${NETSHIELD_SSH_KEY:-"$HOME/Projects/SSH/UPVPN/ssh-key-2026-09-17.key"}
jump=${NETSHIELD_SSH_JUMP:-ubuntu@140.84.183.78}
target=${NETSHIELD_SSH_API:-ubuntu@10.0.0.250}
[[ -f "$key" ]] || { echo 'No se encontró la clave SSH; configure NETSHIELD_SSH_KEY.' >&2; exit 1; }
if [[ "${1:-}" == '--password' ]]; then
  exec ssh -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o "ProxyCommand=ssh -i '$key' -o IdentitiesOnly=yes -o BatchMode=yes -W %h:%p '$jump'" \
    "$target" 'cat "$HOME/netshield-dev/demo-password"'
fi
printf '\nAPI de desarrollo: http://127.0.0.1:18000/docs\n'
printf 'Mantén esta terminal abierta; Ctrl+C cierra el túnel.\n'
printf 'Usuario de prueba: demo. Para ver su contraseña, ejecuta este script con --password.\n\n'
exec ssh -N -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:18000:127.0.0.1:18000 \
  -o "ProxyCommand=ssh -i '$key' -o IdentitiesOnly=yes -o BatchMode=yes -W %h:%p '$jump'" "$target"
