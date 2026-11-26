#!/usr/bin/env bash
# Simulate silent loss of direct WireGuard UDP without changing the host network.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
transport=${WSTUNNEL_BINARY:-/usr/lib/netshield/wstunnel}
if [[ ! -x "$transport" ]]; then
  transport="$root/app/build/transport/wstunnel"
fi
[[ -x "$transport" ]] || { echo 'Falta wstunnel: instala NetShield o define WSTUNNEL_BINARY.' >&2; exit 1; }
for dependency in python3 unshare ip wg nft ping dig curl; do
  command -v "$dependency" >/dev/null || { echo "Falta $dependency." >&2; exit 1; }
done
cat <<'INFO'
NetShield: simulación de restricción UDP de la universidad
1. Verificar WireGuard directo, DNS y HTTPS sin restricciones.
2. Descartar datagramas UDP directos en el relay aislado y comprobar el fallo.
3. Usar el mismo peer por HTTPS/TCP 443 manteniendo la restricción UDP.
4. Interrumpir y recuperar HTTPS sin retirar el bloqueo.

No modifica el Wi-Fi, las rutas ni el firewall de tu equipo.
Usa el servidor real de desarrollo y crea una cuenta de prueba; el peer se revoca
al terminar. Simula pérdida silenciosa de UDP, no DPI ni la política exacta de
la universidad. No controla la ventana de la app ni cambia sus ajustes.
INFO
exec python3 "$root/API/scripts/test-vpn-https-e2e.py" --university --wstunnel "$transport"
