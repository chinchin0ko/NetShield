#!/usr/bin/env bash
# Prueba aislada de la excepcion TCP/443 del killswitch (modo TCP).
# Solo usa namespaces desechables; nunca toca el firewall ni las rutas del host.
# - Con tcp-mode, TCP 443 al servidor VPN esta permitido.
# - TCP 443 a otra IP sigue bloqueado.
# - TCP 80 al servidor sigue bloqueado (solo 443).
set -euo pipefail
for command in unshare nsenter ip nft python3; do command -v "$command" >/dev/null || { echo "Falta $command" >&2; exit 1; }; done
export NETSHIELD_KILLSWITCH_TEST_HELPER="$(realpath "$(dirname "$0")/../../app/linux/netshield/killswitch.py")"
exec unshare --user --map-root-user --mount --net bash -c '
set -euo pipefail
mount -t tmpfs -o mode=755 tmpfs /run
mount -t tmpfs -o mode=755 tmpfs /var/lib
umask 077
workdir=$(mktemp -d)
a=""; b=""
cleanup() {
  [[ -z "$a" ]] || kill "$a" 2>/dev/null || true
  [[ -z "$b" ]] || kill "$b" 2>/dev/null || true
  [[ -z "$a" ]] || wait "$a" 2>/dev/null || true
  [[ -z "$b" ]] || wait "$b" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT
unshare --net sleep 120 & a=$!
unshare --net sleep 120 & b=$!
ip link add nsw-a type veth peer name nsw-b
ip link set nsw-a netns "$a"
ip link set nsw-b netns "$b"
for target in "$a" "$b"; do
  nsenter -t "$target" -n ip link set lo up
done
nsenter -t "$a" -n ip addr add 192.0.2.1/24 dev nsw-a
nsenter -t "$b" -n ip addr add 192.0.2.2/24 dev nsw-b
nsenter -t "$a" -n ip link set nsw-a up
nsenter -t "$b" -n ip link set nsw-b up
nsenter -t "$a" -n ping -4 -c 1 -W 2 192.0.2.2 >/dev/null
# Servidor TCP en 192.0.2.2:443 (el "servidor VPN") dentro del namespace b.
nsenter -t "$b" -n python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((\"192.0.2.2\", 443))
s.listen(5)
open(\"$workdir/server-ready\", \"w\").write(\"ok\")
while True:
    try:
        conn, _ = s.accept()
        conn.sendall(b\"OK\")
        conn.close()
    except OSError:
        break
" &
for n in {1..30}; do [[ -e "$workdir/server-ready" ]] && break; sleep .1; done
[[ -e "$workdir/server-ready" ]]
# Sin bloqueo, TCP 443 al servidor funciona.
nsenter -t "$a" -n python3 -c "import socket; s=socket.create_connection((\"192.0.2.2\", 443), timeout=2); assert s.recv(2) == b\"OK\"; print(\"OK: TCP 443 al servidor sin bloqueo\")"
# Activa el bloqueo con tcp-mode (endpoint = servidor).
nsenter -t "$a" -n python3 "$NETSHIELD_KILLSWITCH_TEST_HELPER" enable ns123456789abc 192.0.2.2 tcp-mode
# La regla debe estar instalada.
nsenter -t "$a" -n nft list table inet netshield_lock | grep -q "tcp dport 443 accept"
echo "OK: regla TCP 443 instalada en el bloqueo"
# Con tcp-mode, TCP 443 al servidor sigue permitido.
nsenter -t "$a" -n python3 -c "import socket; s=socket.create_connection((\"192.0.2.2\", 443), timeout=2); assert s.recv(2) == b\"OK\"; print(\"OK: TCP 443 al servidor permitido con tcp-mode\")"
# TCP 443 a otra IP sigue bloqueado.
if nsenter -t "$a" -n python3 -c "import socket; socket.create_connection((\"192.0.2.99\", 443), timeout=2)" 2>/dev/null; then echo "Error: TCP 443 a otra IP no bloqueado" >&2; exit 1; fi
echo "OK: TCP 443 a otra IP bloqueado con tcp-mode"
# TCP 80 al servidor sigue bloqueado (solo 443).
if nsenter -t "$a" -n python3 -c "import socket; socket.create_connection((\"192.0.2.2\", 80), timeout=2)" 2>/dev/null; then echo "Error: TCP 80 al servidor no bloqueado" >&2; exit 1; fi
echo "OK: TCP 80 al servidor bloqueado con tcp-mode (solo 443)"
# Restaurar desde el estado persistente conserva tcp-mode.
nsenter -t "$a" -n nft delete table inet netshield_lock
rm /run/netshield-lock/active
nsenter -t "$a" -n python3 "$NETSHIELD_KILLSWITCH_TEST_HELPER" restore
nsenter -t "$a" -n nft list table inet netshield_lock | grep -q "tcp dport 443 accept"
nsenter -t "$a" -n python3 -c "import socket; s=socket.create_connection((\"192.0.2.2\", 443), timeout=2); assert s.recv(2) == b\"OK\"; print(\"OK: TCP 443 restaurado con tcp-mode\")"
nsenter -t "$a" -n python3 "$NETSHIELD_KILLSWITCH_TEST_HELPER" disable
test ! -e /var/lib/netshield-lock/active.json
nsenter -t "$a" -n ping -4 -c 1 -W 2 192.0.2.2 >/dev/null
echo "OK: bloqueo retirado, conectividad restaurada"
'
