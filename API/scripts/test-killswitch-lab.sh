#!/usr/bin/env bash
# Disposable namespaces only; never changes the host firewall or host routes.
set -euo pipefail
for command in unshare nsenter ip wg ping nft; do command -v "$command" >/dev/null || { echo "Falta $command" >&2; exit 1; }; done
export NETSHIELD_KILLSWITCH_TEST_HELPER="$(realpath "$(dirname "$0")/../../app/linux/netshield/killswitch.py")"
exec unshare --user --map-root-user --mount --net bash -c '
set -euo pipefail
mount -t tmpfs -o mode=755 tmpfs /run
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
  nsenter -t "$target" -n ip link add ns123456789abc type wireguard
done
nsenter -t "$a" -n ip addr add 192.0.2.1/24 dev nsw-a
nsenter -t "$b" -n ip addr add 192.0.2.2/24 dev nsw-b
nsenter -t "$a" -n ip -6 addr add fd42::1/64 dev nsw-a nodad
nsenter -t "$b" -n ip -6 addr add fd42::2/64 dev nsw-b nodad
nsenter -t "$a" -n ip link set nsw-a up
nsenter -t "$b" -n ip link set nsw-b up
wg genkey > "$workdir/a.key"
wg genkey > "$workdir/b.key"
pub_a=$(wg pubkey < "$workdir/a.key")
pub_b=$(wg pubkey < "$workdir/b.key")
nsenter -t "$a" -n wg set ns123456789abc private-key "$workdir/a.key" listen-port 51831 peer "$pub_b" allowed-ips 10.200.200.2/32 endpoint 192.0.2.2:51820
nsenter -t "$b" -n wg set ns123456789abc private-key "$workdir/b.key" listen-port 51820 peer "$pub_a" allowed-ips 10.200.200.1/32 endpoint 192.0.2.1:51831
nsenter -t "$a" -n ip addr add 10.200.200.1/24 dev ns123456789abc
nsenter -t "$b" -n ip addr add 10.200.200.2/24 dev ns123456789abc
nsenter -t "$a" -n ip link set ns123456789abc up
nsenter -t "$b" -n ip link set ns123456789abc up
nsenter -t "$a" -n ping -4 -c 1 -W 2 192.0.2.2 >/dev/null
nsenter -t "$a" -n ping -6 -c 1 -W 2 fd42::2 >/dev/null
nsenter -t "$a" -n python3 "$NETSHIELD_KILLSWITCH_TEST_HELPER" enable ns123456789abc 192.0.2.2
nsenter -t "$a" -n ping -4 -c 1 -W 3 10.200.200.2 >/dev/null
echo "OK: el tráfico por WireGuard funciona con el bloqueo activo"
if nsenter -t "$a" -n ping -4 -c 1 -W 1 192.0.2.2 >/dev/null 2>&1; then echo "Error: fuga IPv4" >&2; exit 1; fi
if nsenter -t "$a" -n ping -6 -c 1 -W 1 fd42::2 >/dev/null 2>&1; then echo "Error: fuga IPv6" >&2; exit 1; fi
nsenter -t "$a" -n ip link set ns123456789abc down
if nsenter -t "$a" -n ping -4 -c 1 -W 1 192.0.2.2 >/dev/null 2>&1; then echo "Error: fuga con VPN caída" >&2; exit 1; fi
echo "OK: IPv4 e IPv6 directos bloqueados incluso con el túnel caído"
nsenter -t "$a" -n python3 "$NETSHIELD_KILLSWITCH_TEST_HELPER" disable
nsenter -t "$a" -n ping -4 -c 1 -W 2 192.0.2.2 >/dev/null
echo "OK: conectividad restaurada al retirar el bloqueo de prueba"
'
