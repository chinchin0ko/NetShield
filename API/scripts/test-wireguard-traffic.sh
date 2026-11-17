#!/usr/bin/env bash
# Both peers and their underlay exist only in disposable network namespaces.
set -euo pipefail
for command in unshare nsenter ip wg ping mktemp; do
  command -v "$command" >/dev/null || { echo "Falta $command" >&2; exit 1; }
done
exec unshare --user --map-root-user --net bash -c '
set -euo pipefail
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
unshare --net sleep 60 & a=$!
unshare --net sleep 60 & b=$!
ip link add wg-lab-veth-a type veth peer name wg-lab-veth-b
ip link set wg-lab-veth-a netns "$a"
ip link set wg-lab-veth-b netns "$b"
for target in "$a" "$b"; do
  nsenter -t "$target" -n ip link set lo up
  nsenter -t "$target" -n ip link add wg-lab0 type wireguard
done
nsenter -t "$a" -n ip addr add 192.0.2.1/24 dev wg-lab-veth-a
nsenter -t "$b" -n ip addr add 192.0.2.2/24 dev wg-lab-veth-b
nsenter -t "$a" -n ip link set wg-lab-veth-a up
nsenter -t "$b" -n ip link set wg-lab-veth-b up
wg genkey > "$workdir/a.key"
wg genkey > "$workdir/b.key"
pub_a=$(wg pubkey < "$workdir/a.key")
pub_b=$(wg pubkey < "$workdir/b.key")
nsenter -t "$a" -n wg set wg-lab0 private-key "$workdir/a.key" listen-port 51831 peer "$pub_b" allowed-ips 10.200.200.2/32 endpoint 192.0.2.2:51832
nsenter -t "$b" -n wg set wg-lab0 private-key "$workdir/b.key" listen-port 51832 peer "$pub_a" allowed-ips 10.200.200.1/32 endpoint 192.0.2.1:51831
nsenter -t "$a" -n ip addr add 10.200.200.1/24 dev wg-lab0
nsenter -t "$b" -n ip addr add 10.200.200.2/24 dev wg-lab0
nsenter -t "$a" -n ip link set wg-lab0 up
nsenter -t "$b" -n ip link set wg-lab0 up
nsenter -t "$a" -n ping -n -c 1 -W 5 10.200.200.2 >/dev/null
handshake=$(nsenter -t "$a" -n wg show wg-lab0 latest-handshakes | awk "{print \$2}")
[[ "$handshake" =~ ^[0-9]+$ && "$handshake" != 0 ]] || { echo "No hubo handshake" >&2; exit 1; }
echo "OK: tráfico cifrado y handshake entre peers de prueba"
nsenter -t "$b" -n wg set wg-lab0 peer "$pub_a" remove
if nsenter -t "$a" -n ping -n -c 1 -W 2 10.200.200.2 >/dev/null 2>&1; then
  echo "Error: el peer revocado todavía responde" >&2; exit 1
fi
echo "OK: tras revocar el peer ya no pasa el tráfico"
'
