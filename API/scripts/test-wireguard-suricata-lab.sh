#!/usr/bin/env bash
# Disposable WireGuard peers, underlay and Suricata: no live VPN traffic.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Requiere root.' >&2; exit 1; }
for command in ip wg suricata python3; do command -v "$command" >/dev/null || { echo "Falta $command" >&2; exit 1; }; done
suffix=$(python3 -c 'import secrets; print(secrets.token_hex(3))')
a="nwa-$suffix"; b="nwb-$suffix"; left="na$suffix"; right="nb$suffix"
workdir=$(mktemp -d); pid=''
cleanup() {
  [[ -z "$pid" ]] || { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
  ip netns del "$a" 2>/dev/null || true
  ip netns del "$b" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT
umask 077
ip netns add "$a"; ip netns add "$b"
ip link add "$left" type veth peer name "$right"
ip link set "$left" netns "$a"; ip link set "$right" netns "$b"
ip -n "$a" addr add 192.0.2.1/24 dev "$left"; ip -n "$b" addr add 192.0.2.2/24 dev "$right"
for ns in "$a" "$b"; do ip -n "$ns" link set lo up; ip -n "$ns" link add wg-lab0 type wireguard; done
ip -n "$a" link set "$left" up; ip -n "$b" link set "$right" up
wg genkey > "$workdir/a.key"; wg genkey > "$workdir/b.key"
pub_a=$(wg pubkey < "$workdir/a.key"); pub_b=$(wg pubkey < "$workdir/b.key")
ip netns exec "$a" wg set wg-lab0 private-key "$workdir/a.key" listen-port 51831 peer "$pub_b" allowed-ips 10.8.0.2/32 endpoint 192.0.2.2:51832
ip netns exec "$b" wg set wg-lab0 private-key "$workdir/b.key" listen-port 51832 peer "$pub_a" allowed-ips 10.8.0.1/32 endpoint 192.0.2.1:51831
ip -n "$a" addr add 10.8.0.1/24 dev wg-lab0; ip -n "$b" addr add 10.8.0.2/24 dev wg-lab0
ip -n "$a" link set wg-lab0 up; ip -n "$b" link set wg-lab0 up
ip netns exec "$b" python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"handshake", ("10.8.0.1",53535))'
cat > "$workdir/test.rules" <<'RULE'
alert udp any any -> any 53535 (msg:"NETSHIELD isolated WireGuard sensor test"; content:"NETSHIELD-SYNTHETIC"; sid:9900012; rev:1;)
RULE
ip netns exec "$a" suricata -c /etc/suricata/suricata.yaml -i wg-lab0 -S "$workdir/test.rules" -l "$workdir" --runmode single >"$workdir/output" 2>&1 &
pid=$!
for attempt in {1..60}; do
  kill -0 "$pid" 2>/dev/null || { cat "$workdir/output" >&2; exit 1; }
  if [[ -f "$workdir/suricata.log" ]] && grep -qi 'engine started' "$workdir/suricata.log"; then break; fi
  [[ "$attempt" != 60 ]] || { cat "$workdir/output" >&2; echo 'Suricata no inició.' >&2; exit 1; }
  sleep 1
done
ip netns exec "$b" python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"NETSHIELD-SYNTHETIC", ("10.8.0.1",53535))'
for attempt in {1..10}; do
  if [[ -f "$workdir/eve.json" ]] && python3 - "$workdir/eve.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    for line in f:
        event = json.loads(line)
        if (event.get('event_type') == 'alert' and event.get('alert', {}).get('signature_id') == 9900012
            and event.get('src_ip') == '10.8.0.2' and event.get('dest_ip') == '10.8.0.1'):
            sys.exit(0)
sys.exit(1)
PY
  then echo 'OK: Suricata detectó el paquete descifrado y la IP de un peer WireGuard aislado'; exit 0; fi
  sleep 1
done
echo 'Suricata no registró el evento esperado.' >&2
exit 1
