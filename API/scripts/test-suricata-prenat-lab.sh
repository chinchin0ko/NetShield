#!/usr/bin/env bash
# Isolated namespaces; no production VPN interface or traffic is modified.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Requiere root en un equipo con iproute2 y Suricata.' >&2; exit 1; }
for cmd in ip suricata python3; do command -v "$cmd" >/dev/null || { echo "Falta $cmd" >&2; exit 1; }; done
suffix=$(python3 -c 'import secrets; print(secrets.token_hex(3))')
client="nsc-$suffix"; sensor="nss-$suffix"; left="nl$suffix"; right="nr$suffix"
workdir=$(mktemp -d); pid=''
cleanup() {
  [[ -z "$pid" ]] || { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
  ip netns del "$client" 2>/dev/null || true
  ip netns del "$sensor" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT
ip netns add "$client"
ip netns add "$sensor"
ip link add "$left" type veth peer name "$right"
ip link set "$left" netns "$client"
ip link set "$right" netns "$sensor"
ip -n "$client" addr add 10.8.0.2/24 dev "$left"
ip -n "$sensor" addr add 10.8.0.1/24 dev "$right"
ip -n "$client" link set lo up
ip -n "$sensor" link set lo up
ip -n "$client" link set "$left" up
ip -n "$sensor" link set "$right" up
cat > "$workdir/test.rules" <<'RULE'
alert udp any any -> any 53535 (msg:"NETSHIELD isolated pre-NAT test"; content:"NETSHIELD-SYNTHETIC"; sid:9900011; rev:1;)
RULE
ip netns exec "$sensor" suricata -c /etc/suricata/suricata.yaml -i "$right" -S "$workdir/test.rules" -l "$workdir" --runmode single >"$workdir/output" 2>&1 &
pid=$!
for attempt in {1..60}; do
  kill -0 "$pid" 2>/dev/null || { cat "$workdir/output" >&2; exit 1; }
  if [[ -f "$workdir/suricata.log" ]] && grep -qi 'engine started' "$workdir/suricata.log"; then break; fi
  [[ "$attempt" != 60 ]] || { cat "$workdir/output" >&2; echo 'Suricata no inició.' >&2; exit 1; }
  sleep 1
done
ip netns exec "$client" python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"NETSHIELD-SYNTHETIC", ("10.8.0.1",53535))'
for attempt in {1..10}; do
  if [[ -f "$workdir/eve.json" ]] && python3 - "$workdir/eve.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    for line in f:
        event = json.loads(line)
        if (event.get('event_type') == 'alert' and event.get('alert', {}).get('signature_id') == 9900011
            and event.get('src_ip') == '10.8.0.2' and event.get('dest_ip') == '10.8.0.1'):
            sys.exit(0)
sys.exit(1)
PY
  then echo 'OK: Suricata observó la IP privada de origen en la red aislada'; exit 0; fi
  sleep 1
done
echo 'Suricata no registró el evento esperado.' >&2
exit 1
