#!/usr/bin/env bash
# Isolated synthetic UDP events; does not inspect or change the VPN interface.
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo 'Se requiere root para crear un espacio de red aislado.' >&2; exit 1; }
for cmd in ip suricata python3; do command -v "$cmd" >/dev/null; done
work=$(mktemp -d)
ns="nsrot-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
child=''
cleanup() {
  if [[ -n "$child" ]]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
  ip netns del "$ns" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
ip netns add "$ns"
ip -n "$ns" link set lo up
ip -n "$ns" link set lo mtu 1500
cat > "$work/test.rules" <<'RULE'
alert udp any any -> any 5300 (msg:"NETSHIELD ROTATION LAB"; content:"netshield-lab"; sid:9900088; rev:1;)
RULE
ip netns exec "$ns" suricata -c /etc/suricata/suricata.yaml -i lo -S "$work/test.rules" -l "$work" --runmode single >"$work/suricata.out" 2>&1 &
child=$!
for _ in {1..50}; do
  [[ -f "$work/eve.json" ]] && break
  kill -0 "$child" 2>/dev/null || { cat "$work/suricata.out" >&2; exit 1; }
  sleep .1
done
sleep 3
kill -0 "$child" 2>/dev/null || { cat "$work/suricata.out" >&2; exit 1; }
ip netns exec "$ns" python3 - "$work" "$child" "${NETSHIELD_SENSOR_ROTATE_MODULE:-/usr/local/lib/netshield/vpn_sensor_logrotate.py}" <<'PY'
import importlib.util, os, socket, sys, time
from pathlib import Path
work, child = sys.argv[1], int(sys.argv[2])
spec = importlib.util.spec_from_file_location("netshield_rotation", sys.argv[3])
rotation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rotation)
def send(i):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.bind(('127.0.0.1',20000+i))
    s.sendto(b'netshield-lab',('127.0.0.1',5300))
    s.close()
for i in range(10): send(i); time.sleep(.03)
time.sleep(.5)
archive = rotation.rotate(Path(work+'/eve.json'), child, max_size=1)
assert archive is not None
for i in range(10,50): send(i); time.sleep(.03)
time.sleep(2)
cursor = {'inode': archive.stat().st_ino, 'offset': archive.stat().st_size}
assert rotation.may_remove(archive, cursor, child, Path(work+'/eve.json'))
PY
python3 - "$work" <<'PY'
import json, pathlib, sys
work=pathlib.Path(sys.argv[1])
ports=set()
for file in [*work.glob('eve.pending.*'), work/'eve.json']:
    if not file.exists(): continue
    for line in file.read_text().splitlines():
        event=json.loads(line)
        if event.get('event_type')=='alert' and event.get('alert',{}).get('signature_id')==9900088:
            ports.add(event['src_port'])
missing=set(range(20000,20050))-ports
if missing: raise SystemExit('Faltan eventos sintéticos durante la rotación: '+str(len(missing)))
print('OK: 50 eventos sintéticos conservados a través de la rotación y reapertura de Suricata.')
PY
