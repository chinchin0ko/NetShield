#!/usr/bin/env bash
# Validate reopening during idle time using only Suricata's aggregate stats.
set -euo pipefail
[[ ${EUID} -eq 0 ]] || exit 1
work=$(mktemp -d)
ns="nsidle-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
child=''
cleanup() {
  if [[ -n "$child" ]]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
  ip netns del "$ns" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
python3 - "$work" <<'PY'
import sys,yaml
from pathlib import Path
work=Path(sys.argv[1]); c=yaml.safe_load(open('/etc/suricata/suricata.yaml'))
c['outputs']=[{'eve-log':{'enabled':True,'filetype':'regular','filename':'eve.json','types':[{'alert':{'payload':False,'packet':False}},{'stats':{'totals':True,'threads':False,'deltas':False}}]}}]
c['stats']={'enabled':True,'interval':2}
(work/'config.yaml').write_text('%YAML 1.1\n---\n'+yaml.safe_dump(c,sort_keys=False))
(work/'rules').write_text('alert udp any any -> any 5300 (msg:"NETSHIELD IDLE LAB"; content:"unlikely-test"; sid:9900087; rev:1;)\n')
PY
ip netns add "$ns"
ip -n "$ns" link set lo up
ip -n "$ns" link set lo mtu 1500
ip netns exec "$ns" suricata -c "$work/config.yaml" -i lo -S "$work/rules" -l "$work" --runmode single >"$work/output" 2>&1 &
child=$!
for _ in {1..100}; do
  [[ -s "$work/eve.json" ]] && break
  kill -0 "$child" 2>/dev/null || { cat "$work/output" >&2; exit 1; }
  sleep .1
done
[[ -s "$work/eve.json" ]] || { echo 'No llegaron estadísticas iniciales.' >&2; exit 1; }
mv "$work/eve.json" "$work/eve.pending"
kill -HUP "$child"
for _ in {1..100}; do
  [[ -s "$work/eve.json" ]] && break
  kill -0 "$child" 2>/dev/null || { cat "$work/output" >&2; exit 1; }
  sleep .1
done
[[ -s "$work/eve.json" ]] || { echo 'Suricata no reabrió el registro durante inactividad.' >&2; exit 1; }
python3 - "$work/eve.json" <<'PY'
import json,sys
assert any(json.loads(line).get('event_type')=='stats' for line in open(sys.argv[1]))
print('OK: Suricata reabrió el EVE inactivo con estadísticas agregadas, sin tráfico de usuario.')
PY
