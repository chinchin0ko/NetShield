#!/usr/bin/env bash
# Run the ATTACK_RESPONSE/WEB sensor inside the current wg-easy network
# namespace. Exit on container replacement. Mirrors run_vpn_sensor.sh.
set -euo pipefail
pid=$(docker inspect --format '{{.State.Pid}}' wg-easy)
[[ "$pid" =~ ^[1-9][0-9]*$ ]] || { echo 'wg-easy unavailable' >&2; exit 1; }
child=''
cleanup() { if [[ -n "$child" ]]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi; }
trap cleanup EXIT
nsenter -t "$pid" -n suricata -c /etc/netshield-vpn-sensor-ar/suricata.yaml \
  -S /etc/netshield-vpn-sensor-ar/rules.rules -i wg0 --runmode single \
  -l /var/log/netshield-vpn-sensor-ar &
child=$!
while kill -0 "$child" 2>/dev/null; do
  sleep 5
  current=$(docker inspect --format '{{.State.Pid}}' wg-easy 2>/dev/null || true)
  if [[ "$current" != "$pid" ]]; then
    echo 'wg-easy namespace changed; restarting sensor' >&2
    exit 1
  fi
done
wait "$child"
