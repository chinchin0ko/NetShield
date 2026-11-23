#!/usr/bin/env bash
# Update the isolated pre-NAT sensor, preserving the last working rules.
set -euo pipefail
umask 077
base=/var/lib/netshield-vpn-sensor/rule-updates
live=/etc/netshield-vpn-sensor/rules.rules
config=/etc/netshield-vpn-sensor/suricata.yaml
builder=/usr/local/lib/netshield/build_suricata_sensor.py
service=netshield-vpn-sensor.service
install -d -m 700 "$base"
exec 9>"$base/update.lock"
flock -n 9 || { echo 'A rule update is already running.'; exit 0; }
work=$(mktemp -d "$base/staging.XXXXXXXX")
changed=0
cleanup() {
  if (( changed )); then
    echo 'Update interrupted or failed; restoring previous sensor rules.' >&2
    install -m 600 "$base/last-working.rules" /etc/netshield-vpn-sensor/rules.rules.new
    mv -f /etc/netshield-vpn-sensor/rules.rules.new "$live"
    systemctl restart "$service" || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
mkdir "$work/data" "$work/output"
printf '{}\n' > "$work/update.yaml"
timeout 180 suricata-update -c "$work/update.yaml" -D "$work/data" -o "$work/output" --etopen --no-test --no-reload
python3 "$builder" "$config" "$work/output/suricata.rules" "$work/candidate"
count=$(grep -c '^alert ' "$work/candidate/rules.rules")
(( count >= 1000 && count <= 3002 )) || { echo 'Unexpected number of rules.' >&2; exit 1; }
timeout 90 suricata -T --init-errors-fatal -c "$config" -S "$work/candidate/rules.rules" -l "$work" --runmode single
if cmp -s "$live" "$work/candidate/rules.rules"; then
  echo 'Rules are unchanged and validated.'
  exit 0
fi
install -m 600 "$live" "$base/last-working.rules"
install -m 600 "$work/candidate/rules.rules" /etc/netshield-vpn-sensor/rules.rules.new
changed=1
mv -f /etc/netshield-vpn-sensor/rules.rules.new "$live"
systemctl restart "$service"
for attempt in 1 2 3; do
  sleep 5
  pid=$(systemctl show -p MainPID --value "$service")
  if ! systemctl is-active --quiet "$service" || [[ ! "$pid" =~ ^[1-9][0-9]*$ ]] || ! ps -o comm= --ppid "$pid" | grep -qx 'Suricata-Main'; then
    exit 1
  fi
done
changed=0
sha256sum "$live" | cut -d' ' -f1 > "$base/last-installed.sha256"
date -u +%FT%TZ > "$base/last-installed-at"
echo "Installed and verified $((count - 2)) threat rules."
