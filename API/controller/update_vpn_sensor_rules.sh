#!/usr/bin/env bash
# Update the isolated pre-NAT sensors, preserving the last working rules.
# Instance 1 (main): 8 categories + fixed rules.
# Instance 2 (AR): ATTACK_RESPONSE + WEB only, excluding every SID and
# category word the main sensor already covers, so no event alerts twice.
set -euo pipefail
umask 077

builder=/usr/local/lib/netshield/build_suricata_sensor.py
# SIDs already covered by instance 1 (TEST_RULE, ID_CHECK_RULE, the 20
# pinned ATTACK_RESPONSE rules), excluded from instance 2.
EXCLUDE_SIDS="9900099 2100498 2009245 2000499 2000500 2000501 2000502 2000503 2000504 2000505 2000506 2000507 2000508 2002809 2002810 2002811 2009210 2009211 2009579 2006417 2007725 2007726"
# Category words of instance 1; a rule carrying one of these is already
# selected there, so instance 2 must not take it too.
EXCLUDE_WORDS="MALWARE TROJAN EXPLOIT CNC PHISHING SCAN DOS CURRENT_EVENTS"

base=/var/lib/netshield-vpn-sensor/rule-updates
base_ar=/var/lib/netshield-vpn-sensor-ar/rule-updates
install -d -m 700 "$base" "$base_ar"
exec 9>"$base/update.lock"
flock -n 9 || { echo 'A rule update is already running.'; exit 0; }

work=$(mktemp -d "$base/staging.XXXXXXXX")
changed_main=0
changed_ar=0
cleanup() {
  if (( changed_main )); then
    echo 'Update interrupted or failed; restoring previous main sensor rules.' >&2
    install -m 600 "$base/last-working.rules" /etc/netshield-vpn-sensor/rules.rules.new
    mv -f /etc/netshield-vpn-sensor/rules.rules.new /etc/netshield-vpn-sensor/rules.rules
    systemctl restart netshield-vpn-sensor.service || true
  fi
  if (( changed_ar )); then
    echo 'Update interrupted or failed; restoring previous AR sensor rules.' >&2
    install -m 600 "$base_ar/last-working.rules" /etc/netshield-vpn-sensor-ar/rules.rules.new
    mv -f /etc/netshield-vpn-sensor-ar/rules.rules.new /etc/netshield-vpn-sensor-ar/rules.rules
    systemctl restart netshield-vpn-sensor-ar.service || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

mkdir "$work/data" "$work/output"
printf '{}\n' > "$work/update.yaml"
timeout 180 suricata-update -c "$work/update.yaml" -D "$work/data" -o "$work/output" --etopen --no-test --no-reload

# --- Instance 1: main sensor ---
config=/etc/netshield-vpn-sensor/suricata.yaml
live=/etc/netshield-vpn-sensor/rules.rules
service=netshield-vpn-sensor.service
python3 "$builder" "$config" "$work/output/suricata.rules" "$work/candidate"
count=$(grep -c '^alert ' "$work/candidate/rules.rules")
(( count >= 1000 && count <= 6022 )) || { echo 'Unexpected number of rules.' >&2; exit 1; }
timeout 600 suricata -T --init-errors-fatal -c "$config" -S "$work/candidate/rules.rules" -l "$work" --runmode single
if cmp -s "$live" "$work/candidate/rules.rules"; then
  echo 'Main sensor rules are unchanged and validated.'
else
  install -m 600 "$live" "$base/last-working.rules"
  install -m 600 "$work/candidate/rules.rules" /etc/netshield-vpn-sensor/rules.rules.new
  changed_main=1
  mv -f /etc/netshield-vpn-sensor/rules.rules.new "$live"
  systemctl restart "$service"
  for attempt in 1 2 3; do
    sleep 5
    pid=$(systemctl show -p MainPID --value "$service")
    if ! systemctl is-active --quiet "$service" || [[ ! "$pid" =~ ^[1-9][0-9]*$ ]] || ! ps -o comm= --ppid "$pid" | grep -qx 'Suricata-Main'; then
      exit 1
    fi
  done
  changed_main=0
  sha256sum "$live" | cut -d' ' -f1 > "$base/last-installed.sha256"
  date -u +%FT%TZ > "$base/last-installed-at"
  echo "Installed and verified $((count - 2)) threat rules."
fi

# --- Instance 2: ATTACK_RESPONSE + WEB sensor ---
config_ar=/etc/netshield-vpn-sensor-ar/suricata.yaml
live_ar=/etc/netshield-vpn-sensor-ar/rules.rules
service_ar=netshield-vpn-sensor-ar.service
python3 "$builder" "$config_ar" "$work/output/suricata.rules" "$work/candidate_ar" \
  --limit 2000 --categories ATTACK_RESPONSE WEB \
  --exclude-sids $EXCLUDE_SIDS --exclude-words $EXCLUDE_WORDS --no-fixed-rules
count_ar=$(grep -c '^alert ' "$work/candidate_ar/rules.rules")
(( count_ar >= 100 && count_ar <= 2000 )) || { echo 'Unexpected number of AR rules.' >&2; exit 1; }
timeout 600 suricata -T --init-errors-fatal -c "$config_ar" -S "$work/candidate_ar/rules.rules" -l "$work" --runmode single
if cmp -s "$live_ar" "$work/candidate_ar/rules.rules"; then
  echo 'AR sensor rules are unchanged and validated.'
else
  install -m 600 "$live_ar" "$base_ar/last-working.rules"
  install -m 600 "$work/candidate_ar/rules.rules" /etc/netshield-vpn-sensor-ar/rules.rules.new
  changed_ar=1
  mv -f /etc/netshield-vpn-sensor-ar/rules.rules.new "$live_ar"
  systemctl restart "$service_ar"
  for attempt in 1 2 3; do
    sleep 5
    pid=$(systemctl show -p MainPID --value "$service_ar")
    if ! systemctl is-active --quiet "$service_ar" || [[ ! "$pid" =~ ^[1-9][0-9]*$ ]] || ! ps -o comm= --ppid "$pid" | grep -qx 'Suricata-Main'; then
      exit 1
    fi
  done
  changed_ar=0
  sha256sum "$live_ar" | cut -d' ' -f1 > "$base_ar/last-installed.sha256"
  date -u +%FT%TZ > "$base_ar/last-installed-at"
  echo "Installed and verified $count_ar ATTACK_RESPONSE/WEB threat rules."
fi
