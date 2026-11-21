#!/usr/bin/env python3
"""Send minimized pre-NAT sensor alerts over the private mTLS channel."""
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
import suricata_collector as common
from vpn_sensor_logrotate import truncate_consumed

EVE = Path('/var/log/netshield-vpn-sensor/eve.json')
STATE = Path('/var/lib/netshield-vpn-sensor/cursor.json')
KEY = Path('/etc/netshield-vpn-sensor/ingest.key')
URL = 'https://10.0.0.250:18443/internal/suricata/personal'
PKI = Path('/etc/netshield-proxy-client')


def healthy():
    try:
        state = subprocess.run(['systemctl', 'is-active', '--quiet', 'netshield-vpn-sensor.service'], timeout=4)
        ntp = subprocess.run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'],
                             timeout=4, capture_output=True, text=True, check=True)
        return state.returncode == 0 and ntp.stdout.strip() == 'yes'
    except (OSError, subprocess.SubprocessError):
        return False


def send(events):
    key = KEY.read_text().strip()
    if len(key) < 40:
        raise ValueError('invalid sensor key')
    context = ssl.create_default_context(cafile=str(PKI / 'ca.crt'))
    context.load_cert_chain(str(PKI / 'client.crt'), str(PKI / 'client.key'))
    request = urllib.request.Request(URL, data=json.dumps({'events': events}).encode(),
              headers={'Content-Type': 'application/json', 'X-NetShield-Client-IP': '127.0.0.1',
                       'X-NetShield-Sensor-Key': key})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError('sensor ingest failed')


def main():
    common.STATE = STATE
    try:
        cursor = json.loads(STATE.read_text())
        if set(cursor) != {'inode', 'offset'} or any(type(cursor[k]) is not int or cursor[k] < 0 for k in cursor):
            raise ValueError('invalid cursor')
    except FileNotFoundError:
        cursor = None
    while True:
        try:
            if not healthy():
                time.sleep(10)
                continue
            next_cursor, events = common.scan(EVE, cursor, include_network_threats=True)
            send(events)  # Empty batches are a heartbeat, never a detection.
            next_cursor = truncate_consumed(EVE, next_cursor)
            if next_cursor != cursor:
                common.save(next_cursor)
                cursor = next_cursor
            time.sleep(2 if events else 10)
        except (OSError, ValueError, RuntimeError) as exc:
            print('Sensor de alertas no disponible:', type(exc).__name__, file=sys.stderr, flush=True)
            time.sleep(10)


if __name__ == '__main__':
    main()
