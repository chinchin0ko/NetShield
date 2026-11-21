#!/usr/bin/env python3
"""Send minimized pre-NAT sensor alerts over the private mTLS channel."""
import json
import os
import signal
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
import suricata_collector as common
from vpn_sensor_logrotate import may_remove, pending_files, rotate

EVE = Path('/var/log/netshield-vpn-sensor/eve.json')
STATE = Path('/var/lib/netshield-vpn-sensor/cursor.json')
KEY = Path('/etc/netshield-vpn-sensor/ingest.key')
URL = 'https://10.0.0.250:18443/internal/suricata/personal'
PKI = Path('/etc/netshield-proxy-client')
_reopen_requested_pid = None


def healthy():
    try:
        state = subprocess.run(['systemctl', 'is-active', '--quiet', 'netshield-vpn-sensor.service'], timeout=4)
        ntp = subprocess.run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'],
                             timeout=4, capture_output=True, text=True, check=True)
        return state.returncode == 0 and ntp.stdout.strip() == 'yes'
    except (OSError, subprocess.SubprocessError):
        return False


def sensor_pid():
    result = subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', 'netshield-vpn-sensor.service'],
                            timeout=4, capture_output=True, text=True, check=True)
    main_pid = int(result.stdout.strip())
    if main_pid <= 0:
        return None
    children = Path(f'/proc/{main_pid}/task/{main_pid}/children').read_text().split()
    for child in children:
        try:
            if Path(f'/proc/{child}/comm').read_text().strip() == 'Suricata-Main':
                return int(child)
        except FileNotFoundError:
            continue
    return None


def process_one(cursor):
    global _reopen_requested_pid
    pid = sensor_pid()
    if EVE.exists():
        _reopen_requested_pid = None
    elif pid is not None and pid != _reopen_requested_pid:
        try:
            os.kill(pid, signal.SIGHUP)
            _reopen_requested_pid = pid
        except ProcessLookupError:
            pass
    pending = pending_files(EVE.parent)
    target = pending[0] if pending else EVE
    if not target.exists():
        raise FileNotFoundError('sensor log not yet open')
    # Missing cursor means replay, not skip. The server deduplicates by hash.
    initial = cursor if cursor is not None else {'inode': 0, 'offset': 0}
    next_cursor, events = common.scan(target, initial, include_network_threats=True)
    send(events)
    if next_cursor != cursor:
        common.save(next_cursor)
        cursor = next_cursor
    if pending:
        if may_remove(target, cursor, sensor_pid(), EVE):
            target.unlink()
    elif cursor['inode'] == target.stat().st_ino and cursor['offset'] == target.stat().st_size and pid is not None:
        rotate(target, pid)
    return cursor, bool(events)


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
            cursor, had_events = process_one(cursor)
            time.sleep(0.1 if had_events else 10)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            print('Sensor de alertas no disponible:', type(exc).__name__, file=sys.stderr, flush=True)
            time.sleep(10)


if __name__ == '__main__':
    main()
