#!/usr/bin/env python3
"""Collect selected server-wide EVE alerts; never exposes them to VPN users."""
import json
import ipaddress
import os
import re
import ssl
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

EVE = Path('/var/log/suricata/eve.json')
STATE = Path('/var/lib/netshield-suricata/cursor.json')
URL = 'https://10.0.0.250:18443/internal/suricata/alerts'
PKI = Path('/etc/netshield-proxy-client')
MAX_LINE = 256 * 1024


def relevant(line, *, include_network_threats=False):
    try:
        event = json.loads(line)
        alert = event.get('alert', {})
        signature = alert.get('signature', '')
        if event.get('event_type') != 'alert' or not isinstance(signature, str):
            return None
        labels = ('MALWARE', 'TROJAN', 'EXPLOIT', 'CNC', 'PHISHING') if include_network_threats else ('MALWARE', 'TROJAN', 'EXPLOIT')
        if not any(re.search(r'\b' + label + r'\b', signature.upper()) for label in labels):
            return None
        severity = alert['severity']
        timestamp = event['timestamp']
        # Python versions before 3.11 reject Suricata offsets such as +0000.
        if isinstance(timestamp, str):
            timestamp = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', timestamp)
        if not 1 <= len(signature) <= 1024 or type(severity) is not int or not 1 <= severity <= 255:
            return None
        if datetime.fromisoformat(timestamp.replace('Z', '+00:00')).tzinfo is None:
            return None
        for address in (event.get('src_ip'), event.get('dest_ip')):
            if address is not None:
                ipaddress.ip_address(address)
        return {'event_type': 'alert', 'timestamp': timestamp,
                'src_ip': event.get('src_ip'), 'dest_ip': event.get('dest_ip'),
                'alert': {'signature': signature, 'severity': severity}}
    except (ValueError, TypeError, AttributeError, KeyError):
        return None


def scan(path, cursor, limit=500, *, include_network_threats=False):
    events = []
    with path.open('rb') as source:
        stat = os.fstat(source.fileno())
        # New installations begin at EOF; a new file after rotation begins at zero.
        position = stat.st_size if cursor is None else (cursor['offset'] if cursor['inode'] == stat.st_ino else 0)
        if position > stat.st_size:
            position = 0
        source.seek(position)
        for _ in range(limit):
            before = source.tell()
            line = source.readline(MAX_LINE + 1)
            if not line:
                break
            if not line.endswith(b'\n'):
                if len(line) <= MAX_LINE:
                    source.seek(before)
                    break
                while line and not line.endswith(b'\n'):
                    line = source.readline(MAX_LINE + 1)
                if not line:
                    source.seek(before)
                    break
                continue
            if len(line) <= MAX_LINE:
                event = relevant(line, include_network_threats=include_network_threats)
                if event is not None:
                    events.append(event)
                    if len(events) == 25:
                        break
        return {'inode': stat.st_ino, 'offset': source.tell()}, events


def save(cursor):
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = STATE.with_suffix('.tmp')
    with temp.open('w') as output:
        os.chmod(temp, 0o600)
        json.dump(cursor, output)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temp, STATE)
    directory_fd = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def send(events):
    context = ssl.create_default_context(cafile=str(PKI / 'ca.crt'))
    context.load_cert_chain(str(PKI / 'client.crt'), str(PKI / 'client.key'))
    request = urllib.request.Request(URL, data=json.dumps({'events': events}).encode(),
              headers={'Content-Type': 'application/json', 'X-NetShield-Client-IP': '127.0.0.1'})
    # Avoid ambient HTTP proxy configuration for private IPs.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError('ingest failed')


def main():
    try:
        cursor = json.loads(STATE.read_text())
        if set(cursor) != {'inode', 'offset'} or any(type(cursor[k]) is not int or cursor[k] < 0 for k in cursor):
            raise ValueError('invalid cursor')
    except FileNotFoundError:
        cursor = None
    while True:
        try:
            next_cursor, events = scan(EVE, cursor)
            if events:
                send(events)
            if next_cursor != cursor:
                save(next_cursor)
                cursor = next_cursor
            time.sleep(2 if events else 10)
        except (OSError, ValueError, RuntimeError) as exc:
            print('No se pudo procesar o entregar alertas:', type(exc).__name__, file=sys.stderr, flush=True)
            time.sleep(15)


if __name__ == '__main__':
    main()
