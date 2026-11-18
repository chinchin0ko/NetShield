#!/usr/bin/env python3
"""Restricted development bridge; intended for a forced SSH command only."""
import fcntl
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import urllib.request


def main():
    line = sys.stdin.buffer.readline(513)
    if len(line) > 512 or not line.endswith(b'\n'):
        raise ValueError('invalid request')
    data = json.loads(line)
    if set(data) != {'user_id', 'device_id'} or type(data['user_id']) is not int or not 0 < data['user_id'] < 2**63:
        raise ValueError('invalid request')
    device = data['device_id']
    if not isinstance(device, str) or not re.fullmatch(r'[0-9a-f]{32}', device):
        raise ValueError('invalid device')
    name = f"netshield-{data['user_id']}-{device}"
    # Read the manager password locally, without exposing it through process arguments.
    result = subprocess.run(['docker', 'inspect', '--format', '{{json .Config.Env}}', 'wg-easy'], check=True, capture_output=True, timeout=5)
    env = json.loads(result.stdout)
    password = next((v.partition('=')[2] for v in env if v.startswith('PASSWORD=')), '')
    if not password:
        raise RuntimeError('manager password required')
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), urllib.request.ProxyHandler({}))
    def call(path, payload=None):
        request = urllib.request.Request('http://127.0.0.1:51821' + path, data=None if payload is None else json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
        with opener.open(request, timeout=8) as response:
            return response.read(16385)
    os.makedirs('/run/netshield-wg-bridge', mode=0o700, exist_ok=True)
    with open('/run/netshield-wg-bridge/manager.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        call('/api/session', {'password': password})
        clients = json.loads(call('/api/wireguard/client'))
        matches = [x for x in clients if x.get('name') == name]
        if len(matches) > 1:
            raise RuntimeError('duplicate peer')
        if not matches:
            call('/api/wireguard/client', {'name': name})
            matches = [x for x in json.loads(call('/api/wireguard/client')) if x.get('name') == name]
        if len(matches) != 1 or not re.fullmatch(r'[0-9a-f-]{36}', matches[0]['id']):
            raise RuntimeError('peer unavailable')
        if not matches[0].get('enabled'):
            raise RuntimeError('peer disabled')
        config = call('/api/wireguard/client/' + matches[0]['id'] + '/configuration').decode()
        if len(config) > 8192 or '[Interface]' not in config or '[Peer]' not in config:
            raise RuntimeError('invalid configuration')
        sys.stdout.write(json.dumps({'config': config}) + '\n')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'error': 'VPN provisioning failed'}))
        sys.exit(1)
