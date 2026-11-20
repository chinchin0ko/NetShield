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

DEVICE = re.compile(r'[0-9a-f]{32}\Z')
MAX_ACTIVE_DEVICES = 5
MAX_TOTAL_DEVICES = 20


def device_limit_reached(clients, prefix):
    owned = [c for c in clients if isinstance(c.get('name'), str)
             and c['name'].startswith(prefix) and DEVICE.fullmatch(c['name'][len(prefix):])]
    return len(owned) >= MAX_TOTAL_DEVICES or sum(c.get('enabled') is not False for c in owned) >= MAX_ACTIVE_DEVICES


def user_usage(clients, transfer_output, prefix):
    transfers = {}
    for row in transfer_output.splitlines():
        fields = row.split('\t')
        if len(fields) != 3 or fields[0] in transfers:
            raise RuntimeError('invalid WireGuard counters')
        received, sent = int(fields[1]), int(fields[2])
        if not 0 <= received < 2**63 or not 0 <= sent < 2**63:
            raise RuntimeError('invalid WireGuard counters')
        transfers[fields[0]] = (received, sent)
    devices = []
    for client in clients:
        name = client.get('name')
        if not isinstance(name, str) or not name.startswith(prefix):
            continue
        device_id = name[len(prefix):]
        if not DEVICE.fullmatch(device_id) or client.get('enabled') is not True:
            continue
        counters = transfers.get(client.get('publicKey'))
        devices.append({'device_id': device_id,
                        'upload_bytes': counters[0] if counters is not None else None,
                        'download_bytes': counters[1] if counters is not None else None})
    return devices


def main():
    line = sys.stdin.buffer.readline(513)
    if len(line) > 512 or not line.endswith(b'\n'):
        raise ValueError('invalid request')
    data = json.loads(line)
    if not isinstance(data, dict) or type(data.get('user_id')) is not int or not 0 < data['user_id'] < 2**63:
        raise ValueError('invalid request')
    op = data.get('op', 'provision')
    expected = {'op', 'user_id'} if op in {'list', 'usage'} else {'op', 'user_id', 'device_id'}
    if op == 'provision' and 'public_key' in data:
        expected.add('public_key')
    if op == 'provision' and 'op' not in data:
        expected.remove('op')
    if op not in {'provision', 'list', 'usage', 'revoke'} or set(data) != expected:
        raise ValueError('invalid operation')
    device = data.get('device_id')
    if op not in {'list', 'usage'} and (not isinstance(device, str) or not DEVICE.fullmatch(device)):
        raise ValueError('invalid device')
    public_key = data.get('public_key')
    if public_key is not None:
        import base64
        raw = base64.b64decode(public_key, validate=True)
        if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != public_key:
            raise ValueError('invalid public key')
    prefix = f"netshield-{data['user_id']}-"
    name = prefix + device if device else None
    result = subprocess.run(['docker', 'inspect', '--format', '{{json .Config.Env}}', 'wg-easy'], check=True, capture_output=True, timeout=5)
    password = next((v.partition('=')[2] for v in json.loads(result.stdout) if v.startswith('PASSWORD=')), '')
    if not password:
        raise RuntimeError('manager password required')
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), urllib.request.ProxyHandler({}))
    def call(path, payload=None, method=None):
        request = urllib.request.Request('http://127.0.0.1:51821' + path, data=None if payload is None else json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method=method)
        with opener.open(request, timeout=8) as response:
            return response.read(262145)
    os.makedirs('/run/netshield-wg-bridge', mode=0o700, exist_ok=True)
    with open('/run/netshield-wg-bridge/manager.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        call('/api/session', {'password': password})
        clients = json.loads(call('/api/wireguard/client'))
        if op == 'list':
            devices = [{'device_id': c['name'][len(prefix):], 'enabled': c['enabled'], 'created_at': c['createdAt']} for c in clients
                       if c.get('name', '').startswith(prefix) and DEVICE.fullmatch(c['name'][len(prefix):])]
            sys.stdout.write(json.dumps({'devices': devices}) + '\n')
            return
        if op == 'usage':
            # wg reports bytes received by the server first, then sent by it.
            # Never return peer keys or other users' counters.
            result = subprocess.run(['docker', 'exec', 'wg-easy', 'wg', 'show', 'wg0', 'transfer'],
                                    check=True, capture_output=True, text=True, timeout=5)
            sys.stdout.write(json.dumps({'devices': user_usage(clients, result.stdout, prefix)}) + '\n')
            return
        matches = [x for x in clients if x.get('name') == name]
        if len(matches) > 1:
            raise RuntimeError('duplicate peer')
        if op == 'provision' and public_key is not None and any(
            peer.get('publicKey') == public_key and peer.get('name') != name for peer in clients
        ):
            sys.stdout.write(json.dumps({'error': 'key_conflict'}) + '\n')
            return
        if op == 'revoke':
            if not matches:
                sys.stdout.write(json.dumps({'found': False}) + '\n')
                return
            client_id = matches[0]['id']
            if not re.fullmatch(r'[0-9a-f-]{36}', client_id):
                raise RuntimeError('invalid peer')
            if matches[0].get('enabled'):
                call('/api/wireguard/client/' + client_id + '/disable', {})
            sys.stdout.write(json.dumps({'found': True}) + '\n')
            return
        if not matches:
            # The lock also serializes this check with peer creation.
            if device_limit_reached(clients, prefix):
                sys.stdout.write(json.dumps({'error': 'device_limit'}) + '\n')
                return
            if public_key is None:
                call('/api/wireguard/client', {'name': name})
            else:
                call('/api/wireguard/client-external', {'name': name, 'publicKey': public_key})
            matches = [x for x in json.loads(call('/api/wireguard/client')) if x.get('name') == name]
        if len(matches) != 1 or not re.fullmatch(r'[0-9a-f-]{36}', matches[0]['id']):
            raise RuntimeError('peer unavailable')
        if not matches[0].get('enabled'):
            sys.stdout.write(json.dumps({'error': 'revoked'}) + '\n')
            return
        if public_key is not None and (matches[0].get('publicKey') != public_key or matches[0].get('downloadableConfig')):
            call('/api/wireguard/client/' + matches[0]['id'] + '/public-key', {'publicKey': public_key}, method='PUT')
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
