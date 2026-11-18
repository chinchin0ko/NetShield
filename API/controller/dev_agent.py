#!/usr/bin/env python3
"""Private-network WireGuard development agent; no production routing or API access."""
import base64
import binascii
import ipaddress
import json
import os
import socketserver
import subprocess
from pathlib import Path

INTERFACE = 'wg-nsdev'
NETWORK = ipaddress.ip_network('10.254.70.0/24')
SOCKET = Path(os.environ.get('NETSHIELD_AGENT_SOCKET', '/run/netshield-wg-dev/control.sock'))
STATE = Path(os.environ.get('NETSHIELD_AGENT_STATE', '/var/lib/netshield-wg-dev'))


def run(*args, input_bytes=None):
    return subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True, timeout=5).stdout.decode().strip()


def public_key(value):
    if not isinstance(value, str):
        raise ValueError('invalid key')
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('invalid key') from None
    if len(data) != 32 or not any(data) or base64.b64encode(data).decode() != value:
        raise ValueError('invalid key')
    return value


def address(value):
    interface = ipaddress.ip_interface(value)
    if (interface.version != 4 or interface.network.prefixlen != 32 or interface.ip not in NETWORK
            or interface.ip in (NETWORK.network_address, NETWORK.broadcast_address, NETWORK.network_address + 1)):
        raise ValueError('invalid address')
    return str(interface)


def current_routes():
    peers = {}
    for line in run('wg', 'show', INTERFACE, 'allowed-ips').splitlines():
        key, routes = line.split('\t', 1)
        peers[key] = [] if routes == '(none)' else routes.split(',')
    return peers


def dispatch(message):
    if not isinstance(message, dict):
        raise ValueError('invalid request')
    op = message.get('op')
    if op == 'status' and set(message) == {'op'}:
        return {'ok': True, 'interface': INTERFACE, 'peers': len(current_routes())}
    if op == 'add' and set(message) == {'op', 'public_key', 'address'}:
        key, route = public_key(message['public_key']), address(message['address'])
        target = ipaddress.ip_network(route)
        for existing_key, routes in current_routes().items():
            if existing_key != key:
                for route_value in routes:
                    network = ipaddress.ip_network(route_value.strip())
                    if network.version == target.version and network.overlaps(target):
                        raise ValueError('address already assigned')
        run('wg', 'set', INTERFACE, 'peer', key, 'allowed-ips', route)
        return {'ok': True}
    if op == 'remove' and set(message) == {'op', 'public_key'}:
        run('wg', 'set', INTERFACE, 'peer', public_key(message['public_key']), 'remove')
        return {'ok': True}
    raise ValueError('invalid request')


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        try:
            line = self.rfile.readline(2049)
            if len(line) > 2048 or not line.endswith(b'\n'):
                raise ValueError('invalid request')
            response = dispatch(json.loads(line))
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, TimeoutError):
            response = {'ok': False, 'error': 'invalid request'}
        except (OSError, subprocess.SubprocessError):
            response = {'ok': False, 'error': 'operation failed'}
        self.wfile.write(json.dumps(response).encode() + b'\n')


def main():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = STATE / 'server.key'
    if not key.exists():
        generated = subprocess.run(['wg', 'genkey'], check=True, stdout=subprocess.PIPE, timeout=5).stdout
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(generated)
    run('ip', 'link', 'add', INTERFACE, 'type', 'wireguard')
    run('ip', 'address', 'add', '10.254.70.1/24', 'dev', INTERFACE)
    run('wg', 'set', INTERFACE, 'private-key', str(key), 'listen-port', '51822')
    run('ip', 'link', 'set', INTERFACE, 'up')
    SOCKET.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if SOCKET.exists():
        raise RuntimeError('control socket already exists')
    old_umask = os.umask(0o177)
    try:
        with socketserver.UnixStreamServer(str(SOCKET), Handler) as server:
            os.umask(old_umask)
            try:
                server.serve_forever()
            finally:
                SOCKET.unlink(missing_ok=True)
    finally:
        os.umask(old_umask)


if __name__ == '__main__':
    main()
