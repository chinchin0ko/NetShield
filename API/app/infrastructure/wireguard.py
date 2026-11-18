"""Experimental WireGuard adapter. Use only on an isolated lab interface.

This adapter does not persist configuration or coordinate with wg-easy and is
not suitable for production. It intentionally never reads private keys.
"""
import ipaddress
import re
import subprocess


class WireGuardLab:
    def __init__(self, interface: str):
        if not re.fullmatch(r'wg-lab[0-9a-z-]{0,9}', interface):
            raise ValueError('Only wg-lab interfaces are permitted')
        self.interface = interface

    def _run(self, *args: str) -> str:
        result = subprocess.run(['wg', *args], check=True, capture_output=True, text=True, timeout=5)
        return result.stdout

    def add(self, public_key: str, address: str) -> None:
        # Defense in depth: WireGuard would silently move a duplicate route to
        # the latest peer. This is not atomic; an exclusive writer is required.
        network = ipaddress.ip_network(address, strict=False)
        for line in self._run('show', self.interface, 'allowed-ips').splitlines():
            peer, routes = line.split('\t', 1)
            if peer == public_key or routes == '(none)':
                continue
            for route in routes.split(','):
                existing = ipaddress.ip_network(route.strip(), strict=False)
                if existing.version == network.version and existing.overlaps(network):
                    raise ValueError('Peer route overlaps another peer')
        self._run('set', self.interface, 'peer', public_key, 'allowed-ips', address)

    def remove(self, public_key: str) -> None:
        self._run('set', self.interface, 'peer', public_key, 'remove')

    def list_keys(self) -> set[str]:
        return set(self._run('show', self.interface, 'peers').splitlines())
