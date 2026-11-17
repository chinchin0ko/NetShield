"""Experimental WireGuard adapter. Use only on an isolated lab interface.

This adapter does not persist configuration or coordinate with wg-easy and is
not suitable for production. It intentionally never reads private keys.
"""
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
        self._run('set', self.interface, 'peer', public_key, 'allowed-ips', address)

    def remove(self, public_key: str) -> None:
        self._run('set', self.interface, 'peer', public_key, 'remove')

    def list_keys(self) -> set[str]:
        return set(self._run('show', self.interface, 'peers').splitlines())
