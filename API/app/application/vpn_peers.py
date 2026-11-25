"""Application port and use cases for peer changes (not connected to HTTP)."""
import base64
import binascii
import ipaddress
from typing import Protocol


class PeerGateway(Protocol):
    def add(self, public_key: str, address: str) -> None: ...
    def remove(self, public_key: str) -> None: ...
    def list_keys(self) -> set[str]: ...


class PeerService:
    def __init__(self, gateway: PeerGateway):
        self.gateway = gateway

    @staticmethod
    def _key(public_key: str) -> str:
        try:
            decoded = base64.b64decode(public_key, validate=True)
            if len(decoded) != 32 or not any(decoded) or base64.b64encode(decoded).decode() != public_key:
                raise ValueError
        except (binascii.Error, ValueError):
            raise ValueError('Invalid WireGuard public key') from None
        return public_key

    def provision(self, public_key: str, address: str) -> None:
        key = self._key(public_key)
        ip = ipaddress.ip_interface(address)
        if ip.version != 4 or ip.network.prefixlen != 32:
            raise ValueError('Peer address must be an IPv4 /32')
        self.gateway.add(key, str(ip))

    def revoke(self, public_key: str) -> None:
        self.gateway.remove(self._key(public_key))
