"""Register and manage device records belonging to one user."""
import base64
import binascii
from typing import Protocol
from app.domain.devices import Device


class DeviceRepository(Protocol):
    def create(self, user_id: int, name: str, public_key: str) -> Device: ...
    def list_for_user(self, user_id: int) -> list[Device]: ...
    def delete(self, user_id: int, device_id: int) -> bool: ...


class InvalidDevice(ValueError):
    pass


class DeviceAlreadyExists(Exception):
    pass


class DeviceService:
    def __init__(self, devices: DeviceRepository):
        self.devices = devices

    def register(self, user_id: int, name: str, public_key: str) -> Device:
        name = name.strip()
        if not 1 <= len(name) <= 100:
            raise InvalidDevice('Invalid device name')
        try:
            decoded = base64.b64decode(public_key, validate=True)
            if len(decoded) != 32 or base64.b64encode(decoded).decode() != public_key:
                raise ValueError
        except (binascii.Error, ValueError):
            raise InvalidDevice('Invalid WireGuard public key') from None
        return self.devices.create(user_id, name, public_key)

    def list(self, user_id: int) -> list[Device]:
        return self.devices.list_for_user(user_id)

    def delete(self, user_id: int, device_id: int) -> bool:
        return self.devices.delete(user_id, device_id)
