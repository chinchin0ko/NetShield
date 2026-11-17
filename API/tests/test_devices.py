import base64
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from app.application.auth import AuthService
from app.application.devices import DeviceService, InvalidDevice
from app.composition import get_auth_service, get_device_service
from app.domain.devices import Device
from app.domain.users import User
from app.infrastructure.security import Argon2Passwords, JwtTokens
from app.main import app


class Users:
    def by_id(self, user_id):
        return User(user_id, f'user{user_id}', '', True)


class Devices:
    def __init__(self): self.items = []
    def create(self, user_id, name, public_key):
        device = Device(len(self.items) + 1, user_id, name, public_key, datetime.now(timezone.utc))
        self.items.append(device)
        return device
    def list_for_user(self, user_id): return [d for d in self.items if d.user_id == user_id]
    def delete(self, user_id, device_id):
        match = next((d for d in self.items if d.user_id == user_id and d.id == device_id), None)
        if not match: return False
        self.items.remove(match)
        return True


def test_device_key_validation():
    service = DeviceService(Devices())
    with pytest.raises(InvalidDevice): service.register(1, 'Phone', 'bad')
    with pytest.raises(InvalidDevice): service.register(1, ' ', base64.b64encode(b'x' * 32).decode())


def test_device_access_is_limited_to_owner(monkeypatch):
    monkeypatch.setenv('NETSHIELD_JWT_SECRET', 'x' * 40)
    tokens = JwtTokens()
    devices = Devices()
    app.dependency_overrides[get_auth_service] = lambda: AuthService(Users(), Argon2Passwords(), tokens)
    app.dependency_overrides[get_device_service] = lambda: DeviceService(devices)
    try:
        client = TestClient(app)
        alice = {'Authorization': 'Bearer ' + tokens.create(1)}
        bob = {'Authorization': 'Bearer ' + tokens.create(2)}
        key = base64.b64encode(b'x' * 32).decode()
        response = client.post('/devices', headers=alice, json={'name': 'phone', 'public_key': key})
        assert response.status_code == 201
        device_id = response.json()['id']
        assert len(client.get('/devices', headers=alice).json()) == 1
        assert client.get('/devices', headers=bob).json() == []
        assert client.delete(f'/devices/{device_id}', headers=bob).status_code == 404
        assert client.delete(f'/devices/{device_id}', headers=alice).status_code == 204
        assert client.get('/devices').status_code == 401
    finally:
        app.dependency_overrides.clear()
