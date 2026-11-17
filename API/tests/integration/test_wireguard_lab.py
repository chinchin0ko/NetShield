"""Run only in the isolated network namespace created by test-wireguard-lab.sh."""
import os
import subprocess

import pytest

from app.application.vpn_peers import PeerService
from app.infrastructure.wireguard import WireGuardLab


def test_peer_lifecycle_in_isolated_namespace():
    if os.environ.get('NETSHIELD_WG_LAB') != '1':
        pytest.skip('Run through scripts/test-wireguard-lab.sh')
    private_key = subprocess.run(['wg', 'genkey'], check=True, capture_output=True).stdout
    public_key = subprocess.run(['wg', 'pubkey'], input=private_key, check=True, capture_output=True).stdout.decode().strip()
    gateway = WireGuardLab('wg-lab0')
    service = PeerService(gateway)
    assert gateway.list_keys() == set()
    service.provision(public_key, '10.200.200.2/32')
    assert gateway.list_keys() == {public_key}
    service.provision(public_key, '10.200.200.2/32')
    assert gateway.list_keys() == {public_key}
    service.revoke(public_key)
    assert gateway.list_keys() == set()
    service.revoke(public_key)
    assert gateway.list_keys() == set()


def test_coordinator_with_real_peer_and_recovery(tmp_path):
    if os.environ.get('NETSHIELD_WG_LAB') != '1':
        pytest.skip('Run through scripts/test-wireguard-lab.sh')
    from lab.connection import LabConnections

    private = subprocess.run(['wg', 'genkey'], check=True, capture_output=True).stdout
    public = subprocess.run(['wg', 'pubkey'], input=private, check=True, capture_output=True).stdout.decode().strip()
    gateway = WireGuardLab('wg-lab0')
    path = tmp_path / 'connections.sqlite'
    lab = LabConnections(path, PeerService(gateway))
    lab.register(1, 9, public)
    address = lab.connect(9, 1)
    assert address == '10.200.200.2/32'
    assert public in gateway.list_keys()
    restarted = LabConnections(path, PeerService(gateway))
    assert restarted.connect(9, 1) == address
    with pytest.raises(LookupError): restarted.revoke(10, 1)
    assert public in gateway.list_keys()
    restarted.revoke(9, 1)
    assert public not in gateway.list_keys()
    assert restarted.status(9, 1) == ('revoked', None)


def test_authenticated_api_to_kernel_peer(tmp_path, monkeypatch):
    if os.environ.get('NETSHIELD_WG_LAB') != '1':
        pytest.skip('Run through scripts/test-wireguard-lab.sh')
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.application.auth import AuthService
    from app.application.devices import DeviceService
    from app.composition import get_auth_service, get_device_service
    from app.domain.devices import Device
    from app.domain.users import User
    from app.infrastructure.security import Argon2Passwords, JwtTokens
    from app.interfaces.http import router
    from lab.connection import LabConnections
    from lab.http import create_lab_router

    monkeypatch.setenv('NETSHIELD_JWT_SECRET', 'lab-only-secret-' * 4)
    private = subprocess.run(['wg', 'genkey'], check=True, capture_output=True).stdout
    public = subprocess.run(['wg', 'pubkey'], input=private, check=True, capture_output=True).stdout.decode().strip()

    class Users:
        def by_id(self, user_id): return User(user_id, f'user{user_id}', '', True)

    class Devices:
        def __init__(self): self.items = []
        def create(self, user_id, name, public_key):
            device = Device(1, user_id, name, public_key, datetime.now(timezone.utc))
            self.items.append(device)
            return device
        def list_for_user(self, user_id): return [d for d in self.items if d.user_id == user_id]

    tokens, devices = JwtTokens(), Devices()
    gateway = WireGuardLab('wg-lab0')
    connections = LabConnections(tmp_path / 'api-lab.sqlite', PeerService(gateway))
    app = FastAPI()
    app.include_router(router)
    app.include_router(create_lab_router(connections))
    app.dependency_overrides[get_auth_service] = lambda: AuthService(Users(), Argon2Passwords(), tokens)
    app.dependency_overrides[get_device_service] = lambda: DeviceService(devices)
    client = TestClient(app)
    owner = {'Authorization': 'Bearer ' + tokens.create(9)}
    other = {'Authorization': 'Bearer ' + tokens.create(10)}
    registered = client.post('/devices', headers=owner, json={'name': 'phone', 'public_key': public})
    assert registered.status_code == 201
    assert client.post('/lab/devices/1/connect').status_code == 401
    assert client.post('/lab/devices/1/connect', headers=other).status_code == 404
    connected = client.post('/lab/devices/1/connect', headers=owner)
    assert connected.json() == {'state': 'ready', 'address': '10.200.200.2/32'}
    assert client.post('/lab/devices/1/connect', headers=owner).json() == connected.json()
    assert public in gateway.list_keys()
    assert client.post('/lab/devices/1/revoke', headers=other).status_code == 404
    assert client.post('/lab/devices/1/revoke', headers=owner).json() == {'state': 'revoked'}
    assert public not in gateway.list_keys()
