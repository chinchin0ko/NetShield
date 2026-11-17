"""Complete lab test: isolated PostgreSQL + HTTP + real WireGuard peer."""
import os
import subprocess

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.application.vpn_peers import PeerService
from app.infrastructure.wireguard import WireGuardLab
from app.interfaces.http import router
from lab.http import create_lab_router
from lab.postgres_connection import PostgresLabConnections
from tests.integration.test_postgres_api import lab_database  # noqa: F401


def test_http_database_and_real_wireguard(lab_database):
    if os.environ.get('NETSHIELD_WG_LAB') != '1':
        pytest.skip('Requires an isolated WireGuard lab namespace')
    gateway = WireGuardLab('wg-lab0')
    connections = PostgresLabConnections(PeerService(gateway))
    connections.install_schema()
    app = FastAPI()
    app.include_router(router)
    app.include_router(create_lab_router(connections))
    client = TestClient(app)
    login = client.post('/auth/token', json={'username': 'integration-user', 'password': 'test passphrase 1234'})
    assert login.status_code == 200
    auth = {'Authorization': 'Bearer ' + login.json()['access_token']}
    other_login = client.post('/auth/token', json={'username': 'second-user', 'password': 'second passphrase 1234'})
    other = {'Authorization': 'Bearer ' + other_login.json()['access_token']}
    private = subprocess.run(['wg', 'genkey'], check=True, capture_output=True).stdout
    public = subprocess.run(['wg', 'pubkey'], input=private, check=True, capture_output=True).stdout.decode().strip()
    device = client.post('/devices', headers=auth, json={'name': 'lab phone', 'public_key': public})
    assert device.status_code == 201
    device_id = device.json()['id']
    assert client.post(f'/lab/devices/{device_id}/connect', headers=other).status_code == 404
    result = client.post(f'/lab/devices/{device_id}/connect', headers=auth)
    assert result.status_code == 200
    assert result.json()['address'] == '10.200.200.2/32'
    assert public in gateway.list_keys()
    gateway.remove(public)  # simulate an empty interface after restart
    assert public not in gateway.list_keys()
    assert connections.reconcile() == {'ready': 1, 'revoked': 0, 'failed': 0}
    assert public in gateway.list_keys()
    assert client.post(f'/lab/devices/{device_id}/connect', headers=auth).json() == result.json()
    assert client.post(f'/lab/devices/{device_id}/revoke', headers=auth).json() == {'state': 'revoked'}
    assert public not in gateway.list_keys()
    assert connections.status(device.json()['user_id'], device_id) == ('revoked', None)
