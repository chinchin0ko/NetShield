import pytest
from fastapi.testclient import TestClient

from app.application.auth import AuthService
from app.domain.users import User
from app.infrastructure.security import Argon2Passwords, JwtTokens
from app.interfaces.http import get_auth_service
from app.main import app
from controller.wg_easy_bridge import user_usage


def test_usage_is_scoped_to_owner_and_marks_unavailable():
    mine, other, missing, revoked = ('a' * 32, 'b' * 32, 'c' * 32, 'd' * 32)
    clients = [
        {'name': 'netshield-7-' + mine, 'publicKey': 'key-mine', 'enabled': True},
        {'name': 'netshield-8-' + other, 'publicKey': 'key-other', 'enabled': True},
        {'name': 'netshield-7-' + missing, 'publicKey': 'key-missing', 'enabled': True},
        {'name': 'netshield-7-' + revoked, 'publicKey': 'key-revoked', 'enabled': False},
    ]
    result = user_usage(clients, 'key-mine\t123\t456\nkey-other\t987\t654\n', 'netshield-7-')
    assert result == [{'device_id': mine, 'upload_bytes': 123, 'download_bytes': 456},
                      {'device_id': missing, 'upload_bytes': None, 'download_bytes': None}]
    assert 'key-' not in str(result)
    with pytest.raises((ValueError, RuntimeError)):
        user_usage(clients, 'key-mine\t-1\t3\n', 'netshield-7-')


def test_usage_requires_auth_and_passes_authenticated_id(monkeypatch):
    monkeypatch.setenv('NETSHIELD_JWT_SECRET', 'x' * 40)
    passwords = Argon2Passwords()
    class Users:
        user = User(7, 'alice', passwords.hash('long test password'), True)
        def by_username(self, name): return self.user if name == 'alice' else None
        def by_id(self, user_id): return self.user if user_id == 7 else None
    app.dependency_overrides[get_auth_service] = lambda: AuthService(Users(), passwords, JwtTokens())
    calls = []
    monkeypatch.setattr('app.infrastructure.wg_easy_bridge.device_usage', lambda user_id: calls.append(user_id) or [])
    try:
        client = TestClient(app)
        assert client.get('/vpn/usage').status_code == 401
        token = client.post('/auth/token', json={'username': 'alice', 'password': 'long test password'}).json()['access_token']
        response = client.get('/vpn/usage', headers={'Authorization': 'Bearer ' + token})
        assert response.status_code == 200 and calls == [7]
        assert response.json() == {'devices': [], 'scope': 'current_wireguard_counters'}
        assert response.headers['cache-control'] == 'no-store'
    finally:
        app.dependency_overrides.clear()
