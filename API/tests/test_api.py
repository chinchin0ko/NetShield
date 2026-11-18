from fastapi.testclient import TestClient

from app.application.auth import AuthService
from app.domain.users import User
from app.infrastructure.security import Argon2Passwords, JwtTokens
from app.interfaces.http import get_auth_service
from app.main import app


class FakeUsers:
    def __init__(self, user):
        self.user = user

    def by_username(self, username):
        return self.user if username == self.user.username else None

    def by_id(self, user_id):
        return self.user if user_id == self.user.id else None

    def ping(self):
        pass


def test_health_and_missing_credentials():
    client = TestClient(app)
    assert client.get('/health/live').json() == {'status': 'ok'}
    assert client.get('/users/me').status_code == 401


def test_development_registration_is_opt_in(monkeypatch):
    class RecordingUsers:
        def __init__(self):
            self.created = []
        def create(self, username, password_hash):
            self.created.append((username, password_hash))

    users = RecordingUsers()
    passwords = Argon2Passwords()
    app.dependency_overrides[get_auth_service] = lambda: AuthService(users, passwords, JwtTokens())
    client = TestClient(app)
    body = {'username': 'alice', 'password': 'a long test password'}
    try:
        monkeypatch.delenv('NETSHIELD_DEV_REGISTRATION', raising=False)
        assert client.post('/auth/register', json=body).status_code == 404
        assert users.created == []
        monkeypatch.setenv('NETSHIELD_DEV_REGISTRATION', '1')
        assert client.post('/auth/register', json={**body, 'password': 'short'}).status_code == 422
        assert client.post('/auth/register', json=body).status_code == 201
        assert users.created[0][0] == 'alice'
        assert passwords.verify(users.created[0][1], body['password'])
    finally:
        app.dependency_overrides.clear()


def test_login_and_invalid_password(monkeypatch):
    monkeypatch.setenv('NETSHIELD_JWT_SECRET', 'x' * 40)
    passwords = Argon2Passwords()
    user = User(1, 'alice', passwords.hash('correct horse battery staple'), True)
    users = FakeUsers(user)
    app.dependency_overrides[get_auth_service] = lambda: AuthService(users, passwords, JwtTokens())
    try:
        client = TestClient(app)
        assert client.get('/health/ready').json() == {'status': 'ok'}
        assert client.post('/auth/token', json={'username': 'alice', 'password': 'wrong'}).status_code == 401
        result = client.post('/auth/token', json={'username': 'alice', 'password': 'correct horse battery staple'})
        assert result.status_code == 200
        token = result.json()['access_token']
        assert client.get('/users/me', headers={'Authorization': f'Bearer {token}'}).json() == {'username': 'alice'}
        assert client.get('/users/me', headers={'Authorization': 'Bearer altered'}).status_code == 401
        users.user = User(1, 'alice', user.password_hash, False)
        assert client.get('/users/me', headers={'Authorization': f'Bearer {token}'}).status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_vpn_config_requires_identity_and_uses_authenticated_user(monkeypatch):
    monkeypatch.setenv('NETSHIELD_JWT_SECRET', 'x' * 40)
    passwords = Argon2Passwords()
    users = FakeUsers(User(7, 'alice', passwords.hash('long test password'), True))
    app.dependency_overrides[get_auth_service] = lambda: AuthService(users, passwords, JwtTokens())
    calls = []
    def provision(user_id, device_id, public_key):
        calls.append((user_id, device_id, public_key))
        return '[Interface]\n[Peer]\n'
    monkeypatch.setattr('app.infrastructure.wg_easy_bridge.provision', provision)
    try:
        client = TestClient(app)
        device = 'a' * 32
        public_key = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
        assert client.post('/vpn/config', json={'device_id': device, 'public_key': public_key}).status_code == 401
        token = client.post('/auth/token', json={'username': 'alice', 'password': 'long test password'}).json()['access_token']
        result = client.post('/vpn/config', json={'device_id': device, 'public_key': public_key}, headers={'Authorization': f'Bearer {token}'})
        assert result.status_code == 200
        assert result.headers['cache-control'] == 'no-store'
        assert calls == [(7, device, public_key)]
        assert client.post('/vpn/config', json={'device_id': 'invalid', 'public_key': public_key}, headers={'Authorization': f'Bearer {token}'}).status_code == 422
    finally:
        app.dependency_overrides.clear()


def test_vpn_device_listing_and_revocation_use_authenticated_owner(monkeypatch):
    monkeypatch.setenv('NETSHIELD_JWT_SECRET', 'x' * 40)
    passwords = Argon2Passwords()
    users = FakeUsers(User(7, 'alice', passwords.hash('long test password'), True))
    app.dependency_overrides[get_auth_service] = lambda: AuthService(users, passwords, JwtTokens())
    calls = []
    monkeypatch.setattr('app.infrastructure.wg_easy_bridge.list_devices', lambda user_id: [{'device_id': 'a' * 32, 'enabled': True}] if user_id == 7 else [])
    monkeypatch.setattr('app.infrastructure.wg_easy_bridge.revoke', lambda user_id, device_id: calls.append((user_id, device_id)) or True)
    try:
        client = TestClient(app)
        assert client.get('/vpn/devices').status_code == 401
        token = client.post('/auth/token', json={'username': 'alice', 'password': 'long test password'}).json()['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        assert len(client.get('/vpn/devices', headers=headers).json()['devices']) == 1
        assert client.post('/vpn/devices/' + 'a' * 32 + '/revoke', headers=headers).status_code == 204
        assert calls == [(7, 'a' * 32)]
        assert client.post('/vpn/devices/invalid/revoke', headers=headers).status_code == 422
    finally:
        app.dependency_overrides.clear()
