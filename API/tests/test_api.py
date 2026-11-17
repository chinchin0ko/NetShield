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
