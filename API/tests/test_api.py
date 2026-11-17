from fastapi.testclient import TestClient
from app import main


class FakeConnection:
    def __init__(self, row):
        self.row = row

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params=None):
        return self

    def fetchone(self):
        return self.row


def test_health_and_missing_credentials():
    client = TestClient(main.app)
    assert client.get('/health/live').json() == {'status': 'ok'}
    assert client.get('/users/me').status_code == 401


def test_login_and_invalid_password(monkeypatch):
    monkeypatch.setenv('NETSHIELD_JWT_SECRET', 'x' * 40)
    password_hash = main.hasher.hash('correct horse battery staple')
    monkeypatch.setattr(main, 'database', lambda: FakeConnection((1, password_hash, True)))
    client = TestClient(main.app)
    assert client.post('/auth/token', json={'username': 'alice', 'password': 'wrong'}).status_code == 401
    result = client.post('/auth/token', json={'username': 'alice', 'password': 'correct horse battery staple'})
    assert result.status_code == 200
    token = result.json()['access_token']
    monkeypatch.setattr(main, 'database', lambda: FakeConnection(('alice',)))
    assert client.get('/users/me', headers={'Authorization': f'Bearer {token}'}).json() == {'username': 'alice'}
    assert client.get('/users/me', headers={'Authorization': 'Bearer altered'}).status_code == 401
