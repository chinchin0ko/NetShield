from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.infrastructure.public_limit import PublicLimit


def test_public_limit_requires_single_valid_address_and_limits_per_origin(monkeypatch):
    monkeypatch.setenv('NETSHIELD_PUBLIC_LIMIT', '1')
    app = FastAPI()
    app.add_middleware(PublicLimit)

    @app.post('/auth/token')
    def login():
        return {'ok': True}

    @app.post('/auth/register')
    def register():
        return {'ok': True}

    client = TestClient(app)
    assert client.post('/auth/token').status_code == 400
    assert client.post('/auth/token', headers={'X-NetShield-Client-IP': '1.2.3.4, 2.3.4.5'}).status_code == 400
    assert client.post('/auth/token', headers=[('X-NetShield-Client-IP', '1.2.3.4'), ('X-NetShield-Client-IP', '2.3.4.5')]).status_code == 400
    for _ in range(20):
        assert client.post('/auth/token', headers={'X-NetShield-Client-IP': '1.2.3.4'}).status_code == 200
    response = client.post('/auth/token', headers={'X-NetShield-Client-IP': '1.2.3.4'})
    assert response.status_code == 429
    assert int(response.headers['retry-after']) > 0
    assert client.post('/auth/token', headers={'X-NetShield-Client-IP': '2.3.4.5'}).status_code == 200
    for _ in range(5):
        assert client.post('/auth/register', headers={'X-NetShield-Client-IP': '1.2.3.4'}).status_code == 200
    assert client.post('/auth/register', headers={'X-NetShield-Client-IP': '1.2.3.4'}).status_code == 429
