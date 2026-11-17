"""Optional integration test: NETSHIELD_TEST_DSN must point to netshield_lab."""
import os
import uuid
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import make_conninfo

from app.infrastructure.security import Argon2Passwords
from app.main import app


@pytest.fixture
def lab_database(monkeypatch):
    dsn = os.environ.get('NETSHIELD_TEST_DSN')
    if not dsn:
        pytest.skip('NETSHIELD_TEST_DSN is not configured')
    schema = 'test_' + uuid.uuid4().hex
    with psycopg.connect(dsn, sslmode='verify-full', autocommit=True) as conn:
        if conn.info.dbname != 'netshield_lab':
            pytest.fail('Integration tests require a database named netshield_lab')
        conn.execute(f'CREATE SCHEMA {schema}')
        try:
            conn.execute(f'SET search_path TO {schema}')
            migrations = Path(__file__).resolve().parents[2] / 'migrations'
            for migration in sorted(migrations.glob('*.sql')):
                conn.execute(migration.read_text())
            conn.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)',
                         ('integration-user', Argon2Passwords().hash('test passphrase 1234')))
            conn.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)',
                         ('second-user', Argon2Passwords().hash('second passphrase 1234')))
            monkeypatch.setenv('NETSHIELD_DATABASE_URL', make_conninfo(dsn, options=f'-csearch_path={schema}'))
            monkeypatch.setenv('NETSHIELD_JWT_SECRET', 'integration-test-key-' * 3)
            yield
        finally:
            conn.execute(f'DROP SCHEMA {schema} CASCADE')


def test_full_flow_against_postgresql(lab_database):
    import base64
    from concurrent.futures import ThreadPoolExecutor
    client = TestClient(app)
    assert client.get('/health/ready').status_code == 200
    response = client.post('/auth/token', json={'username': 'integration-user', 'password': 'test passphrase 1234'})
    assert response.status_code == 200
    headers = {'Authorization': 'Bearer ' + response.json()['access_token']}
    assert client.get('/users/me', headers=headers).json() == {'username': 'integration-user'}
    data = {'name': 'test phone', 'public_key': base64.b64encode(b'a' * 32).decode()}
    created = client.post('/devices', headers=headers, json=data)
    assert created.status_code == 201
    with ThreadPoolExecutor(max_workers=4) as executor:
        repeated = list(executor.map(lambda _: client.post('/devices', headers=headers, json=data), range(4)))
    assert all(response.status_code == 201 for response in repeated)
    assert all(response.json()['id'] == created.json()['id'] for response in repeated)
    assert len(client.get('/devices', headers=headers).json()) == 1
    second_login = client.post('/auth/token', json={'username': 'second-user', 'password': 'second passphrase 1234'})
    assert second_login.status_code == 200
    second_headers = {'Authorization': 'Bearer ' + second_login.json()['access_token']}
    assert client.get('/devices', headers=second_headers).json() == []
    assert client.post('/devices', headers=second_headers, json=data).status_code == 409
    assert client.delete('/devices/' + str(created.json()['id']), headers=second_headers).status_code == 404
    assert client.get('/devices').status_code == 401
    assert client.delete('/devices/' + str(created.json()['id']), headers=headers).status_code == 204
    assert client.get('/devices', headers=headers).json() == []
