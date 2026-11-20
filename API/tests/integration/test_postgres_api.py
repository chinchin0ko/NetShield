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


def test_login_limit_is_atomic_and_expires(lab_database):
    from concurrent.futures import ThreadPoolExecutor
    from app.infrastructure.login_limiter import PostgresLoginLimiter
    from app.infrastructure.postgres import database
    limiter = PostgresLoginLimiter()
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _: limiter.consume('limiter-user'), range(12)))
    assert sum(value == 0 for value in results) == 10
    assert all(value > 0 for value in results if value != 0)
    with database() as conn:
        stored = conn.execute('SELECT subject_hash FROM login_attempt_windows').fetchall()
        assert len(stored) == 1 and stored[0][0] != 'limiter-user'
        conn.execute("UPDATE login_attempt_windows SET window_started = now() - interval '6 minutes'")
    assert limiter.consume('limiter-user') == 0


def test_http_login_throttle_and_recovery(lab_database):
    from app.infrastructure.postgres import database
    client = TestClient(app)
    data = {'username': 'integration-user', 'password': 'wrong-password'}
    for _ in range(10):
        assert client.post('/auth/token', json=data).status_code == 401
    limited = client.post('/auth/token', json=data)
    assert limited.status_code == 429
    assert 1 <= int(limited.headers['retry-after']) <= 300
    with database() as conn:
        conn.execute("UPDATE login_attempt_windows SET window_started = now() - interval '6 minutes'")
    data['password'] = 'test passphrase 1234'
    assert client.post('/auth/token', json=data).status_code == 200


def test_assignment_history_rejects_overlaps_and_resolves_reused_addresses(lab_database):
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timedelta, timezone
    from ipaddress import IPv4Address
    from app.infrastructure.assignments import PostgresAssignments
    from app.infrastructure.postgres import database

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    def insert(owner, device):
        try:
            with database() as conn:
                conn.execute('INSERT INTO vpn_address_assignments '
                             '(address, user_id, device_id, valid_from) VALUES (%s, %s, %s, %s)',
                             ('10.8.0.2', owner, device * 32, now))
            return True
        except psycopg.errors.ExclusionViolation:
            return False
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda pair: insert(*pair), [(1, 'a'), (2, 'b')]))
    assert sorted(outcomes) == [False, True]
    with database() as conn:
        conn.execute('UPDATE vpn_address_assignments SET valid_until = %s', (now + timedelta(hours=1),))
        conn.execute('INSERT INTO vpn_address_assignments '
                     '(address, user_id, device_id, valid_from) VALUES (%s, %s, %s, %s)',
                     ('10.8.0.2', 2, 'c' * 32, now + timedelta(hours=1)))
    store = PostgresAssignments()
    assert len(store.find_at(IPv4Address('10.8.0.2'), now)) == 1
    assert store.find_at(IPv4Address('10.8.0.2'), now + timedelta(hours=1))[0].device_id == 'c' * 32
    assert store.find_at(IPv4Address('10.8.0.2'), now - timedelta(seconds=1)) == []


def test_coordinator_commits_fail_closed_history_and_serializes_mutations(lab_database):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Lock
    from app.application.assignment_lifecycle import SnapshotPeer, mutate_with_history
    from app.infrastructure.assignments import PostgresAssignments
    from app.infrastructure.postgres import database

    state = {'active': 0, 'maximum': 0}
    mutex = Lock()
    class Controller:
        def __init__(self, fail=False): self.fail = fail
        def mutate_and_snapshot(self, operation):
            import time
            with mutex:
                state['active'] += 1
                state['maximum'] = max(state['maximum'], state['active'])
            try:
                with database() as conn:
                    assert conn.execute('SELECT count(*) FROM vpn_address_assignments WHERE valid_until IS NULL').fetchone()[0] == 0
                time.sleep(.05)
                if self.fail:
                    raise RuntimeError('simulated bridge failure')
                return operation, [SnapshotPeer(1, 'a'*32, '10.8.0.2')]
            finally:
                with mutex: state['active'] -= 1
    def run(_): return mutate_with_history(PostgresAssignments(), Controller(), 'ok')
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert list(executor.map(run, range(2))) == ['ok', 'ok']
    assert state['maximum'] == 1
    with pytest.raises(RuntimeError):
        mutate_with_history(PostgresAssignments(), Controller(True), 'fail')
    with database() as conn:
        rows = conn.execute('SELECT valid_from, valid_until FROM vpn_address_assignments ORDER BY id').fetchall()
    assert len(rows) == 2 and all(end is not None and start < end for start, end in rows)
