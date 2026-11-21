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


def test_personal_alerts_isolate_accounts_and_deduplicate(lab_database):
    import json
    from datetime import datetime, timezone
    from app.application.personal_alerts import ingest_personal_alert
    from app.infrastructure.assignments import PostgresAssignments
    from app.infrastructure.personal_alerts import PostgresPersonalAlerts
    from app.infrastructure.postgres import database
    with database() as conn:
        conn.execute('INSERT INTO vpn_address_assignments (address,user_id,device_id,valid_from) VALUES (%s,%s,%s,%s)',
                     ('10.8.0.2', 1, 'a'*32, datetime(2026, 1, 1, tzinfo=timezone.utc)))
    alert = {'event_type': 'alert', 'timestamp': '2026-01-01T00:01:00Z', 'src_ip': '10.8.0.2', 'dest_ip': '1.1.1.1',
             'alert': {'signature': 'Synthetic test', 'severity': 2}}
    repo = PostgresPersonalAlerts()
    assert ingest_personal_alert(json.dumps(alert), PostgresAssignments(), repo, evidence_trusted=True)
    assert not ingest_personal_alert(json.dumps(alert), PostgresAssignments(), repo, evidence_trusted=True)
    assert len(repo.list_for_user(1)) == 1
    assert repo.list_for_user(2) == []


def test_alert_test_endpoint_is_scoped_and_limited(lab_database, monkeypatch):
    from datetime import datetime, timezone
    from app.infrastructure.postgres import database
    monkeypatch.setenv('NETSHIELD_DEV_ALERT_TEST', '1')
    with database() as conn:
        conn.execute('INSERT INTO vpn_address_assignments (address,user_id,device_id,valid_from) VALUES (%s,%s,%s,%s)',
                     ('10.8.0.2', 1, 'a'*32, datetime(2026, 1, 1, tzinfo=timezone.utc)))
    client = TestClient(app)
    def login(username, password):
        token = client.post('/auth/token', json={'username': username, 'password': password}).json()['access_token']
        return {'Authorization': 'Bearer ' + token}
    first = login('integration-user', 'test passphrase 1234')
    second = login('second-user', 'second passphrase 1234')
    assert client.get('/security/alerts').status_code == 401
    assert client.post('/security/alerts/test', headers=second).status_code == 409
    for _ in range(5): assert client.post('/security/alerts/test', headers=first).status_code == 201
    assert client.post('/security/alerts/test', headers=first).status_code == 429
    assert len(client.get('/security/alerts', headers=first).json()['alerts']) == 5
    assert client.get('/security/alerts', headers=second).json()['alerts'] == []
    monkeypatch.delenv('NETSHIELD_DEV_ALERT_TEST')
    assert client.post('/security/alerts/test', headers=first).status_code == 404


def test_sensor_ingestion_authenticates_and_checks_current_owner(lab_database, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from app.infrastructure.postgres import database
    now = datetime.now(timezone.utc)
    with database() as conn:
        conn.execute('INSERT INTO vpn_address_assignments (address,user_id,device_id,valid_from) VALUES (%s,%s,%s,%s)',
                     ('10.8.0.2', 1, 'a'*32, now - timedelta(days=2)))
    secret = 't' * 64
    monkeypatch.setenv('NETSHIELD_PERSONAL_SENSOR_KEY', secret)
    monkeypatch.setattr('app.infrastructure.wg_easy_bridge._request',
                        lambda *args, **kwargs: {'ownership_snapshot': [{'user_id': 1, 'device_id': 'a'*32, 'address': '10.8.0.2'}]})
    client = TestClient(app)
    event = {'event_type': 'alert', 'timestamp': (now - timedelta(hours=1)).isoformat(), 'src_ip': '10.8.0.2', 'dest_ip': '1.1.1.1',
             'alert': {'signature': 'MALWARE synthetic', 'severity': 2}}
    assert client.post('/internal/suricata/personal', json={'events': [event]}).status_code == 404
    headers = {'X-NetShield-Sensor-Key': secret}
    assert client.post('/internal/suricata/personal', headers=headers, json={'events': [event]}).json()['inserted'] == 1
    assert client.post('/internal/suricata/personal', headers=headers, json={'events': [event]}).json()['inserted'] == 0
    monkeypatch.setattr('app.infrastructure.wg_easy_bridge._request',
                        lambda *args, **kwargs: {'ownership_snapshot': [{'user_id': 2, 'device_id': 'b'*32, 'address': '10.8.0.2'}]})
    event['alert']['signature'] = 'MALWARE another synthetic'
    assert client.post('/internal/suricata/personal', headers=headers, json={'events': [event]}).json()['inserted'] == 0
    with database() as conn:
        assert conn.execute('SELECT count(*) FROM personal_security_alerts WHERE user_id=1').fetchone()[0] == 1
        assert conn.execute('SELECT count(*) FROM personal_security_alerts WHERE user_id=2').fetchone()[0] == 0
        assert conn.execute('SELECT count(*) FROM unattributed_sensor_alerts').fetchone()[0] == 1
    monkeypatch.setattr('app.infrastructure.wg_easy_bridge._request',
                        lambda *args, **kwargs: {'ownership_snapshot': [{'user_id': 1, 'device_id': 'a'*32, 'address': '10.8.0.2'}]})
    # An empty heartbeat retries the retained event without requiring a replay.
    assert client.post('/internal/suricata/personal', headers=headers, json={'events': []}).json()['inserted'] == 1
    with database() as conn:
        assert conn.execute('SELECT count(*) FROM unattributed_sensor_alerts').fetchone()[0] == 0
        assert conn.execute('SELECT count(*) FROM personal_security_alerts WHERE user_id=1').fetchone()[0] == 2


def test_usage_history_isolated_and_reset_gaps(lab_database, monkeypatch):
    from app.infrastructure.postgres import database
    from app.infrastructure.usage_history import collect_samples
    device = 'a' * 32
    other_device = 'b' * 32
    with database() as conn:
        conn.execute("INSERT INTO vpn_address_assignments (address,user_id,device_id,valid_from) VALUES ('10.8.0.2',1,%s,now()-interval '1 hour'), ('10.8.0.3',2,%s,now()-interval '1 hour')", (device, other_device))
    values = {1: (100, 200), 2: (400, 500)}
    def fake_usage(user_id):
        upload, download = values[user_id]
        return [{'device_id': device if user_id == 1 else other_device, 'upload_bytes': upload, 'download_bytes': download}]
    monkeypatch.setattr('app.infrastructure.wg_easy_bridge.device_usage', fake_usage)
    assert collect_samples() == (2, 0)
    values[1] = (150, 280)
    values[2] = (450, 550)
    assert collect_samples() == (2, 0)
    client = TestClient(app)
    login = client.post('/auth/token', json={'username': 'integration-user', 'password': 'test passphrase 1234'}).json()['access_token']
    headers = {'Authorization': 'Bearer ' + login}
    assert client.get('/vpn/usage/history').status_code == 401
    response = client.get('/vpn/usage/history', headers=headers)
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    days = response.json()['days']
    assert len(days) == 1 and days[0]['device_id'] == device
    assert days[0]['upload_bytes'] == 50 and days[0]['download_bytes'] == 80
    assert days[0]['incomplete'] is True
    values[1] = (3, 4)  # a reset must not turn the old total into traffic
    assert collect_samples() == (2, 0)
    days = client.get('/vpn/usage/history', headers=headers).json()['days']
    assert days[0]['upload_bytes'] == 50 and days[0]['download_bytes'] == 80



def test_alert_review_requires_owner_and_preserves_classification(lab_database):
    from app.infrastructure.postgres import database
    with database() as conn:
        alert_id = conn.execute("INSERT INTO personal_security_alerts (event_hash,user_id,device_id,occurred_at,signature,severity) VALUES (%s,1,%s,now(),'test',2) RETURNING id", ('f' * 64, 'a' * 32)).fetchone()[0]
    client = TestClient(app)
    def login(username, password):
        token = client.post('/auth/token', json={'username': username, 'password': password}).json()['access_token']
        return {'Authorization': 'Bearer ' + token}
    first = login('integration-user', 'test passphrase 1234')
    second = login('second-user', 'second passphrase 1234')
    path = f'/security/alerts/{alert_id}/review'
    assert client.post(path, json={'status': 'reviewed'}).status_code == 401
    assert client.post(path, headers=second, json={'status': 'false_positive'}).status_code == 404
    assert client.post(path, headers=first, json={'status': 'invalid'}).status_code == 422
    assert client.post(path, headers=first, json={'status': 'false_positive'}).status_code == 204
    alert = client.get('/security/alerts', headers=first).json()['alerts'][0]
    assert alert['id'] == alert_id and alert['review_status'] == 'false_positive' and alert['reviewed_at']
    assert client.get('/security/alerts', headers=second).json()['alerts'] == []
    assert client.post(path, headers=first, json={'status': 'new'}).status_code == 204
    assert client.get('/security/alerts', headers=first).json()['alerts'][0]['reviewed_at'] is None
    with database() as conn:
        reviews = conn.execute('SELECT status FROM personal_alert_reviews WHERE alert_id = %s ORDER BY id', (alert_id,)).fetchall()
    assert reviews == [('false_positive',), ('new',)]
