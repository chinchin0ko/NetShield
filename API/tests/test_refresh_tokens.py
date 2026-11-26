"""Refresh-token flow: login issues a rotating refresh token, /auth/refresh
rotates it (single use, reuse revokes the whole family), /auth/logout revokes it."""
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.application.auth import AuthService
from app.domain.refresh_tokens import RefreshTokenRecord
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


class FakeRefreshStore:
    """In-memory stand-in for PostgresRefreshTokens (records are frozen)."""
    def __init__(self):
        self.records = {}
        self.next_id = 1

    def issue(self, user_id, token_hash, family_id, expires_at):
        record = RefreshTokenRecord(self.next_id, user_id, token_hash, family_id, expires_at, datetime.now(timezone.utc), None, None)
        self.records[token_hash] = record
        self.next_id += 1
        return record.id

    def find_by_hash(self, token_hash):
        return self.records.get(token_hash)

    def _revoke(self, record, replaced_by=None):
        self.records[record.token_hash] = RefreshTokenRecord(
            record.id, record.user_id, record.token_hash, record.family_id,
            record.expires_at, record.created_at, datetime.now(timezone.utc), replaced_by)

    def revoke(self, token_id, replaced_by=None):
        for record in self.records.values():
            if record.id == token_id and record.revoked_at is None:
                self._revoke(record, replaced_by)

    def revoke_family(self, family_id):
        for record in list(self.records.values()):
            if record.family_id == family_id and record.revoked_at is None:
                self._revoke(record)

    def revoke_user(self, user_id):
        for record in list(self.records.values()):
            if record.user_id == user_id and record.revoked_at is None:
                self._revoke(record)


def _client(monkeypatch):
    monkeypatch.setenv('NETSHIELD_JWT_SECRET', 'x' * 40)
    passwords = Argon2Passwords()
    user = User(1, 'alice', passwords.hash('correct horse battery staple'), True)
    users = FakeUsers(user)
    store = FakeRefreshStore()
    app.dependency_overrides[get_auth_service] = lambda: AuthService(users, passwords, JwtTokens(), None, store)
    return TestClient(app), users, store


def _login(client):
    result = client.post('/auth/token', json={'username': 'alice', 'password': 'correct horse battery staple'})
    assert result.status_code == 200
    assert result.headers['cache-control'] == 'no-store'
    return result.json()


def test_login_returns_refresh_token_and_it_rotates(monkeypatch):
    client, users, store = _client(monkeypatch)
    try:
        body = _login(client)
        assert body['access_token'] and body['refresh_token']
        assert body['refresh_token'] != body['access_token']
        # The raw refresh token is never stored: only its hash is in the store.
        assert all(record.token_hash != body['refresh_token'] for record in store.records.values())
        assert client.get('/users/me', headers={'Authorization': f"Bearer {body['access_token']}"}).json() == {'username': 'alice'}
        result = client.post('/auth/refresh', json={'refresh_token': body['refresh_token']})
        assert result.status_code == 200
        fresh = result.json()
        # The access token is deterministic per second (JWT iat/exp have
        # second precision), so it may equal the previous one; the refresh
        # token must always be new.
        assert fresh['refresh_token'] != body['refresh_token']
        # The old refresh token no longer works (single use).
        assert client.post('/auth/refresh', json={'refresh_token': body['refresh_token']}).status_code == 401
        # And the new one does, with its own access token.
        assert client.get('/users/me', headers={'Authorization': f"Bearer {fresh['access_token']}"}).json() == {'username': 'alice'}
    finally:
        app.dependency_overrides.clear()


def test_reused_rotated_token_revokes_the_family(monkeypatch):
    client, users, store = _client(monkeypatch)
    try:
        body = _login(client)
        fresh = client.post('/auth/refresh', json={'refresh_token': body['refresh_token']}).json()
        # Presenting the old (rotated) token again is reuse: the whole family dies.
        assert client.post('/auth/refresh', json={'refresh_token': body['refresh_token']}).status_code == 401
        assert client.post('/auth/refresh', json={'refresh_token': fresh['refresh_token']}).status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_unknown_and_expired_refresh_tokens_are_rejected(monkeypatch):
    client, users, store = _client(monkeypatch)
    try:
        assert client.post('/auth/refresh', json={'refresh_token': 'x' * 64}).status_code == 401
        body = _login(client)
        # Expire the stored token by hand.
        record = store.find_by_hash(JwtTokens.hash_refresh_token(body['refresh_token']))
        store.records[record.token_hash] = RefreshTokenRecord(
            record.id, record.user_id, record.token_hash, record.family_id,
            datetime.now(timezone.utc) - timedelta(seconds=1), record.created_at, None, None)
        assert client.post('/auth/refresh', json={'refresh_token': body['refresh_token']}).status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_logout_revokes_the_refresh_token(monkeypatch):
    client, users, store = _client(monkeypatch)
    try:
        body = _login(client)
        assert client.post('/auth/logout', json={'refresh_token': body['refresh_token']}).status_code == 204
        assert client.post('/auth/refresh', json={'refresh_token': body['refresh_token']}).status_code == 401
        # Logging out twice is fine (idempotent).
        assert client.post('/auth/logout', json={'refresh_token': body['refresh_token']}).status_code == 204
    finally:
        app.dependency_overrides.clear()
