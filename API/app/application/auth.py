"""Use cases: no HTTP, SQL, or cryptography library dependencies."""
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.application.ports import Passwords, RefreshTokenStore, Tokens, UserRepository


class AuthenticationError(Exception):
    pass


class LoginRateLimited(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after


@dataclass(frozen=True)
class SessionTokens:
    access_token: str
    # None when no refresh store is configured (tests); the client then falls
    # back to the old behaviour of asking the user to log in again.
    refresh_token: str | None


# The access token stays short-lived (30 min). The refresh token lives 30 days
# and is rotated on every use, so a session survives idle time with the VPN
# off without the user re-entering their password.
REFRESH_TOKEN_TTL = timedelta(days=30)


class AuthService:
    def __init__(self, users: UserRepository, passwords: Passwords, tokens: Tokens, limiter=None, refresh_store: RefreshTokenStore | None = None):
        self.users = users
        self.passwords = passwords
        self.tokens = tokens
        self.limiter = limiter
        self.refresh_store = refresh_store

    def login(self, username: str, password: str) -> SessionTokens:
        if self.limiter is not None:
            retry_after = self.limiter.consume(username)
            if retry_after:
                raise LoginRateLimited(retry_after)
        user = self.users.by_username(username)
        if user is None:
            self.passwords.verify_dummy(password)
            raise AuthenticationError
        valid_password = self.passwords.verify(user.password_hash, password)
        if not user.is_active or not valid_password:
            raise AuthenticationError
        refresh = None
        if self.refresh_store is not None:
            raw = self.tokens.create_refresh_token()
            self.refresh_store.issue(
                user.id,
                self.tokens.hash_refresh_token(raw),
                str(uuid.uuid4()),
                datetime.now(timezone.utc) + REFRESH_TOKEN_TTL,
            )
            refresh = raw
        return SessionTokens(self.tokens.create(user.id), refresh)

    def refresh(self, presented: str) -> SessionTokens:
        if self.refresh_store is None:
            raise AuthenticationError
        record = self.refresh_store.find_by_hash(self.tokens.hash_refresh_token(presented))
        if record is None:
            raise AuthenticationError
        now = datetime.now(timezone.utc)
        if record.is_revoked:
            if record.replaced_by is not None:
                # A rotated token was presented again: it was likely stolen,
                # so revoke the whole login family.
                self.refresh_store.revoke_family(record.family_id)
            raise AuthenticationError
        if record.is_expired(now):
            self.refresh_store.revoke(record.id)
            raise AuthenticationError
        user = self.users.by_id(record.user_id)
        if not user or not user.is_active:
            raise AuthenticationError
        raw = self.tokens.create_refresh_token()
        new_id = self.refresh_store.issue(
            record.user_id,
            self.tokens.hash_refresh_token(raw),
            record.family_id,
            now + REFRESH_TOKEN_TTL,
        )
        self.refresh_store.revoke(record.id, replaced_by=new_id)
        return SessionTokens(self.tokens.create(user.id), raw)

    def logout(self, presented: str) -> None:
        if self.refresh_store is None:
            return
        record = self.refresh_store.find_by_hash(self.tokens.hash_refresh_token(presented))
        if record is not None:
            self.refresh_store.revoke(record.id)

    def current_identity(self, token: str):
        user = self.users.by_id(self.tokens.user_id(token))
        if not user or not user.is_active:
            raise AuthenticationError
        return user

    def current_user(self, token: str) -> str:
        return self.current_identity(token).username

    def create_user(self, username: str, password: str) -> None:
        self.users.create(username, self.passwords.hash(password))
