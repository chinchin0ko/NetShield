"""Refresh-token entity: a long-lived, single-use credential.

Only the SHA-256 hash is stored; the raw token is shown to the client once
(at login or on rotation) and never persisted. A token belongs to a family
(one login); presenting an already-rotated token revokes the whole family,
so a stolen refresh token cannot be replayed after the legitimate client
has rotated it.
"""
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class RefreshTokenRecord:
    id: int
    user_id: int
    token_hash: str
    family_id: str
    expires_at: datetime
    created_at: datetime
    revoked_at: datetime | None
    replaced_by: int | None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at <= now
