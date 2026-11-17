"""Argon2 and JWT adapters for application ports."""
import os
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.application.auth import AuthenticationError


class Argon2Passwords:
    def __init__(self):
        self.hasher = PasswordHasher()

    def hash(self, password: str) -> str:
        return self.hasher.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self.hasher.verify(password_hash, password)
        except (VerificationError, InvalidHashError):
            return False


class JwtTokens:
    @staticmethod
    def _key() -> str:
        key = os.environ.get("NETSHIELD_JWT_SECRET", "")
        if len(key.encode()) < 32:
            raise RuntimeError("NETSHIELD_JWT_SECRET must be at least 32 bytes")
        return key

    def create(self, user_id: int) -> str:
        now = datetime.now(timezone.utc)
        return jwt.encode({"sub": str(user_id), "iat": now, "exp": now + timedelta(minutes=30)}, self._key(), algorithm="HS256")

    def user_id(self, token: str) -> int:
        try:
            claims = jwt.decode(token, self._key(), algorithms=["HS256"], options={"require": ["sub", "exp", "iat"]})
            user_id = int(claims["sub"])
            if user_id < 1 or user_id > 9223372036854775807:
                raise ValueError("Invalid user id")
            return user_id
        except (jwt.PyJWTError, ValueError, TypeError):
            raise AuthenticationError from None
