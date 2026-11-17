"""Initial private-only API. Do not expose publicly without further hardening."""
import os
from datetime import datetime, timedelta, timezone

import jwt
import psycopg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

app = FastAPI(title="NetShield API", version="0.1.0")
hasher = PasswordHasher()
bearer = HTTPBearer(auto_error=False)


def database():
    dsn = os.environ.get("NETSHIELD_DATABASE_URL")
    if not dsn:
        raise RuntimeError("NETSHIELD_DATABASE_URL is required")
    return psycopg.connect(dsn, connect_timeout=3, sslmode="verify-full")


def jwt_key():
    key = os.environ.get("NETSHIELD_JWT_SECRET", "")
    if len(key.encode()) < 32:
        raise RuntimeError("NETSHIELD_JWT_SECRET must be at least 32 bytes")
    return key


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


def authenticated(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = jwt.decode(credentials.credentials, jwt_key(), algorithms=["HS256"], options={"require": ["sub", "exp", "iat"]})
        with database() as conn:
            row = conn.execute("SELECT username FROM users WHERE id = %s AND is_active", (claims["sub"],)).fetchone()
        if not row:
            raise ValueError("Inactive account")
    except (jwt.PyJWTError, ValueError, psycopg.DataError):
        raise HTTPException(status_code=401, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"}) from None
    return row[0]


@app.get("/health/live")
def liveness():
    return {"status": "ok"}


@app.get("/health/ready")
def readiness():
    try:
        with database() as conn:
            conn.execute("SELECT 1")
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail="Database unavailable") from None
    return {"status": "ok"}


@app.post("/auth/token")
def login(credentials: Credentials):
    with database() as conn:
        row = conn.execute("SELECT id, password_hash, is_active FROM users WHERE username = %s", (credentials.username,)).fetchone()
    try:
        verified = row is not None and row[2] and hasher.verify(row[1], credentials.password)
    except (VerificationError, InvalidHashError):
        verified = False
    if not verified:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    now = datetime.now(timezone.utc)
    token = jwt.encode({"sub": str(row[0]), "iat": now, "exp": now + timedelta(minutes=30)}, jwt_key(), algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "expires_in": 1800}


@app.get("/users/me")
def me(username: str = Depends(authenticated)):
    return {"username": username}
