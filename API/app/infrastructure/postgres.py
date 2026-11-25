"""PostgreSQL adapter for the user repository port."""
import os

import psycopg

from app.domain.users import User


def database():
    dsn = os.environ.get("NETSHIELD_DATABASE_URL")
    if not dsn:
        raise RuntimeError("NETSHIELD_DATABASE_URL is required")
    return psycopg.connect(dsn, connect_timeout=3, sslmode="verify-full")


class PostgresUsers:
    def by_username(self, username: str) -> User | None:
        with database() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, is_active FROM users WHERE username = %s", (username,)
            ).fetchone()
        return User(*row) if row else None

    def by_id(self, user_id: int) -> User | None:
        with database() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, is_active FROM users WHERE id = %s", (user_id,)
            ).fetchone()
        return User(*row) if row else None

    def create(self, username: str, password_hash: str) -> None:
        with database() as conn:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))

    def ping(self) -> None:
        with database() as conn:
            conn.execute("SELECT 1")
