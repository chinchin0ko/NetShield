"""PostgreSQL adapter for the refresh-token store port."""
from datetime import datetime

from app.domain.refresh_tokens import RefreshTokenRecord
from app.infrastructure.postgres import database


class PostgresRefreshTokens:
    def issue(self, user_id: int, token_hash: str, family_id: str, expires_at: datetime) -> int:
        with database() as conn:
            row = conn.execute(
                "INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at) "
                "VALUES (%s, %s, %s, %s) RETURNING id",
                (user_id, token_hash, family_id, expires_at),
            ).fetchone()
        return row[0]

    def find_by_hash(self, token_hash: str) -> RefreshTokenRecord | None:
        with database() as conn:
            row = conn.execute(
                "SELECT id, user_id, token_hash, family_id, expires_at, created_at, revoked_at, replaced_by "
                "FROM refresh_tokens WHERE token_hash = %s",
                (token_hash,),
            ).fetchone()
        return RefreshTokenRecord(*row) if row else None

    def revoke(self, token_id: int, replaced_by: int | None = None) -> None:
        with database() as conn:
            conn.execute(
                "UPDATE refresh_tokens SET revoked_at = clock_timestamp(), replaced_by = %s "
                "WHERE id = %s AND revoked_at IS NULL",
                (replaced_by, token_id),
            )

    def revoke_family(self, family_id: str) -> None:
        with database() as conn:
            conn.execute(
                "UPDATE refresh_tokens SET revoked_at = clock_timestamp() "
                "WHERE family_id = %s AND revoked_at IS NULL",
                (family_id,),
            )

    def revoke_user(self, user_id: int) -> None:
        with database() as conn:
            conn.execute(
                "UPDATE refresh_tokens SET revoked_at = clock_timestamp() "
                "WHERE user_id = %s AND revoked_at IS NULL",
                (user_id,),
            )
