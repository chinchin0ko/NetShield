"""PostgreSQL-backed per-account request limit shared by API workers."""
import hashlib
import hmac
import os
import secrets

from app.infrastructure.postgres import database


class PostgresLoginLimiter:
    """Ten attempts per exact username per five-minute fixed window.

    This is one layer, not a substitute for proxy IP limits and account recovery.
    """
    def consume(self, username: str) -> int:
        secret = os.environ.get('NETSHIELD_JWT_SECRET', '')
        if len(secret.encode()) < 32:
            raise RuntimeError('NETSHIELD_JWT_SECRET must be at least 32 bytes')
        subject = hmac.new(secret.encode(), b'netshield-login-rate-v1\x00' + username.encode(), hashlib.sha256).hexdigest()
        with database() as conn:
            row = conn.execute('''
                INSERT INTO login_attempt_windows (subject_hash, attempts, window_started)
                VALUES (%s, 1, now())
                ON CONFLICT (subject_hash) DO UPDATE SET
                  attempts = CASE WHEN login_attempt_windows.window_started <= now() - interval '5 minutes'
                    THEN 1 ELSE LEAST(login_attempt_windows.attempts + 1, 11) END,
                  window_started = CASE WHEN login_attempt_windows.window_started <= now() - interval '5 minutes'
                    THEN now() ELSE login_attempt_windows.window_started END
                RETURNING attempts, GREATEST(1, CEIL(EXTRACT(EPOCH FROM (window_started + interval '5 minutes' - now())))::int)
            ''', (subject,)).fetchone()
            if secrets.randbelow(100) == 0:
                conn.execute("DELETE FROM login_attempt_windows WHERE window_started < now() - interval '1 day'")
        return row[1] if row[0] > 10 else 0
