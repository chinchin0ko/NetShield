"""Minimal per-account alerts, without packet contents or browsing history."""
from app.infrastructure.postgres import database


class PostgresPersonalAlerts:
    def save_for_owner(self, alert, owner):
        with database() as conn:
            row = conn.execute(
                'INSERT INTO personal_security_alerts '
                '(event_hash, user_id, device_id, occurred_at, signature, severity) '
                'VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (event_hash) DO NOTHING RETURNING id',
                (alert.event_hash, owner.user_id, owner.device_id, alert.occurred_at, alert.signature, alert.severity),
            ).fetchone()
        return row is not None

    def list_for_user(self, user_id, limit=50):
        if type(user_id) is not int or user_id <= 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('invalid query')
        with database() as conn:
            rows = conn.execute(
                'SELECT device_id, occurred_at, signature, severity FROM personal_security_alerts '
                'WHERE user_id = %s ORDER BY occurred_at DESC, id DESC LIMIT %s', (user_id, limit),
            ).fetchall()
        return [{'device_id': row[0], 'occurred_at': row[1], 'signature': row[2], 'severity': row[3]} for row in rows]
