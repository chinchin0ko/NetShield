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
                'SELECT device_id, occurred_at, signature, severity, id, review_status, reviewed_at FROM personal_security_alerts '
                'WHERE user_id = %s ORDER BY occurred_at DESC, id DESC LIMIT %s', (user_id, limit),
            ).fetchall()
        return [{'device_id': row[0], 'occurred_at': row[1], 'signature': row[2], 'severity': row[3], 'id': row[4], 'review_status': row[5], 'reviewed_at': row[6]} for row in rows]


    def review_for_user(self, user_id, alert_id, status):
        if type(user_id) is not int or user_id <= 0 or type(alert_id) is not int or alert_id <= 0 or status not in ('new', 'reviewed', 'false_positive'):
            raise ValueError('invalid review')
        with database() as conn:
            row = conn.execute(
                "UPDATE personal_security_alerts SET review_status = %s, reviewed_at = CASE WHEN %s = 'new' THEN NULL ELSE clock_timestamp() END "
                'WHERE id = %s AND user_id = %s AND review_status <> %s RETURNING id',
                (status, status, alert_id, user_id, status),
            ).fetchone()
            if row is not None:
                conn.execute('INSERT INTO personal_alert_reviews (alert_id, user_id, status) VALUES (%s, %s, %s)',
                             (alert_id, user_id, status))
                return True
            return conn.execute('SELECT 1 FROM personal_security_alerts WHERE id = %s AND user_id = %s',
                                (alert_id, user_id)).fetchone() is not None
