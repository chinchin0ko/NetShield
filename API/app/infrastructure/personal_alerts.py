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


    def hold_if_unattributed(self, alert):
        """Retain minimal event data when no safe personal attribution exists."""
        with database() as conn:
            row = conn.execute(
                'INSERT INTO unattributed_sensor_alerts (event_hash, occurred_at, signature, severity, source_ip, destination_ip) '
                'SELECT %s, %s, %s, %s, %s, %s WHERE NOT EXISTS '
                '(SELECT 1 FROM personal_security_alerts WHERE event_hash = %s) '
                'ON CONFLICT (event_hash) DO NOTHING RETURNING event_hash',
                (alert.event_hash, alert.occurred_at, alert.signature, alert.severity,
                 alert.source_ip, alert.destination_ip, alert.event_hash),
            ).fetchone()
        return row is not None

    def remove_hold(self, alert):
        with database() as conn:
            conn.execute('DELETE FROM unattributed_sensor_alerts WHERE event_hash = %s', (alert.event_hash,))


    def pending_for_retry(self, limit=25):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('invalid limit')
        from app.domain.alerts import SecurityAlert
        with database() as conn:
            rows = conn.execute(
                'SELECT event_hash, occurred_at, signature, severity, source_ip, destination_ip '
                'FROM unattributed_sensor_alerts ORDER BY last_checked_at ASC NULLS FIRST, first_received_at, event_hash LIMIT %s',
                (limit,),
            ).fetchall()
        return [SecurityAlert(row[0], row[1], row[2], row[3],
                              str(row[4]) if row[4] is not None else None,
                              str(row[5]) if row[5] is not None else None) for row in rows]

    def note_checked_or_remove_delivered(self, alert):
        with database() as conn:
            deleted = conn.execute(
                'DELETE FROM unattributed_sensor_alerts WHERE event_hash = %s '
                'AND EXISTS (SELECT 1 FROM personal_security_alerts WHERE event_hash = %s) RETURNING event_hash',
                (alert.event_hash, alert.event_hash),
            ).fetchone()
            if deleted is None:
                conn.execute('UPDATE unattributed_sensor_alerts SET last_checked_at = clock_timestamp() WHERE event_hash = %s',
                             (alert.event_hash,))
