from app.infrastructure.postgres import database


class PostgresAlerts:
    def save(self, alert):
        with database() as conn:
            row = conn.execute(
                'INSERT INTO security_alerts (event_hash, occurred_at, signature, severity, source_ip, destination_ip) '
                'VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (event_hash) DO NOTHING RETURNING id',
                (alert.event_hash, alert.occurred_at, alert.signature, alert.severity,
                 alert.source_ip, alert.destination_ip),
            ).fetchone()
        return row is not None
