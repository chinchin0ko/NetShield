"""Experimental PostgreSQL coordinator for isolated lab use only."""
import ipaddress
import subprocess

from app.infrastructure.postgres import database


class PostgresLabConnections:
    def __init__(self, peers, subnet='10.200.200.0/29'):
        self.peers = peers
        self.network = ipaddress.ip_network(subnet, strict=True)
        if self.network.version != 4 or not 24 <= self.network.prefixlen <= 29:
            raise ValueError('Expected IPv4 lab subnet between /24 and /29')

    @staticmethod
    def install_schema():
        with database() as conn:
            conn.execute('''CREATE TABLE lab_connections (
                device_id bigint PRIMARY KEY REFERENCES devices(id) ON DELETE RESTRICT,
                address inet UNIQUE,
                state text NOT NULL CHECK (state IN ('provisioning', 'ready', 'revoking', 'revoked'))
            )''')

    @staticmethod
    def _device(conn, user_id, device_id):
        row = conn.execute('SELECT public_key FROM devices WHERE id=%s AND user_id=%s',
                           (device_id, user_id)).fetchone()
        if row is None:
            raise LookupError('Device not found')
        return row[0]

    def register(self, device_id, user_id, public_key):
        with database() as conn:
            if self._device(conn, user_id, device_id) != public_key:
                raise LookupError('Device not found')

    @staticmethod
    def _lock(conn, device_id):
        # Session lock survives intermediate commits and is released on connection close.
        conn.execute("SELECT pg_advisory_lock(hashtextextended(current_schema() || ':lab-device:' || %s, 0))",
                     (str(device_id),))
        conn.commit()

    def connect(self, user_id, device_id):
        with database() as conn:
            self._lock(conn, device_id)
            key = self._device(conn, user_id, device_id)
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':lab-addresses', 0))")
            row = conn.execute("SELECT host(address) || '/32', state FROM lab_connections WHERE device_id=%s FOR UPDATE",
                               (device_id,)).fetchone()
            if row and row[1] in ('revoking', 'revoked'):
                raise ValueError('Device is being revoked or has been revoked')
            address = row[0] if row else None
            if address is None:
                used = {r[0] for r in conn.execute("SELECT host(address) || '/32' FROM lab_connections WHERE address IS NOT NULL")}
                address = next((f'{ip}/32' for ip in list(self.network.hosts())[1:] if f'{ip}/32' not in used), None)
                if address is None:
                    raise RuntimeError('No lab addresses available')
            conn.execute('''INSERT INTO lab_connections (device_id, address, state) VALUES (%s, %s, 'provisioning')
                            ON CONFLICT (device_id) DO UPDATE SET address=EXCLUDED.address, state=EXCLUDED.state''',
                         (device_id, address))
            conn.commit()
            # Pending state remains committed if the external operation fails.
            self.peers.provision(key, address)
            conn.execute("UPDATE lab_connections SET state='ready' WHERE device_id=%s", (device_id,))
            conn.commit()
            return address

    def revoke(self, user_id, device_id):
        with database() as conn:
            self._lock(conn, device_id)
            key = self._device(conn, user_id, device_id)
            row = conn.execute('SELECT state FROM lab_connections WHERE device_id=%s FOR UPDATE', (device_id,)).fetchone()
            if row is None:
                raise LookupError('Connection not found')
            if row[0] == 'revoked':
                return
            conn.execute("UPDATE lab_connections SET state='revoking' WHERE device_id=%s", (device_id,))
            conn.commit()
            self.peers.revoke(key)
            conn.execute("UPDATE lab_connections SET state='revoked', address=NULL WHERE device_id=%s", (device_id,))
            conn.commit()

    def status(self, user_id, device_id):
        with database() as conn:
            self._device(conn, user_id, device_id)
            row = conn.execute("SELECT state, host(address) || '/32' FROM lab_connections WHERE device_id=%s",
                               (device_id,)).fetchone()
            if row is None:
                raise LookupError('Connection not found')
            return row

    def reconcile(self):
        """Reapply known peers after a lab interface restart; never delete unknown peers."""
        with database() as conn:
            rows = conn.execute(
                "SELECT d.user_id, d.id, c.state FROM lab_connections c "
                "JOIN devices d ON d.id=c.device_id "
                "WHERE c.state IN ('provisioning', 'ready', 'revoking') ORDER BY d.id"
            ).fetchall()
        outcomes = {'ready': 0, 'revoked': 0, 'failed': 0}
        for user_id, device_id, state in rows:
            try:
                if state == 'revoking':
                    self.revoke(user_id, device_id)
                    outcomes['revoked'] += 1
                else:
                    self.connect(user_id, device_id)
                    outcomes['ready'] += 1
            except (OSError, RuntimeError, LookupError, ValueError, subprocess.SubprocessError):
                outcomes['failed'] += 1
        return outcomes
