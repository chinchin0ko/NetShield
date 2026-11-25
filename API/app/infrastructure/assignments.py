"""Storage for verified VPN address ownership intervals.

Mutations must go through the coordinator; the lock survives SSH round trips.
"""
from contextlib import contextmanager

from app.application.attribution import Assignment
from app.infrastructure.postgres import database


class PostgresAssignments:
    def __init__(self):
        self._locked_conn = None

    @contextmanager
    def exclusive(self):
        # A session lock survives the commits on each side of the SSH call.
        with database() as conn:
            conn.execute("SELECT pg_advisory_lock(hashtextextended('netshield:assignments', 0))")
            conn.commit()
            self._locked_conn = conn
            try:
                yield
            finally:
                self._locked_conn = None
                # Closing the connection releases the lock even after a failed transaction.

    def suspend(self):
        conn = self._locked_conn
        if conn is None:
            raise RuntimeError('assignment lock required')
        # Close all active intervals in a committed transaction before mutation.
        conn.execute('UPDATE vpn_address_assignments SET valid_until = clock_timestamp() '
                     'WHERE valid_until IS NULL')
        conn.commit()

    def resume(self, peers):
        conn = self._locked_conn
        if conn is None:
            raise RuntimeError('assignment lock required')
        for peer in peers:
            conn.execute('INSERT INTO vpn_address_assignments '
                         '(address, user_id, device_id, valid_from) '
                         'VALUES (%s, %s, %s, clock_timestamp())',
                         (peer.address, peer.user_id, peer.device_id))
        conn.commit()

    def find_at(self, address, occurred_at):
        """Return matching history; callers still enforce attribution policy."""
        with database() as conn:
            rows = conn.execute(
                "SELECT address, user_id, device_id, valid_from, valid_until "
                "FROM vpn_address_assignments WHERE address = %s "
                "AND valid_from <= %s AND (valid_until IS NULL OR valid_until > %s)",
                (str(address), occurred_at, occurred_at),
            ).fetchall()
        return [Assignment(*row) for row in rows]
