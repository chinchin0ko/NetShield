"""Storage for verified VPN address ownership intervals.

Not wired to the live controller: a successful peer change alone is not proof
that its database record was committed. Reconciliation is required first.
"""
from app.application.attribution import Assignment
from app.infrastructure.postgres import database


class PostgresAssignments:
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
