"""PostgreSQL coordinator tests; share the isolated schema fixture."""
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.infrastructure.postgres import database
from lab.postgres_connection import PostgresLabConnections
from tests.integration.test_postgres_api import lab_database  # noqa: F401


class Peers:
    def __init__(self): self.items = {}; self.fail_add = False; self.fail_remove = False
    def provision(self, key, address):
        self.items[key] = address
        if self.fail_add: raise OSError('response lost')
    def revoke(self, key):
        if self.fail_remove: raise OSError('controller unavailable')
        self.items.pop(key, None)


def test_postgres_allocation_ownership_and_recovery(lab_database):
    peers = Peers()
    lab = PostgresLabConnections(peers)
    lab.install_schema()
    with database() as conn:
        users = conn.execute('SELECT id FROM users ORDER BY id').fetchall()
        first = conn.execute("INSERT INTO devices (user_id, name, public_key) VALUES (%s, 'a', %s) RETURNING id",
                             (users[0][0], 'a' * 44)).fetchone()[0]
        second = conn.execute("INSERT INTO devices (user_id, name, public_key) VALUES (%s, 'b', %s) RETURNING id",
                              (users[1][0], 'b' * 44)).fetchone()[0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        addresses = list(pool.map(lambda item: lab.connect(*item), [(users[0][0], first), (users[1][0], second)]))
    assert len(set(addresses)) == 2
    assert lab.connect(users[0][0], first) == addresses[0]
    # Simulate loss of all active peers after a WireGuard restart.
    peers.items.clear()
    assert lab.reconcile() == {'ready': 2, 'revoked': 0, 'failed': 0}
    assert set(peers.items) == {'a' * 44, 'b' * 44}
    peers.fail_add = True
    with pytest.raises(OSError): lab.connect(users[0][0], first)
    assert lab.status(users[0][0], first) == ('provisioning', addresses[0])
    peers.fail_add = False
    restarted = PostgresLabConnections(peers)
    assert restarted.connect(users[0][0], first) == addresses[0]
    with pytest.raises(LookupError): lab.revoke(users[1][0], first)
    peers.fail_remove = True
    with pytest.raises(OSError): lab.revoke(users[0][0], first)
    assert lab.status(users[0][0], first) == ('revoking', addresses[0])
    peers.fail_remove = False
    assert lab.reconcile() == {'ready': 1, 'revoked': 1, 'failed': 0}
    lab.revoke(users[0][0], first)
    assert lab.status(users[0][0], first) == ('revoked', None)
