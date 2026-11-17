"""Single-process laboratory coordinator. Never use with production peers."""
import ipaddress
import sqlite3
import threading


class LabConnections:
    def __init__(self, path, peers, subnet='10.200.200.0/29'):
        self.path, self.peers = str(path), peers
        self.network = ipaddress.ip_network(subnet, strict=True)
        if self.network.version != 4 or not 24 <= self.network.prefixlen <= 29:
            raise ValueError('Expected an IPv4 lab subnet between /24 and /29')
        self.lock = threading.RLock()
        with self.db() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS lab_devices (
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
                public_key TEXT NOT NULL UNIQUE, address TEXT UNIQUE,
                state TEXT NOT NULL CHECK (state IN ('registered','provisioning','ready','revoking','revoked'))
            )''')

    def db(self):
        return sqlite3.connect(self.path, timeout=5)

    def register(self, device_id, user_id, public_key):
        # The real peer gateway validates the key before provisioning.
        with self.lock, self.db() as conn:
            conn.execute('INSERT INTO lab_devices (id, user_id, public_key, state) VALUES (?, ?, ?, ?)',
                         (device_id, user_id, public_key, 'registered'))

    def _get(self, conn, user_id, device_id):
        row = conn.execute('SELECT public_key, address, state FROM lab_devices WHERE id=? AND user_id=?',
                           (device_id, user_id)).fetchone()
        if row is None:
            raise LookupError('Device not found')
        return row

    def connect(self, user_id, device_id):
        with self.lock:
            with self.db() as conn:
                key, address, state = self._get(conn, user_id, device_id)
                if state in ('revoking', 'revoked'):
                    raise ValueError('Device is being revoked or has been revoked')
                if address is None:
                    used = {row[0] for row in conn.execute('SELECT address FROM lab_devices WHERE address IS NOT NULL')}
                    # Reserve the first usable address for the server.
                    available = (str(ip) + '/32' for ip in list(self.network.hosts())[1:])
                    address = next((ip for ip in available if ip not in used), None)
                    if address is None:
                        raise RuntimeError('No lab addresses available')
                conn.execute("UPDATE lab_devices SET address=?, state='provisioning' WHERE id=?", (address, device_id))
            # Pending state is committed before external action; failures retain it for retry.
            self.peers.provision(key, address)
            with self.db() as conn:
                conn.execute("UPDATE lab_devices SET state='ready' WHERE id=?", (device_id,))
            return address

    def revoke(self, user_id, device_id):
        with self.lock:
            with self.db() as conn:
                key, address, state = self._get(conn, user_id, device_id)
                if state == 'revoked':
                    return
                conn.execute("UPDATE lab_devices SET state='revoking' WHERE id=?", (device_id,))
            # Do not release the address on failure; a retry can finish revocation.
            self.peers.revoke(key)
            with self.db() as conn:
                conn.execute("UPDATE lab_devices SET state='revoked', address=NULL WHERE id=?", (device_id,))

    def status(self, user_id, device_id):
        with self.db() as conn:
            _, address, state = self._get(conn, user_id, device_id)
            return state, address
