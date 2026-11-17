import base64
from concurrent.futures import ThreadPoolExecutor

import pytest
from app.application.vpn_peers import PeerService
from lab.connection import LabConnections


class Peers:
    def __init__(self): self.items = {}; self.fail_add = False; self.fail_remove = False
    def provision(self, key, address):
        self.items[key] = address
        if self.fail_add: raise OSError('response lost')
    def revoke(self, key):
        if self.fail_remove: raise OSError('unavailable')
        self.items.pop(key, None)


def key(n): return base64.b64encode(bytes([n]) * 32).decode()


def test_idempotence_ownership_and_concurrent_allocation(tmp_path):
    peers = Peers()
    lab = LabConnections(tmp_path / 'lab.sqlite', peers)
    lab.register(1, 1, key(1)); lab.register(2, 2, key(2))
    with ThreadPoolExecutor(max_workers=2) as pool:
        addresses = list(pool.map(lambda args: lab.connect(*args), [(1, 1), (2, 2)]))
    assert len(set(addresses)) == 2
    assert lab.connect(1, 1) == addresses[0]
    with pytest.raises(LookupError): lab.revoke(2, 1)
    assert lab.status(1, 1) == ('ready', addresses[0])
    lab.revoke(1, 1)
    lab.revoke(1, 1)
    assert lab.status(1, 1) == ('revoked', None)
    with pytest.raises(ValueError): lab.connect(1, 1)


def test_recovery_keeps_address_until_revocation_succeeds(tmp_path):
    peers = Peers()
    path = tmp_path / 'lab.sqlite'
    lab = LabConnections(path, peers)
    lab.register(1, 1, key(1))
    peers.fail_add = True
    with pytest.raises(OSError): lab.connect(1, 1)
    state, address = lab.status(1, 1)
    assert state == 'provisioning' and address is not None
    # A restarted coordinator can retry even if the peer was already added.
    peers.fail_add = False
    restarted = LabConnections(path, peers)
    assert restarted.connect(1, 1) == address
    peers.fail_remove = True
    with pytest.raises(OSError): restarted.revoke(1, 1)
    assert restarted.status(1, 1) == ('revoking', address)
    peers.fail_remove = False
    restarted.revoke(1, 1)
    assert restarted.status(1, 1) == ('revoked', None)
