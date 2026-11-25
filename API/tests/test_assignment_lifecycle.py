import pytest
from contextlib import contextmanager
from app.application.assignment_lifecycle import SnapshotPeer, mutate_with_history


class Store:
    def __init__(self):
        self.active = ['previous']
        self.locked = False
    @contextmanager
    def exclusive(self):
        assert not self.locked
        self.locked = True
        try:
            yield
        finally:
            self.locked = False
    def suspend(self):
        assert self.locked
        self.active = []
    def resume(self, peers):
        assert self.locked
        self.active = peers


class Controller:
    def __init__(self, store, peers, fail=False):
        self.store, self.peers, self.fail = store, peers, fail
    def mutate_and_snapshot(self, operation):
        assert self.store.locked and self.store.active == []
        if self.fail:
            raise RuntimeError('controller failure')
        return operation, self.peers


def test_history_is_suspended_before_mutation_and_restored_after_verified_snapshot():
    store = Store()
    peer = SnapshotPeer(1, 'a' * 32, '10.8.0.2')
    assert mutate_with_history(store, Controller(store, [peer]), 'provision') == 'provision'
    assert store.active == [peer] and not store.locked


@pytest.mark.parametrize('peers,fail', [
    ([], True),
    ([SnapshotPeer(1, 'a'*32, '10.8.0.2'), SnapshotPeer(2, 'b'*32, '10.8.0.2')], False),
    ([SnapshotPeer(1, 'a'*32, '192.0.2.2')], False),
    ([SnapshotPeer(1, 'a'*32, '10.8.0.2'), SnapshotPeer(1, 'a'*32, '10.8.0.3')], False),
])
def test_failure_or_ambiguous_snapshot_leaves_history_closed(peers, fail):
    store = Store()
    with pytest.raises((ValueError, RuntimeError)):
        mutate_with_history(store, Controller(store, peers, fail), 'revoke')
    assert store.active == [] and not store.locked
