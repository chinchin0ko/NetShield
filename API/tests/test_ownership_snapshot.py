import pytest
from controller.wg_easy_bridge import ownership_snapshot


def peer(user, device, address, key):
    return {'name': f'netshield-{user}-{device * 32}', 'address': address, 'publicKey': key, 'enabled': True}


def test_snapshot_cross_checks_kernel_and_filters_unmanaged():
    clients = [peer(1, 'a', '10.8.0.2', 'k1'),
               {'name': 'legacy', 'address': '10.8.0.3', 'publicKey': 'k2', 'enabled': True},
               {**peer(2, 'b', '10.8.0.4', 'k3'), 'enabled': False}]
    assert ownership_snapshot(clients, 'k1\t10.8.0.2/32\nk2\t10.8.0.3/32\n') == [
        {'user_id': 1, 'device_id': 'a' * 32, 'address': '10.8.0.2'}]


@pytest.mark.parametrize('kernel', ['', 'k1\t10.8.0.3/32', 'k1\t10.8.0.2/24',
                                     'k1\t10.8.0.2/32,10.8.0.3/32',
                                     'k1\t10.8.0.2/32\nk1\t10.8.0.2/32'])
def test_snapshot_fails_closed_when_manager_and_kernel_disagree(kernel):
    with pytest.raises(RuntimeError):
        ownership_snapshot([peer(1, 'a', '10.8.0.2', 'k1')], kernel)


def test_bridge_coordinated_revocation_returns_snapshot_after_disable(monkeypatch, capsys):
    import io
    import json
    from types import SimpleNamespace
    from controller import wg_easy_bridge as bridge

    device = 'a' * 32
    client = {'id': '11111111-1111-1111-1111-111111111111', 'name': 'netshield-1-' + device,
              'address': '10.8.0.2', 'publicKey': 'k1', 'enabled': True}
    class Reply:
        def __init__(self, body): self.body = body
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): return self.body
    class Opener:
        def open(self, request, timeout):
            if request.full_url.endswith('/api/session'): return Reply(b'{}')
            if request.full_url.endswith('/disable'):
                client['enabled'] = False
                return Reply(b'{}')
            return Reply(json.dumps([client]).encode())
    def run(args, **kwargs):
        if args[1] == 'inspect': return SimpleNamespace(stdout=b'["PASSWORD=test"]')
        assert client['enabled'] is False
        return SimpleNamespace(stdout='')
    monkeypatch.setattr(bridge.urllib.request, 'build_opener', lambda *args: Opener())
    monkeypatch.setattr(bridge.subprocess, 'run', run)
    monkeypatch.setattr(bridge.os, 'makedirs', lambda *args, **kwargs: None)
    monkeypatch.setattr('builtins.open', lambda *args, **kwargs: io.StringIO())
    monkeypatch.setattr(bridge.fcntl, 'flock', lambda *args: None)
    request = json.dumps({'op': 'revoke', 'user_id': 1, 'device_id': device, 'history': True}) + '\n'
    monkeypatch.setattr(bridge.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(request.encode())))
    bridge.main()
    assert json.loads(capsys.readouterr().out) == {'found': True, 'ownership_snapshot': []}


def test_bridge_enforcement_rejects_uncoordinated_mutation(monkeypatch):
    import io
    import json
    from types import SimpleNamespace
    from controller import wg_easy_bridge as bridge
    request = json.dumps({'op': 'revoke', 'user_id': 1, 'device_id': 'a' * 32}) + '\n'
    monkeypatch.setattr(bridge.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(request.encode())))
    monkeypatch.setattr(bridge.os.path, 'exists', lambda path: True)
    with pytest.raises(ValueError, match='coordination required'):
        bridge.main()
