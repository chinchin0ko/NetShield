from controller.wg_easy_bridge import device_limit_reached
import pytest
import io
import json
import types

from app.infrastructure import wg_easy_bridge
from controller import wg_easy_bridge as controller


def test_device_quota_counts_only_valid_devices_owned_by_user():
    prefix = 'netshield-7-'
    def peer(index, enabled=True, owner=prefix):
        return {'name': owner + f'{index:032x}', 'enabled': enabled}

    assert not device_limit_reached([peer(i) for i in range(4)] + [peer(7, owner='netshield-8-')], prefix)
    assert device_limit_reached([peer(i) for i in range(5)], prefix)
    assert not device_limit_reached([peer(i, enabled=False) for i in range(19)], prefix)
    assert device_limit_reached([peer(i, enabled=False) for i in range(20)], prefix)
    assert not device_limit_reached([{'name': prefix + 'invalid', 'enabled': True}], prefix)


def test_backend_recognizes_bridge_quota_error(monkeypatch):
    for name in ('NETSHIELD_WG_BRIDGE_KEY', 'NETSHIELD_WG_BRIDGE_HOST', 'NETSHIELD_WG_BRIDGE_KNOWN_HOSTS'):
        monkeypatch.setenv(name, 'test')
    class Result:
        stdout = '{"error":"device_limit"}'
    monkeypatch.setattr(wg_easy_bridge.subprocess, 'run', lambda *args, **kwargs: Result())
    with pytest.raises(wg_easy_bridge.DeviceLimitReached):
        wg_easy_bridge.provision(7, 'a' * 32, 'key')


def test_bridge_blocks_new_peer_but_allows_existing_at_limit(monkeypatch, tmp_path, capsys):
    key = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
    clients = [{'name': 'netshield-7-' + f'{i:032x}', 'enabled': True,
                'id': 'a' * 8 + '-' + 'b' * 4 + '-' + 'c' * 4 + '-' + 'd' * 4 + '-' + 'e' * 12,
                'publicKey': key if i == 0 else 'other', 'downloadableConfig': False} for i in range(5)]
    calls = []
    class Response:
        def __init__(self, data): self.data = data
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, *_): return self.data
    class Opener:
        def open(self, request, timeout):
            calls.append((request.get_method(), request.full_url))
            if request.full_url.endswith('/api/wireguard/client'): return Response(json.dumps(clients).encode())
            if request.full_url.endswith('/configuration'): return Response(b'[Interface]\n[Peer]\n')
            return Response(b'{}')
    monkeypatch.setattr(controller.subprocess, 'run', lambda *a, **k: types.SimpleNamespace(stdout='["PASSWORD=test"]'))
    monkeypatch.setattr(controller.urllib.request, 'build_opener', lambda *a: Opener())
    monkeypatch.setattr(controller.os, 'makedirs', lambda *a, **k: None)
    monkeypatch.setattr(controller, 'open', lambda *a, **k: open(tmp_path / 'lock', 'w'), raising=False)
    def run(device):
        request = {'op': 'provision', 'user_id': 7, 'device_id': device, 'public_key': key}
        monkeypatch.setattr(controller.sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO((json.dumps(request) + '\n').encode())))
        controller.main()
        return json.loads(capsys.readouterr().out)
    # Use a distinct key to reach the quota check for a new device.
    clients[0]['publicKey'] = 'other'
    assert run(f'{10:032x}') == {'error': 'device_limit'}
    assert not any(method == 'POST' and url.endswith('/api/wireguard/client-external') for method, url in calls)
    clients[0]['publicKey'] = key
    assert 'config' in run(f'{0:032x}')
