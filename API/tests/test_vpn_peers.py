import base64
import pytest

from app.application.vpn_peers import PeerService
from app.infrastructure.wireguard import WireGuardLab


class FakeGateway:
    def __init__(self): self.peers = {}
    def add(self, public_key, address): self.peers[public_key] = address
    def remove(self, public_key): self.peers.pop(public_key, None)
    def list_keys(self): return set(self.peers)


def test_validation_blocks_malformed_keys_and_routes():
    service = PeerService(FakeGateway())
    key = base64.b64encode(b'x' * 32).decode()
    for invalid in ('bad', base64.b64encode(bytes(32)).decode()):
        with pytest.raises(ValueError): service.provision(invalid, '10.0.0.2/32')
    for route in ('10.0.0.0/24', '::1/128', 'not-an-ip'):
        with pytest.raises(ValueError): service.provision(key, route)
    service.provision(key, '10.0.0.2/32')
    assert service.gateway.peers[key] == '10.0.0.2/32'


def test_adapter_rejects_non_lab_interfaces():
    with pytest.raises(ValueError): WireGuardLab('wg0')
    with pytest.raises(ValueError): WireGuardLab('wg-lab0;bad')
