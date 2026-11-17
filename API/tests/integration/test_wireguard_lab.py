"""Run only in the isolated network namespace created by test-wireguard-lab.sh."""
import os
import subprocess

import pytest

from app.application.vpn_peers import PeerService
from app.infrastructure.wireguard import WireGuardLab


def test_peer_lifecycle_in_isolated_namespace():
    if os.environ.get('NETSHIELD_WG_LAB') != '1':
        pytest.skip('Run through scripts/test-wireguard-lab.sh')
    private_key = subprocess.run(['wg', 'genkey'], check=True, capture_output=True).stdout
    public_key = subprocess.run(['wg', 'pubkey'], input=private_key, check=True, capture_output=True).stdout.decode().strip()
    gateway = WireGuardLab('wg-lab0')
    service = PeerService(gateway)
    assert gateway.list_keys() == set()
    service.provision(public_key, '10.200.200.2/32')
    assert gateway.list_keys() == {public_key}
    service.provision(public_key, '10.200.200.2/32')
    assert gateway.list_keys() == {public_key}
    service.revoke(public_key)
    assert gateway.list_keys() == set()
    service.revoke(public_key)
    assert gateway.list_keys() == set()
