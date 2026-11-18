"""Runs only in an isolated network namespace."""
import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest


def test_controller_scoped_operations(tmp_path):
    if os.environ.get('NETSHIELD_AGENT_LAB') != '1':
        pytest.skip('Run inside the isolated agent lab')
    sockpath = tmp_path / 'control.sock'
    env = dict(os.environ, NETSHIELD_AGENT_SOCKET=str(sockpath), NETSHIELD_AGENT_STATE=str(tmp_path / 'state'))
    agent = subprocess.Popen([sys.executable, 'controller/dev_agent.py'], env=env)
    try:
        for _ in range(50):
            if sockpath.exists(): break
            assert agent.poll() is None
            time.sleep(0.1)
        assert sockpath.exists()
        assert stat.S_IMODE(sockpath.stat().st_mode) == 0o600
        def call(data):
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(sockpath))
                client.sendall(json.dumps(data).encode() + b'\n')
                return json.loads(client.makefile('rb').readline())
        def generate():
            private = subprocess.run(['wg', 'genkey'], check=True, capture_output=True).stdout
            return subprocess.run(['wg', 'pubkey'], input=private, check=True, capture_output=True).stdout.decode().strip()
        key1, key2 = generate(), generate()
        assert call({'op':'status'}) == {'ok':True, 'interface':'wg-nsdev', 'peers':0}
        assert call({'op':'add', 'public_key':key1, 'address':'10.254.70.2/32'}) == {'ok':True}
        assert call({'op':'add', 'public_key':key2, 'address':'10.254.70.2/32'})['ok'] is False
        assert call({'op':'add', 'public_key':key2, 'address':'0.0.0.0/0'})['ok'] is False
        assert call({'op':'add', 'public_key':key2, 'address':'10.254.70.3/32', 'interface':'wg0'})['ok'] is False
        assert call({'op':'status'})['peers'] == 1
        assert call({'op':'remove', 'public_key':key1}) == {'ok':True}
        assert call({'op':'status'})['peers'] == 0
        assert stat.S_IMODE((tmp_path / 'state/server.key').stat().st_mode) == 0o600
    finally:
        agent.terminate()
        agent.wait(timeout=5)
