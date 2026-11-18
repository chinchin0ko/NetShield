"""Connect to the restricted WireGuard manager over SSH."""
import json
import os
import re
import subprocess


class ProvisioningError(Exception):
    pass


def provision(user_id: int, device_id: str) -> str:
    if not re.fullmatch(r'[0-9a-f]{32}', device_id):
        raise ValueError('invalid device id')
    key = os.environ.get('NETSHIELD_WG_BRIDGE_KEY')
    host = os.environ.get('NETSHIELD_WG_BRIDGE_HOST')
    known_hosts = os.environ.get('NETSHIELD_WG_BRIDGE_KNOWN_HOSTS')
    if not key or not host or not known_hosts:
        raise ProvisioningError('VPN unavailable')
    try:
        result = subprocess.run(['ssh', '-T', '-i', key, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'ConnectTimeout=5', host], input=json.dumps({'user_id': user_id, 'device_id': device_id}) + '\n', text=True, capture_output=True, timeout=20, check=True)
        if len(result.stdout) > 16384:
            raise ValueError('response too large')
        config = json.loads(result.stdout)['config']
        if not isinstance(config, str) or len(config) > 8192:
            raise ValueError('invalid response')
        return config
    except (subprocess.SubprocessError, OSError, KeyError, ValueError):
        raise ProvisioningError('VPN unavailable') from None
