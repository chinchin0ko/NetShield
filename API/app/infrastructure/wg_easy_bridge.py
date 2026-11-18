"""Connect to the restricted WireGuard manager over SSH."""
import json
import os
import re
import subprocess


class ProvisioningError(Exception):
    pass


class DeviceRevoked(Exception):
    pass


def _request(user_id: int, operation: str, device_id: str | None = None, public_key: str | None = None) -> dict:
    if operation not in {'provision', 'revoke', 'list'} or (device_id is not None and not re.fullmatch(r'[0-9a-f]{32}', device_id)):
        raise ValueError('invalid request')
    key = os.environ.get('NETSHIELD_WG_BRIDGE_KEY')
    host = os.environ.get('NETSHIELD_WG_BRIDGE_HOST')
    known_hosts = os.environ.get('NETSHIELD_WG_BRIDGE_KNOWN_HOSTS')
    if not key or not host or not known_hosts:
        raise ProvisioningError('VPN unavailable')
    request = {'op': operation, 'user_id': user_id}
    if device_id is not None:
        request['device_id'] = device_id
    if public_key is not None:
        request['public_key'] = public_key
    try:
        result = subprocess.run(['ssh', '-T', '-i', key, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'ConnectTimeout=5', host], input=json.dumps(request) + '\n', text=True, capture_output=True, timeout=20, check=True)
        if len(result.stdout) > 131072:
            raise ValueError('response too large')
        data = json.loads(result.stdout)
        if not isinstance(data, dict):
            raise ValueError('invalid response')
        if data.get('error') == 'revoked':
            raise DeviceRevoked
        if 'error' in data:
            raise ValueError('bridge error')
        return data
    except (subprocess.SubprocessError, OSError, KeyError, ValueError):
        raise ProvisioningError('VPN unavailable') from None


def provision(user_id: int, device_id: str, public_key: str) -> str:
    data = _request(user_id, 'provision', device_id, public_key)
    config = data.get('config')
    if not isinstance(config, str) or len(config) > 8192:
        raise ProvisioningError('VPN unavailable')
    return config


def list_devices(user_id: int) -> list:
    devices = _request(user_id, 'list').get('devices')
    if not isinstance(devices, list):
        raise ProvisioningError('VPN unavailable')
    return devices


def revoke(user_id: int, device_id: str) -> bool:
    found = _request(user_id, 'revoke', device_id).get('found')
    if not isinstance(found, bool):
        raise ProvisioningError('VPN unavailable')
    return found
