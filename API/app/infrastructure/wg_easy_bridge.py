"""Connect to the restricted WireGuard manager over SSH."""
import json
import os
import re
import subprocess


class ProvisioningError(Exception):
    pass


class DeviceRevoked(Exception):
    pass


class DeviceKeyConflict(Exception):
    pass


class DeviceLimitReached(Exception):
    pass


def _request(user_id: int, operation: str, device_id: str | None = None, public_key: str | None = None, history: bool = False) -> dict:
    if operation not in {'provision', 'revoke', 'list', 'usage'} or (device_id is not None and not re.fullmatch(r'[0-9a-f]{32}', device_id)):
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
    if history:
        request['history'] = True
    try:
        result = subprocess.run(['ssh', '-T', '-i', key, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'ConnectTimeout=5', host], input=json.dumps(request) + '\n', text=True, capture_output=True, timeout=20, check=True)
        if len(result.stdout) > 131072:
            raise ValueError('response too large')
        data = json.loads(result.stdout)
        if not isinstance(data, dict):
            raise ValueError('invalid response')
        if data.get('error') == 'revoked':
            raise DeviceRevoked
        if data.get('error') == 'key_conflict':
            raise DeviceKeyConflict
        if data.get('error') == 'device_limit':
            raise DeviceLimitReached
        if 'error' in data:
            raise ValueError('bridge error')
        return data
    except (subprocess.SubprocessError, OSError, KeyError, ValueError):
        raise ProvisioningError('VPN unavailable') from None


def provision(user_id: int, device_id: str, public_key: str) -> str:
    data = (coordinated_request(user_id, 'provision', device_id, public_key)
            if os.environ.get('NETSHIELD_TRACK_ASSIGNMENTS') == '1'
            else _request(user_id, 'provision', device_id, public_key))
    config = data.get('config')
    if not isinstance(config, str) or len(config) > 8192:
        raise ProvisioningError('VPN unavailable')
    return config


def list_devices(user_id: int) -> list:
    devices = _request(user_id, 'list').get('devices')
    if not isinstance(devices, list):
        raise ProvisioningError('VPN unavailable')
    return devices


def device_usage(user_id: int) -> list:
    devices = _request(user_id, 'usage').get('devices')
    if not isinstance(devices, list):
        raise ProvisioningError('VPN unavailable')
    for device in devices:
        if (not isinstance(device, dict) or not isinstance(device.get('device_id'), str)
                or not re.fullmatch(r'[0-9a-f]{32}', device['device_id'])
                or not {'upload_bytes', 'download_bytes'} <= device.keys()):
            raise ProvisioningError('VPN unavailable')
        for field in ('upload_bytes', 'download_bytes'):
            value = device.get(field)
            if value is not None and (type(value) is not int or not 0 <= value < 2**63):
                raise ProvisioningError('VPN unavailable')
    return devices


def revoke(user_id: int, device_id: str) -> bool:
    data = (coordinated_request(user_id, 'revoke', device_id)
            if os.environ.get('NETSHIELD_TRACK_ASSIGNMENTS') == '1'
            else _request(user_id, 'revoke', device_id))
    found = data.get('found')
    if not isinstance(found, bool):
        raise ProvisioningError('VPN unavailable')
    return found


def coordinated_request(user_id, operation, device_id, public_key=None):
    """Run one peer mutation under a DB session lock and persist ownership."""
    import psycopg
    from app.application.assignment_lifecycle import SnapshotPeer, mutate_with_history
    from app.infrastructure.assignments import PostgresAssignments

    class Controller:
        def mutate_and_snapshot(self, unused):
            data = _request(user_id, operation, device_id, public_key, history=True)
            raw = data.pop('ownership_snapshot', None)
            if not isinstance(raw, list):
                raise ProvisioningError('VPN unavailable')
            try:
                peers = [SnapshotPeer(**item) for item in raw]
            except (TypeError, ValueError):
                raise ProvisioningError('VPN unavailable') from None
            return data, peers

    try:
        return mutate_with_history(PostgresAssignments(), Controller(), operation)
    except (psycopg.Error, RuntimeError, ValueError):
        raise ProvisioningError('VPN unavailable') from None
