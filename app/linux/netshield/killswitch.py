#!/usr/bin/env python3
"""Privileged, fixed-purpose nftables switch. Installed root-owned via polkit."""
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path

TABLE = 'netshield_lock'
NFT = '/usr/sbin/nft'
STATE = Path('/run/netshield-lock')
PERSIST = Path('/var/lib/netshield-lock')


def nft(*args, data=None):
    return subprocess.run([NFT, *args], input=data, text=True, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE, timeout=10)


def main(argv):
    if argv == ['disable']:
        # Clear the persistent intent first: a crash must not unexpectedly
        # restore a lock the user has deliberately disabled.
        (PERSIST / 'active.json').unlink(missing_ok=True)
        result = nft('list', 'table', 'inet', TABLE)
        if result.returncode == 0 and nft('delete', 'table', 'inet', TABLE).returncode:
            raise RuntimeError('failed to remove rules')
        (STATE / 'active').unlink(missing_ok=True)
        return
    restoring = argv == ['restore']
    if restoring:
        try:
            config = json.loads((PERSIST / 'active.json').read_text())
        except FileNotFoundError:
            return
        if not isinstance(config, dict) or set(config) != {'interface', 'endpoint'}:
            raise ValueError('invalid persisted state')
        argv = ['enable', config['interface'], config['endpoint']]
    if len(argv) != 3 or argv[0] != 'enable' or not re.fullmatch(r'ns[0-9a-f]{12}', argv[1]):
        raise ValueError('invalid request')
    interface = argv[1]
    endpoint = ipaddress.IPv4Address(argv[2])
    if endpoint.is_multicast or endpoint.is_unspecified or endpoint.is_loopback:
        raise ValueError('invalid endpoint')
    if nft('list', 'table', 'inet', TABLE).returncode == 0:
        if not restoring:
            raise RuntimeError('switch already active')
        STATE.mkdir(mode=0o755, exist_ok=True)
        (STATE / 'active').write_text('active\n')
        return
    rules = f'''table inet {TABLE} {{
 chain output {{
  type filter hook output priority filter; policy drop;
  oifname "lo" accept
  # The VPN currently has no IPv6 egress. Reject locally so applications can
  # retry IPv4 promptly; no IPv6 packet may leave through any interface.
  meta nfproto ipv6 reject with icmpv6 type no-route
  oifname "{interface}" accept
  ip daddr {endpoint} udp dport 51820 accept
 }}
}}
'''
    if not restoring:
        PERSIST.mkdir(mode=0o700, exist_ok=True)
        os.chmod(PERSIST, 0o700)
        temporary = PERSIST / 'active.json.tmp'
        temporary.write_text(json.dumps({'interface': interface, 'endpoint': str(endpoint)}))
        os.chmod(temporary, 0o600)
        os.replace(temporary, PERSIST / 'active.json')
    STATE.mkdir(mode=0o755, exist_ok=True)
    (STATE / 'active').write_text('active\n')
    if nft('-f', '-', data=rules).returncode:
        (STATE / 'active').unlink(missing_ok=True)
        if not restoring:
            (PERSIST / 'active.json').unlink(missing_ok=True)
        raise RuntimeError('failed to install rules')
    # Existing IPv6 TCP sessions bound to the physical network cannot migrate
    # to IPv4. Closing them after the lock is installed lets their applications
    # reconnect, while loopback sessions are retained. This is best-effort.
    try:
        subprocess.run(['/usr/bin/ss', '-K', '-6', '-t', 'state', 'connected',
                        'not ( dst [::1] )'], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (TypeError, ValueError, RuntimeError, OSError, subprocess.TimeoutExpired):
        print('No se pudo cambiar el bloqueo de tráfico de NetShield.', file=sys.stderr)
        raise SystemExit(1)
