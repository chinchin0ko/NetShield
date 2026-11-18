#!/usr/bin/env python3
"""Privileged, fixed-purpose nftables switch. Installed root-owned via polkit."""
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

TABLE = 'netshield_lock'
NFT = '/usr/sbin/nft'
STATE = Path('/run/netshield-lock')


def nft(*args, data=None):
    return subprocess.run([NFT, *args], input=data, text=True, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE, timeout=10)


def main(argv):
    if argv == ['disable']:
        result = nft('list', 'table', 'inet', TABLE)
        if result.returncode == 0 and nft('delete', 'table', 'inet', TABLE).returncode:
            raise RuntimeError('failed to remove rules')
        (STATE / 'active').unlink(missing_ok=True)
        return
    if len(argv) != 3 or argv[0] != 'enable' or not re.fullmatch(r'ns[0-9a-f]{12}', argv[1]):
        raise ValueError('invalid request')
    interface = argv[1]
    endpoint = ipaddress.IPv4Address(argv[2])
    if endpoint.is_multicast or endpoint.is_unspecified or endpoint.is_loopback:
        raise ValueError('invalid endpoint')
    if nft('list', 'table', 'inet', TABLE).returncode == 0:
        raise RuntimeError('switch already active')
    rules = f'''table inet {TABLE} {{
 chain output {{
  type filter hook output priority filter; policy drop;
  oifname "lo" accept
  oifname "{interface}" accept
  ip daddr {endpoint} udp dport 51820 accept
  ip daddr {endpoint} tcp dport 22 accept
 }}
}}
'''
    STATE.mkdir(mode=0o755, exist_ok=True)
    (STATE / 'active').write_text('active\n')
    if nft('-f', '-', data=rules).returncode:
        (STATE / 'active').unlink(missing_ok=True)
        raise RuntimeError('failed to install rules')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired):
        print('No se pudo cambiar el bloqueo de tráfico de NetShield.', file=sys.stderr)
        raise SystemExit(1)
