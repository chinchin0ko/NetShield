#!/usr/bin/env python3
"""Privileged, fixed-purpose nftables switch. Installed root-owned via polkit.

Optional SSH access: `enable <iface> <endpoint> allow-ssh` also permits the
traffic needed for an inbound SSH session (carried over Tailscale in the
usual desktop setup): the Tailscale interface, Tailscale's WireGuard UDP
port, and TCP 443 to Tailscale's controlplane / DERP infrastructure. This is
opt-in and off by default: it deliberately weakens the lock, so the app only
enables it when the user turns on "Permitir conexiones SSH" in Ajustes.
"""
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

# Tailscale controlplane + DERP nodes (IPv4), fetched from the DERP map on
# 2026-11-22. Only used when the SSH exception is explicitly enabled.
TS_INFRA_IPS = (
    '102.67.165.185', '102.67.165.36', '102.67.165.90', '102.67.167.188',
    '102.67.167.245', '102.67.167.37', '103.6.84.152', '157.180.28.32',
    '162.248.221.199', '162.248.221.215', '162.248.221.248', '167.235.72.200',
    '172.105.166.103', '172.105.169.57', '172.105.179.230', '172.236.162.33',
    '172.236.162.40', '172.236.162.42', '172.237.28.183', '172.237.61.190',
    '172.237.61.194', '172.237.61.197', '172.237.66.30', '172.237.72.43',
    '172.237.72.79', '172.237.72.8', '172.238.6.179', '172.238.6.180',
    '172.238.6.34', '176.58.88.183', '176.58.90.104', '176.58.90.147',
    '176.58.90.207', '176.58.92.144', '176.58.92.254', '176.58.93.147',
    '176.58.93.154', '176.58.93.248', '178.156.134.232', '178.156.152.106',
    '178.156.152.91', '185.178.202.101', '185.178.202.33', '185.34.3.207',
    '185.34.3.232', '185.34.3.75', '185.40.234.113', '185.40.234.176',
    '185.40.234.219', '185.40.234.53', '185.40.234.77', '192.73.240.121',
    '192.73.240.132', '192.73.240.161', '192.73.242.187', '192.73.242.204',
    '192.73.242.28', '192.73.243.135', '192.73.243.141', '192.73.243.229',
    '192.73.244.245', '192.73.248.83', '192.73.252.134', '192.73.252.65',
    '198.18.186.205', '199.38.181.103', '199.38.181.104', '199.38.181.71',
    '199.38.181.93', '199.38.182.118', '205.147.105.30', '205.147.105.78',
    '208.111.34.178', '208.111.40.12', '208.111.40.216', '208.72.155.133',
    '208.83.233.233', '208.83.234.151', '209.177.145.118', '209.177.145.120',
    '209.177.156.197', '209.177.156.94', '209.177.158.15', '209.177.158.246',
    '45.159.97.144', '45.159.97.233', '45.159.97.61', '45.159.98.145',
    '45.159.98.196', '45.159.98.253', '46.62.141.44', '49.12.193.137',
    '49.13.204.141', '5.161.218.233', '65.109.143.62', '95.217.2.165',
)


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
        if not isinstance(config, dict) or set(config) - {'interface', 'endpoint', 'allow_ssh'}:
            raise ValueError('invalid persisted state')
        if not isinstance(config.get('interface'), str) or not isinstance(config.get('endpoint'), str):
            raise ValueError('invalid persisted state')
        allow_ssh = bool(config.get('allow_ssh', False))
        argv = ['enable', config['interface'], config['endpoint']]
        if allow_ssh:
            argv.append('allow-ssh')
    if len(argv) not in (3, 4) or argv[0] != 'enable' or not re.fullmatch(r'ns[0-9a-f]{12}', argv[1]):
        raise ValueError('invalid request')
    allow_ssh = len(argv) == 4 and argv[3] == 'allow-ssh'
    if len(argv) == 4 and argv[3] != 'allow-ssh':
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
    ssh_set = ''
    ssh_rules = ''
    if allow_ssh:
        elements = ', '.join(TS_INFRA_IPS)
        ssh_set = f''' set ts_infra {{
  type ipv4_addr
  elements = {{ {elements} }}
 }}
'''
        ssh_rules = '''  # SSH exception (opt-in, Ajustes > Permitir conexiones SSH):
  # Tailscale carries the inbound SSH session, so its interface, its
  # WireGuard UDP port and TCP 443 to its infrastructure must be allowed.
  oifname "tailscale0" accept
  udp dport 41641 accept
  ip daddr @ts_infra tcp dport 443 accept
'''
    rules = f'''table inet {TABLE} {{
{ssh_set} chain output {{
  type filter hook output priority filter; policy drop;
  oifname "lo" accept
  # The VPN currently has no IPv6 egress. Reject locally so applications can
  # retry IPv4 promptly; no IPv6 packet may leave through any interface.
  meta nfproto ipv6 reject with icmpv6 type no-route
{ssh_rules}  oifname "{interface}" accept
  ip daddr {endpoint} udp accept
 }}
}}
'''
    if not restoring:
        PERSIST.mkdir(mode=0o700, exist_ok=True)
        os.chmod(PERSIST, 0o700)
        temporary = PERSIST / 'active.json.tmp'
        temporary.write_text(json.dumps({'interface': interface, 'endpoint': str(endpoint), 'allow_ssh': allow_ssh}))
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
