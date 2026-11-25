#!/usr/bin/env bash
# Offline synthetic DNS packet and rule. Does not inspect live traffic.
set -euo pipefail
command -v suricata >/dev/null || { echo 'Falta suricata.' >&2; exit 1; }
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
cat > "$workdir/test.rules" <<'RULE'
alert dns any any -> any any (msg:"NETSHIELD LAB MALWARE indicator"; dns.query; content:"netshield-lab-test.invalid"; nocase; sid:9900001; rev:1;)
RULE
python3 - "$workdir/test.pcap" <<'PY'
import socket, struct, sys, time
def checksum(data):
    if len(data) % 2: data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data)//2), data))
    total = (total & 65535) + (total >> 16)
    total = (total & 65535) + (total >> 16)
    return (~total) & 65535
name = b''.join(bytes([len(part)]) + part for part in b'netshield-lab-test.invalid'.split(b'.')) + b'\0'
dns = struct.pack('!HHHHHH', 1, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', 1, 1)
udp = struct.pack('!HHHH', 54321, 53, 8 + len(dns), 0) + dns
src, dst = socket.inet_aton('10.8.0.2'), socket.inet_aton('1.1.1.1')
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
packet = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + udp
with open(sys.argv[1], 'wb') as f:
    f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    f.write(struct.pack('<IIII', int(time.time()), 0, len(packet), len(packet)))
    f.write(packet)
PY
suricata -c /etc/suricata/suricata.yaml -r "$workdir/test.pcap" -S "$workdir/test.rules" -l "$workdir" --runmode single >/dev/null 2>&1
python3 - "$workdir/eve.json" <<'PY'
import json, sys
events = [json.loads(line) for line in open(sys.argv[1])]
assert any(e.get('event_type') == 'alert' and e.get('alert', {}).get('signature_id') == 9900001 for e in events)
print('OK: Suricata detectó el indicador DNS sintético sin tráfico real')
PY
