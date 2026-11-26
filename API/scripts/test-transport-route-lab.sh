#!/usr/bin/env bash
# Rootless namespaces only: verify policy-route loop avoidance and real negative
# controls for TCP/443. Every tested destination is reachable before locking.
set -euo pipefail
export NS_HELPER="$(realpath "$(dirname "$0")/../../app/linux/netshield/killswitch.py")"
exec unshare --user --map-root-user --mount --net bash <<'LAB'
set -euo pipefail
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /var/lib
work=$(mktemp -d)
peer='';server=''
cleanup(){ [[ -z "$server" ]] || kill "$server" 2>/dev/null || true; [[ -z "$peer" ]] || kill "$peer" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
ip link set lo up
unshare --net sleep 90 & peer=$!
ip link add nst-a type veth peer name nst-b
ip link set nst-b netns "$peer"
ip addr add 192.0.2.1/24 dev nst-a
ip link set nst-a up
nsenter -t "$peer" -n ip link set lo up
nsenter -t "$peer" -n ip addr add 192.0.2.2/24 dev nst-b
nsenter -t "$peer" -n ip link set nst-b up
nsenter -t "$peer" -n ip addr add 203.0.113.3/32 dev lo
nsenter -t "$peer" -n ip addr add 203.0.113.4/32 dev lo
cat > "$work/server.py" <<'PY'
import socket,select,sys,time
listeners=[]
for address,port in [('203.0.113.3',443),('203.0.113.3',80),('203.0.113.4',443)]:
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((address,port));s.listen();listeners.append(s)
open(sys.argv[1],'w').close()
while True:
 for s in select.select(listeners,[],[],1)[0]:
  c,_=s.accept();c.sendall(b'OK');c.close()
PY
nsenter -t "$peer" -n python3 "$work/server.py" "$work/ready" & server=$!
for n in {1..30}; do [[ -e "$work/ready" ]] && break; sleep .1; done
[[ -e "$work/ready" ]]
ip route add default via 192.0.2.2
ip link add ns123456789abc type wireguard
ip link set ns123456789abc up
ip route add default dev ns123456789abc table 51820
ip rule add priority 100 table main suppress_prefixlength 0
ip rule add priority 110 table 51820
ip route get 203.0.113.3 | grep -q 'dev ns123456789abc'
echo 'OK: without host route, transport is swallowed by WireGuard'
ip route add 203.0.113.3/32 via 192.0.2.2 dev nst-a metric 42777
ip route add 203.0.113.4/32 via 192.0.2.2 dev nst-a metric 42777
ip route get 203.0.113.3 | grep -q 'dev nst-a'
probe(){ python3 -c 'import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1); assert s.recv(2)==b"OK"' "$1" "$2"; }
probe 203.0.113.3 443;probe 203.0.113.3 80;probe 203.0.113.4 443
echo 'OK: all three destinations reachable before lock (negative controls)'
python3 "$NS_HELPER" enable ns123456789abc 203.0.113.3 tcp-mode
probe 203.0.113.3 443
if probe 203.0.113.3 80 2>/dev/null; then exit 1; fi
if probe 203.0.113.4 443 2>/dev/null; then exit 1; fi
echo 'OK: TLS server allowed, HTTP and unrelated TLS destination blocked'
ip link set ns123456789abc down
probe 203.0.113.3 443
if probe 203.0.113.4 443 2>/dev/null; then exit 1; fi
echo 'OK: transport route survives VPN failure without permitting unrelated traffic'
nft delete table inet netshield_lock
rm /run/netshield-lock/active
python3 "$NS_HELPER" restore
probe 203.0.113.3 443
if probe 203.0.113.3 80 2>/dev/null; then exit 1; fi
if probe 203.0.113.4 443 2>/dev/null; then exit 1; fi
python3 "$NS_HELPER" disable
probe 203.0.113.3 80;probe 203.0.113.4 443
echo 'OK: restore preserves protection and deliberate unlock restores baseline'
LAB
