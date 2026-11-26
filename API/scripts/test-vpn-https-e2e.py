#!/usr/bin/env python3
"""Live development test: disposable account/peer and rootless network namespace.

No host routes/firewall changes. A Unix datagram bridge carries encrypted WG
packets between the namespace and either UDP or a real WSS client on the host.
Temporary keys are mode 600, removed at exit; the test peer is revoked.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess as sp
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = 'https://api.netshield.lat'


def command(*args, **kw):
    return sp.check_output(args, text=True, stderr=sp.PIPE, **kw).strip()


def api(path, payload, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=35) as response:
        body = response.read()
        return json.loads(body) if body else None


def relay(unix_path, peer_path, udp_target, stop, child=False, policy=None):
    us = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    us.bind(str(unix_path))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if child:
        udp.bind(('127.0.0.1', 51821))
    else:
        udp.connect(udp_target)
    last = None
    try:
        while not stop.is_set():
            ready, _, _ = select.select([us, udp], [], [], .1)
            for sock in ready:
                try:
                    if sock is us:
                        data = us.recv(65535)
                        if child:
                            if last:
                                udp.sendto(data, last)
                        else:
                            target = policy['target'] if policy else udp_target
                            if policy and policy['block_udp'] and target[0] != '127.0.0.1':
                                policy['dropped'] += 1
                                continue
                            udp.connect(target)
                            udp.send(data)
                    else:
                        data, last = udp.recvfrom(65535)
                        us.sendto(data, str(peer_path))
                except (FileNotFoundError, ConnectionRefusedError):
                    pass
    finally:
        us.close()
        udp.close()


def child_test(work):
    command('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    command('mount', '-t', 'tmpfs', 'tmpfs', '/var/lib')
    command('ip', 'link', 'set', 'lo', 'up')
    config = json.loads((work / 'settings.json').read_text())
    stop = threading.Event()
    thread = threading.Thread(target=relay, args=(work/'child.sock', work/'parent.sock', None, stop, True), daemon=True)
    thread.start()
    name = 'ns000000000001'
    command('ip', 'link', 'add', name, 'type', 'wireguard')
    command('wg', 'setconf', name, str(work/'wg.conf'))
    command('ip', 'addr', 'add', config['address'], 'dev', name)
    command('ip', 'link', 'set', name, 'mtu', '1280', 'up')
    command('ip', 'route', 'add', 'default', 'dev', name)
    helper = str(ROOT/'app/linux/netshield/killswitch.py')
    command(sys.executable, helper, 'enable', name, config['endpoint'], 'tcp-mode')
    def ping_ok():
        return sp.run(['ping','-4','-I',name,'-c','1','-W','2','10.8.0.1'],stdout=sp.DEVNULL,stderr=sp.DEVNULL).returncode == 0
    for _ in range(8):
        if ping_ok():
            break
    else:
        raise RuntimeError('gateway did not answer')
    print('OK: authenticated WireGuard handshake and gateway', flush=True)
    def check_navigation():
        answers = command('dig', '@'+config['dns'], 'api.ipify.org', 'A', '+short', '+time=3', '+tries=1')
        ip = next(line for line in answers.splitlines() if re.fullmatch(r'[0-9.]+', line))
        result = command('curl','-4','--fail','--silent','--show-error','--max-time','15','--interface',name,'--resolve',f'api.ipify.org:443:{ip}','https://api.ipify.org')
        ipaddress.IPv4Address(result)
        print('OK: VPN DNS and HTTPS with exit IP '+result, flush=True)
    check_navigation()
    if config.get('university'):
        def request(stage):
            (work/stage).touch()
            deadline = time.monotonic()+20
            while not (work/(stage+'-done')).exists():
                if time.monotonic()>deadline:
                    raise RuntimeError('simulation stage timed out: '+stage)
                time.sleep(.1)
        request('block-udp')
        if ping_ok() or ping_ok():
            raise RuntimeError('UDP unexpectedly works despite simulated restriction')
        assert Path('/run/netshield-lock/active').exists()
        print('OK: university simulation drops UDP; gateway fails with lock retained', flush=True)
        request('switch-wss')
        for _ in range(10):
            if ping_ok(): break
        else: raise RuntimeError('WSS did not recover under simulated UDP restriction')
        print('OK: same WireGuard peer works over HTTPS while direct UDP remains blocked', flush=True)
        check_navigation()
    if config['recovery']:
        (work/'interrupt').touch()
        deadline=time.monotonic()+15
        while not (work/'interrupted').exists():
            if time.monotonic()>deadline: raise RuntimeError('missing interruption')
            time.sleep(.1)
        if ping_ok(): raise RuntimeError('transport still working during interruption')
        assert Path('/run/netshield-lock/active').exists()
        print('OK: interrupted transport fails closed', flush=True)
        (work/'resume').touch()
        for _ in range(10):
            if ping_ok(): break
        else: raise RuntimeError('transport did not recover')
        print('OK: WireGuard recovered after restarting WSS', flush=True)
    stop.set()
    thread.join(2)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--wstunnel', type=Path)
    parser.add_argument('--udp', action='store_true')
    parser.add_argument('--university', action='store_true', help='Baseline UDP, silently drop direct UDP, switch same peer to WSS and test recovery')
    parser.add_argument('--child', type=Path)
    args=parser.parse_args()
    if args.child:
        child_test(args.child)
        return
    if args.university and args.udp:
        parser.error('--university and --udp are mutually exclusive')
    if not args.udp and not args.wstunnel:
        parser.error('--wstunnel is required for HTTPS')
    identity={'username':'transport_'+uuid.uuid4().hex[:12], 'password':uuid.uuid4().hex+uuid.uuid4().hex}
    api('/auth/register', identity)
    token=api('/auth/token', identity)['access_token']
    device=uuid.uuid4().hex
    process=None
    tunnel=None
    stop=threading.Event()
    with tempfile.TemporaryDirectory(prefix='netshield-wss-e2e-') as tmp:
        work=Path(tmp)
        os.chmod(work,0o700)
        try:
            key=command('wg','genkey')
            pub=command('wg','pubkey',input=key+'\n')
            template=api('/vpn/config', {'device_id':device,'public_key':pub},token)['config']
            endpoint, port=re.search(r'^Endpoint\s*=\s*([0-9.]+):(\d+)', template,re.M).groups()
            mode = ' (UDP baseline → UDP blocked → WSS/443)' if args.university else (' via UDP' if args.udp else ' via WSS/443')
            print('Testing configured VPN endpoint '+endpoint+':'+port+mode,flush=True)
            address=re.search(r'^Address\s*=\s*([^,\s]+)',template,re.M)[1]
            dns=re.search(r'^DNS\s*=\s*([^,\s]+)',template,re.M)[1]
            config=template.replace('REPLACE_ME',key)
            config=re.sub(r'^Endpoint\s*=.*$', 'Endpoint = 127.0.0.1:51821', config, flags=re.M)
            config='\n'.join(line for line in config.splitlines() if not re.match(r'^(Address|DNS|MTU|Table|PostUp|PostDown|PreUp|PreDown)\s*=',line))
            (work/'wg.conf').write_text(config+'\n');os.chmod(work/'wg.conf',0o600)
            (work/'settings.json').write_text(json.dumps(dict(endpoint=endpoint,address=address,dns=dns,recovery=not args.udp,university=args.university)))
            reserve=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);reserve.bind(('127.0.0.1',0));local_port=reserve.getsockname()[1];reserve.close()
            def start_tunnel():
                return sp.Popen([str(args.wstunnel),'client','--tls-verify-certificate','--tls-sni-override','api.netshield.lat','-H','Host: api.netshield.lat','-P','wstunnel','--connection-retry-max-backoff','5s','-L',f'udp://127.0.0.1:{local_port}:127.0.0.1:443?timeout_sec=0',f'wss://{endpoint}:443'],stdout=log,stderr=log,env={**{k:v for k,v in os.environ.items() if k.lower() not in {'http_proxy','https_proxy','all_proxy'}},'NO_COLOR':'true'})
            with (work/'transport.log').open('w') as log:
                if not args.udp and not args.university:
                    tunnel=start_tunnel();time.sleep(.4)
                target=(endpoint,int(port)) if args.udp or args.university else ('127.0.0.1',local_port)
                policy={'target':target,'block_udp':False,'dropped':0}
                thread=threading.Thread(target=relay,args=(work/'parent.sock',work/'child.sock',target,stop),kwargs={'policy':policy},daemon=True);thread.start()
                process=sp.Popen(['unshare','--user','--map-root-user','--mount','--net',sys.executable,str(Path(__file__).resolve()),'--child',tmp])
                deadline=time.monotonic()+160
                interrupted=False
                while process.poll() is None:
                    if time.monotonic()>deadline: raise RuntimeError('e2e timeout')
                    if args.university and (work/'block-udp').exists() and not (work/'block-udp-done').exists():
                        policy['block_udp']=True
                        (work/'block-udp-done').touch()
                    if args.university and (work/'switch-wss').exists() and not (work/'switch-wss-done').exists():
                        if not policy['dropped']:
                            raise RuntimeError('no UDP packets reached the simulated filter')
                        print('OK: simulated filter discarded '+str(policy['dropped'])+' encrypted datagrams',flush=True)
                        tunnel=start_tunnel();time.sleep(.4)
                        policy['target']=('127.0.0.1',local_port)
                        (work/'switch-wss-done').touch()
                    if (work/'interrupt').exists() and not interrupted:
                        tunnel.terminate();tunnel.wait(5);tunnel=None;interrupted=True;(work/'interrupted').touch()
                    if (work/'resume').exists() and tunnel is None and not args.udp:
                        tunnel=start_tunnel()
                    time.sleep(.1)
                if process.returncode: raise RuntimeError('isolated VPN test failed')
        finally:
            if process and process.poll() is None: process.terminate();process.wait(5)
            if tunnel and tunnel.poll() is None: tunnel.terminate();tunnel.wait(5)
            stop.set()
            if 'thread' in locals(): thread.join(2)
            api('/vpn/devices/'+device+'/revoke',{},token)
            print('Test peer revoked; namespace, temporary keys and transport removed.',flush=True)


if __name__ == '__main__':
    main()
