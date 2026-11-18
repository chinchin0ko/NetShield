#!/usr/bin/env bash
# Isolated disposable wg-easy 13 instance; no host ports or production volumes.
set -euo pipefail
command -v docker >/dev/null || { echo 'Docker no está disponible' >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo 'No se puede acceder a Docker' >&2; exit 1; }
labdir=$(mktemp -d)
name="netshield-wgeasy-lab-$(openssl rand -hex 5)"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$labdir"
}
trap cleanup EXIT
chmod 700 "$labdir"
docker run -d --name "$name" --network none --cap-add NET_ADMIN \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  --label com.centurylinklabs.watchtower.enable=false \
  -e WG_HOST=127.0.0.1 -e WG_DEFAULT_ADDRESS=10.253.87.x \
  -e WG_PRE_UP=true -e WG_POST_UP=true -e WG_PRE_DOWN=true -e WG_POST_DOWN=true \
  -v "$labdir:/etc/wireguard" ghcr.io/wg-easy/wg-easy:13 >/dev/null
for attempt in {1..30}; do
  if docker exec "$name" node -e "fetch('http://127.0.0.1:51821/api/session').then(x=>process.exit(x.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then break; fi
  if [[ "$attempt" == 30 ]]; then docker logs --tail 20 "$name" >&2; exit 1; fi
  sleep 1
done
docker exec -i "$name" node <<'NODE'
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const url='http://127.0.0.1:51821/api/wireguard/client';
async function request(method, body) {
  const response=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  if(!response.ok) throw new Error(`API ${method} failed: ${response.status}`);
  return response.json();
}
function peers() { return execFileSync('wg',['show','wg0','peers'],{encoding:'utf8'}).trim().split('\n').filter(Boolean); }
(async()=>{
  await request('POST',{name:'lab-owned'});
  let clients=await request('GET');
  if(clients.length!==1 || !peers().includes(clients[0].publicKey)) throw Error('Peer administrado no aplicado');
  const privateKey=execFileSync('wg',['genkey']);
  const publicKey=execFileSync('wg',['pubkey'],{input:privateKey,encoding:'utf8'}).trim();
  execFileSync('wg',['set','wg0','peer',publicKey,'allowed-ips','10.253.87.240/32']);
  if(!peers().includes(publicKey)) throw Error('Peer externo no añadido');
  await request('POST',{name:'lab-trigger-save'});
  clients=await request('GET');
  if(peers().includes(publicKey)) throw Error('Peer externo inesperadamente persistió');
  if(clients.length!==2) throw Error('Peers administrados inesperados');
  const ids=clients.map(x=>x.id);
  fs.writeFileSync('/tmp/netshield-lab-ids.json', JSON.stringify(ids));
  console.log('OK: guardar wg-easy elimina el peer externo y conserva sus dos peers administrados');
})().catch(e=>{console.error(e.message);process.exit(1)});
NODE
docker restart "$name" >/dev/null
for attempt in {1..30}; do
  if docker exec "$name" node -e "fetch('http://127.0.0.1:51821/api/session').then(x=>process.exit(x.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then break; fi
  if [[ "$attempt" == 30 ]]; then docker logs --tail 20 "$name" >&2; exit 1; fi
  sleep 1
done
docker exec "$name" node -e "fetch('http://127.0.0.1:51821/api/wireguard/client').then(async r=>{if(!r.ok)throw Error('HTTP '+r.status);let c=await r.json();if(c.length!==2)throw Error('No se restauraron los peers');console.log('OK: los peers propios de wg-easy persisten tras reinicio')}).catch(e=>{console.error(e.message);process.exit(1)})"
