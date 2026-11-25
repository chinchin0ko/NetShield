#!/usr/bin/env bash
set -euo pipefail
labdir=$(mktemp -d)
name="ns-key-test-$(openssl rand -hex 5)"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$labdir"; }
trap cleanup EXIT
chmod 700 "$labdir"
docker run -d --name "$name" --network none --cap-add NET_ADMIN --sysctl net.ipv4.conf.all.src_valid_mark=1 --label com.centurylinklabs.watchtower.enable=false -e WG_HOST=127.0.0.1 -e WG_DEFAULT_ADDRESS=10.253.89.x -e WG_PRE_UP=true -e WG_POST_UP=true -e WG_PRE_DOWN=true -e WG_POST_DOWN=true -v "$labdir:/etc/wireguard" netshield-wg-easy:dev >/dev/null
for attempt in {1..30}; do
 if docker exec "$name" node -e "fetch('http://127.0.0.1:51821/api/session').then(x=>process.exit(x.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then break; fi
 if [[ "$attempt" == 30 ]]; then docker logs --tail 20 "$name" >&2; exit 1; fi
 sleep 1
done
docker exec -i "$name" node <<'NODE'
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const base='http://127.0.0.1:51821/api/wireguard';
async function request(path,method='GET',body) {
 const r=await fetch(base+path,{method,headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
 if(!r.ok)throw Error('API '+path+' '+r.status);return r.json();
}
function key(){const priv=execFileSync('wg',['genkey']);return execFileSync('wg',['pubkey'],{input:priv,encoding:'utf8'}).trim();}
(async()=>{
 const pub=key(); const name='netshield-12-0123456789abcdef0123456789abcdef';
 await request('/client-external','POST',{name,publicKey:pub});
 let clients=await request('/client');const client=clients.find(c=>c.name===name);
 if(!client || client.publicKey!==pub || client.downloadableConfig)throw Error('Public key client invalid');
 let state=JSON.parse(fs.readFileSync('/etc/wireguard/wg0.json'));if(state.clients[client.id].privateKey || state.clients[client.id].preSharedKey)throw Error('Server retained private key');
 if(!execFileSync('wg',['show','wg0','peers'],{encoding:'utf8'}).includes(pub))throw Error('Peer missing');
 const newPub=key();await request('/client/'+client.id+'/public-key','PUT',{publicKey:newPub});
 state=JSON.parse(fs.readFileSync('/etc/wireguard/wg0.json'));if(state.clients[client.id].publicKey!==newPub || state.clients[client.id].privateKey)throw Error('Rotation invalid');
 await request('/client/'+client.id+'/disable','POST',{});
 let r=await fetch(base+'/client/'+client.id+'/public-key',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({publicKey:pub})});if(r.ok)throw Error('Revoked client accepted rotation');
 const legacyName='netshield-13-0123456789abcdef0123456789abcdef';
 await request('/client','POST',{name:legacyName});
 clients=await request('/client');const legacy=clients.find(c=>c.name===legacyName);
 if(!legacy.downloadableConfig)throw Error('Legacy private key not present before migration');
 await request('/client/'+legacy.id+'/public-key','PUT',{publicKey:key()});
 state=JSON.parse(fs.readFileSync('/etc/wireguard/wg0.json'));
 if(state.clients[legacy.id].privateKey || state.clients[legacy.id].preSharedKey)throw Error('Legacy secrets still present');
 r=await fetch(base+'/client-external',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'netshield-14-0123456789abcdef0123456789abcdef',publicKey:'invalid'})});
 if(r.ok)throw Error('Invalid public key accepted');
 console.log('OK: clave pública, rotación y revocación sin clave privada en servidor');
})().catch(e=>{console.error(e.message);process.exit(1)});
NODE
docker restart "$name" >/dev/null
for attempt in {1..30}; do
 if docker exec "$name" node -e "fetch('http://127.0.0.1:51821/api/session').then(x=>process.exit(x.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then break; fi
 if [[ "$attempt" == 30 ]]; then docker logs --tail 20 "$name" >&2; exit 1; fi
 sleep 1
done
docker exec "$name" node -e "fetch('http://127.0.0.1:51821/api/wireguard/client').then(async r=>{let c=await r.json();if(c.length!==2 || c.some(x=>x.downloadableConfig) || !c.some(x=>!x.enabled))throw Error('Estado no persistió');console.log('OK: revocación y ausencia de clave privada sobreviven reinicio')}).catch(e=>{console.error(e.message);process.exit(1)})"
