#!/usr/bin/env bash
# Loopback-only lab: disposable keys, mock backend, no production services.
set -euo pipefail
workdir=$(mktemp -d)
container="netshield-mtls-lab-$(openssl rand -hex 6)"
container_bad="${container}-bad"
backend_pid=''
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker rm -f "$container_bad" >/dev/null 2>&1 || true
  [[ -z "$backend_pid" ]] || kill "$backend_pid" 2>/dev/null || true
  [[ -z "$backend_pid" ]] || wait "$backend_pid" 2>/dev/null || true
  python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$workdir"
}
trap cleanup EXIT
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=NetShield test CA' -keyout "$workdir/ca.key" -out "$workdir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' -keyout "$workdir/server.key" -out "$workdir/server.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$workdir/server.ext"
openssl x509 -req -in "$workdir/server.csr" -CA "$workdir/ca.crt" -CAkey "$workdir/ca.key" -CAcreateserial -days 1 -extfile "$workdir/server.ext" -out "$workdir/server.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=NetShield test proxy' -keyout "$workdir/client.key" -out "$workdir/client.csr" >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > "$workdir/client.ext"
openssl x509 -req -in "$workdir/client.csr" -CA "$workdir/ca.crt" -CAkey "$workdir/ca.key" -CAcreateserial -days 1 -extfile "$workdir/client.ext" -out "$workdir/client.crt" >/dev/null 2>&1
# Allocate ports and have the backend bind one immediately. Only loopback is used.
python3 - "$workdir" <<'PY' &
import http.server,pathlib,socket,ssl,sys
root=pathlib.Path(sys.argv[1])
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200); self.end_headers(); self.wfile.write(b'private-lab-ok')
 def log_message(self,*args): pass
srv=http.server.HTTPServer(('127.0.0.1',0),Handler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(root/'server.crt',root/'server.key');ctx.load_verify_locations(root/'ca.crt');ctx.verify_mode=ssl.CERT_REQUIRED
srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
(root/'backend.port').write_text(str(srv.server_port))
srv.serve_forever()
PY
backend_pid=$!
for _ in {1..30}; do [[ -s "$workdir/backend.port" ]] && break; sleep .1; done
[[ -s "$workdir/backend.port" ]]
backend_port=$(cat "$workdir/backend.port")
proxy_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
cat > "$workdir/Caddyfile" <<CADDY
{
 admin off
}
http://127.0.0.1:$proxy_port {
 reverse_proxy https://127.0.0.1:$backend_port {
  transport http {
   tls_trust_pool file /pki/ca.crt
   tls_client_auth /pki/client.crt /pki/client.key
  }
 }
}
CADDY
image='caddy@sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b'
docker run -d --name "$container" --network host --cap-drop ALL --security-opt no-new-privileges:true \
  --label com.centurylinklabs.watchtower.enable=false \
  -v "$workdir:/pki:ro" "$image" caddy run --config /pki/Caddyfile --adapter caddyfile >/dev/null
for _ in {1..50}; do
 if curl --noproxy '*' -fsS --max-time 2 "http://127.0.0.1:$proxy_port/" > "$workdir/result" 2>/dev/null; then break; fi
 sleep .1
done
[[ "$(cat "$workdir/result")" == 'private-lab-ok' ]]
if curl --noproxy '*' --cacert "$workdir/ca.crt" -fsS --max-time 3 "https://127.0.0.1:$backend_port/" >/dev/null 2>&1; then
 echo 'Error: backend accepted a request without a client certificate' >&2; exit 1
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Untrusted CA' -keyout "$workdir/wrong.key" -out "$workdir/wrong.crt" >/dev/null 2>&1
bad_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
sed -e "s/$proxy_port/$bad_port/g" -e 's@/pki/ca.crt@/pki/wrong.crt@g' "$workdir/Caddyfile" > "$workdir/Caddyfile-bad"
docker run -d --name "$container_bad" --network host --cap-drop ALL --security-opt no-new-privileges:true \
  --label com.centurylinklabs.watchtower.enable=false \
  -v "$workdir:/pki:ro" "$image" caddy run --config /pki/Caddyfile-bad --adapter caddyfile >/dev/null
status=''
for _ in {1..50}; do
 status=$(curl --noproxy '*' -sS --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$bad_port/" 2>/dev/null || true)
 [[ "$status" != '' && "$status" != '000' ]] && break
 sleep .1
done
[[ "$status" == 502 ]] || { echo 'Error: proxy did not reject untrusted server' >&2; exit 1; }
printf 'OK: proxy verified the backend and authenticated with a client certificate.\n'
printf 'OK: backend rejected a client without a certificate.\n'
printf 'OK: proxy rejected an untrusted backend certificate.\n'
