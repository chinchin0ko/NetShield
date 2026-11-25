#!/usr/bin/env bash
# Disposable local-only test. Uses a temporary internal CA, not public ACME.
set -euo pipefail
cd "$(dirname "$0")"
workdir=$(mktemp -d)
name="netshield-tls-lab-$(openssl rand -hex 6)"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$workdir"
}
trap cleanup EXIT
python3 - "$PWD/Caddyfile" "$workdir/Caddyfile" <<'PY'
import pathlib,sys
source=pathlib.Path(sys.argv[1]).read_text()
needle='api.netshield.lat {'
assert source.count(needle)==1
pathlib.Path(sys.argv[2]).write_text(source.replace(needle, needle+'\n\ttls internal'))
PY
chmod 755 "$workdir"
image='caddy@sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b'
docker run -d --name "$name" --label com.centurylinklabs.watchtower.enable=false \
  --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges:true \
  -p 127.0.0.1::443/tcp -v "$workdir/Caddyfile:/etc/caddy/Caddyfile:ro" "$image" >/dev/null
for attempt in {1..30}; do
  if docker cp "$name:/data/caddy/pki/authorities/local/root.crt" "$workdir/root.crt" 2>/dev/null; then break; fi
  if [[ "$attempt" == 30 ]]; then docker logs --tail 30 "$name" >&2; exit 1; fi
  sleep 1
done
port=$(docker port "$name" 443/tcp | sed 's/.*://')
code=$(curl --noproxy '*' --cacert "$workdir/root.crt" --resolve "api.netshield.lat:$port:127.0.0.1" --max-time 8 -sS -o "$workdir/response" -w '%{http_code}' "https://api.netshield.lat:$port/")
[[ "$code" == 503 ]] && grep -q 'API en preparación' "$workdir/response"
printf 'OK: TLS verificado con CA temporal y respuesta 503 de espera.\n'
