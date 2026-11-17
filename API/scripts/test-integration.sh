#!/usr/bin/env bash
# Create a disposable local PostgreSQL with TLS; never points at the real database.
set -euo pipefail
cd "$(dirname "$0")/.."
for cmd in docker openssl python; do command -v "$cmd" >/dev/null || { echo "Falta $cmd" >&2; exit 1; }; done
docker info >/dev/null 2>&1 || { echo 'Docker no está disponible o el usuario no tiene acceso.' >&2; exit 1; }
workdir=$(mktemp -d)
container="netshield-test-$(openssl rand -hex 6)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$workdir"; }
trap cleanup EXIT
password=$(openssl rand -hex 24)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=netshield-test' \
  -addext 'subjectAltName=IP:127.0.0.1' -keyout "$workdir/server.key" \
  -out "$workdir/server.crt" >/dev/null 2>&1
chmod 600 "$workdir/server.key"
docker run -d --name "$container" --label com.centurylinklabs.watchtower.enable=false \
  -p 127.0.0.1::5432 --tmpfs /var/lib/postgresql/data:rw,size=256m \
  -e POSTGRES_DB=netshield_lab -e POSTGRES_PASSWORD="$password" \
  -v "$workdir:/certs:ro" --entrypoint sh postgres:16 -c \
  'cp /certs/server.key /tmp/server.key && cp /certs/server.crt /tmp/server.crt && chown postgres:postgres /tmp/server.key && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key' >/dev/null
for attempt in {1..60}; do
  docker exec "$container" pg_isready -U postgres -d netshield_lab >/dev/null 2>&1 && break
  if [[ "$attempt" == 60 ]]; then docker logs "$container" >&2; exit 1; fi
  sleep 1
done
port=$(docker port "$container" 5432/tcp | sed 's/.*://')
export PGPASSWORD="$password"
export NETSHIELD_TEST_DSN="host=127.0.0.1 port=$port dbname=netshield_lab user=postgres sslmode=verify-full sslrootcert=$workdir/server.crt connect_timeout=5"
python -m pytest -q tests/integration
