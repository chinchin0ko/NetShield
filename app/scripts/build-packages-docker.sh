#!/usr/bin/env bash
# Construye el .deb (en contenedor Debian 12) y el .rpm (en contenedor
# Fedora 43) de NetShield, compilando el bundle dentro de cada contenedor
# para enlazar con las librerías de cada distribución. Requiere Docker.
# Uso: scripts/build-packages-docker.sh
set -euo pipefail
app_dir=$(cd "$(dirname "$0")/.." && pwd)
flutter_sdk="$HOME/.local/share/netshield-tools/flutter"
[[ -d "$flutter_sdk" ]] || { echo "No se encontró el Flutter SDK en $flutter_sdk" >&2; exit 1; }
command -v docker >/dev/null || { echo 'Falta docker.' >&2; exit 1; }
uid=$(id -u); gid=$(id -g)

docker build -q -t netshield-debian-builder \
  --build-arg UID="$uid" --build-arg GID="$gid" \
  -f "$app_dir/packaging/docker/Dockerfile.debian" "$app_dir/packaging/docker"
docker run --rm \
  -v "$app_dir:/work/app" -v "$flutter_sdk:/opt/flutter" -v "$HOME/.pub-cache:/home/chinchin/.pub-cache" -w /work/app \
  netshield-debian-builder \
  bash -c 'rm -rf build/linux && flutter build linux --release && dart compile exe bin/netshield.dart -o build/cli/netshield && bash scripts/package-deb.sh'

docker build -q -t netshield-fedora-builder \
  --build-arg UID="$uid" --build-arg GID="$gid" \
  -f "$app_dir/packaging/docker/Dockerfile.fedora" "$app_dir/packaging/docker"
docker run --rm \
  -v "$app_dir:/work/app" -v "$flutter_sdk:/opt/flutter" -v "$HOME/.pub-cache:/home/chinchin/.pub-cache" -w /work/app \
  netshield-fedora-builder \
  bash -c 'rm -rf build/linux && flutter build linux --release && dart compile exe bin/netshield.dart -o build/cli/netshield && bash scripts/package-rpm.sh'

printf 'Paquetes en %s/dist\n' "$app_dir"
ls -lh "$app_dir"/dist/*.deb "$app_dir"/dist/*.rpm
