#!/usr/bin/env bash
# Build an .rpm from an already-built Flutter Linux bundle.
# Para distribuir en Fedora, compila el bundle dentro de un contenedor
# Fedora (ver packaging/README) para enlazar con sus librerías.
# Uso: scripts/package-rpm.sh [ruta-al-bundle] [version] [release]
set -euo pipefail
app_dir=$(cd "$(dirname "$0")/.." && pwd)
bundle="${1:-$app_dir/build/linux/x64/release/bundle}"
version="${2:-0.1.0}"
release="${3:-25}"
[[ $(uname -m) == x86_64 ]] || { echo 'Este paquete requiere x86_64.' >&2; exit 1; }
[[ -x "$bundle/netshield_app" && -d "$bundle/data" && -d "$bundle/lib" ]] || { echo 'Compila primero flutter build linux --release.' >&2; exit 1; }
command -v rpmbuild >/dev/null || { echo 'Falta rpmbuild (paquete rpm-build).' >&2; exit 1; }
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
mkdir -p "$workdir/input/bundle" "$workdir/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS} "$app_dir/dist"
cp -a "$bundle/." "$workdir/input/bundle/"
install -m755 "$app_dir/linux/netshield/killswitch.py" "$workdir/input/netshield-killswitch"
install -m644 "$app_dir/packaging/arch/com.netshield.killswitch.packaged.policy" "$workdir/input/netshield.policy"
install -m644 "$app_dir/packaging/arch/netshield-lock-restore.service" "$workdir/input/netshield-lock-restore.service"
install -m644 "$app_dir/packaging/arch/netshield.desktop" "$workdir/input/netshield.desktop"
install -m644 "$app_dir/assets/netshield.svg" "$workdir/input/netshield.svg"
# El CLI (bin/netshield.dart compilado a binario nativo) es obligatorio:
# lo compila build-packages-docker.sh a build/cli/netshield.
if [[ -x "$app_dir/build/cli/netshield" ]]; then
  install -m755 "$app_dir/build/cli/netshield" "$workdir/input/netshield-cli"
else
  echo 'Falta build/cli/netshield. Compílalo con:' >&2
  echo '  dart compile exe bin/netshield.dart -o build/cli/netshield' >&2
  exit 1
fi
tar -C "$workdir/input" -czf "$workdir/rpmbuild/SOURCES/netshield-rpm-input.tar.gz" .
sed -e "s/@VERSION@/$version/" -e "s/@RELEASE@/$release/" "$app_dir/packaging/fedora/netshield-vpn.spec" > "$workdir/rpmbuild/SPECS/netshield-vpn.spec"
rpmbuild --define "_topdir $workdir/rpmbuild" -bb "$workdir/rpmbuild/SPECS/netshield-vpn.spec"
cp "$workdir/rpmbuild/RPMS/x86_64/"*.rpm "$app_dir/dist/"
printf 'Paquete en %s/dist\n' "$app_dir"
