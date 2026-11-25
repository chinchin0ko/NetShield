#!/usr/bin/env bash
# Build a .deb from an already-built Flutter Linux bundle.
# Para distribuir en Debian/Ubuntu/Kali, compila el bundle dentro de un
# contenedor Debian (ver packaging/README) para enlazar con sus librerías.
# Uso: scripts/package-deb.sh [ruta-al-bundle] [version]
set -euo pipefail
app_dir=$(cd "$(dirname "$0")/.." && pwd)
bundle="${1:-$app_dir/build/linux/x64/release/bundle}"
version="${2:-0.1.0-25}"
[[ $(uname -m) == x86_64 ]] || { echo 'Este paquete requiere x86_64.' >&2; exit 1; }
[[ -x "$bundle/netshield_app" && -d "$bundle/data" && -d "$bundle/lib" ]] || { echo 'Compila primero flutter build linux --release.' >&2; exit 1; }
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
root="$workdir/root"
mkdir -p "$root/opt/netshield" "$root/usr/bin" "$root/usr/lib/netshield" "$root/usr/share/polkit-1/actions" "$root/usr/lib/systemd/system" "$root/usr/share/applications" "$root/usr/share/icons/hicolor/scalable/apps" "$root/DEBIAN"
cp -a "$bundle/." "$root/opt/netshield/"
install -m755 "$app_dir/linux/netshield/killswitch.py" "$root/usr/lib/netshield/netshield-killswitch"
install -m644 "$app_dir/packaging/arch/com.netshield.killswitch.packaged.policy" "$root/usr/share/polkit-1/actions/com.netshield.killswitch.packaged.policy"
install -m644 "$app_dir/packaging/arch/netshield-lock-restore.service" "$root/usr/lib/systemd/system/netshield-lock-restore.service"
install -m644 "$app_dir/packaging/arch/netshield.desktop" "$root/usr/share/applications/netshield-vpn.desktop"
install -m644 "$app_dir/packaging/arch/netshield.desktop" "$root/usr/share/applications/com.netshield.netshield_app.desktop"
printf 'NoDisplay=true\n' >> "$root/usr/share/applications/com.netshield.netshield_app.desktop"
install -m644 "$app_dir/assets/netshield.svg" "$root/usr/share/icons/hicolor/scalable/apps/netshield.svg"
printf '#!/bin/sh\nexec /opt/netshield/netshield_app "$@"\n' > "$root/usr/bin/netshield-vpn"
chmod 755 "$root/usr/bin/netshield-vpn"
# El CLI (bin/netshield.dart compilado a binario nativo) es obligatorio:
# lo compila build-packages-docker.sh a build/cli/netshield.
if [[ -x "$app_dir/build/cli/netshield" ]]; then
  install -m755 "$app_dir/build/cli/netshield" "$root/usr/bin/netshield"
  ln -s netshield "$root/usr/bin/nsv"
else
  echo 'Falta build/cli/netshield. Compílalo con:' >&2
  echo '  dart compile exe bin/netshield.dart -o build/cli/netshield' >&2
  exit 1
fi
sed "s/@VERSION@/$version/" "$app_dir/packaging/debian/control" > "$root/DEBIAN/control"
install -m755 "$app_dir/packaging/debian/postinst" "$root/DEBIAN/postinst"
install -m755 "$app_dir/packaging/debian/prerm" "$root/DEBIAN/prerm"
install -m755 "$app_dir/packaging/debian/postrm" "$root/DEBIAN/postrm"
mkdir -p "$app_dir/dist"
out="$app_dir/dist/netshield-vpn_${version}_amd64.deb"
if command -v dpkg-deb >/dev/null; then
  dpkg-deb --build --root-owner-group "$root" "$out"
else
  # Sin dpkg-deb: un .deb es un archivo ar con debian-binary, control.tar.gz y data.tar.xz
  (cd "$root/DEBIAN" && tar --owner=0 --group=0 -czf "$workdir/control.tar.gz" .)
  (cd "$root" && tar --owner=0 --group=0 --exclude=DEBIAN -cJf "$workdir/data.tar.xz" .)
  printf '2.0\n' > "$workdir/debian-binary"
  (cd "$workdir" && ar rcs "$out" debian-binary control.tar.gz data.tar.xz)
fi
printf 'Paquete en %s\n' "$out"
