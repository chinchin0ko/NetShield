#!/usr/bin/env bash
# Package an already-built local Flutter bundle; no private keys are included.
set -euo pipefail
app_dir=$(cd "$(dirname "$0")/.." && pwd)
bundle="$app_dir/build/linux/x64/release/bundle"
[[ $(uname -m) == x86_64 ]] || { echo 'Este paquete requiere x86_64.' >&2; exit 1; }
[[ -x "$bundle/netshield_app" && -d "$bundle/data" && -d "$bundle/lib" ]] || { echo 'Compila primero flutter build linux --release.' >&2; exit 1; }
command -v makepkg >/dev/null || { echo 'Falta makepkg (paquete pacman).' >&2; exit 1; }
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
mkdir -p "$workdir/input/bundle" "$app_dir/dist"
cp -a "$bundle/." "$workdir/input/bundle/"
install -m755 "$app_dir/linux/netshield/killswitch.py" "$workdir/input/netshield-killswitch"
install -m644 "$app_dir/packaging/arch/com.netshield.killswitch.packaged.policy" "$workdir/input/netshield.policy"
install -m644 "$app_dir/packaging/arch/netshield.desktop" "$workdir/input/netshield.desktop"
install -m644 "$app_dir/packaging/arch/netshield-lock-restore.service" "$workdir/input/netshield-lock-restore.service"
install -m644 "$app_dir/packaging/arch/netshield.install" "$workdir/netshield.install"
install -m644 "$app_dir/assets/netshield.svg" "$workdir/input/netshield.svg"
# El CLI (bin/netshield.dart compilado a binario nativo) es obligatorio:
# lo compila build-packages-docker.sh a build/cli/netshield (o dart compile exe).
if [[ -x "$app_dir/build/cli/netshield" ]]; then
  install -m755 "$app_dir/build/cli/netshield" "$workdir/input/netshield-cli"
else
  echo 'Falta build/cli/netshield. Compílalo con:' >&2
  echo '  dart compile exe bin/netshield.dart -o build/cli/netshield' >&2
  exit 1
fi
tar -C "$workdir" -czf "$workdir/netshield-arch-input.tar.gz" input
hash=$(sha256sum "$workdir/netshield-arch-input.tar.gz" | cut -d' ' -f1)
sed "s/@SHA256@/$hash/" "$app_dir/packaging/arch/PKGBUILD.template" > "$workdir/PKGBUILD"
(cd "$workdir" && PKGDEST="$app_dir/dist" makepkg --force --noconfirm)
printf 'Paquete en %s/dist\n' "$app_dir"
