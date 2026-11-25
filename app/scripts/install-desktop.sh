#!/usr/bin/env bash
set -euo pipefail
app_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary="$app_dir/build/linux/x64/release/bundle/netshield_app"
icon="$app_dir/assets/netshield.svg"
[[ -x "$binary" ]] || { echo 'Compila primero la aplicación para Linux.' >&2; exit 1; }
# Desktop Exec supports quoted arguments; reject characters that need extra escaping.
[[ "$binary$icon" != *'"'* && "$binary$icon" != *'\'* && "$binary$icon" != *'$'* && "$binary$icon" != *'`'* && "$binary$icon" != *'%'* && "$binary$icon" != *$'\n'* ]] || { echo 'La ruta contiene caracteres no admitidos por el acceso directo.' >&2; exit 1; }
desktop_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$desktop_dir"
cat > "$desktop_dir/netshield.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=NetShield VPN
Comment=Cliente VPN de desarrollo
Exec="$binary"
Icon=$icon
Terminal=false
Categories=Network;
StartupNotify=true
DESKTOP
command -v update-desktop-database >/dev/null && update-desktop-database "$desktop_dir" || true
printf 'NetShield VPN instalado en el menú de aplicaciones.\n'
