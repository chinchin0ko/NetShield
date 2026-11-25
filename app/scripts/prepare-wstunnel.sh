#!/usr/bin/env bash
# Fetch the pinned upstream Linux x86_64 transport, verify before extraction.
set -euo pipefail
app_dir=$(cd "$(dirname "$0")/.." && pwd)
[[ $(uname -m) == x86_64 ]] || { echo 'wstunnel: solo x86_64 en este paquete' >&2; exit 1; }
target="$app_dir/build/transport"
mkdir -p "$target"
archive="$target/wstunnel_11.1.0_linux_amd64.tar.gz"
expected=512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23
if [[ ! -f "$archive" ]] || [[ $(sha256sum "$archive" | cut -d' ' -f1) != "$expected" ]]; then
  curl --fail --location --proto '=https' --tlsv1.2 --max-time 120 \
    https://github.com/erebe/wstunnel/releases/download/v11.1.0/wstunnel_11.1.0_linux_amd64.tar.gz -o "$archive"
fi
printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status
tar -xzf "$archive" -C "$target" wstunnel LICENSE
chmod 755 "$target/wstunnel"
