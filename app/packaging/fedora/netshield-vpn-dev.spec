Name:           netshield-vpn-dev
Version:        @VERSION@
Release:        @RELEASE@%{?dist}
Summary:        NetShield VPN development desktop client
License:        Proprietary
URL:            https://github.com/chinchin0ko/NetShield
Source0:        netshield-rpm-input.tar.gz
BuildArch:      x86_64
# El paquete solo trae binarios ya compilados, sin fuentes para depurar.
%global debug_package %{nil}
Requires:       gtk3, NetworkManager, wireguard-tools, nftables, polkit, python3, iputils, hicolor-icon-theme, libnotify

%description
Cliente VPN de desarrollo con bloqueo de tráfico (killswitch),
alertas de seguridad y notificaciones de escritorio.
Funciona en Fedora, RHEL y derivadas.

%prep
%setup -q -c -n input

%install
install -d %{buildroot}/opt/netshield %{buildroot}/usr/bin %{buildroot}/usr/lib/netshield
cp -a bundle/. %{buildroot}/opt/netshield/
install -Dm755 netshield-killswitch %{buildroot}/usr/lib/netshield/netshield-killswitch
install -Dm644 netshield.policy %{buildroot}/usr/share/polkit-1/actions/com.netshield.killswitch.packaged.policy
install -Dm644 netshield-lock-restore.service %{buildroot}/usr/lib/systemd/system/netshield-lock-restore.service
install -Dm644 netshield.desktop %{buildroot}/usr/share/applications/netshield-vpn.desktop
install -Dm644 netshield.desktop %{buildroot}/usr/share/applications/com.netshield.netshield_app.desktop
printf 'NoDisplay=true\n' >> %{buildroot}/usr/share/applications/com.netshield.netshield_app.desktop
install -Dm644 netshield.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/netshield.svg
install -Dm755 netshield-cli %{buildroot}/usr/bin/netshield
ln -s netshield %{buildroot}/usr/bin/nsv
printf '#!/bin/sh\nexec /opt/netshield/netshield_app "$@"\n' > %{buildroot}/usr/bin/netshield-vpn
chmod 755 %{buildroot}/usr/bin/netshield-vpn

%files
/opt/netshield/
/usr/bin/netshield-vpn
/usr/bin/netshield
/usr/bin/nsv
/usr/lib/netshield/netshield-killswitch
/usr/share/polkit-1/actions/com.netshield.killswitch.packaged.policy
/usr/lib/systemd/system/netshield-lock-restore.service
/usr/share/applications/netshield-vpn.desktop
/usr/share/applications/com.netshield.netshield_app.desktop
/usr/share/icons/hicolor/scalable/apps/netshield.svg

%post
systemctl enable netshield-lock-restore.service >/dev/null 2>&1 || echo 'Activa netshield-lock-restore.service para proteger el arranque.'

%preun
if [ "$1" = 0 ] && [ -e /var/lib/netshield-lock/active.json ]; then
  echo 'ATENCIÓN: desactiva el bloqueo de NetShield antes de retirar el paquete.'
fi

%postun
if [ "$1" = 0 ]; then
  systemctl disable netshield-lock-restore.service >/dev/null 2>&1 || true
fi
