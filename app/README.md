# NetShield — aplicación de escritorio

Cliente de desarrollo en Flutter para Linux. Incluye registro, inicio de sesión y conexión WireGuard mediante NetworkManager. La API privada solicita la configuración al administrador wg-easy existente.

## Probar en el equipo de desarrollo

En una terminal, abrir y mantener activo el túnel SSH de la API:

```bash
~/Projects/NetShield/API/scripts/abrir-api-dev.sh
```

En otra terminal, consultar la contraseña del usuario de prueba `demo`:

```bash
~/Projects/NetShield/API/scripts/abrir-api-dev.sh --password
```

Ejecutar la aplicación compilada (si ya se compiló en este equipo):

```bash
~/Projects/NetShield/app/build/linux/x64/release/bundle/netshield_app
```

Para compilarla desde el código se necesita Flutter con soporte de escritorio Linux y las dependencias de compilación GTK. Desde `app/`:

```bash
flutter pub get
flutter run -d linux
```

Por defecto se conecta a `http://127.0.0.1:18000` a través del túnel. Para otra API puede configurarse `--dart-define=NETSHIELD_API_URL=https://...`; HTTP solo se permite en localhost. El token se conserva únicamente en memoria durante la sesión.

En la pantalla principal, pulsa **Conectar**. La aplicación importa un perfil WireGuard en NetworkManager y comprueba que responda la puerta de enlace de la VPN. Pulsa **Desconectar** para eliminar el perfil local y recuperar la ruta anterior. Al cerrar sesión también se desconecta. Si cierras la ventana sin desconectar, el perfil puede continuar activo; al volver a iniciar sesión la aplicación consulta su estado en NetworkManager. Necesita `nmcli`, `ping` y autorización de NetworkManager.

La clave privada de los nuevos dispositivos se genera localmente en `~/.local/share/netshield/wireguard.key` con permisos 0600. La API solo recibe la clave pública. La primera conexión de un dispositivo anterior cambia su peer a la nueva clave local. Los peers antiguos no migrados y las copias protegidas anteriores a la migración pueden conservar claves antiguas.

El bloqueo de tráfico usa nftables y necesita instalar una herramienta y una política de polkit protegidas por root. En esta máquina ya están instaladas; en otra instalación Arch se puede instalar desde el directorio `app/` con:

```bash
sudo install -o root -g root -m 755 linux/netshield/killswitch.py /usr/local/sbin/netshield-killswitch
sudo install -o root -g root -m 644 linux/netshield/com.netshield.killswitch.policy /usr/share/polkit-1/actions/com.netshield.killswitch.policy
```

Al conectar, KDE puede pedir autorización de administrador. El bloqueo permanece si el túnel cae o la ventana se cierra. Para volver a permitir tráfico, pulsa **Desconectar** o **Desactivar bloqueo**. Si no puedes abrir la aplicación, ejecuta `pkexec /usr/local/sbin/netshield-killswitch disable`. El bloqueo se aplica mientras está activado; después de reiniciar el equipo no se activa automáticamente. En desarrollo se permiten al servidor VPN el puerto UDP 51820 y SSH TCP 22 para mantener el túnel de administración.

La aplicación permite listar y revocar dispositivos de la cuenta. Un dispositivo revocado no puede reinscribirse automáticamente con su mismo identificador. La revocación no invalida el token de usuario; si fue comprometido, también hay que desactivar la cuenta o cambiar las credenciales.

En las pruebas de este equipo, el DNS configurado de la VPN resolvió consultas, los intentos de salida directa por Wi-Fi IPv4/IPv6 quedaron bloqueados y el bloqueo resistió la caída de WireGuard. IPv6 se bloquea mientras la VPN está activa porque el servidor aún no ofrece salida IPv6; no proporciona conectividad IPv6 a través de la VPN. Estas pruebas no son una auditoría ni garantizan ausencia de fugas en otros equipos o configuraciones. La integración sigue siendo de desarrollo y no debe exponerse a Internet como producción.

El registro de desarrollo requiere `NETSHIELD_DEV_REGISTRATION=1` en la API privada. No debe habilitarse en una API pública: aún faltan controles contra abuso y otros requisitos de producción.

La estructura incluye proyectos iniciales de Android y Windows para trabajo futuro; esta versión solo se compiló y verificó en Linux.
