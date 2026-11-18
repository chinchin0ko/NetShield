# NetShield — aplicación de escritorio

Cliente de desarrollo en Flutter para Linux. Incluye registro, inicio de sesión y conexión WireGuard mediante NetworkManager. La API privada solicita la configuración al administrador wg-easy existente.

## Probar en el equipo de desarrollo

En esta máquina abre **NetShield VPN** desde el menú de aplicaciones. La aplicación abre automáticamente su propio acceso SSH a la API al iniciar sesión o registrarse y lo cierra al salir. No hace falta abrir una terminal para crear el túnel. Requiere `ssh`, `python3`, la clave de desarrollo en `~/Projects/SSH/UPVPN/ssh-key-2026-09-17.key` y las huellas SSH previamente verificadas en `~/.ssh/known_hosts`. No se incluye ni distribuye la clave privada.

Para instalar el acceso directo en otra copia del proyecto, compila la aplicación y ejecuta `./scripts/install-desktop.sh` desde `app/`.

Para consultar la contraseña de la cuenta de prueba una vez, puedes usar una terminal:

El usuario de prueba es `demo`:

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

Por defecto crea un túnel privado de desarrollo en un puerto local temporal. Para otra API puede configurarse `--dart-define=NETSHIELD_API_URL=https://...`; HTTP solo se permite en localhost. El token se conserva únicamente en memoria durante la sesión.

En la pantalla principal, pulsa **Conectar**. La aplicación importa un perfil WireGuard en NetworkManager y comprueba que responda la puerta de enlace de la VPN. Pulsa **Desconectar** para eliminar el perfil local y recuperar la ruta anterior. Al cerrar sesión también se desconecta. Si cierras la ventana sin desconectar, el perfil puede continuar activo; al volver a iniciar sesión la aplicación consulta su estado en NetworkManager. Necesita `nmcli`, `ping` y autorización de NetworkManager.

Las claves privadas se generan localmente con permisos 0600 en `~/.local/share/netshield/accounts/`, con una clave distinta por cada cuenta que usa el equipo. La API solo recibe la clave pública. Al conectar con una versión anterior del cliente, el peer de esa cuenta se actualiza con su nueva clave local. Los peers antiguos no migrados y las copias protegidas anteriores a la migración pueden conservar claves antiguas.

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

El acceso automático SSH usa las credenciales administrativas existentes solo en esta máquina de desarrollo. No es una distribución para usuarios finales: para producción se necesita una API HTTPS pública autenticada, sin distribuir claves SSH de administración.
