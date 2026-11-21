# NetShield — aplicación de escritorio

Cliente de desarrollo en Flutter para Linux. Incluye inicio de sesión y conexión WireGuard mediante NetworkManager. El servidor administra los peers de WireGuard; el cliente no necesita SSH administrativo.

## Paquete de prueba para Arch Linux x86_64

`dist/netshield-vpn-dev-0.1.0-22-x86_64.pkg.tar.zst` se genera localmente con `./scripts/package-arch.sh` después de `flutter build linux --release`. El equipo de compilación necesita Flutter y `makepkg`; quien instala el paquete no necesita Flutter ni el código fuente. El paquete declara sus dependencias de Arch y se instala con:

```bash
sudo pacman -U ./dist/netshield-vpn-dev-0.1.0-22-x86_64.pkg.tar.zst
```

Abre **NetShield VPN** desde el menú o ejecuta `netshield-vpn`. Al cerrar la ventana con la equis, NetShield permanece en la bandeja del sistema; usa **Abrir NetShield** en el icono o vuelve a abrir la aplicación desde el menú para recuperarla. **Salir de la aplicación (mantener VPN)** termina el programa sin desconectar la VPN; para desconectarla usa el botón de la aplicación. Si el escritorio no dispone de bandeja compatible, la ventana se minimiza. Es necesario tener NetworkManager activo y un agente gráfico de polkit. Puedes crear una cuenta desde la aplicación. Para retirar el paquete, desconecta primero la VPN y desactiva el bloqueo desde la aplicación; después ejecuta `sudo pacman -R netshield-vpn-dev`. Esto no elimina las claves privadas o el identificador guardados en `~/.local/share/netshield/`.

Para crear una cuenta de prueba, el administrador ejecuta `API/scripts/crear-usuario-dev.sh` desde el repositorio en su máquina autorizada. El comando solicita usuario y contraseña de forma interactiva en la instancia API; la persona que usa el paquete no necesita acceso SSH. Comparte las credenciales mediante un canal seguro.

Este paquete es una compilación de desarrollo para pruebas controladas: aún no está firmado y fue compilado en CachyOS, por lo que falta comprobarlo en una instalación limpia de Arch y establecer una compilación y firma para distribución. [Flutter requiere distribuir el directorio completo `bundle` y verificar las bibliotecas del sistema de destino](https://docs.flutter.dev/platform-integration/linux/building).

## Probar en el equipo de desarrollo

En esta máquina abre **NetShield VPN** desde el menú de aplicaciones. La aplicación se conecta a `https://api.netshield.lat`; no necesita un túnel SSH ni una clave administrativa en el cliente. El registro público está habilitado para pruebas de desarrollo.

Para el flujo anterior de desarrollo, puedes compilar la aplicación y ejecutar `./scripts/install-desktop.sh` desde `app/`; ese acceso directo depende de la ubicación del proyecto.

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

Para otra API puede configurarse `--dart-define=NETSHIELD_API_URL=https://...`; HTTP solo se permite en localhost. El túnel SSH anterior queda disponible explícitamente para desarrollo mediante `--dart-define=NETSHIELD_API_URL=http://127.0.0.1:18000`. El token se conserva únicamente en memoria durante la sesión.

En la pantalla principal, pulsa **Conectar**. La aplicación importa un perfil WireGuard en NetworkManager y comprueba que responda la puerta de enlace de la VPN. Mientras el perfil está activo, la aplicación consulta periódicamente la puerta de enlace del túnel; tras dos respuestas fallidas avisa sin desconectarlo ni desactivar el bloqueo. Esto no verifica el DNS ni garantiza acceso a Internet. Pulsa **Desconectar** para eliminar el perfil local y recuperar la ruta anterior. Al cerrar sesión también se desconecta. Si cierras la ventana sin desconectar, el perfil puede continuar activo; al volver a iniciar sesión la aplicación consulta su estado en NetworkManager. Necesita `nmcli`, `ping` y autorización de NetworkManager.

En **Ajustes** puedes desactivar o volver a activar el Kill Switch durante una conexión; desactivarlo permite la salida directa si el túnel falla. Al conectar de nuevo se activa por defecto. Si vienes de una conexión anterior a esta versión, desconecta y conecta una vez antes de volver a activarlo desde Ajustes. **Consumo** muestra bytes recibidos y enviados de la interfaz local actual, y los contadores disponibles en el servidor de tus dispositivos habilitados. Los contadores actuales del servidor se reinician con WireGuard. Una gráfica interactiva muestra siete días, permite consultar el desglose diario por dirección y señala los días sin datos o con muestras incompletas. El historial reciente muestra estimaciones por dispositivo y día UTC, calculadas con muestras; puede tener huecos o reinicios no detectados y no sirve para facturación. **Alertas** consulta los eventos atribuibles a la cuenta; el sensor usa reglas limitadas; los eventos que no pueden atribuirse de forma segura se conservan para revisión. Cada alerta puede desplegarse para consultar firma, severidad, dispositivo, fecha y revisión; los filtros permiten separar pendientes, revisadas y posibles falsos positivos. Los detalles se limitan a los datos que conserva el sensor. Las alertas de prueba están identificadas como simuladas y no indican una infección. Mientras la aplicación está abierta, consulta alertas cada 15 segundos y señala las nuevas en el panel y la barra de navegación. Las alertas nuevas también generan una notificación del escritorio Linux sin incluir detalles sensibles. La primera consulta establece el estado inicial y no notifica las alertas anteriores. La aplicación debe permanecer abierta y la sesión iniciada; no se reciben notificaciones cuando está cerrada.

Las claves privadas se generan localmente con permisos 0600 en `~/.local/share/netshield/accounts/`, con una clave distinta por cada cuenta que usa el equipo. La API solo recibe la clave pública. Al conectar con una versión anterior del cliente, el peer de esa cuenta se actualiza con su nueva clave local. Los peers antiguos no migrados y las copias protegidas anteriores a la migración pueden conservar claves antiguas.

El bloqueo de tráfico usa nftables y necesita instalar una herramienta y una política de polkit protegidas por root. En esta máquina ya están instaladas; en otra instalación Arch se puede instalar desde el directorio `app/` con:

```bash
sudo install -o root -g root -m 755 linux/netshield/killswitch.py /usr/local/sbin/netshield-killswitch
sudo install -o root -g root -m 644 linux/netshield/com.netshield.killswitch.policy /usr/share/polkit-1/actions/com.netshield.killswitch.policy
```

Al conectar, KDE puede pedir autorización de administrador. El bloqueo permanece si el túnel cae o la ventana se cierra. El paquete instala un servicio que restaura el bloqueo antes de la red tras reiniciar, si estaba activado. Después del reinicio, la pantalla de inicio permite desconectar y desactivar el bloqueo para recuperar la conexión antes de iniciar sesión; esta acción permite salir fuera de la VPN. Para volver a permitir tráfico, pulsa **Desconectar** o **Desactivar bloqueo**. Si instalaste el paquete y no puedes abrir la aplicación, ejecuta `pkexec /usr/lib/netshield/netshield-killswitch disable`. Para la instalación manual anterior, la ruta es `/usr/local/sbin/netshield-killswitch`; esa instalación requiere configurar por separado el servicio de arranque. Fuera del túnel solo se permite UDP 51820 hacia el servidor para mantener WireGuard; el túnel SSH opcional de desarrollo dejará de funcionar mientras esté activo el bloqueo. La restauración se ha probado en un espacio aislado, todavía no en un reinicio completo real; un fallo del servicio o de nftables requiere intervención manual.

La aplicación permite listar y revocar dispositivos de la cuenta. Un dispositivo revocado no puede reinscribirse automáticamente con su mismo identificador. La revocación no invalida el token de usuario; si fue comprometido, también hay que desactivar la cuenta o cambiar las credenciales.

En las pruebas de este equipo, el DNS configurado de la VPN resolvió consultas, los intentos de salida directa por Wi-Fi IPv4/IPv6 quedaron bloqueados y el bloqueo resistió la caída de WireGuard. IPv6 se bloquea mientras la VPN está activa porque el servidor aún no ofrece salida IPv6; no proporciona conectividad IPv6 a través de la VPN. Estas pruebas no son una auditoría ni garantizan ausencia de fugas en otros equipos o configuraciones. La integración sigue siendo de desarrollo y no debe exponerse a Internet como producción.

El registro de desarrollo está habilitado mediante `NETSHIELD_DEV_REGISTRATION=1`. Esta versión pública es experimental y aún le faltan controles contra abuso y otros requisitos de producción.

La estructura incluye proyectos iniciales de Android y Windows para trabajo futuro; esta versión solo se compiló y verificó en Linux.

El acceso SSH opcional de desarrollo solo se activa mediante la configuración explícita de localhost; el paquete usa HTTPS por defecto y no incluye claves SSH administrativas.
