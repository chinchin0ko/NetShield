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

Esta integración es para desarrollo: wg-easy genera y almacena las claves del cliente en el servidor. Todavía no hay kill switch, revocación de dispositivos desde la aplicación ni verificación continua del túnel; no se ha comprobado la ausencia de fugas DNS o IPv6. No se debe considerar lista para producción.

El registro de desarrollo requiere `NETSHIELD_DEV_REGISTRATION=1` en la API privada. No debe habilitarse en una API pública: aún faltan controles contra abuso y otros requisitos de producción.

La estructura incluye proyectos iniciales de Android y Windows para trabajo futuro; esta versión solo se compiló y verificó en Linux.
