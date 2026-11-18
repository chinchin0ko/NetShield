# NetShield — aplicación de escritorio

Primera versión de la interfaz en Flutter para Linux. Incluye inicio de sesión contra la API de desarrollo y una pantalla de conexión. El registro y el botón de VPN todavía no están habilitados: requieren integración adicional en el backend y con WireGuard.

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

La estructura incluye proyectos iniciales de Android y Windows para trabajo futuro; esta versión solo se compiló y verificó en Linux.
