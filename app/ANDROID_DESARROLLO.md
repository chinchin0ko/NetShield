# Android: desarrollo

La aplicación reutiliza las pantallas y la API de Linux; el controlador Android utiliza la biblioteca oficial de WireGuard y solicita la autorización VPN al sistema. El identificador es `com.netshield.netshield_app`. Las claves privadas se generan en el dispositivo y se cifran con Android Keystore; no se envían al servidor. El APK de depuración no está firmado para distribución.

Esta versión está en desarrollo: no se ha probado en un teléfono real. La función de bloqueo permanente de tráfico aún no está implementada en Android y se muestra deshabilitada. La activación del túnel no demuestra por sí misma que haya tráfico o handshake. En particular, comprueba IPv4, IPv6, DNS, pérdida de red, cambio entre Wi-Fi y datos, cierre de la aplicación y revocación antes de considerar su distribución.

Hay una integración de notificaciones push preparada con Firebase y una cola persistente en el backend. No está desplegada ni verificada de extremo a extremo. Se necesita un proyecto Firebase, registrar la app con el identificador anterior, configurar el cliente y el emisor autenticado del servidor, y verificar envío y revocación en un teléfono. `google-services.json` pertenece en `android/app/`; las credenciales privadas del emisor deben permanecer fuera del repositorio y del cliente.

Compilación de depuración (requiere Flutter y Android SDK con licencias aceptadas):

```sh
cd app
flutter pub get
flutter build apk --debug
```
