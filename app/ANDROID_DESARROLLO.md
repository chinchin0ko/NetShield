# Android: desarrollo

Los APK de prueba se pueden descargar desde [versiones de NetShield en GitHub](https://github.com/chinchin0ko/NetShield/releases). En la versión Android más reciente, elige `arm64` para la mayoría de los teléfonos, `armv7` para equipos de 32 bits o `x86_64` para un emulador x86-64. Los APK de desarrollo están firmados con una clave de depuración y no son para producción.

La aplicación reutiliza las pantallas y la API de Linux; el controlador Android utiliza la biblioteca oficial de WireGuard y solicita la autorización VPN al sistema. El identificador es `com.netshield.netshield_app`. Las claves privadas se generan en el dispositivo y se cifran con Android Keystore; no se envían al servidor. El APK de depuración no está firmado para distribución.

Esta versión está en desarrollo: no se ha probado en un teléfono real. La función de bloqueo permanente de tráfico aún no está implementada en Android y se muestra deshabilitada. La activación del túnel no demuestra por sí misma que haya tráfico o handshake. En particular, comprueba IPv4, IPv6, DNS, pérdida de red, cambio entre Wi-Fi y datos, cierre de la aplicación y revocación antes de considerar su distribución.

Firebase y la cola persistente de notificaciones están configurados en el servidor de desarrollo. La compilación local incluye `google-services.json`; el servidor autentica con una cuenta de servicio protegida. Se ha probado el registro autenticado y la conectividad a FCM, pero falta verificar la recepción y la revocación en un teléfono. `google-services.json` pertenece en `android/app/`; las credenciales privadas del emisor deben permanecer fuera del repositorio y del cliente.

Compilación de depuración (requiere Flutter y Android SDK con licencias aceptadas):

```sh
cd app
flutter pub get
flutter build apk --debug
```
