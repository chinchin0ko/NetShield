# Preparación de notificaciones push para Android

Esta integración aún requiere un proyecto Firebase y una prueba completa en dispositivo. No activar en el servidor hasta validar migración, credenciales y servicio en un entorno de pruebas.

1. Registrar `com.netshield.netshield_app` en Firebase y poner `google-services.json` en `app/android/app/` antes de compilar. El archivo está excluido de Git. El APK sin este archivo compila, pero no registra push.
2. En el servidor de API, instalar las dependencias fijadas en `API/requirements.txt`, aplicar `012_push_notifications.sql` mediante el procedimiento de migraciones y actualizar la API. Añadir las rutas `/push/subscription` y `/push/subscription/*` al proxy público correspondiente.
3. Proveer credenciales de una identidad de servicio con permiso para enviar mensajes FCM. Mantenerlas exclusivamente en el servidor, con permisos de lectura restringidos. Configurar `NETSHIELD_DATABASE_URL`, `NETSHIELD_FIREBASE_PROJECT` y `GOOGLE_APPLICATION_CREDENTIALS` en `/etc/netshield-api-dev/push.env`; adaptar rutas y usuario del ejemplo de systemd al despliegue real.
4. Instalar e iniciar `netshield-push.service` y comprobar su estado sin imprimir credenciales ni tokens. La tabla de cola se rellena en la misma transacción que la alerta; el servicio reintenta los fallos y elimina registros FCM marcados `UNREGISTERED`. Un fallo después de enviar y antes de confirmar puede duplicar un aviso. El envío a FCM no garantiza que el teléfono lo muestre o lo reciba inmediatamente.
5. En un teléfono con Google Play services, conceder permisos de notificación, iniciar sesión y comprobar registro, recepción con app abierta y cerrada, reintentos, cambio de cuenta, cierre de sesión y ausencia de avisos entre cuentas. No se ha validado todavía.

Los avisos no incluyen firmas ni direcciones. El envío depende de la conexión del dispositivo y la plataforma, y la app forzada a detenerse puede no recibir mensajes hasta que vuelva a abrirse.
