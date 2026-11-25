# Notificaciones push de Android en desarrollo

El proyecto Firebase es `netshield-481a4` y la aplicación Android utiliza el identificador `com.netshield.netshield_app`. El archivo `app/android/app/google-services.json` se usa al compilar y está excluido de Git. Las credenciales privadas del emisor permanecen fuera del repositorio y del cliente.

La migración `012_push_notifications.sql` está aplicada en la base de desarrollo. El servidor API ofrece `PUT /push/subscription` y `DELETE /push/subscription/{device_id}` autenticados. Cada alerta personal crea en la misma transacción los mensajes pendientes para las suscripciones de su cuenta. La cola reintenta fallos y elimina las suscripciones que FCM confirme como `UNREGISTERED`. Una caída después de enviar y antes de confirmar puede duplicar un aviso; la aceptación de FCM no garantiza su entrega inmediata.

En la instancia API, `netshield-push.service` envía los mensajes y utiliza `/etc/netshield-api-dev/push.env` y una cuenta de servicio protegida en `/etc/netshield-api-dev/firebase-service.json`. El aviso contiene texto genérico, sin firmas ni direcciones. El registro y eliminación autenticados se probaron mediante una cuenta temporal eliminada después.

La instancia API es privada y no dispone de salida directa a Internet. `netshield-fcm-tunnel.service` mantiene un túnel SSH de infraestructura hacia la instancia VPN. Su clave está restringida a esa IP de origen y a un único destino, sin acceso de shell. En la VPN, `netshield-fcm-proxy.service` escucha únicamente en loopback y admite conexiones TLS salientes exclusivamente a `oauth2.googleapis.com:443` y `fcm.googleapis.com:443`. El TLS se establece entre la API y Google, sin descifrado en el proxy. Los clientes de NetShield no necesitan SSH.

Para diagnóstico, consultar el estado y el registro de esos tres servicios sin imprimir tokens ni credenciales. Ya se verificaron la autenticación OAuth desde la API, los permisos de envío y el bloqueo de destinos ajenos a Google. Una consulta de validación llegó a FCM con un token deliberadamente inválido; no confirma la recepción en un teléfono.

Falta probar en Android real: conceder permisos, iniciar sesión, conectar la VPN, recibir alertas con la app abierta y cerrada, cambiar de cuenta, cerrar sesión y comprobar el aislamiento. La app forzada a detenerse puede no recibir mensajes hasta volver a abrirla. El bloqueo permanente de Android sigue deshabilitado y requiere implementación y pruebas antes de distribución.
