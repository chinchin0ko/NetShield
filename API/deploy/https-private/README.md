# Enlace privado mTLS de desarrollo

El propósito es conectar el proxy de la instancia pública con la API privada a través de TLS mutuo, sin publicar la API directamente. El backend valida el certificado del proxy y el proxy debe validar la CA y el nombre o IP del backend. La plantilla de systemd mantiene intacto el servicio SSH de desarrollo existente. No activa el proxy público ni sustituye sus protecciones.

`./test-mtls.sh` genera una CA y certificados temporales y levanta un backend simulado y dos proxies accesibles solo por loopback en el host donde se ejecuta. Comprueba el caso válido, el rechazo de clientes sin certificado y el rechazo por el proxy de una CA incorrecta. Requiere Docker y puede necesitar privilegios de administrador. No crea credenciales reales ni modifica las instancias permanentes.

Antes de usar la plantilla real deben generarse y custodiarse las claves y los certificados por separado; el servidor privado debe permitir TCP 18443 únicamente desde la instancia de la VPN, además de exigir certificado de cliente. El servicio debe ejecutarse como `netshield-api` sin privilegios de administrador. El proxy público sigue devolviendo 503 hasta completar las pruebas de acceso y los controles contra abuso. Deben definirse expiración, renovación, revocación, respaldo y recuperación de certificados antes de producción.

La plantilla usa las direcciones actuales de desarrollo y `--no-proxy-headers`: no permite atribuir solicitudes a la IP pública real. Antes de añadir límites por origen hay que definir y probar la cadena de proxies de confianza para que ningún cliente pueda suplantar esa IP.

En el entorno de desarrollo se instaló la plantilla como `netshield-api-mtls-dev`, adicional al servicio local existente. Escucha únicamente en `10.0.0.250:18443`; el firewall del sistema permite ese puerto desde `10.0.0.124/32`. La CA y la clave del servidor se crearon en la instancia API; la clave del proxy se generó en la instancia VPN y no se transfirió. El proxy público aún responde 503. Al preparar esta documentación, la conexión entre instancias seguía pendiente de la regla de entrada de OCI para TCP 18443 desde `10.0.0.124/32`.
