# Enlace privado mTLS de desarrollo

El proxy de la instancia pública conecta con la API privada a través de TLS mutuo, sin publicar la API directamente. El backend valida el certificado del proxy y el proxy valida la CA y la IP del backend. La plantilla de systemd mantiene el servicio SSH de desarrollo existente.

`./test-mtls.sh` genera una CA y certificados temporales y levanta un backend simulado y dos proxies accesibles solo por loopback en el host donde se ejecuta. Comprueba el caso válido, el rechazo de clientes sin certificado y el rechazo por el proxy de una CA incorrecta. Requiere Docker y puede necesitar privilegios de administrador. No crea credenciales reales ni modifica las instancias permanentes.

Antes de usar la plantilla real deben generarse y custodiarse las claves y los certificados por separado; el servidor privado debe permitir TCP 18443 únicamente desde la instancia de la VPN, además de exigir certificado de cliente. El servicio debe ejecutarse como `netshield-api` sin privilegios de administrador. Deben definirse expiración, renovación, revocación, respaldo y recuperación de certificados antes de producción.

La plantilla usa las direcciones actuales de desarrollo y `--no-proxy-headers`. El límite por origen utiliza exclusivamente la cabecera que establece el proxy autenticado, como se describe abajo.

En el entorno de desarrollo se instaló la plantilla como `netshield-api-mtls-dev`, adicional al servicio local existente. Escucha únicamente en `10.0.0.250:18443`; el firewall del sistema permite ese puerto desde `10.0.0.124/32`. La CA y la clave del servidor se crearon en la instancia API; la clave del proxy se generó en la instancia VPN y no se transfirió. El proxy público está activo para los endpoints especificados.

Tras configurar la regla de OCI se verificó desde la instancia VPN que `/health/live` responde con el certificado de cliente y que la conexión sin certificado se rechaza. También se probó un Caddy temporal, accesible únicamente en el loopback de la instancia VPN: transmitió la consulta de salud por mTLS y devolvió 404 para una ruta no habilitada. Esta prueba no publica los endpoints de la API.

La configuración `Caddyfile` publica registro, inicio de sesión y los endpoints de sesión y VPN. Sobrescribe la cabecera `X-NetShield-Client-IP` con la dirección de la conexión y el servicio mTLS activa un límite en memoria por origen. Es una protección de desarrollo para un único proceso: se reinicia al reiniciar el servicio y no se comparte entre réplicas. La cabecera solo es confiable porque este servicio exige el certificado del proxy y el proxy la reemplaza. El registro público está habilitado para pruebas. El proxy monta `/etc/netshield-proxy-client` como `/pki`, en modo de solo lectura. No usar esta configuración como despliegue de producción sin completar la gestión de certificados y los controles de abuso compartidos y duraderos.
