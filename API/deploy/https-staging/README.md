# Comprobación HTTPS de desarrollo

Esta configuración sirve exclusivamente una respuesta 503 sin datos de usuario. No conecta con FastAPI ni publica registro, inicio de sesión ni administración. Su propósito es comprobar DNS, acceso desde Internet y emisión y renovación de certificados antes de integrar la API.

Requisitos para un despliegue posterior: un registro DNS A de `api.netshield.lat` hacia la IP pública de la instancia VPN; TCP 80 y 443 permitidos tanto en OCI como en el firewall del sistema; una imagen Caddy revisada y fijada por digest; volúmenes persistentes para `/data` y `/config`. No añadir un registro AAAA hasta contar con conectividad IPv6 funcional.

El archivo `compose.yaml` es una plantilla de desarrollo con una imagen fijada por digest. Debe revisarse y comprobarse que los puertos estén libres antes de desplegarla. La respuesta 503 es intencional. No contiene configuración del puente hacia la API privada: esa integración debe conservar la confidencialidad y autenticidad entre instancias y añadir controles de abuso antes de hacerse pública.

`./test-local-tls.sh` crea un contenedor desechable enlazado únicamente a localhost y verifica la respuesta con una CA temporal. Esta prueba no verifica el certificado público ni las reglas de OCI. En el entorno de desarrollo se preparó el servicio en `/opt/netshield-https-staging`; se dejó detenido mientras se habilitan los puertos de entrada 80 y 443, para evitar intentos ACME repetidos.
