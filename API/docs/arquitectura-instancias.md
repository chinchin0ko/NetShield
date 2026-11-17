# Arquitectura propuesta para las instancias OCI

## Tráfico y acceso

- **Instancia VPN pública existente:** recibe WireGuard UDP 51820. Un proxy HTTPS público puede recibir conexiones de clientes en TCP 443 y reenviarlas a la API privada por la VCN. Requiere nombre DNS, certificado válido y reglas/firewalls explícitos; el cliente debe acceder a la API antes de conectar la VPN. Los paneles administrativos no deben exponerse públicamente.
- **Instancia API privada:** FastAPI y el componente de gestión de peers son distintos. La API no recibe acceso a Docker, llaves del servidor ni `sudo`. El controlador de peers debe ejecutarse cerca de WireGuard con autenticación, autorización y privilegios mínimos, usando un único gestor como fuente de verdad.
- **Instancia PostgreSQL privada:** TCP 5432 solo desde API/controlador autorizados, con TLS verificado. Secretos y certificados no se guardan en el repositorio. Backups cifrados y prueba de restauración.

## Una sola fuente de verdad para WireGuard

La versión actual `wg-easy:13` genera claves privadas de clientes y reescribe `wg0.json` y `wg0.conf`. Su interfaz observada crea clientes por nombre, no recibe una clave pública externa. Modificar manualmente archivos o ejecutar `wg set` sobre su interfaz no es una integración segura: un guardado o reinicio puede sobrescribir esos cambios.

La solución propuesta es **sustituir la administración de peers** por un controlador único diseñado para claves públicas generadas por el cliente. PostgreSQL debe conservar el estado deseado y el controlador rehidratarlo y reconciliarlo en el arranque. El prototipo `lab/` comprueba la idea, pero aún no es ese controlador: no proporciona aislamiento de privilegios ni compatibilidad con la instancia real. Una migración debe ensayarse con una copia aislada, comparar el inventario, contemplar migración o nueva inscripción de clientes y probar la reversión. No borrar ni reemplazar el gestor existente antes de tener una prueba y una ventana de mantenimiento aprobada.

## Salida a internet y actualizaciones

La ausencia de IP pública no impide comunicaciones privadas dentro de OCI. Sí impide, con la ruta actual, obtener paquetes directamente. Las cuentas Free Tier no pueden crear NAT Gateway según la documentación de Oracle. Opciones: proxy de salida restringido y supervisado a través de la instancia pública; o, para mantenimiento, túnel SSH con autenticación restringida y ventanas automáticas. El túnel es para instalaciones/actualizaciones, no para tráfico ordinario API ↔ PostgreSQL. La solución definitiva requiere control de destinos, logs sin secretos, actualizaciones probadas y alertas ante fallos. El comprobador existente de PostgreSQL solo detecta actualizaciones; no las instala ni notifica.

## Reinicio de fábrica o reconstrucción

No ejecutar una reconstrucción antes de inventariar y verificar copias restaurables de la configuración, base, claves y archivos de despliegue, así como el método de recuperación de SSH y los cambios de IP/DNS. Elegir expresamente qué instancia reconstruir y si se conservan clientes y datos. El reemplazo del volumen de arranque o la terminación pueden eliminar información; Oracle permite preservar el volumen en determinados flujos. Crear un plan con ventana, validación y reversión antes de ejecutar. No se ha reiniciado ni borrado ninguna instancia.

## Pendientes antes de producción

Autenticación endurecida y límites; exposición segura HTTPS; controlador restringido y recuperación verificada; configuración DNS y IPv6; actualización y respaldo comprobados; supervisión y auditoría; pruebas de fugas y Kill Switch en plataformas reales. La prueba de laboratorio no demuestra estos controles.
