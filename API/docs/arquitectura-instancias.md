# Arquitectura propuesta para las instancias OCI

## Tráfico y acceso

- **Instancia VPN pública existente:** recibe WireGuard UDP 51820. El panel de wg-easy se publica únicamente en `127.0.0.1:51821` desde el 19 de noviembre de 2026; puede administrarse mediante un túnel SSH. Un proxy HTTPS público podría recibir conexiones de clientes en TCP 443 y reenviarlas a la API privada. Requiere un nombre DNS, certificado válido, controles de abuso, conexión autenticada al backend y reglas de firewall; el cliente debe alcanzar la API antes de conectar la VPN.
- **Instancia API privada:** FastAPI y el componente de gestión de peers son distintos. La API no recibe acceso a Docker, llaves del servidor ni `sudo`. El controlador de peers debe ejecutarse cerca de WireGuard con autenticación, autorización y privilegios mínimos, usando un único gestor como fuente de verdad.
- **Instancia PostgreSQL privada:** TCP 5432 solo desde API/controlador autorizados, con TLS verificado. Secretos y certificados no se guardan en el repositorio. Backups cifrados y prueba de restauración.

En desarrollo, los paneles de wg-easy y Pi-hole escuchan en `127.0.0.1:51821` y `127.0.0.1:8080` de la instancia VPN, respectivamente. Para administrarlos desde el equipo autorizado, se puede abrir un túnel SSH hacia esos puertos; los servicios de WireGuard y DNS siguen utilizando sus conexiones habituales. Que un puerto no responda desde una sola red no demuestra la configuración completa de las reglas OCI.

## Una sola fuente de verdad para WireGuard

La versión original `wg-easy:13` genera claves privadas de clientes y reescribe `wg0.json` y `wg0.conf`. La instancia de desarrollo usa actualmente una imagen derivada fijada por digest, con operaciones para aprovisionar claves públicas generadas en el cliente. El puente restringido llama a ese único administrador; no modifica sus archivos ni administra peers con `wg set` por separado. Modificar manualmente archivos o ejecutar `wg set` por fuera sigue siendo inseguro: un guardado o reinicio puede sobrescribir esos cambios.

La imagen personalizada es una solución de desarrollo, no un controlador de producción auditado. El estado de peers sigue en wg-easy; PostgreSQL no es todavía la fuente de verdad para ese estado. Antes de migrar el administrador se necesita ensayar la reconciliación y recuperación con una copia aislada, comparar el inventario, contemplar la migración o reinscripción de clientes y probar la reversión.

## Salida a internet y actualizaciones

La ausencia de IP pública no impide comunicaciones privadas dentro de OCI. Sí impide, con la ruta actual, obtener paquetes directamente. Las cuentas Free Tier no pueden crear NAT Gateway según la documentación de Oracle. Opciones: proxy de salida restringido y supervisado a través de la instancia pública; o, para mantenimiento, túnel SSH con autenticación restringida y ventanas automáticas. El túnel es para instalaciones/actualizaciones, no para tráfico ordinario API ↔ PostgreSQL. La solución definitiva requiere control de destinos, logs sin secretos, actualizaciones probadas y alertas ante fallos. El comprobador existente de PostgreSQL solo detecta actualizaciones; no las instala ni notifica.

## Reinicio de fábrica o reconstrucción

No ejecutar una reconstrucción antes de inventariar y verificar copias restaurables de la configuración, base, claves y archivos de despliegue, así como el método de recuperación de SSH y los cambios de IP/DNS. Elegir expresamente qué instancia reconstruir y si se conservan clientes y datos. El reemplazo del volumen de arranque o la terminación pueden eliminar información; Oracle permite preservar el volumen en determinados flujos. Crear un plan con ventana, validación y reversión antes de ejecutar. No se ha reiniciado ni borrado ninguna instancia.

## Pendientes antes de producción

Autenticación endurecida y límites; exposición segura HTTPS; controlador restringido y recuperación verificada; configuración DNS y IPv6; actualización y respaldo comprobados; supervisión y auditoría; pruebas de fugas y Kill Switch en plataformas reales. La prueba de laboratorio no demuestra estos controles.


## Resultado del ensayo de propiedad de peers

Se ejecutó `scripts/test-wg-easy-ownership.sh` con un contenedor `wg-easy:13` temporal, sin red externa ni puertos publicados y con un volumen independiente. Al añadir un peer directamente con `wg set` y después crear otro mediante la API de wg-easy, el guardado eliminó el peer externo; los peers administrados por wg-easy se restauraron tras reiniciar el contenedor. Este resultado confirma que no se deben ejecutar dos administradores en la misma interfaz.

La transición a un controlador independiente, aún no ejecutada, requiere: 1) probar una interfaz y un controlador nuevos sin alterar el servicio actual; 2) preparar reglas de red, persistencia y recuperación del controlador; 3) inventariar clientes y acordar si serán migrados o se reinscribirán; 4) verificar respaldo y un procedimiento de regreso; 5) detener un gestor antes de activar el otro, verificar conectividad y revocación, y no tener dos procesos escribiendo la misma interfaz. Las claves privadas y precompartidas existentes requieren tratamiento confidencial; no deben volcarse en logs ni al repositorio.
