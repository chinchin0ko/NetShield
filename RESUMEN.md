# NetShield: estado y prioridades

## Prioridad alta: conectividad en Politécnica software

En una prueba con Android, conectado a «Politécnica software» y con datos móviles desactivados, el servidor registró un handshake reciente de WireGuard por UDP 51820, pero el teléfono no pudo navegar. No se capturaron paquetes y no está establecida la causa. En «Politécnica» se observó navegación, pero no se confirmó que los datos móviles estuvieran desactivados, por lo que falta repetir esa prueba.

Próximas comprobaciones, sin interrumpir la conexión de trabajo: verificar conectividad de la red sin VPN y portal cautivo; comparar una dirección IP con resolución DNS; observar contadores de tráfico a ambos lados; comprobar MTU y posible pérdida de paquetes; revisar las rutas y el IPv6 del túnel, para el que el servidor aún no ofrece salida. Probar otro puerto UDP solo si la evidencia apunta al transporte y coordinando servidor, OCI y cliente. No asumir que el handshake demuestra que todo el tráfico funciona.

## Desarrollo y seguridad

El registro público y la API HTTPS están habilitados para pruebas. PostgreSQL y la API se comunican por redes privadas, y el proxy usa mTLS hacia la API. El cliente Arch dispone de un paquete experimental. Antes de producción siguen pendientes, entre otros, protección contra abuso compartida y persistente, recuperación y revocación de sesiones, gestión y renovación de certificados, respaldos probados, auditoría, pruebas de clientes y controles operativos. El paquete de desarrollo no está firmado ni probado en un Arch limpio.

Suricata está activo en la interfaz pública y se ha observado en sus registros una consulta DNS de prueba originada desde el entorno del contenedor VPN. El recolector toma desde el final del EVE existente las nuevas alertas cuya firma contiene MALWARE, TROJAN o EXPLOIT, conserva solo campos mínimos y las guarda en PostgreSQL por mTLS con deduplicación. Son alertas generales del servidor; el NAT impide atribuirlas de forma fiable a una cuenta y no existe todavía una API pública para consultarlas. HTTPS y otros contenidos cifrados no son inspeccionados como texto plano. La prueba offline usa un indicador sintético y no demuestra detección completa de malware.

El cursor detecta rotación por cambio de inode o reducción del archivo y reintenta la entrega antes de avanzar. Una rotación durante una caída prolongada puede dejar datos en archivos antiguos sin procesar: falta una estrategia de recuperación completa, retención, control de volumen y monitoreo. Los registros históricos de Suricata pueden contener datos sensibles; limitar acceso y establecer rotación y retención es prioritario.
