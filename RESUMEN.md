# NetShield: estado y prioridades

## Prioridad alta: conectividad en Politécnica software

En una prueba con Android, conectado a «Politécnica software» y con datos móviles desactivados, el servidor registró un handshake reciente de WireGuard por UDP 51820, pero el teléfono no pudo navegar. No se capturaron paquetes y no está establecida la causa. En «Politécnica» se observó navegación, pero no se confirmó que los datos móviles estuvieran desactivados, por lo que falta repetir esa prueba.

Próximas comprobaciones, sin interrumpir la conexión de trabajo: verificar conectividad de la red sin VPN y portal cautivo; comparar una dirección IP con resolución DNS; observar contadores de tráfico a ambos lados; comprobar MTU y posible pérdida de paquetes; revisar las rutas y el IPv6 del túnel, para el que el servidor aún no ofrece salida. Probar otro puerto UDP solo si la evidencia apunta al transporte y coordinando servidor, OCI y cliente. No asumir que el handshake demuestra que todo el tráfico funciona.

## Desarrollo y seguridad

El registro público y la API HTTPS están habilitados para pruebas. PostgreSQL y la API se comunican por redes privadas, y el proxy usa mTLS hacia la API. El cliente Arch dispone de un paquete experimental. Antes de producción siguen pendientes, entre otros, protección contra abuso compartida y persistente, recuperación y revocación de sesiones, gestión y renovación de certificados, respaldos probados, auditoría, pruebas de clientes y controles operativos. El paquete de desarrollo no está firmado ni probado en un Arch limpio.
