# Transporte VPN por HTTPS

Despliegue verificado el 25 de noviembre de 2026. El cliente Linux verifica el
certificado de `api.netshield.lat`, pero conecta directamente a la IP del endpoint
para poder recuperar el transporte sin depender de DNS mientras hay bloqueo.

## Camino de los paquetes

```text
WireGuard cliente → UDP local → wstunnel cliente
  → WSS/TLS TCP 443 → Caddy /wstunnel/*
  → ws://172.18.0.1:18081 → UDP 127.0.0.1:443
  → publicación Docker → wg-easy UDP 51820
```

El listener 18081 se enlaza al gateway privado de la red de Caddy. Si esa red
cambia, actualizar tanto la unidad systemd como el upstream de Caddy. No publicar
18081 en todas las interfaces. La configuración de restricciones solo permite
UDP a 127.0.0.1:443; no permite TCP ni túneles inversos.

## WireGuard y compatibilidad

El compose privado de wg-easy usa `WG_PORT=51820` y estas publicaciones:

```yaml
ports:
  - "51820:51820/udp"
  - "443:51820/udp"
  - "127.0.0.1:51821:51821/tcp"
```

La API entrega UDP/51820 a perfiles nuevos. Conservar la publicación UDP/443:
es el destino local de WSS y mantiene compatibilidad con perfiles anteriores.
UDP/443 no respondió desde Internet en las pruebas; UDP/51820 sí. Cambiar
solo el puerto de WSS sin adaptar estas publicaciones rompería el transporte.
La API HTTPS y WSS comparten TCP/443; UDP/443 es un protocolo distinto.

Los archivos de este directorio son plantillas del servicio y sus restricciones.
En el servidor, las restricciones se instalan en
`/etc/netshield/wstunnel-restrictions.yaml` y la unidad en
`/etc/systemd/system/netshield-wstunnel-https.service`. El servicio anterior
`netshield-wstunnel` en TCP/80 está deshabilitado.

## Comprobación

Desde la raíz del repositorio:

```bash
API/scripts/test-transport-route-lab.sh
python3 API/scripts/test-vpn-https-e2e.py --udp
python3 API/scripts/test-vpn-https-e2e.py --wstunnel app/build/transport/wstunnel
```

El laboratorio no cambia rutas ni reglas del host. Las pruebas E2E crean una
cuenta y un peer propios en el backend de desarrollo: revocan el peer y eliminan
claves/procesos al terminar, pero la cuenta queda registrada. No ejecutarlas en
bucle. WSS comprueba también interrupción y recuperación con bloqueo activo.

Revisar salud de wg-easy, servicios `netshield-wstunnel-https`,
`netshield-vpn-sensor` y `netshield-suricata-collector`. El sensor debe reiniciarse
en el nuevo namespace si se recrea el contenedor; comprobarlo en su journal.

## Reversión y precauciones operativas

Las copias previas están en el servidor, con permisos restringidos:

- `/home/ubuntu/wireguard-docker/docker-compose.yml.before-udp-compat-20261125`
- `/opt/netshield-https-staging/Caddyfile.before-wss-20261125`

No copiar esos archivos privados al repositorio. Restaurar compose exige recrear
wg-easy y puede interrumpir sesiones: coordinarlo y verificar las publicaciones
después. Volver al compose anterior devuelve UDP/443, cuyo acceso externo falló.
Mantener WSS hasta comprobar una alternativa; no reactivar TCP/80 por defecto.

Si Caddy tiene un archivo individual montado desde el host, reemplazarlo mediante
rename puede dejar al contenedor usando el inode anterior. Validar y recargar la
configuración realmente visible dentro del contenedor, además de actualizar el
archivo del host para el siguiente arranque.
