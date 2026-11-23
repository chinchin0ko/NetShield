# CoreDNS en NetShield VPN

## Que hace

CoreDNS es el resolutor DNS que esta detras de Pi-hole. La cadena queda asi:

```
Cliente VPN -> Pi-hole (10.5.0.2, filtra) -> CoreDNS (10.5.0.5, resuelve) -> 1.1.1.1 / 8.8.8.8
```

Los clientes no cambian nada: siguen usando 10.5.0.2 como DNS (WG_DEFAULT_DNS).
Pi-hole sigue bloqueando publicidad, rastreadores y dominios maliciosos; lo unico
que cambia es a quien le pide Pi-hole las respuestas que no estan bloqueadas
(antes: 8.8.8.8 y 8.8.4.4 directamente; ahora: CoreDNS en 10.5.0.5).

## Archivos

- `Corefile`: configuracion de CoreDNS (zona .:53, cache 30s, forward a
  1.1.1.1 y 8.8.8.8, log de consultas y de errores).
- `docker-compose.coredns.yml`: fragmento del servicio para el compose del VPS.

## Despliegue (VPS 140.84.183.78, ~/wireguard-docker)

1. Copiar el Corefile: `mkdir -p ~/wireguard-docker/coredns` y dejar el
   Corefile en `~/wireguard-docker/coredns/Corefile` con permiso **644**
   (el contenedor corre como UID 65532; con 640 no puede leerlo y entra
   en bucle de reinicio con "open Corefile: permission denied").
2. Agregar el servicio `coredns` del fragmento a `docker-compose.yml`
   (IP fija 10.5.0.5 en la red netshield_net). Imagen fijada a 1.15.0
   (la version que resolvio `latest` al desplegar; el VPS es ARM64 y la
   imagen es multi-arquitectura).
3. Levantar solo ese servicio: `sudo docker compose up -d coredns`.
4. Probar CoreDNS directo (desde un contenedor en la misma red):
   `nslookup example.com 10.5.0.5` (debe resolver).
5. Cambiar el upstream de Pi-hole a CoreDNS en
   `pihole/etc-pihole/pihole.toml`: `upstreams = ["10.5.0.5"]`
   (guardar antes el valor anterior: `["8.8.8.8", "8.8.4.4"]`).
6. Reiniciar Pi-hole: `sudo docker restart pihole`.
7. Probar de extremo a extremo: `nslookup example.com 10.5.0.2` debe
   resolver, y un dominio de publicidad conocido debe devolver 0.0.0.0
   (bloqueado por Pi-hole). Revisar `sudo docker logs coredns` para ver
   que las consultas llegan a CoreDNS.

## Verificacion (22/11/2026)

- CoreDNS 1.15.0 corriendo (Up) y resolviendo directo:
  `nslookup example.com 10.5.0.5` devuelve 104.20.23.154 y 172.66.147.243.
- Upstream de Pi-hole cambiado a `["10.5.0.5"]` (antes `["8.8.8.8",
  "8.8.4.4"]`, respaldado en `pihole.toml.bak-2026-11-22`).
- Cadena completa: `nslookup example.com 10.5.0.2` resuelve, y
  `nslookup doubleclick.net 10.5.0.2` devuelve 0.0.0.0 (bloqueo de
  Pi-hole intacto). Los logs de CoreDNS muestran las consultas llegando
  desde 10.5.0.2 (Pi-hole), lo que confirma que Pi-hole reenvia a CoreDNS.

## Rollback

Si el DNS falla: volver a poner en `pihole.toml`
`upstreams = ["8.8.8.8", "8.8.4.4"]`, reiniciar Pi-hole, y bajar el
servicio con `sudo docker compose stop coredns` (o quitarlo del compose).
Los clientes no notan el cambio porque siempre consultan a 10.5.0.2.
