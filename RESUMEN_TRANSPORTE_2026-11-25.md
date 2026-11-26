# NetShield: diagnóstico y corrección del transporte VPN

Actualizado: 25 de noviembre de 2026. Resumen para continuar el trabajo y compartir
el estado técnico. No incluye contraseñas, tokens, claves ni contenido de navegación.

## Objetivo y situación actual

El usuario reportó que NetShield no conecta en «Politecnica Software», aunque otras
VPN funcionan. Autorizó corregir el transporte TCP, ofrecer WebSocket seguro por
HTTPS/443, corregir el estado mostrado por la app y verificar el kill switch.

**Servidor verificado con WireGuard UDP/51820 y WSS/TLS/TCP 443**, con DNS y
navegación por la VPN. La prueba WSS también verifica interrupción y recuperación
sin retirar el bloqueo. Los cambios principales están en `751f9f8`, incorporados
por otra sesión; se comprobó la instalación de `netshield-vpn 0.1.0-26`.
La supervisión adicional del CLI y las pruebas de rutas se completaron después.
El paquete 0.1.0-27 ya está generado y revisado. KDE rechazó la primera solicitud
de instalación; queda pendiente esa autorización y sigue instalada la versión
0.1.0-26. La red universitaria todavía requiere una prueba presencial.

El usuario está usando los datos de su teléfono para mantener la sesión de trabajo.
No cambiarlo a la red universitaria ni activar una VPN sobre su conexión de trabajo
sin coordinarlo. La prueba en la universidad sigue pendiente.

## Ubicación del trabajo

- Repositorio: `/home/chinchin/Projects/NetShield`.
- Base inicial revisada: commit `878b3b1`, «Modo TCP (wstunnel) para redes que bloquean UDP».
- App: `app/`; API e infraestructura: `API/`.
- API pública: `https://api.netshield.lat`.
- Servidor VPN: `140.84.183.78`; WireGuard escucha en UDP/51820; Docker publica 51820 y 443 hacia ese mismo listener.
- Diagnóstico detallado: `docs/diagnostico-red-universidad-2026-11-25.md`.
- Acceso administrativo existente: usuario `ubuntu`; clave local en
  `/home/chinchin/Projects/SSH/UPVPN/ssh-key-2026-09-17.key`. No publicarla.

## Qué mostró la captura

Se analizó `/home/chinchin/Documents/capturaredup5.pcapng`, no la conexión actual
por datos móviles. Contiene 2312 paquetes y unos 21 segundos del intento fallido.

- Cinco inicios de handshake WireGuard a `140.84.183.78:443/UDP`, sin respuestas
  WireGuard ni datos de transporte. Los intentos se repiten aproximadamente cada
  cinco segundos.
- El mismo servidor sí intercambia TCP/TLS por 443.
- Otros destinos reciben intentos QUIC por UDP/443 sin respuestas en esa ventana.
- DNS y STUN sí reciben respuestas: no corresponde afirmar que todo UDP está bloqueado.
- Había una conexión TCP/80 abierta, pero solamente se observaron mensajes de dos
  bytes. El intento WireGuard observado estaba saliendo directamente por UDP;
  no estaba siendo llevado por el transporte TCP.
- El tráfico TCP externo posterior al intento coincide con las IP permitidas por
  la excepción de Tailscale del código actual. No basta para afirmar una fuga
  general del kill switch; se necesitan las reglas efectivas de ese momento.

El patrón es compatible con filtrado/pérdida de UDP/443, pero la captura del cliente
no identifica el punto de descarte ni demuestra DPI. No se debe presentar la
universidad como causa única confirmada.

Como referencia limitada, `capturacondatos.pcapng` sí contiene handshakes y miles
de paquetes de transporte por UDP/51820 en otro momento. No prueba que UDP/443
funcione con la configuración actual.

## Fallos encontrados en el código y el despliegue anterior

1. `LinuxVpn.isConnected()` solamente comprueba si el perfil está activo en
   NetworkManager. Un perfil activo no demuestra un túnel operativo. El fallo del
   ping inicial dejaba el perfil activo y la pantalla podía decir «Conectado».
2. El mapa obtenía la IP con una petición sin vincularla al túnel ni al intento de
   conexión. Una consulta iniciada antes de conectar podía aparecer después como
   «IP con la VPN». La ubicación de Querétaro era fija, no una comprobación de salida.
3. El modo TCP no conservaba una ruta física al servidor cuando la API era pública:
   la función de preservación de ruta solo se ejecutaba para una API localhost.
   Esto puede introducir un bucle al instalar la ruta completa de WireGuard.
4. El cliente usaba `ws://...:80`, esperaba dos segundos y no verificaba la escucha,
   no consumía stdout/stderr ni supervisaba la terminación del proceso.
5. Caddy apuntaba a `172.18.0.1:18081`, donde no había servicio. Su matcher también
   era solamente `/wstunnel`; el cliente real usa `/wstunnel/events`.
6. wstunnel 11.1.0 no verifica certificados por defecto: hay que pasar explícitamente
   `--tls-verify-certificate`. Además, `NO_COLOR=1` en este entorno provoca un error
   de argumentos; el cliente corregido le pasa `NO_COLOR=true`.

## Cambios hechos en el cliente

### Transporte Linux

Archivo nuevo: `app/lib/services/wstunnel_transport.dart`.

- Conecta a la IPv4 del endpoint por **WSS/TLS/TCP 443**.
- Verifica el certificado contra el dominio de API con SNI y Host coherentes.
- Usa `--http-upgrade-path-prefix wstunnel`.
- La conexión usa la IP directamente, evitando necesitar DNS para reiniciar el
  transporte mientras el kill switch está activo.
- El listener local UDP usa un puerto libre, para no chocar con el wstunnel manual
  que el usuario tenía abierto en 51821.
- Se comprueba la escucha del proceso mediante `ss`, se consumen ambos streams y
  se puede reiniciar el proceso sobre el mismo puerto desde el monitor.
- Al detenerlo solo se termina el proceso propio; no otros wstunnel del usuario.
- No hereda proxies HTTP/HTTPS/ALL del entorno.

`app/lib/services/linux_vpn.dart`:

- Conserva la ruta externa al servidor también para el modo TCP con API pública.
- Reescribe el endpoint WireGuard al listener local del transporte.
- Comprueba que la ruta al servidor no vuelva a entrar en la interfaz VPN.
- Comprueba la puerta de enlace vinculando el ping a la interfaz del dispositivo.
- Si falla la conexión, elimina su perfil, termina el transporte y trata de retirar
  la ruta temporal. **Conserva el kill switch** para evitar salida accidental.
- Consulta la IP de salida con una conexión HTTPS vinculada a la dirección IPv4
  del túnel y solamente con el bloqueo activo. Devuelve dato no disponible ante fallo.
- Prefiere el binario empaquetado de wstunnel al instalado en la carpeta del usuario.

### Interfaz

Archivos: `app/lib/main.dart`, `app/lib/screens/vpn_map.dart`,
`app/lib/screens/dashboard_panels.dart`.

- En escritorio distingue interfaz activa de túnel comprobado. No afirma
  «Conectado» mientras falta la comprobación y muestra «VPN sin respuesta» cuando falla.
- El icono de conexión usa el estado comprobado.
- El mapa recibe la IP verificada desde el controlador; ya no hace consultas
  independientes. No muestra una IP anterior cuando el túnel no está verificado.
- La ubicación se presenta como ubicación del servidor, no como geolocalización
  demostrada del usuario. Se eliminó la afirmación fija de que el usuario está en Tuxtla.
- Se descartan resultados de diagnóstico si cambió la generación de conexión.
- No se retira/reaplica el bloqueo para cambiar el modo TCP durante una conexión:
  el cambio exige desconectar primero.
- El texto de Ajustes explica HTTPS/TCP 443 sin afirmar que la red bloquea todo UDP.
- Se corrigió el mixin de animación del mapa: creaba dos controladores con
  `SingleTickerProviderStateMixin`; ahora utiliza `TickerProviderStateMixin`.

### Kill switch y empaquetado

- `app/linux/netshield/killswitch.py`: la excepción del modo TCP permite solamente
  TCP/443 hacia el servidor, en lugar de TCP/80. Se conserva el resto de la protección.
- Nuevo `app/scripts/prepare-wstunnel.sh`: descarga wstunnel 11.1.0 Linux amd64 y
  comprueba el SHA-256 del archivo oficial antes de extraer el binario y su licencia.
- SHA-256 del tar.gz:
  `512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23`.
- Se modificaron los empaquetadores Arch/Debian/Fedora para incluir el transporte y
  su licencia. Se añadió la dependencia de iproute/iproute2 donde corresponde.
- La plantilla Arch apunta a `0.1.0-26`. **El paquete aún no se generó ni instaló.**

## Cambios ya aplicados al servidor

Archivos versionables nuevos en `API/deploy/wstunnel/`:

- `netshield-wstunnel-https.service`.
- `restrictions.yaml`.

Se instalaron en `/etc/systemd/system/` y `/etc/netshield/`, respectivamente.
El servicio `netshield-wstunnel-https` está habilitado y se inició correctamente.

- Escucha en la dirección interna del bridge de Caddy: `172.18.0.1:18081`.
- Caddy termina TLS con el certificado de `api.netshield.lat` y hace proxy de
  `/wstunnel` y `/wstunnel/*` al servicio interno.
- La restricción de wstunnel permite únicamente transporte **UDP a 127.0.0.1:443**.
  No permite túneles TCP arbitrarios ni túneles inversos. WireGuard autentica al peer.
- Servicio con usuario dinámico `netshield-wss`, `NoNewPrivileges`, protección del
  filesystem y reinicio ante fallos.
- Se actualizó también `API/deploy/https-private/Caddyfile` en el repo.

Detalle operativo importante: el Caddyfile existente es un bind mount de archivo.
Reemplazarlo con `sed -i` no cambia el inode que ve el contenedor en marcha. Por eso
se copió la configuración actualizada al contenedor como `/tmp/Caddyfile.wss`, se
validó y se hizo `caddy reload --config /tmp/Caddyfile.wss`. El archivo del host
`/opt/netshield-https-staging/Caddyfile` también está actualizado para próximos
arranques. No se reinició el contenedor para este cambio.

Copia anterior de la configuración:
`/opt/netshield-https-staging/Caddyfile.before-wss-20261125`.

El servicio anterior `netshield-wstunnel` en TCP/80 está **deshabilitado e
inactivo**, comprobado en el servidor. `netshield-wstunnel-https` está habilitado
y activo. El sensor y el recolector están activos; el supervisor del sensor
detectó la sustitución del contenedor y se reenganchó a su nuevo namespace.

## Pruebas realizadas y resultados

1. **41 pruebas Flutter pasaron**, incluidas nuevas comprobaciones de:
   - conexión fallida que conserva bloqueo sin afirmar conectividad;
   - mapa que oculta IP antigua al perder la verificación;
   - parámetros de TLS verificado;
   - arranque de un proceso wstunnel real, terminación forzada, reinicio con el
     mismo puerto y parada sin dejar el listener abierto.
2. `flutter analyze`: sin incidencias en la ejecución realizada. Repetir al finalizar
   si se añaden modificaciones posteriores.
3. `API/scripts/test-killswitch-lab.sh`: pasó. Comprueba WireGuard con bloqueo,
   rechazo IPv6, cierre de conexiones IPv6 externas existentes, conservación de
   loopback, bloqueo directo IPv4/IPv6 al caer el túnel, restauración persistente y
   retirada del bloqueo en namespaces aislados. La prueba original usa transporte UDP;
   la matriz TCP/443 quedó cubierta posteriormente por `test-transport-route-lab.sh` (ver abajo).
4. TLS real y upgrade WebSocket: certificado validado con SNI `api.netshield.lat`,
   conexión a la IP del servidor y respuesta **101 Switching Protocols**.
5. **Prueba real WSS de extremo a extremo pasó** mediante el nuevo script
   `API/scripts/test-vpn-https-e2e.py`:
   - crea una cuenta temporal de prueba y un peer propio mediante la API;
   - ejecuta WireGuard en namespace rootless, con claves temporales de permisos 600;
   - usa un puente Unix que lleva únicamente datagramas WireGuard cifrados hasta
     el wstunnel del host, sin cambiar rutas ni firewall del host;
   - handshake, ping a la puerta de enlace, DNS VPN y HTTPS correctos;
   - IP de salida observada: `140.84.183.78`;
   - interrumpe wstunnel, comprueba fallo y persistencia del bloqueo, reinicia y
     comprueba recuperación de WireGuard;
   - revoca el peer y elimina procesos y claves temporales al terminar.
   Las cuentas de prueba quedan registradas, con sus peers revocados. No se
   eliminaron usuarios ni datos de otras cuentas.
6. `flutter build linux --release`: compilación correcta en
   `app/build/linux/x64/release/bundle/netshield_app`.

Comandos reproducibles, desde el repo salvo indicación:

```bash
cd /home/chinchin/Projects/NetShield/app
WSTUNNEL_BINARY=/home/chinchin/.local/share/netshield/wstunnel \
  /home/chinchin/.local/share/netshield-tools/flutter/bin/flutter test
/home/chinchin/.local/share/netshield-tools/flutter/bin/flutter analyze

cd /home/chinchin/Projects/NetShield
API/scripts/test-killswitch-lab.sh
python3 API/scripts/test-vpn-https-e2e.py \
  --wstunnel app/build/transport/wstunnel
```

El último comando crea recursos de prueba en el backend: no ejecutarlo en bucle.

## Corrección adicional del puerto UDP y comprobaciones finales

UDP/443 tampoco respondió desde los datos móviles: la captura simultánea en el
servidor no mostró esos paquetes. Un relay temporal de prueba en UDP/51820 sí
permitió handshake, DNS y HTTPS. Se retiró ese relay después de la prueba.
Esto apunta a filtrado/pérdida anterior al servidor; no identifica si corresponde
a Oracle, al operador o a otro equipo. No se localizaron credenciales OCI para
inspeccionar las reglas de ingreso desde esta sesión.

Se aplicó una corrección permanente en el compose de wg-easy:

- `WG_PORT=51820` y publicaciones `443:51820/udp` y `51820:51820/udp`.
- Se conservan volúmenes, claves y peers. Solo se recreó wg-easy, tras comprobar
  que no había peers con handshake reciente en los últimos 180 segundos.
- Copia previa protegida: `/home/ubuntu/wireguard-docker/docker-compose.yml.before-udp-compat-20261125`.
- La API ya entrega `140.84.183.78:51820`. La publicación 443 conserva compatibilidad
  con perfiles anteriores, aunque su accesibilidad UDP externa no quedó demostrada.
- WSS mantiene su destino interno `127.0.0.1:443`, traducido por Docker a 51820.
- Tanto UDP/51820 como WSS/443 pasaron pruebas reales con salida `140.84.183.78`.
  WSS se volvió a probar después de la modificación de puertos y recuperó el túnel
  tras interrumpir el transporte. Cada peer de prueba fue revocado al finalizar.

Comprobaciones adicionales:

1. `API/scripts/test-transport-route-lab.sh` pasó en namespaces sin modificar la
   red del host. Demuestra el bucle sin ruta /32 y su corrección; comprueba que
   tres destinos son alcanzables antes del bloqueo, permite solo el servidor
   TCP/443 después y bloquea TCP/80 y otro servidor TCP/443. Repite con interfaz
   VPN caída y restauración del bloqueo persistente; retirar el bloqueo recupera
   los tres destinos. Los controles negativos evitan confundir un puerto cerrado
   con una regla de firewall que funciona.
2. Certificado autofirmado local: sin verificación el control llega al HTTP;
   con `--tls-verify-certificate` el servidor observa el rechazo TLS de la CA.
   La prueba no cambia la configuración desplegada ni instala ninguna CA.
3. Destino TCP/22 por WSS: el servidor rechazó explícitamente el destino/protocolo
   no autorizado. Solo permite datagramas a `127.0.0.1:443`.
4. `flutter analyze` pasó después del cambio del CLI. El CLI TCP comprueba cada
   cuatro segundos el túnel y reinicia su hijo si terminó, manteniendo el bloqueo.
   Anteriormente solo esperaba Ctrl+C, pese a anunciar supervisión.
5. El servidor informa `wg-easy` saludable, puerto interno 51820 y ambas
   publicaciones UDP. Suricata detectó el nuevo namespace y reinició su captura.

## Entrega y verificaciones pendientes en el entorno del usuario

- Código principal: commit `751f9f8`, ya presente en la rama remota al revisarlo.
  No atribuir a esta sesión el commit o instalación realizados por la otra sesión.
- Instalar el paquete generado `app/dist/netshield-vpn-0.1.0-27-x86_64.pkg.tar.zst`
  para incorporar el supervisor del CLI. La primera autorización KDE fue
  rechazada; se solicitó confirmar una nueva solicitud. Comprobar después con
  `pacman -Q netshield-vpn` y hashes del binario instalado.
- La prueba de red real utiliza WireGuard en namespace; no sustituye probar
  NetworkManager y la interfaz gráfica en la conexión de trabajo. No se activó
  una VPN ni se cambió de Wi-Fi en el equipo del usuario durante estas pruebas.
- En «Politecnica Software», activar **Ajustes → Modo TCP** antes de conectar.
  Mantener los datos móviles como alternativa. Ninguna prueba fuera de esa red
  garantiza que permita el WebSocket HTTPS. Registrar el error/handshake si falla.
- Investigar ingreso UDP/443 en OCI cuando se disponga de acceso; no es necesario
  para utilizar los modos ya verificados UDP/51820 y WSS/443.
- El Android modificado por el usuario no se ha validado ni entregado como parte
  de esta corrección Linux. No anunciar paridad de WSS o cambios Android aquí.

## Cambios preexistentes que deben conservarse

Al empezar ya había cambios sin commit en Android (`build.gradle.kts`, manifest,
`MainActivity.kt`, servicios Kotlin nuevos, vector de notificación) y `app/pubspec.yaml`.
También existían `RESUMEN_CONTINUIDAD.md`, `app-backup-2026-11-22/` y `diagnosticos/`.
No se deben mezclar automáticamente con este commit, borrarlos ni deshacerlos.
El usuario ha avanzado por su cuenta y su código debe preservarse.

La clave administrativa de Firebase y cualquier configuración privada existente
no deben añadirse al repositorio. No publicar capturas de red ni logs con datos
personales. El historial antiguo de `RESUMEN_CONTINUIDAD.md` contiene estados que
ya no son actuales: contrastarlo con este resumen, el diff y los servicios reales.
