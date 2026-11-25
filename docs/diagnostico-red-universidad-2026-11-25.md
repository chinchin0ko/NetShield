# Diagnóstico de conexión en Politecnica Software

Fecha: 2026-11-25. Análisis pasivo de archivos existentes y lectura del código en
el commit `878b3b1`. No se cambió la red, no se activó la VPN ni se modificaron
el servidor o las reglas de firewall. El usuario confirmó que la conexión actual
es mediante datos del teléfono; no se usa como evidencia de la red universitaria.

## Captura principal

Archivo local: `/home/chinchin/Documents/capturaredup5.pcapng`.
SHA-256: `3c2df4b5ba0e28da3eee4cc91e21e06d4ef1803ca46c906d6f48a74f5d915bfb`.
Interfaz: `wlan0`. 2312 paquetes, 20.931 segundos, del 25 de noviembre de 2026
12:55:33 al 12:55:54, según la hora local mostrada por capinfos.
No se incorpora la captura al repositorio ni se reproducen contenidos de navegación.

| Observación | Evidencia |
| --- | --- |
| WireGuard no completa el intercambio inicial | Cinco paquetes Handshake Initiation hacia `140.84.183.78:443/UDP`, cero respuestas WireGuard y cero Transport Data |
| Hay reintentos | Tramas 724, 729, 1347, 2271 y 2306; tiempos relativos 5.254, 5.386, 10.386, 15.413 y 20.575 s |
| El servidor responde mediante TCP | 46 paquetes TCP/443 entre cliente y servidor, con negociación TLS y datos cifrados; no se verifican respuestas HTTP dentro de TLS |
| UDP/443 falla también para otros destinos en esta ventana | 52 paquetes QUIC salientes y ninguna respuesta UDP/443, contando también WireGuard |
| No es ausencia total de respuestas UDP | 25 consultas y 25 respuestas DNS; tres solicitudes y tres respuestas STUN |
| Existía una conexión TCP/80 al servidor | Siete paquetes, cuatro con carga de dos bytes; no se observa tráfico WireGuard transportado por esta conexión durante el intento |

El intento observado usa WireGuard directo por UDP/443. Una conexión TCP abierta
no demuestra que el perfil WireGuard esté usando el adaptador wstunnel. La captura
no incluye loopback y no permite descartar otros intentos anteriores o posteriores.

## Interpretación y límites

El patrón es compatible con filtrado o pérdida de UDP/443 en el trayecto. Cambiar
de 51820/UDP a 443/UDP no hizo funcionar este intento. No se puede atribuir con
certeza el descarte a un equipo de la universidad, demostrar inspección profunda
de paquetes ni excluir un problema del listener, firewall o configuración del
servidor usando solo esta captura del cliente. Haría falta correlacionar ambos
extremos durante una prueba en la misma red.

La avería observada precede al tráfico IP interno del túnel; no hay evidencia aquí
para atribuirla primero al DNS interno, a Suricata o al tamaño de paquetes de datos.

Como comparación limitada, `capturacondatos.pcapng` contiene dos respuestas de
handshake y miles de paquetes de transporte con el servidor por UDP/51820. Es de
otra hora y otro puerto, por lo que no valida el listener UDP/443 durante la captura
principal. `capturaredup4.pcapng` contiene seis inicios por UDP/443 sin respuesta.
`capturaredup.pcapng` sí contiene dos respuestas de handshake por UDP/51820 y
transporte saliente: tampoco corresponde afirmar que todas las pruebas fallaron
exactamente igual. No se asume el SSID de esos archivos a partir de sus nombres.

Después del inicio de WireGuard hay 745 paquetes TCP salientes hacia otros
destinos. Todos coinciden con IP y puerto permitidos por la excepción de Tailscale
del código actual (`TS_INFRA_IPS`, TCP/443). No son prueba suficiente de una fuga
general del kill switch; es necesario conocer las reglas y opciones activas en
ese momento. El cambio posterior a otra red no altera estas observaciones.

## Problemas encontrados al revisar el cliente

1. `LinuxVpn.isConnected()` comprueba que NetworkManager tenga el perfil activo.
   Esto no comprueba un handshake ni conectividad útil. Si el ping inicial falla,
   `connect()` deja el perfil activo y propaga el error; el monitor puede mostrar
   «Conectado» junto al error. Hay que separar interfaz activa, comprobación en
   curso, túnel operativo y conexión fallida, conservando el bloqueo cuando proceda.
2. `VpnMapCard` recibe solo ese booleano. La consulta de IP no se vincula a una
   generación de conexión ni se invalida inmediatamente al cambiar de estado.
   Una consulta anterior puede terminar después y etiquetarse como «IP con la VPN».
   La ubicación del servidor es fija, no una validación de la salida real.
3. El modo TCP reescribe el endpoint a `127.0.0.1:51821`, pero la preservación de
   ruta al servidor en `_keepDevelopmentTunnel()` solo se ejecuta si la API usa
   localhost. Con la API pública, el transporte TCP necesita conservar su ruta
   externa antes de instalar las rutas completas de WireGuard; de lo contrario
   puede acabar intentando pasar por el túnel que él mismo debe transportar.
4. El proceso wstunnel se lanza esperando dos segundos, sin comprobar disponibilidad
   ni consumir sus salidas. Tampoco se supervisa su terminación. Se debe resolver
   el servidor antes del bloqueo, comprobar la escucha y gestionar errores y
   reconexión; no basta con que exista el proceso o que TCP acepte una conexión.

Estos son hallazgos de revisión, no correcciones instaladas ni una prueba de que
el modo TCP funcione de extremo a extremo en la universidad.

## Siguiente validación

- Corregir la indicación de estado y la invalidación de la IP del mapa.
- Completar la integración del transporte TCP: ruta externa, resolución previa,
  supervisión del proceso y coherencia con el kill switch.
- Probar primero fuera de la universidad handshake, DNS, navegación, reconexión y
  bloqueo ante caída del transporte, sin usar la sesión de trabajo como prueba.
- En una prueba coordinada desde la red universitaria, capturar únicamente el
  tráfico del cliente de prueba hacia el servidor en ambos extremos. Verificar
  llegada, respuesta, handshake y salida a Internet; mantener una conexión de
  trabajo separada por datos móviles.

Referencias primarias:
- WireGuard, protocolo y reintentos: https://www.wireguard.com/protocol/
- wstunnel, integración con WireGuard y ruta estática: https://github.com/erebe/wstunnel
