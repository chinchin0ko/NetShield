# Pruebas del laboratorio de conexión

## Qué se verifica

1. `python -m pytest -q` ejecuta pruebas de la lógica y adaptadores con dobles. Las pruebas que requieren PostgreSQL o WireGuard aislado se omiten salvo que se ejecuten con sus scripts.
2. `./scripts/test-integration.sh` levanta PostgreSQL temporal con TLS, aplica las migraciones en un esquema aislado y comprueba autenticación, registro, reintentos simultáneos, aislamiento entre usuarios y eliminación de registros. Requiere Docker accesible para el usuario y las dependencias de desarrollo.
3. `./scripts/test-wireguard-lab.sh` crea un espacio de red aislado y verifica el adaptador experimental frente a una interfaz WireGuard del kernel. Requiere Linux, `wg`, `ip`, `unshare` y espacios de usuario y red habilitados.
4. `./scripts/test-wireguard-traffic.sh` establece un túnel entre dos espacios de red efímeros, comprueba handshake y tráfico y confirma que al quitar el peer el tráfico deja de pasar. Requiere también `nsenter` y `ping`.

Los scripts de WireGuard no acceden a la interfaz ni a las claves de producción. El script PostgreSQL crea un contenedor y certificado de prueba temporales; use únicamente datos de laboratorio.

## Criterios pendientes para una prueba de punta a punta

- Se probó la operación de la API de laboratorio con PostgreSQL temporal y un peer WireGuard real aislado en un único flujo; falta trasladar el diseño a un controlador compatible con la infraestructura real y ejecutar pruebas independientes de seguridad.
- Resolver persistencia del estado, asignación única de direcciones, idempotencia concurrente y recuperación si falla alguna operación entre PostgreSQL y WireGuard.
- Validar que la clave pública la controla el dispositivo sin inventar una firma X25519.
- Comprobar que una revocación en la API retire efectivamente el peer antes de marcarla completa, incluso después de reiniciar.
- Probar colisiones, falta de capacidad, rutas IPv4/IPv6, DNS, errores de red, y límites de acceso. El túnel en espacios de red no prueba Kill Switch ni fugas en móviles.
- Evaluar la compatibilidad con `wg-easy:13` aislado o una transición del gestor. Los adaptadores de laboratorio actuales no son compatibles con su persistencia y no deben aplicarse a la interfaz existente.

Las pruebas pasan para las funciones indicadas, no equivalen a una revisión de seguridad completa ni a una VPN de un clic lista para desplegar.

## Coordinador experimental

`lab/connection.py` persiste estados y reserva direcciones en SQLite para probar reintentos, fallos y reinicios. `lab/http.py` añade rutas solo a una aplicación de prueba; no se importa en `app/main.py`. Se ha probado el flujo autenticado hasta un peer real aislado y la revocación desde otra cuenta. La sincronización solo cubre un proceso y una instancia del coordinador: no es una garantía para múltiples procesos o servidores. No usa PostgreSQL para el estado del peer, no controla la infraestructura real y no sustituye una solución transaccional y reconciliable para producción.


## Integración PostgreSQL y WireGuard

`lab/postgres_connection.py` es un coordinador experimental con estados persistentes, bloqueos transaccionales para asignación de direcciones y bloqueos de sesión por dispositivo. Una prueba con PostgreSQL comprueba concurrencia entre dispositivos, recuperación de fallos y autorización; `test-postgres-wireguard.sh` requiere `NETSHIELD_TEST_DSN` apuntando a una base temporal `netshield_lab` accesible en 127.0.0.1, TLS, `socat`, `unshare`, `wg` e `ip`. El script conecta esa base al espacio de red de laboratorio a través de un socket temporal y ejecuta la prueba API → PostgreSQL → WireGuard real.

El coordinador es una prueba, no administra ni reconcilia `wg-easy`, y no debe usarse en producción. Aún faltan pruebas de interrupción real de procesos, aislamiento con privilegios mínimos, reconciliación después de reinicios del servidor WireGuard, y conexión con el cliente móvil. El handshake y el tráfico se comprueban por separado en `test-wireguard-traffic.sh`.

Se probó también la reconciliación simulando la pérdida del peer de la interfaz y restaurándolo desde el estado almacenado, además de completar revocaciones pendientes. Esto no prueba compatibilidad con wg-easy ni reinicios reales del servidor.


## Recuperación ante terminación del proceso

La prueba conjunta termina procesos auxiliares justo después de crear o retirar un peer, antes de registrar el resultado en PostgreSQL. Un coordinador nuevo reconcilia los estados `provisioning` y `revoking` y se verifican nuevamente los peers y el estado persistido. También se comprueba la restauración después de borrar el peer de la interfaz de laboratorio. Esto no simula un reinicio completo del VPS ni resuelve la coexistencia con wg-easy.

La prueba de colisión comprueba que una segunda clave no pueda desplazar la ruta asignada a otro peer. Esta comprobación no es atómica: el controlador todavía necesita garantizar que sea el único proceso que escribe en la interfaz.
