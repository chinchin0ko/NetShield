# Consumo y atribución de alertas

## Consumo disponible

`GET /vpn/usage` requiere JWT. La API toma el identificador de usuario del token y pide al puente los contadores `wg show wg0 transfer` de los peers habilitados que pertenecen a esa cuenta. La respuesta solo incluye el identificador de dispositivo y bytes enviados y recibidos desde el punto de vista del cliente; no contiene claves, direcciones ni datos de otras cuentas. Los valores `null` significan que no hay contador disponible, no que el consumo sea cero. Los contadores se reinician al reiniciar WireGuard o eliminar/recrear un peer; no son históricos, ni medición de facturación.

## Alertas: límite actual y condiciones para activarlas por usuario

La instancia Suricata actual observa `enp0s6` del host, después de que el contenedor de WireGuard aplique NAT. El recolector existente guarda eventos generales del servidor; sus IP no permiten identificar de manera fiable al dispositivo VPN de origen. No se deben filtrar esas alertas por la cuenta ni mostrarlas como visitas individuales.

Para una implementación por cuenta se necesita, como mínimo:

1. Una fuente autenticada que observe los paquetes descifrados en la interfaz `wg0` del espacio de red VPN, antes del NAT, con reglas y capacidad probadas. No convertir eventos del sensor actual en eventos pre-NAT mediante una etiqueta enviada por el propio evento.
2. Un historial duradero de asignación IP-dispositivo-usuario con intervalos temporales sin solapamientos, actualizado y reconciliado con la creación, revocación y eliminación de peers. Los cambios deben ser atómicos o dejar estados ambiguos sin publicar.
3. Atribución por la hora real del evento y ese historial; descartar eventos sin dueño único o con horas inválidas, observaciones posteriores al NAT y eventos entre dos clientes hasta definir autorización para ambos extremos. La regla de referencia probada está en `app/application/attribution.py`; todavía no está conectada a producción.
4. Almacenamiento de eventos atribuibles, consulta autenticada filtrada por identidad en la base de datos y pruebas de aislamiento entre cuentas. Definir retención, volumen y acceso administrativo. No incluir URLs, consultas DNS completas ni otro contenido sensible sin una política explícita.
5. Pruebas con tráfico sintético por un túnel real aislado: detección, reenvío autenticado, IP reutilizada, reintento y deduplicación, desconexión y reinicio, y ausencia de datos de otra cuenta. Probar también rotación del EVE y retrasos de la cola.

Una firma IDS es un indicador, no prueba concluyente de infección. HTTPS cifrado y DNS cifrado limitan lo que el servidor puede observar. La detección de dominios peligrosos requiere verificar además qué consultas recibe Pi-hole y sus listas; una conexión a un sitio y un dispositivo infectado no son equivalentes.

## Avance de laboratorio: historial y captura aislada

La migración `005_vpn_address_assignments.sql` define intervalos de propiedad y usa una restricción GiST de exclusión para impedir asignaciones de una misma IP con intervalos solapados, incluso con transacciones concurrentes. `PostgresAssignments.find_at` consulta los intervalos aplicables a un instante. Se probó con PostgreSQL aislado, incluidas escrituras concurrentes y reutilización de IP. La activación en desarrollo se detalla al final de este documento; una consulta del estado actual no reconstruye el pasado.

`scripts/test-suricata-prenat-lab.sh` crea dos espacios de red y una interfaz virtual temporales, ejecuta una instancia independiente de Suricata con una regla sintética y verifica que el evento incluya la IP privada de origen. No observa la interfaz de producción ni reproduce todavía un túnel WireGuard real. No prueba cobertura de amenazas. Antes de instalar un sensor real en el espacio de red de wg-easy se deben verificar arranque y ciclo de vida del contenedor, permisos mínimos, consumo de memoria, pérdida de paquetes y recuperación segura.

## Coordinación segura y prueba con WireGuard

`scripts/test-wireguard-suricata-lab.sh` crea dos peers WireGuard en espacios de red temporales, establece un túnel y ejecuta Suricata en la interfaz del servidor de ese túnel. Una firma sintética comprueba que el motor recibe el paquete descifrado con la IP privada del peer. Es una prueba aislada, no una instalación del sensor ni una prueba de detección de amenazas reales.

`app/application/assignment_lifecycle.py` contiene un coordinador experimental y pruebas de fallos: cierra la atribución antes de cada cambio, y solo la reabre después de recibir una instantánea completa y validada del controlador. Una caída o instantánea ambigua deja un hueco sin atribuir. La integración posterior con el controlador y PostgreSQL se detalla más abajo; sigue siendo necesario detectar cambios por rutas que evadan el coordinador. No se deben inferir propietarios dentro de los huecos.

## Integración preparada detrás de una opción

El puente admite solicitudes coordinadas que, mientras mantiene su bloqueo, contrastan el inventario de wg-easy con `wg show wg0 allowed-ips` y devuelven a la API una instantánea interna sin claves. La API puede coordinar provisión y revocación con `NETSHIELD_TRACK_ASSIGNMENTS=1`: obtiene un bloqueo PostgreSQL de sesión, cierra y confirma los intervalos activos antes de la mutación, y abre nuevos intervalos solo después de validar la instantánea. Fallos o discrepancias dejan un hueco sin atribución. El bloqueo se probó con dos operaciones simultáneas y fallos en PostgreSQL aislado.

La opción se activó en desarrollo como se describe a continuación. Antes de atribuir alertas se necesita detectar operaciones alternativas que cambien los peers sin cerrar el historial y resolver el desfase entre el reloj del sensor y PostgreSQL. Las instantáneas tampoco permiten recuperar el historial anterior a su activación. Por ello todavía no se deben publicar alertas por cuenta usando esta tabla.

## Activación en desarrollo

La migración se aplicó a la base de desarrollo. Ambos servicios API ejecutan `NETSHIELD_TRACK_ASSIGNMENTS=1`; el puente instalado requiere solicitudes coordinadas para alta y revocación de peers. Se sincronizaron los peers existentes mediante una instantánea a través de la clave SSH restringida, sin modificar esos peers. Una prueba de desarrollo creó y revocó un peer para una cuenta inactiva de prueba y verificó que su intervalo quedara cerrado. La cuenta y el peer revocado se conservan para inspección; no tienen credenciales utilizables.

La obligación de coordinación se aplica al puente de la API, no impide a administradores con acceso root alterar directamente wg-easy, sus archivos o WireGuard. Los cambios manuales no deben hacerse mientras se pretenda usar atribución; antes de implementarla se necesita detectar y gestionar cambios fuera del puente, asegurar sincronización y tolerancia de reloj, instalar el sensor real y probar la ingestión y autorización por usuario. No se han habilitado alertas personales.

## Relojes y almacenamiento personal (desarrollo)

El 20 de noviembre de 2026 se detectó que las instancias privadas ejecutaban chrony sin sincronizar y adelantaban sus relojes aproximadamente 6–7 segundos. Se configuró chrony en ambas para usar el servicio horario local de OCI `169.254.169.254`; se conservaron desactivadas las fuentes NTS externas originales porque la política predeterminada impedía elegir OCI mientras aquellas no fueran accesibles. OCI local no proporciona autenticación NTS; su fiabilidad depende de la red y el servicio de OCI. Tras comprobar `Leap status: Normal`, se renovó la instantánea de asignaciones. **Los intervalos anteriores a esa renovación no son evidencia fiable para atribuir alertas**; tampoco se debe aceptar un evento sin comprobar el estado y el error temporal de todos los relojes implicados.

La migración `006_personal_security_alerts.sql` y los módulos `personal_alerts.py` se probaron solo en PostgreSQL aislado. La tabla guarda propietario, dispositivo, fecha, firma y severidad, sin URLs o contenido de paquetes. Se probaron aislamiento de dos cuentas y deduplicación. No existe todavía un endpoint público ni ingestión activada: la señal `evidence_trusted` es una precondición interna, no puede obtenerse de un evento aportado por el cliente y todavía requiere implementación verificable de continuidad del sensor, relojes y ausencia de cambios externos a la coordinación.

El servicio Suricata existente reportó aproximadamente 2,36 GB de memoria (cgroup) en la instancia VPN. Una segunda instancia con las mismas reglas puede elevar significativamente el consumo; antes de desplegarla se necesita una prueba de capacidad y un supervisor que detecte reemplazos del contenedor WireGuard. El sensor actual sigue siendo posterior al NAT y sus alertas no se atribuyen a usuarios.
