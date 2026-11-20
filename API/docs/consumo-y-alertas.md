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

La migración `005_vpn_address_assignments.sql` define intervalos de propiedad y usa una restricción GiST de exclusión para impedir asignaciones de una misma IP con intervalos solapados, incluso con transacciones concurrentes. `PostgresAssignments.find_at` consulta los intervalos aplicables a un instante. Se probó con PostgreSQL aislado, incluidas escrituras concurrentes y reutilización de IP. **No se ha aplicado la migración a la instancia real ni conectado a provisión o revocación**: se requiere diseñar reconciliación y estados seguros ante fallos entre WireGuard y PostgreSQL; una consulta de estado actual no reconstruye el pasado.

`scripts/test-suricata-prenat-lab.sh` crea dos espacios de red y una interfaz virtual temporales, ejecuta una instancia independiente de Suricata con una regla sintética y verifica que el evento incluya la IP privada de origen. No observa la interfaz de producción ni reproduce todavía un túnel WireGuard real. No prueba cobertura de amenazas. Antes de instalar un sensor real en el espacio de red de wg-easy se deben verificar arranque y ciclo de vida del contenedor, permisos mínimos, consumo de memoria, pérdida de paquetes y recuperación segura.

## Coordinación segura y prueba con WireGuard

`scripts/test-wireguard-suricata-lab.sh` crea dos peers WireGuard en espacios de red temporales, establece un túnel y ejecuta Suricata en la interfaz del servidor de ese túnel. Una firma sintética comprueba que el motor recibe el paquete descifrado con la IP privada del peer. Es una prueba aislada, no una instalación del sensor ni una prueba de detección de amenazas reales.

`app/application/assignment_lifecycle.py` contiene un coordinador experimental y pruebas de fallos: cierra la atribución antes de cada cambio, y solo la reabre después de recibir una instantánea completa y validada del controlador. Una caída o instantánea ambigua deja un hueco sin atribuir. **Aún no está conectado al controlador o a PostgreSQL.** Para habilitarlo hace falta implementar el bloqueo de sesión persistente y las transacciones, obtener una instantánea completa bajo el mismo bloqueo que la mutación del controlador, probar fallos reales y asegurar que no existan cambios por rutas que evadan el coordinador. No se deben inferir propietarios dentro de los huecos.

## Integración preparada detrás de una opción

El puente admite solicitudes coordinadas que, mientras mantiene su bloqueo, contrastan el inventario de wg-easy con `wg show wg0 allowed-ips` y devuelven a la API una instantánea interna sin claves. La API puede coordinar provisión y revocación con `NETSHIELD_TRACK_ASSIGNMENTS=1`: obtiene un bloqueo PostgreSQL de sesión, cierra y confirma los intervalos activos antes de la mutación, y abre nuevos intervalos solo después de validar la instantánea. Fallos o discrepancias dejan un hueco sin atribución. El bloqueo se probó con dos operaciones simultáneas y fallos en PostgreSQL aislado.

**La opción no está habilitada en las instancias reales**. Antes se necesita aplicar la migración, probar todo el recorrido con el puente SSH y PostgreSQL de laboratorio, garantizar que ninguna operación alternativa cambie los peers sin cerrar el historial y resolver el desfase entre reloj del sensor y PostgreSQL. Las instantáneas tampoco permiten recuperar el historial anterior a su activación. Por ello todavía no se deben publicar alertas por cuenta usando esta tabla.
