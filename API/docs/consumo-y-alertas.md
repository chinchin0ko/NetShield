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
