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

La migración `006_personal_security_alerts.sql` se probó primero en PostgreSQL aislado y posteriormente se aplicó en desarrollo. La tabla guarda propietario, dispositivo, fecha, firma y severidad, sin URLs o contenido de paquetes. Se probaron aislamiento de dos cuentas y deduplicación. Existe una consulta autenticada para el panel de prueba, pero no hay ingestión de detecciones reales activada: la señal `evidence_trusted` es una precondición interna, no puede obtenerse de un evento aportado por el cliente y todavía requiere implementación verificable de continuidad del sensor, relojes y ausencia de cambios externos a la coordinación.

El servicio Suricata existente reportó aproximadamente 2,36 GB de memoria (cgroup) en la instancia VPN. Una segunda instancia con las mismas reglas puede elevar significativamente el consumo; antes de desplegarla se necesita una prueba de capacidad y un supervisor que detecte reemplazos del contenedor WireGuard. El sensor actual sigue siendo posterior al NAT y sus alertas no se atribuyen a usuarios.

## Panel de prueba

En desarrollo se aplicó la migración 006 y se habilitaron `GET /security/alerts` y `POST /security/alerts/test` para cuentas autenticadas. La creación de eventos simulados requiere un dispositivo habilitado y está limitada a cinco por cuenta y hora. Cada evento se identifica expresamente como prueba. El resultado incluye `monitoring: not_active`: el sensor real antes del NAT y la ingesta atribuida siguen sin estar habilitados. El panel no debe presentar una lista vacía como garantía de seguridad. El endpoint de prueba depende de `NETSHIELD_DEV_ALERT_TEST=1` y debe desactivarse fuera de desarrollo.

## Sensor pre-NAT experimental en la instancia VPN

En desarrollo hay un segundo servicio `netshield-vpn-sensor` dentro del espacio de red de wg-easy que observa `wg0` antes del NAT. Usa como máximo 3.000 reglas seleccionadas del conjunto instalado y escribe solamente eventos de alerta, sin payload ni paquetes. Incluye una regla claramente simulada para `netshield-sensor-test.invalid`. El recolector usa mTLS y un secreto dedicado para un endpoint privado que no se expone a través del proxy público; comprueba sincronización horaria del sensor y envía solo datos mínimos.

Antes de atribuir un evento, la API toma el bloqueo de asignaciones, compara la instantánea del gestor y kernel con el historial y exige una asignación activa y única, un margen de 60 segundos desde su inicio y una antigüedad máxima de 15 segundos respecto al reloj de PostgreSQL. Los eventos dudosos o retrasados se descartan. La marca `experimental` indica un heartbeat reciente del recolector, no garantiza que toda amenaza se detecte ni que no haya pérdida de eventos. La selección de firmas es limitada, el contenido HTTPS no se descifra y las alertas son indicios sujetos a falsos positivos.

El supervisor reinicia el sensor si cambia el PID del contenedor. Las rutas administrativas directas que alteran WireGuard sin el puente coordinado siguen fuera de este control; no deben utilizarse mientras se atribuyen alertas. La rotación de EVE es best-effort y puede perder eventos. Una consulta sintética al dominio reservado atravesó el túnel y generó un evento real en Suricata; el recolector, PostgreSQL y la API lo entregaron a la cuenta propietaria y no a una segunda cuenta. El evento está etiquetado como simulado; no demuestra detección de malware real ni cobertura completa. La recuperación tras reemplazar el contenedor sigue pendiente; no confundir los eventos del botón de prueba con eventos del sensor.

El recolector normaliza la zona horaria `+0000` que genera Suricata para compatibilidad con versiones antiguas de Python. Antes de esa corrección descartaba silenciosamente esos eventos.


## Historial muestreado en desarrollo

La migración 008 guarda muestras de contadores por cuenta y dispositivo, sin sitios visitados ni contenido. `netshield-usage-sampler.timer` ejecuta el recolector cada cinco minutos; conserva muestras durante 30 días y la API autenticada `GET /vpn/usage/history` muestra hasta siete días UTC para el propietario. La primera muestra, los huecos mayores de 30 minutos y las bajadas de contador no se suman y se marcan como incompletos. Un reinicio seguido de tráfico suficiente para superar el contador anterior puede pasar inadvertido, por lo que las cifras son estimaciones, no facturación ni medición exacta. La lectura y limpieza requieren que el servicio y PostgreSQL estén disponibles. La recolección actualmente consulta cuentas secuencialmente y deberá revisarse antes de crecer.

El 21 de noviembre de 2026 se aplicó la migración y se activó el temporizador en desarrollo; el primer ciclo registró muestras para cuatro cuentas. PostgreSQL aislado verificó separación de cuentas, reinicios y autenticación. El estado de alerta experimental indica un heartbeat reciente, no una garantía de detección ni de entrega sin pérdida.

## Firmas del sensor VPN y actualización (21 de noviembre de 2026)

El sensor de desarrollo usa Emerging Threats Open para Suricata 6, descargado mediante HTTPS con `suricata-update`. La selección anterior tomaba las primeras 3.000 firmas con coincidencias en el texto, lo que favorecía las primeras categorías del archivo. `controller/build_suricata_sensor.py` ahora distribuye hasta 3.000 reglas entre indicios de malware, troyanos, exploits, comando y control y phishing, con selección estable por SID. Se excluyen reglas que requieren estado de flowbits/xbits de firmas no incluidas y reglas `noalert`. La selección parcial no ofrece la misma cobertura que el conjunto completo; un nombre de categoría es solo una aproximación y los indicadores pueden producir falsos positivos.

El servicio `netshield-vpn-rules-update` descarga el conjunto en un directorio temporal aislado, construye un candidato, comprueba sus límites y ejecuta `suricata -T --init-errors-fatal` antes de cambiar el archivo activo. Conserva la versión anterior y la restaura si el reinicio falla. El temporizador semanal `netshield-vpn-rules-update.timer` quedó activado. La sustitución requiere un breve reinicio del sensor durante el cual puede perderse alguna alerta; no modifica la VPN. Se debe vigilar el estado del servicio y el journal: `systemctl status netshield-vpn-rules-update.timer` y `journalctl -u netshield-vpn-rules-update.service`. Si falla la descarga o la validación se conservan las reglas anteriores; la interfaz aún no muestra la antigüedad de las firmas.

En desarrollo se validaron e instalaron 3.000 firmas y se confirmó el arranque del sensor y el heartbeat de su recolector. Una prueba sin conexión alimentó un paquete DNS sintético a Suricata y comprobó que una firma real de ET Open lo detectaba; no se consultó el dominio en Internet. El recorrido completo hasta una cuenta se probó anteriormente con la firma reservada de NetShield, pero no se repitió con un dispositivo real después de esta actualización. La señal experimental no garantiza cobertura total, ausencia de falsos positivos ni entrega sin pérdidas, y HTTPS cifrado no se descifra.

## Revisión de alertas y corrección del recolector

El 21 de noviembre se corrigió el recolector del sensor VPN para admitir las firmas de phishing y CNC seleccionadas, además de malware, troyanos y exploits. El recolector del sensor general conserva su filtro anterior. Las pruebas cubren que las categorías nuevas lleguen al procesamiento minimizado y que las alertas sin categorías relevantes se omitan.

La migración 009 añade un estado por alerta (`new`, `reviewed`, `false_positive`) y un registro de cambios con fecha y propietario. Una cuenta puede cambiar únicamente la revisión de sus propias alertas. La marca de posible falso positivo es una valoración del usuario, no una verificación automática ni una sentencia definitiva. El historial de cambios se almacena en PostgreSQL y todavía no se muestra en la interfaz. El aislamiento de dos cuentas se comprobó en PostgreSQL aislado y mediante dos cuentas temporales eliminadas tras la prueba en desarrollo.

La aplicación indica si el sensor se comunicó recientemente y permite marcar alertas como revisadas o posibles falsos positivos. El heartbeat no verifica cobertura ni entrega completa. Persisten limitaciones de confiabilidad importantes: los eventos con más de 15 segundos se descartan para preservar atribución segura, y la rotación actual puede perder eventos por una escritura concurrente. El sensor es apto para pruebas de uso en desarrollo, pero esto no acredita una entrega íntegra ni disponibilidad de producción. Hace falta reemplazar la rotación y probar recuperación, retrasos y continuidad antes de afirmar esas garantías.

## Entrega tras interrupciones y rotación sin truncado

El recolector confirma cada lote a la API antes de guardar y sincronizar su cursor en disco. Si la entrega falla, conserva el archivo y vuelve a intentar; la API deduplica los reintentos. La rotación renombra el EVE a un archivo `eve.pending.*` y solicita a Suricata la reapertura con SIGHUP. El archivo antiguo no se elimina hasta que el cursor confirma todo su contenido y existe un EVE nuevo con otro inodo, conforme al cierre y reapertura del registrador de Suricata. La reapertura puede ocurrir con la siguiente alerta; mientras tanto el archivo pendiente se conserva. El directorio es privado y solo el sensor y el recolector deben modificarlo. La documentación de Suricata describe [la reapertura de registros](https://docs.suricata.io/en/suricata-6.0.20/output/log-rotation.html).

La API ya no impone el límite de 15 segundos: un evento atrasado se asigna si el intervalo histórico y la instantánea actual siguen identificando de forma única el mismo propietario y dispositivo y se cumple el margen de seguridad existente. Si no se puede atribuir con seguridad, la migración 010 conserva la fecha, firma, severidad e IP de origen y destino en `unattributed_sensor_alerts`; no se muestra a ninguna cuenta por deducción. Si el mismo evento se reenvía posteriormente y la atribución pasa, se mueve a la cuenta y se elimina de esa tabla. La tabla no tiene todavía interfaz de revisión ni borrado automático; su acceso y retención deben administrarse como datos sensibles. Las alertas ambiguas no pasan por sí solas al panel.

Las pruebas incluyen fallo de entrega y reintento, retención de archivos, un evento de una hora de antigüedad, deduplicación y asignación ambigua en PostgreSQL aislado. Una prueba con 50 paquetes sintéticos en un espacio de red independiente verificó el cambio de archivo y SIGHUP con Suricata 6. Los cambios se desplegaron en desarrollo. En una rotación controlada del sensor real se conservó el archivo antiguo; Suricata mantiene abierto ese archivo hasta que procese una siguiente alerta, por lo que su reapertura y eliminación finales aún no se han observado en tráfico real. Ningún mecanismo puede conservar eventos si se agota el disco o el sensor no los registra; vigilar capacidad y fallos del servicio sigue siendo necesario.

## Recuperación automática y reapertura en reposo

La migración 011 añade una marca de último intento para reexaminar hasta 25 eventos retenidos por heartbeat, con orden justo. Si más tarde la propiedad se vuelve verificable, se entrega a la cuenta y se retira de la cola; si ya se había entregado, se elimina el duplicado retenido. Los casos que siguen siendo ambiguos permanecen restringidos. `python -m app.sensor_queue_status` consulta el número de eventos; `--details` muestra IP y firmas y está reservado a administración.

El sensor escribe estadísticas agregadas EVE cada 30 segundos, sin payload ni registros de navegación, además de las alertas. Esto fuerza la reapertura tras SIGHUP incluso cuando no ocurre ninguna alerta. La selección de reglas conserva esta configuración. Una prueba en red aislada comprobó la reapertura en reposo; tras desplegarla se provocó otra rotación controlada en el sensor real y se comprobó que el archivo nuevo apareció y que el recolector retiró el archivo pendiente ya confirmado. También se comprobó en vivo que el heartbeat vuelve a revisar un evento sintético retenido. El contrato de datos para nuevos clientes está en `contrato-alertas-clientes.md`.
