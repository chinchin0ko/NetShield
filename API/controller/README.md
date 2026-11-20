# Controlador WireGuard de desarrollo

`dev_agent.py` controla exclusivamente `wg-nsdev` dentro de una red privada de systemd. El servicio usa la cuenta sin shell `netshield-wg`, sin sudo, y recibe solo `CAP_NET_ADMIN` en ese espacio de red. El socket local y la clave del servidor tienen permisos 0600. No controla `wg0`, no recibe órdenes de shell y no tiene conectividad externa ni transporte de tráfico VPN.

El socket acepta una línea JSON terminada en salto de línea, máximo 2048 bytes: `status`, `add` (clave pública y dirección /32 dentro de 10.254.70.0/24) y `remove`. Las rutas deben ser únicas; las solicitudes con campos adicionales se rechazan. El servidor es secuencial y nunca imprime la clave privada. `client.py` reenvía una solicitud al socket; en el entorno instalado, una clave SSH restringida a la IP privada del backend y con comando forzado lo invoca como `netshield-wg`. No admite terminal, reenvío de puertos ni comandos arbitrarios.

`./scripts/test-dev-agent.sh` prueba el agente en un espacio de red efímero. El archivo de servicio es una referencia para el entorno de desarrollo existente; no concede acceso desde FastAPI automáticamente.

## Limitaciones

El agente todavía no se integra con las rutas de FastAPI ni con la base de datos. Los peers no se restauran automáticamente después de reiniciar el servicio. Su red no está conectada a Internet o a los clientes móviles. Las restricciones y pruebas aquí realizadas no constituyen una auditoría de seguridad; antes de producción faltan reconciliación, privilegios y acceso de servicio revisados, conectividad de túnel y pruebas de extremo a extremo.

## Puente de desarrollo con wg-easy

`wg_easy_bridge.py` ofrece una integración temporal con wg-easy 13, que sigue siendo el único administrador de `wg0`. La API invoca el puente mediante SSH con clave dedicada y comando forzado; el puente acepta exclusivamente el identificador de usuario que la API obtuvo del token y un identificador de dispositivo de 32 caracteres hexadecimales. Bajo un bloqueo, busca o crea el peer correspondiente y devuelve su configuración. El puente corre con privilegios para leer la contraseña local del contenedor; la clave SSH está restringida por origen y comando. El archivo de host conocido está fijado en la instancia API. No se almacenan claves SSH o contraseñas en el repositorio.

El endpoint autenticado `POST /vpn/config` entrega el archivo con `Cache-Control: no-store`. El cliente accede mediante HTTPS y el proxy llega al backend privado mediante mTLS. La imagen personalizada fijada por digest incorpora operaciones de alta y rotación por clave pública: los nuevos clientes generan y conservan localmente sus claves privadas. Los peers antiguos se migran al reconectar; las copias previas y otros peers antiguos pueden contener claves antiguas. El puente deshabilita los peers revocados en wg-easy y conserva ese estado tras reinicio. Aún faltan identidad criptográfica por dispositivo, rotación y revocación de credenciales y una estrategia de producción.

El límite de desarrollo admite cinco dispositivos activos y veinte registros totales por cuenta, incluidos los revocados. El límite se comprueba bajo el mismo bloqueo que la creación; reconectar un dispositivo existente no consume otro lugar. Al agotar los veinte registros se necesita intervención administrativa; la eliminación segura de registros revocados y la recuperación aún no están implementadas.

## Ingestión de alertas Suricata

`suricata_collector.py` procesa eventos nuevos de `/var/log/suricata/eve.json`; selecciona firmas que contienen MALWARE, TROJAN o EXPLOIT, descarta contenido HTTP y otros datos adicionales y envía timestamp, direcciones, firma y severidad por mTLS al endpoint interno de la API. PostgreSQL deduplica reintentos. El estado se guarda en `/var/lib/netshield-suricata/cursor.json`; al instalar por primera vez comienza al final del archivo. El servicio del servidor VPN se ejecuta como root porque necesita leer el registro protegido y el certificado privado; se instala sin capacidades Linux adicionales.

Estas alertas corresponden al servidor en general, no se atribuyen a un usuario: el tráfico WireGuard se traduce con NAT antes de pasar por la interfaz observada. No habilitar una vista por cuenta hasta resolver atribución y autorización. La selección por firma no cubre todas las amenazas ni significa que se haya inspeccionado el contenido cifrado HTTPS. La rotación durante caídas prolongadas puede dejar eventos sin procesar; falta recuperación de archivos rotados, retención y límites de almacenamiento. El directorio `/var/log/suricata` está restringido a root en la instancia actual.

`scripts/test-suricata-offline.sh` genera un paquete DNS y una regla sintéticos y ejecuta Suricata sobre un PCAP local temporal. El test verifica el motor y el procesamiento de una regla conocida, no la efectividad completa del conjunto de reglas ni la detección de malware real.
