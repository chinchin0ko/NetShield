# Controlador WireGuard de desarrollo

`dev_agent.py` controla exclusivamente `wg-nsdev` dentro de una red privada de systemd. El servicio usa la cuenta sin shell `netshield-wg`, sin sudo, y recibe solo `CAP_NET_ADMIN` en ese espacio de red. El socket local y la clave del servidor tienen permisos 0600. No controla `wg0`, no recibe órdenes de shell y no tiene conectividad externa ni transporte de tráfico VPN.

El socket acepta una línea JSON terminada en salto de línea, máximo 2048 bytes: `status`, `add` (clave pública y dirección /32 dentro de 10.254.70.0/24) y `remove`. Las rutas deben ser únicas; las solicitudes con campos adicionales se rechazan. El servidor es secuencial y nunca imprime la clave privada. `client.py` reenvía una solicitud al socket; en el entorno instalado, una clave SSH restringida a la IP privada del backend y con comando forzado lo invoca como `netshield-wg`. No admite terminal, reenvío de puertos ni comandos arbitrarios.

`./scripts/test-dev-agent.sh` prueba el agente en un espacio de red efímero. El archivo de servicio es una referencia para el entorno de desarrollo existente; no concede acceso desde FastAPI automáticamente.

## Limitaciones

El agente todavía no se integra con las rutas de FastAPI ni con la base de datos. Los peers no se restauran automáticamente después de reiniciar el servicio. Su red no está conectada a Internet o a los clientes móviles. Las restricciones y pruebas aquí realizadas no constituyen una auditoría de seguridad; antes de producción faltan reconciliación, privilegios y acceso de servicio revisados, conectividad de túnel y pruebas de extremo a extremo.

## Puente de desarrollo con wg-easy

`wg_easy_bridge.py` ofrece una integración temporal con wg-easy 13, que sigue siendo el único administrador de `wg0`. La API invoca el puente mediante SSH con clave dedicada y comando forzado; el puente acepta exclusivamente el identificador de usuario que la API obtuvo del token y un identificador de dispositivo de 32 caracteres hexadecimales. Bajo un bloqueo, busca o crea el peer correspondiente y devuelve su configuración. El puente corre con privilegios para leer la contraseña local del contenedor; la clave SSH está restringida por origen y comando. El archivo de host conocido está fijado en la instancia API. No se almacenan claves SSH o contraseñas en el repositorio.

El endpoint autenticado `POST /vpn/config` entrega el archivo con `Cache-Control: no-store`. En desarrollo, el backend sigue limitado a localhost y se accede mediante el túnel SSH existente. La imagen personalizada fijada por digest incorpora operaciones de alta y rotación por clave pública: los nuevos clientes generan y conservan localmente sus claves privadas. Los peers antiguos se migran al reconectar; las copias previas y otros peers antiguos pueden contener claves antiguas. El puente deshabilita los peers revocados en wg-easy y conserva ese estado tras reinicio. Aún faltan límites de creación, identidad criptográfica por dispositivo, rotación y revocación de credenciales y una estrategia de producción antes de exponer la API a Internet.
