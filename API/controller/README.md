# Controlador WireGuard de desarrollo

`dev_agent.py` controla exclusivamente `wg-nsdev` dentro de una red privada de systemd. El servicio usa la cuenta sin shell `netshield-wg`, sin sudo, y recibe solo `CAP_NET_ADMIN` en ese espacio de red. El socket local y la clave del servidor tienen permisos 0600. No controla `wg0`, no recibe órdenes de shell y no tiene conectividad externa ni transporte de tráfico VPN.

El socket acepta una línea JSON terminada en salto de línea, máximo 2048 bytes: `status`, `add` (clave pública y dirección /32 dentro de 10.254.70.0/24) y `remove`. Las rutas deben ser únicas; las solicitudes con campos adicionales se rechazan. El servidor es secuencial y nunca imprime la clave privada. `client.py` reenvía una solicitud al socket; en el entorno instalado, una clave SSH restringida a la IP privada del backend y con comando forzado lo invoca como `netshield-wg`. No admite terminal, reenvío de puertos ni comandos arbitrarios.

`./scripts/test-dev-agent.sh` prueba el agente en un espacio de red efímero. El archivo de servicio es una referencia para el entorno de desarrollo existente; no concede acceso desde FastAPI automáticamente.

## Limitaciones

El agente todavía no se integra con las rutas de FastAPI ni con la base de datos. Los peers no se restauran automáticamente después de reiniciar el servicio. Su red no está conectada a Internet o a los clientes móviles. Las restricciones y pruebas aquí realizadas no constituyen una auditoría de seguridad; antes de producción faltan reconciliación, privilegios y acceso de servicio revisados, conectividad de túnel y pruebas de extremo a extremo.
