# Probar NetShield con UDP restringido

Ejecutar desde cualquier terminal, con la VPN de la app desconectada para que
la conexión del laboratorio no quede anidada dentro de otra VPN:

```bash
/home/chinchin/Projects/NetShield/API/scripts/test-university-network.sh
```

No requiere sudo. Necesita las herramientas de NetShield, `dig`, `curl` y soporte
de namespaces de usuario del kernel. Usa wstunnel instalado con NetShield o el
binario de compilación si no está instalado; admite `WSTUNNEL_BINARY` para elegirlo.

## Qué comprueba

La prueba crea un peer propio contra el backend de desarrollo y levanta WireGuard
en un namespace aislado. Un relay transporta sus datagramas cifrados hacia el
servidor; el host conserva sus interfaces, rutas y reglas originales.

1. **Control inicial:** UDP directo debe conectar y permitir DNS y HTTPS. Si ya
   falla, la prueba se detiene: no puede atribuirse el fallo al bloqueo simulado.
2. **Restricción:** el relay descarta silenciosamente el UDP directo al servidor.
   Se comprueba que no responde la puerta de enlace, que permanece el kill switch
   y que el filtro efectivamente descartó datagramas.
3. **Alternativa HTTPS:** el mismo peer pasa a wstunnel con certificado verificado,
   TCP/443 y el mismo servidor. La restricción de UDP externo continúa activa.
   Deben recuperarse la puerta de enlace, DNS y navegación HTTPS por la VPN.
4. **Recuperación:** se termina el proceso wstunnel; la conexión debe fallar con
   el bloqueo presente. Tras reiniciarlo, la puerta de enlace debe responder.

Un resultado correcto muestra `OK` para cada fase y termina con código 0. El
primer fallo detiene la prueba. No basta con ver el mensaje de inicio.

La simulación no descarga malware ni genera alertas de amenaza. Al terminar
normalmente se revoca el peer y se eliminan claves temporales y procesos; queda
la cuenta de prueba en el backend. No ejecutar continuamente ni enviar señales
SIGKILL: una terminación forzada puede impedir la revocación remota.

## Alcance

Reproduce un síntoma observado: UDP sin respuestas, con HTTPS disponible. El
descarte ocurre en el relay del laboratorio, no en el firewall del host. No
reproduce una política universitaria conocida ni confirma DPI, límites de ancho
de banda o filtrado de WebSocket. Tampoco ejecuta NetworkManager ni la interfaz
gráfica: verifica el transporte WireGuard/WSS real y el helper de bloqueo.

No garantiza que la universidad permita WSS. Esa confirmación requiere probar
allí el cliente con **Ajustes → Modo TCP** antes de conectar. Para probar de forma
interactiva la ventana completa bajo un firewall simulado, hace falta un entorno
de escritorio aislado (por ejemplo, una VM con NetworkManager).
