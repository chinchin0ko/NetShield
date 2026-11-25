# Plan: conexión segura de un clic

## Resultado buscado

La aplicación autentica al usuario, genera y protege la clave privada en el dispositivo, y registra solo la clave pública. Al pulsar Conectar, el usuario obtiene configuración y establece un túnel WireGuard. La interfaz debe distinguir registrado, aprovisionando, listo, conectado, revocando y error; una fila en PostgreSQL no significa que exista un peer o que haya un túnel activo.

## Hallazgo en el servidor actual

La versión instalada de `wg-easy:13` crea la clave privada y la precompartida en el servidor al crear un cliente. Su guardado reescribe `wg0.json` y `wg0.conf`, y sincroniza el estado con `wg syncconf`. No se verificó una interfaz compatible para crear un peer usando una clave generada por el móvil. Por tanto, no se debe escribir en sus archivos ni agregar peers por otra vía mientras `wg-easy` los controla: una operación posterior puede sobrescribirlos. No se ha cambiado la configuración en producción.

## Pasos

1. **Diseño y laboratorio aislado.** Documentar amenazas, inventario de peers y red, y probar fuera de producción las opciones: adaptar un componente compatible con claves públicas externas o sustituir el gestor por un controlador que tenga una única fuente de verdad. Decidir con evidencia antes de migrar. El controlador debe ofrecer alta, consulta, revocación y reconciliación, sin proporcionar acceso general a Docker, `sudo` o la clave privada del servidor a la API.
2. **Identidad.** Terminar creación y verificación de cuentas, contraseñas Argon2, limitación distribuida de intentos y auditoría sin secretos. Diseñar recuperación y sesiones con expiración, revocación y rotación; añadir MFA según el riesgo. En el estado actual no hay registro público, limitación de intentos ni revocación de sesiones.
3. **Ciclo de vida del dispositivo.** El móvil genera las claves, protege la privada y envía la pública por TLS; registro idempotente por usuario y clave, cuota por cuenta y pruebas de pertenencia. La API conserva estados transitorios, identificador de operación y errores. Resolver registro y alta en WireGuard con reintentos, reconciliación y compensación; las IP se asignan de forma transaccional y única. La revocación solo se confirma tras retirar el peer y debe sobrevivir a reinicios. Diseñar explícitamente cómo demostrar posesión de una clave X25519: no asumir que una clave pública demuestra control de la privada.
4. **Red y transporte.** Mantener PostgreSQL y el controlador privados, solo las reglas mínimas por origen y destino. Diseñar un punto de entrada HTTPS para la API con certificados válidos, verificación y límites. Auditar las listas de seguridad, los puertos administrativos 8080 y 51821 y el firewall del host; aplicar cambios con un método de acceso de recuperación verificado. Añadir y probar actualización de certificados y claves.
5. **App y privacidad.** Integrar implementaciones nativas WireGuard en Android e iOS; evaluar almacenamiento según las capacidades reales de cada biblioteca y plataforma. Establecer comportamiento de DNS, IPv4 e IPv6, arranque, suspensión y cambios de red. Implementar Kill Switch en las condiciones que permita cada sistema y comunicar sus límites; no afirmar paridad sin pruebas.
6. **Alertas y DNS.** Verificar qué tráfico puede observar Suricata, transportar eventos de forma autenticada y con reanudación, y definir autorización y atribución antes de mostrar alertas. Integrar Pi-hole con credenciales limitadas y una política de datos mínima. El importador actual es por lote y no es monitoreo en vivo.
7. **Validación y lanzamiento.** Ejecutar pruebas contra PostgreSQL y WireGuard aislados, concurrencia, fallos y recuperación; probar aislamiento entre usuarios, revocación, fugas DNS e IPv6, caída de red y Kill Switch en dispositivos reales. Preparar respaldos probados y monitoreo. Desplegar después de revisar el resultado y con una forma documentada de volver atrás.

## Intervención manual prevista

- En OCI, el propietario revisa disponibilidad, reglas de red y costos antes de crear recursos o modificar exposición. No cambiar la security list compartida sin comprobar su impacto en las instancias existentes.
- Para la app, se requieren dispositivos Android e iOS y, para distribuir en iOS, las capacidades y cuenta de desarrollo de Apple que correspondan. Las autorizaciones y configuraciones de VPN del sistema pueden requerir interacción del usuario.
- El propietario debe confirmar el método de acceso administrativo de recuperación antes de restringir los paneles o migrar el gestor WireGuard. No compartir contraseñas ni claves privadas.
- Se requiere decidir políticas de cuenta, recuperación, retención de alertas y plataformas soportadas; el diseño puede avanzar con los supuestos documentados sin operar en producción.

## Riesgos abiertos

- `wg-easy` actual guarda claves privadas de clientes y es dueño de su configuración; la propuesta de claves generadas en el móvil requiere confirmar la integración o una migración segura.
- El mecanismo dos veces al mes en la VM de PostgreSQL solo consulta actualizaciones; no las instala ni avisa automáticamente. Una política de parches debe cubrir también las demás instancias.
- `POST /devices` registra una clave y no crea un peer; `DELETE` solo borra el registro. No usar estas operaciones para afirmar que se concedió o revocó acceso VPN.
- Los certificados y secretos deben gestionarse fuera del repositorio, con rotación y pruebas. El certificado de PostgreSQL configurado es propio y necesita distribución confiable y rotación.

## Avance del laboratorio

Se agregó un adaptador experimental limitado a interfaces `wg-lab*` y una prueba en un espacio de red efímero. La prueba utiliza WireGuard del kernel para agregar la clave pública de un peer, repetir el alta y retirarlo. Otra prueba aislada conecta dos peers, verifica handshake y tráfico, y confirma que la revocación interrumpe la comunicación. No conecta con la API ni con `wg-easy` y no implementa persistencia, asignación exclusiva de direcciones o reconciliación. Deben resolverse esas funciones antes de su uso fuera del laboratorio.
