# NetShield API

Backend en desarrollo para una instancia privada. Incluye autenticación básica, registro de dispositivos y procesamiento inicial de alertas Suricata. No está listo para exponerse a internet: faltan límites de intentos, aprovisionamiento de WireGuard, transporte y entrega de alertas en vivo, e integración con Pi-hole.

## Contenido

- `app/domain/`: entidades y reglas centrales del dominio.
- `app/application/`: casos de uso y puertos (interfaces) requeridos por la aplicación.
- `app/infrastructure/`: adaptadores de PostgreSQL y seguridad (Argon2 y JWT).
- `app/interfaces/`: adaptador HTTP con endpoints FastAPI.
- `app/composition.py`: conecta los puertos con sus adaptadores.
- `app/main.py`: punto de entrada de FastAPI.
- `app/create_user.py`: creación interactiva del primer usuario.
- `migrations/`: esquemas de usuarios, dispositivos y alertas; aplicar en orden numérico una sola vez.
- `tests/`: pruebas de autenticación y estado con base simulada.

Las dependencias apuntan hacia el centro: HTTP llama a los casos de uso; estos dependen de puertos y entidades, no de PostgreSQL ni de FastAPI. La composición conecta cada puerto con su implementación. Es una versión ligera de arquitectura hexagonal, con un flujo secuencial fácil de seguir.

## Preparación local

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
```

Para conectarse a PostgreSQL, configure `NETSHIELD_DATABASE_URL` y `NETSHIELD_JWT_SECRET` como variables de entorno. Consulte `.env.example`; el archivo es una referencia y no se carga automáticamente. La conexión exige `sslmode=verify-full` y un certificado confiable mediante `sslrootcert`. Proporcione la contraseña de la base por un mecanismo seguro, como un archivo `PGPASSFILE` con permisos restrictivos. Nunca suba contraseñas, claves ni certificados privados al repositorio.

Después de verificar el destino y tener respaldo, aplique una sola vez las migraciones `001_users.sql`, `002_devices.sql` y `003_security_alerts.sql`, en ese orden, y cree el primer usuario con `python -m app.create_user`. Para iniciar el servidor localmente:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

`GET /health/live` comprueba el proceso y `GET /health/ready` la conexión con la base. `POST /auth/token` recibe `username` y `password` en JSON; `GET /users/me` requiere el token Bearer resultante. Use HTTPS para transportar credenciales y tokens.


## Dispositivos y alertas

`POST /devices` recibe `name` y una clave pública WireGuard de 32 bytes en base64. `GET /devices` lista solo los registros del usuario y `DELETE /devices/{id}` elimina solo un registro propio. El registro **no crea, elimina ni activa peers WireGuard**; la clave privada debe permanecer en el dispositivo.

`python -m app.import_alerts < eventos-eve.jsonl` importa registros JSONL previamente obtenidos de una fuente confiable. Los eventos que no son alertas se omiten y las alertas duplicadas se identifican mediante un hash del evento canónico. El proceso reporta totales y devuelve código 1 si encuentra líneas inválidas. La base puede contener parcialmente los eventos válidos si otra línea falla; los eventos repetidos no vuelven a insertarse. No lee en vivo ni configura el transporte desde el VPS; no se exponen alertas por API hasta definir acceso y atribución seguros.

Las migraciones e importaciones modifican datos: primero pruébelas en una base de desarrollo. Los tests incluyen repositorios simulados; no sustituyen pruebas de integración con PostgreSQL.
