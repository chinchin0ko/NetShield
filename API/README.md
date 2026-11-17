# NetShield API

Primera versión del backend en FastAPI para una instancia privada. Incluye autenticación básica, conexión a PostgreSQL y pruebas locales. No está lista para exponerse a internet: faltan límites de intentos, controles de acceso adicionales, gestión de dispositivos WireGuard e integración con Suricata.

## Contenido

- `app/domain/`: entidades y reglas centrales del dominio.
- `app/application/`: casos de uso y puertos (interfaces) requeridos por la aplicación.
- `app/infrastructure/`: adaptadores de PostgreSQL y seguridad (Argon2 y JWT).
- `app/interfaces/`: adaptador HTTP con endpoints FastAPI.
- `app/composition.py`: conecta los puertos con sus adaptadores.
- `app/main.py`: punto de entrada de FastAPI.
- `app/create_user.py`: creación interactiva del primer usuario.
- `migrations/001_users.sql`: esquema inicial de usuarios.
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

Después de verificar el destino y tener respaldo, aplique una sola vez `migrations/001_users.sql` y cree el primer usuario con `python -m app.create_user`. Para iniciar el servidor localmente:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

`GET /health/live` comprueba el proceso y `GET /health/ready` la conexión con la base. `POST /auth/token` recibe `username` y `password` en JSON; `GET /users/me` requiere el token Bearer resultante. Use HTTPS para transportar credenciales y tokens.
