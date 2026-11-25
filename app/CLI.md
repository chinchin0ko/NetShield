# NetShield CLI

Controla NetShield VPN desde la terminal, sin abrir la app. Hace lo mismo que la interfaz gráfica: conectar, desconectar, ver alertas, consumo, dispositivos y el bloqueo de tráfico.

## Atajo

El CLI se instala como `netshield`, y también como **`nsv`** (más corto). Los dos son el mismo programa:

```sh
nsv status
nsv connect
```

## Instalación

El CLI viene **junto con la app** en todos los instaladores, no se instala por separado:

| Sistema | Paquete | El CLI queda en |
| --- | --- | --- |
| Debian / Ubuntu / Kali | `.deb` | `/usr/bin/netshield` y `/usr/bin/nsv` |
| Fedora | `.rpm` | `/usr/bin/netshield` y `/usr/bin/nsv` |
| Arch Linux | `.pkg.tar.zst` | `/usr/bin/netshield` y `/usr/bin/nsv` |
| Windows | `netshield-setup-0.1.0.exe` | `netshield.exe` y `nsv.bat` en el PATH |

Si lo compilas a mano:

```sh
dart compile exe bin/netshield.dart -o netshield
```

## Inicio rápido

```sh
nsv login        # te pide usuario y contraseña (la clave no se ve al teclearla)
nsv connect      # conecta la VPN (te pide tu clave de sudo)
nsv status       # ve si estás conectado
nsv disconnect   # desconecta
```

## Comandos

### Sesión

| Comando | Qué hace |
| --- | --- |
| `nsv login` | Inicia sesión y guarda el token para el CLI. |
| `nsv logout` | Desconecta la VPN y cierra la sesión. |

### VPN

| Comando | Qué hace |
| --- | --- |
| `nsv connect` | Conecta la VPN. |
| `nsv disconnect` | Desconecta la VPN. |
| `nsv status` | Muestra el estado de la sesión y del túnel, y cuando estás conectado también revisa la puerta de enlace, el DNS, internet y tu IP pública. |
| `nsv killswitch on` | Activa el bloqueo de tráfico. |
| `nsv killswitch off` | Desactiva el bloqueo de tráfico. |
| `nsv killswitch status` | Dice si el bloqueo está activo. |
| `nsv ssh on` | Permite conexiones SSH entrantes con la VPN activa. |
| `nsv ssh off` | Bloquea SSH con la VPN activa. |
| `nsv ssh status` | Dice si SSH está permitido. |

### Cuenta

| Comando | Qué hace |
| --- | --- |
| `nsv devices` | Lista tus dispositivos VPN. Marca `(este equipo)` el que estás usando. |
| `nsv devices revoke <id>` | Revoca un dispositivo por su id. |
| `nsv alerts` | Muestra tus alertas de seguridad recientes (las pendientes en rojo, con su severidad y hace cuánto pasaron). |
| `nsv usage` | Muestra el consumo de datos (subida, bajada y total) y los últimos 7 días. |

### Otros

| Comando | Qué hace |
| --- | --- |
| `nsv version` | Muestra la versión. |
| `nsv help` | Muestra la ayuda. |

## Ejemplos

```sh
# Conectar y ver que todo va bien
nsv login
nsv connect
nsv status

# Revisar si hay alertas nuevas
nsv alerts

# Ver cuánto has consumido
nsv usage

# Quitar un dispositivo viejo (copia su id de `nsv devices`)
nsv devices revoke 3b7a3ff3...

# Salir de todo
nsv logout
```

## La sesión

- El token se guarda en `~/.local/share/netshield/cli-session.json` (Linux) o `%APPDATA%\NetShield\cli-session.json` (Windows), solo legible por ti (permiso 600 en Linux).
- **La sesión dura 30 minutos.** Si caduca, el CLI te avisa y solo tienes que hacer `nsv login` otra vez.
- `nsv logout` desconecta la VPN antes de cerrar la sesión.

## Permisos (sudo / UAC)

- `connect`, `disconnect`, `logout`, `killswitch on|off` y `ssh on|off` cambian el sistema, así que en Linux el CLI se vuelve a ejecutar solo con `sudo -E` y te pide tu clave en la terminal. En Windows usa el UAC de la propia VPN.
- `status`, `alerts`, `usage`, `devices`, `killswitch status` y `ssh status` nunca piden sudo.
- Si corres el CLI por SSH sin terminal y te dice que sudo necesita una terminal, correlo en una terminal normal de tu equipo.

## Solución de problemas

- **`No hay sesión. Primero ejecuta: netshield login`** — haz `nsv login` otra vez (la sesión caducó o nunca iniciaste).
- **`No se pudo cambiar el bloqueo de tráfico. Revisa la autorización de administrador.`** — el `pkexec` no pudo pedir la clave porque no hay terminal gráfica; corre el comando en una terminal normal.
- **`sudo: a terminal is required to read the password`** — lo mismo: usa una terminal interactiva, no SSH sin TTY.
- **El CLI dice que estás desconectado pero la app dice que sí** — revisa con `nsv status`; el CLI y la app leen el mismo túnel, así que si difieren, cierra la sesión del CLI (`nsv logout`) y vuelve a entrar.
