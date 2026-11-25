# NetShield VPN

VPN con cifrado, detección de amenazas y protección ante fallos de conexión.

NetShield es una VPN que no solo cifra tu tráfico: lo inspecciona en busca de amenazas conocidas, filtra el DNS malicioso y bloquea todo el tráfico si el túnel se cae. Está hecha con Flutter (la app), Python + FastAPI (la API), WireGuard (el túnel), Suricata (la detección) y Pi-hole + CoreDNS (el filtro DNS).

## Las cuatro capas

1. **Túnel VPN WireGuard** — cifra todo el tráfico entre tu equipo y el servidor.
2. **Kill Switch** — si el túnel se cae, bloquea todo el tráfico para que nada salga sin cifrar.
3. **Detección IDS Suricata** — dos sensores inspeccionan el tráfico dentro del túnel y generan alertas personales cuando ven un indicador conocido (malware, exploits, respuestas de ataque, escaneos y más).
4. **Filtro DNS Pi-hole + CoreDNS** — bloquea dominios de publicidad, rastreo y malware antes de que se resuelvan.

## Descargas

Última versión: [v0.1.0-25](https://github.com/chinchin0ko/NetShield/releases/tag/v0.1.0-25).

| Sistema | Archivo | Instalación |
| --- | --- | --- |
| Debian / Ubuntu / Kali | `netshield-vpn_0.1.0-25_amd64.deb` | `sudo apt install ./netshield-vpn_0.1.0-25_amd64.deb` |
| Fedora | `netshield-vpn-0.1.0-25.fc43.x86_64.rpm` | `sudo dnf install ./netshield-vpn-0.1.0-25.fc43.x86_64.rpm` |
| Arch Linux | `netshield-vpn-0.1.0-25-x86_64.pkg.tar.zst` | `sudo pacman -U ./netshield-vpn-0.1.0-25-x86_64.pkg.tar.zst` |
| Windows (x64) | `netshield-setup-0.1.0.exe` | Ejecuta el instalador (instala WireGuard para Windows primero) |
| Android (arm64) | [APK en MediaFire](https://www.mediafire.com/file/vsb9l5xcgfschm0/netshield-android-arm64-v8a-0.1.0.apk/file) | Descarga e instala el APK |

Todos los paquetes de escritorio incluyen la app y el CLI (`netshield`, atajo `nsv`).

## Inicio rápido

1. Instala el paquete de tu sistema.
2. Abre **NetShield VPN** (o ejecuta `netshield-vpn`).
3. Inicia sesión con tu cuenta.
4. Pulsa **Conectar**. El Kill Switch se activa solo al conectar.

También puedes hacerlo todo desde la terminal:

```sh
nsv login
nsv connect
nsv status
```

Guía completa del CLI: [`app/CLI.md`](app/CLI.md).

## La app

- **Inicio** — conecta/desconecta la VPN, ve tu estado y el mapa animado de tu ruta VPN: primero tu ubicación real, y al conectar, el vuelo animado hasta el servidor (Querétaro, México).
- **Ajustes** — Kill Switch, permitir conexiones SSH (escritorio, desactivado por defecto), dispositivos y cerrar sesión.
- **Consumo** — subida, bajada y total, con gráfica de los últimos 7 días.
- **Alertas** — amenazas detectadas por Suricata, con severidad y filtros (pendientes, revisadas, posibles falsos positivos). Las pendientes muestran su contador en el filtro.

En Linux, las alertas nuevas generan una notificación del sistema. En Android, llegan como notificación push (Firebase).

Cerrar la ventana con la equis **oculta** la app (sigue corriendo y la VPN sigue activa). Para salir de verdad usa el botón **Salir**: desconecta la VPN, cierra la sesión y cierra la app.

## El CLI

`netshield` (atajo `nsv`) controla la VPN desde la terminal: `login`, `logout`, `connect`, `disconnect`, `status`, `devices`, `alerts`, `usage`, `killswitch on|off|status`, `ssh on|off|status`, `version`, `help`. Tiene banner, colores y un spinner animado mientras trabaja. Ver la guía completa en [`app/CLI.md`](app/CLI.md).

## Arquitectura

```
┌──────────────┐   WireGuard    ┌─────────────────────┐
│  App Flutter │ ◄────────────► │  Servidor (Oracle)  │
│ Linux / Win  │   10.8.0.0/24  │  wg-easy + Pi-hole  │
│ Android      │                │  + CoreDNS          │
└──────┬───────┘                └──────┬──────────────┘
       │ HTTPS                         │ Suricata (2 sensores)
       ▼                               ▼
┌──────────────┐                ┌─────────────────────┐
│  API FastAPI │ ◄──────────────│  Alertas personales │
│  api.netshield.lat            │  + push (FCM)       │
└──────┬───────┘                └─────────────────────┘
       │ PostgreSQL
       ▼
┌──────────────┐
│  Usuarios,   │
│  dispositivos│
│  y alertas   │
└──────────────┘
```

### Componentes

| Parte | Qué es | Dónde está |
| --- | --- | --- |
| App | Cliente Flutter (Linux, Windows, Android) + CLI en Dart puro | `app/` |
| API | FastAPI con autenticación JWT, aprovisionamiento WireGuard e ingesta de alertas | `API/` |
| Sensores Suricata | Dos instancias que inspeccionan el tráfico del túnel (reglas ET Open) y envían eventos a la API | `API/controller/` |
| DNS | Pi-hole (bloqueo) con CoreDNS como resolutor upstream | `infra/coredns/` |
| Infra | Docker Compose en el VPS (wg-easy, Pi-hole, CoreDNS) | `infra/` |

La API usa arquitectura hexagonal ligera: HTTP llama a casos de uso, que dependen de puertos y entidades, no de PostgreSQL ni de FastAPI. Detalles en [`API/README.md`](API/README.md).

## Seguridad

- **Contraseñas** con Argon2id; **sesiones** con JWT HS256 de 30 minutos.
- **Límite de intentos** de inicio de sesión: 10 por cuenta cada 5 minutos (429 al excederlo).
- **Kill Switch**: en Linux usa nftables (solo permite loopback, el túnel y UDP al endpoint del VPN); en Windows usa el Firewall de Windows; en Android usa el Always-on VPN del sistema con "Bloquear conexiones sin VPN".
- **Permitir conexiones SSH** (escritorio, desactivado por defecto): abre una salida solo para SSH mientras la VPN está activa. Debilita el bloqueo, así que solo se activa si se necesita.
- **Claves WireGuard** generadas localmente (permiso 0600), una por cuenta; la API solo recibe la clave pública.
- **Alertas**: el sensor solo envía eventos con firmas relevantes; la API atribuye cada evento a su dueño por la asignación VPN vigente y lo guarda como alerta personal.
- **DNS**: Pi-hole ve todas las consultas como un solo origen (la puerta de enlace), así que no se registra qué usuario consultó qué dominio bloqueado.

## Desarrollo

### Estructura del repo

```
NetShield/
├── app/            # Cliente Flutter + CLI (bin/netshield.dart)
│   ├── lib/        # App: main.dart, screens/, services/
│   ├── bin/        # CLI netshield
│   ├── linux/      # Runner Linux + killswitch.py
│   ├── windows/    # Runner Windows + instalador (installer/)
│   ├── android/    # App Android (Kotlin: VpnEngine, VpnStore)
│   ├── packaging/  # .deb, .rpm, Arch
│   └── scripts/    # package-*.sh, build-packages-docker.sh
├── API/            # Backend FastAPI + controlador del sensor
│   ├── app/        # Dominio, aplicación, infraestructura, HTTP
│   ├── controller/ # build_suricata_sensor.py, suricata_collector.py
│   └── tests/      # 63 pruebas de la API
├── infra/          # CoreDNS, Docker Compose del VPS
└── docs/           # Documentación del proyecto
```

Rama de desarrollo actual: `desarrollo/android`.

### Compilar la app

```sh
cd app
flutter pub get
flutter analyze
flutter test
flutter build linux --release
```

### Compilar el CLI

```sh
cd app
dart compile exe bin/netshield.dart -o netshield
```

### Empaquetar (Linux)

```sh
cd app
./scripts/build-packages-docker.sh   # .deb (Debian 12) y .rpm (Fedora 43) en contenedores
./scripts/package-arch.sh            # .pkg.tar.zst de Arch (en Arch)
```

### Windows

La build de Windows corre en GitHub Actions (`.github/workflows/build-windows.yml`): analiza, prueba, compila la app y el CLI, construye el instalador con Inno Setup y sube el artefacto. Se dispara con un tag `v*`.

### Probar la API

```sh
cd API
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
```

## Estado y trabajo futuro

Hecho y verificado: túnel WireGuard en Linux/Windows/Android, Kill Switch en los tres, alertas reales de Suricata (dos sensores, ~6000 + 858 reglas), notificaciones push en Android y de escritorio en Linux, filtro DNS Pi-hole + CoreDNS, paquetes .deb/.rpm/Arch, instalador de Windows, CLI con `nsv`, mapa animado de la ruta VPN en escritorio y Android.

Pendiente: probar la versión de Windows en un PC real (túnel, alerta del sensor y Kill Switch), iOS, grabar el video demostrativo, y los controles de producción (protección contra abuso del registro, recuperación de cuenta, renovación de certificados, firma de paquetes).

## Licencia

MIT — ver [`LICENSE`](LICENSE).
