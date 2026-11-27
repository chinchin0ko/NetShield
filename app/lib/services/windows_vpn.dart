import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'api_client.dart';
import 'linux_vpn.dart';
import 'windows_admin_commands.dart';
import 'windows_service_client.dart';

/// Windows uses the official WireGuard for Windows client for the tunnel
/// and Windows Firewall rules for the killswitch.
///
/// Requirements: WireGuard for Windows installed
/// (https://www.wireguard.com/install, free). Tunnel and firewall changes
/// need administrator rights. They run through the NetShield Windows
/// Service (SYSTEM) when it is installed, so the user is only asked once
/// (when the service is installed); without the service, every privileged
/// step asks for it through a UAC prompt (an elevated PowerShell helper).
class WindowsVpn extends LinuxVpn {
  WindowsVpn(super.api);

  String? _windowsConnection;

  // -- Pure helpers (also covered by unit tests). ---------------------------

  /// Tunnel name from the device id, same scheme as Linux (`ns` + 12 hex).
  static String tunnelName(String deviceId) => 'ns${deviceId.substring(0, 12)}';

  /// Windows service name for a tunnel, as created by wireguard.exe.
  static String serviceName(String tunnel) => 'WireGuardTunnel\$$tunnel';

  /// IPv4 endpoint (host only) from a WireGuard config template.
  /// The port is not fixed: the server may listen on 51820, 443 or any
  /// other UDP port, so any numeric port is accepted here.
  static String? parseEndpoint(String config) =>
      RegExp(r'^Endpoint\s*=\s*([0-9.]+):\d+\s*$', multiLine: true)
          .firstMatch(config)
          ?.group(1);

  /// DNS server from a WireGuard config template, when present.
  static String? parseDns(String config) =>
      RegExp(r'^DNS\s*=\s*([0-9.]+)\b', multiLine: true)
          .firstMatch(config)
          ?.group(1);

  /// `wg show <tunnel> transfer` prints one `<key>\t<rx>\t<tx>` line per peer.
  static TrafficUsage? parseTransfer(String output) {
    for (final line in output.split('\n')) {
      final parts = line.trim().split(RegExp(r'\s+'));
      if (parts.length >= 3) {
        final rx = int.tryParse(parts[1]);
        final tx = int.tryParse(parts[2]);
        if (rx != null && tx != null && rx >= 0 && tx >= 0) {
          return TrafficUsage(rx, tx);
        }
      }
    }
    return null;
  }

  // -- Paths (per-user, %APPDATA% is private to the account). ---------------

  Future<Directory> _appDir() async {
    final roaming = Platform.environment['APPDATA'];
    final profile = Platform.environment['USERPROFILE'];
    final base = roaming ??
        (profile == null ? null : '$profile\\AppData\\Roaming');
    if (base == null) {
      throw const ApiException('No se encontró tu carpeta personal.');
    }
    final dir = Directory('$base\\NetShield');
    await dir.create(recursive: true);
    return dir;
  }

  Future<File> _endpointFile() async =>
      File('${(await _appDir()).path}\\vpn-endpoint');

  Future<File> _lockFile() async {
    final dir = Directory('${(await _appDir()).path}\\lock');
    await dir.create(recursive: true);
    return File('${dir.path}\\active.json');
  }

  Future<File> _configFile(String tunnel) async {
    final dir = Directory('${(await _appDir()).path}\\configs');
    await dir.create(recursive: true);
    return File('${dir.path}\\$tunnel.conf');
  }

  Future<File> _routeFile() async =>
      File('${(await _appDir()).path}\\management-route.json');

  /// The SSH exception setting lives under %APPDATA%\NetShield on Windows
  /// (Linux uses ~/.local/share/netshield). See LinuxVpn for the meaning.
  @override
  Future<bool> isSshAllowed() async {
    try {
      final file = File('${(await _appDir()).path}\\allow-ssh');
      if (!await file.exists()) return false;
      return (await file.readAsString()).trim() == '1';
    } catch (_) {
      return false;
    }
  }

  @override
  Future<void> setSshAllowed(bool allowed) async {
    final file = File('${(await _appDir()).path}\\allow-ssh');
    await file.writeAsString(allowed ? '1' : '0', flush: true);
  }

  // -- WireGuard for Windows detection. -------------------------------------

  Future<String> _wireguardExe() async {
    const programFiles =
        r'C:\Program Files\WireGuard\wireguard.exe';
    if (await File(programFiles).exists()) return programFiles;
    final found = await _runWireGuardCommand('where.exe', ['wireguard.exe'],
        failure: 'No se pudo localizar WireGuard para Windows.');
    if (found.exitCode == 0) {
      final first = found.stdout.toString().split('\n').first.trim();
      if (first.isNotEmpty) return first;
    }
    throw const ApiException(
        'Falta instalar WireGuard para Windows (gratis en wireguard.com/install).');
  }

  Future<String> _wgExe(String wireguardExe) async {
    final dir = File(wireguardExe).parent.path;
    final bundled = File('$dir\\wg.exe');
    if (await bundled.exists()) return bundled.path;
    final found = await _runWireGuardCommand('where.exe', ['wg.exe'],
        failure: 'No se pudo localizar wg.exe.');
    if (found.exitCode == 0) {
      final first = found.stdout.toString().split('\n').first.trim();
      if (first.isNotEmpty) return first;
    }
    throw const ApiException(
        'No se encontró wg.exe junto a WireGuard para Windows.');
  }

  // -- Privileged helper (UAC prompt, waits for the elevated step). ---------
  //
  // Every _runElevated call is one UAC prompt. Connect and disconnect batch
  // all of their privileged steps into a single script (see
  // _connectAdminScript / _disconnectAdminScript), so the user is asked
  // exactly once per connect and once per disconnect.

  /// Exit codes for the combined admin scripts (see WindowsAdminExit):
  /// the script exits with the code of the first step that failed, so the
  /// caller knows what broke and whether the traffic lock is already on.
  static const _adminOk = WindowsAdminExit.ok;
  static const _adminFirewallFailed = WindowsAdminExit.firewallFailed;
  static const _adminTunnelFailed = WindowsAdminExit.tunnelFailed;

  /// Runs [psLines] as administrator and returns the exit code. The user
  /// sees one UAC prompt per call; denying it fails the step. The elevated
  /// window itself stays hidden so PowerShell does not flash on screen.
  Future<int> _runElevated(List<String> psLines) async {
    final temp = await Directory.systemTemp.createTemp('netshield-');
    try {
      final script = File('${temp.path}\\netshield-admin.ps1');
      await script.writeAsString(psLines.join('\r\n'), flush: true);
      final launcher =
          '\$p = Start-Process -FilePath "powershell" -ArgumentList '
          '"-NoProfile","-ExecutionPolicy","Bypass","-File",'
          '"${script.path}" -Verb RunAs -WindowStyle Hidden -PassThru -Wait; '
          'exit \$p.ExitCode';
      final result = await Process.run('powershell',
              ['-NoProfile', '-Command', launcher])
          .timeout(const Duration(seconds: 120));
      return result.exitCode;
    } on TimeoutException {
      throw const ApiException(
          'La operación con permisos de administrador tardó demasiado.');
    } finally {
      await temp.delete(recursive: true);
    }
  }

  // -- Windows Service (ask once, then no more UAC prompts). ---------------
  //
  // When the NetShield Windows Service is installed (SYSTEM), privileged
  // steps run through it over a loopback socket instead of a UAC prompt.
  // _serviceOrElevated tries the service first and falls back to one UAC
  // prompt when the service is missing or does not answer. _ensureService
  // installs the service once (one UAC prompt) the first time it is
  // needed; the installer normally does this already, so the app rarely
  // has to.

  final _service = WindowsServiceClient();
  bool _serviceInstallTried = false;

  /// True when the NetShield Windows Service answers on the loopback
  /// socket. Checked fresh each time (cheap, localhost) so a service
  /// that starts later is picked up without restarting the app.
  Future<bool> _serviceAvailable() async {
    try {
      return await _service.ping();
    } catch (_) {
      return false;
    }
  }

  /// Runs a privileged operation through the service when it is
  /// available, else through one UAC prompt. [viaService] and
  /// [viaElevated] both return the admin exit code (0/10/20).
  Future<int> _serviceOrElevated(Future<int> Function() viaService,
      Future<int> Function() viaElevated) async {
    if (await _serviceAvailable()) {
      try {
        return await viaService();
      } catch (_) {
        // The service did not answer: fall through to the UAC path.
      }
    }
    return viaElevated();
  }

  /// Installs + starts the NetShield Windows Service once (one UAC
  /// prompt) when it is missing, so later connects go through the
  /// service. Best effort: if the install fails, connects keep using
  /// the UAC path. Only attempted once per app run.
  Future<void> _ensureService() async {
    if (_serviceInstallTried) return;
    _serviceInstallTried = true;
    if (await _serviceAvailable()) return;
    final exe = _serviceExePath();
    if (exe == null) return;
    // Already registered but stopped: try starting it without a prompt.
    try {
      final query =
          await Process.run('sc', ['query', 'NetShieldService']);
      if (query.exitCode == 0) {
        await Process.run('sc', ['start', 'NetShieldService']);
        if (await _serviceAvailable()) return;
      }
    } catch (_) {}
    // Not installed (or could not be started): create + start it.
    // One UAC prompt for the whole thing. New-Service handles the
    // quoting of a path with spaces; creating an existing service is
    // skipped so a stopped service is just started.
    try {
      await _runElevated([
        "if (-not (Get-Service NetShieldService -ErrorAction SilentlyContinue)) { New-Service -Name NetShieldService -BinaryPathName '\"$exe\"' -DisplayName 'NetShield Service' -StartupType Automatic | Out-Null }",
        'Start-Service NetShieldService',
        r'exit $LASTEXITCODE',
      ]);
    } catch (_) {
      // Install failed: keep using the UAC path per operation.
    }
  }

  /// The service exe next to this app's exe (the installer puts them
  /// together). Null when it is not there (a portable run without it).
  String? _serviceExePath() {
    final exe = File(
        '${File(Platform.resolvedExecutable).parent.path}\\netshield-service.exe');
    return exe.existsSync() ? exe.path : null;
  }

  // -- Identity (per-account keys, same scheme as Linux). -------------------

  static const _wireguardTimeout = Duration(seconds: 10);

  Future<ProcessResult> _runWireGuardCommand(
    String executable,
    List<String> arguments, {
    String? input,
    required String failure,
  }) async {
    var timedOut = false;
    Process? child;

    Future<ProcessResult> run() async {
      final process = await Process.start(executable, arguments);
      child = process;
      if (timedOut) process.kill();

      // Drain both pipes while writing stdin so a child waiting on either
      // pipe cannot prevent the other from being read.
      final output = systemEncoding.decoder.bind(process.stdout).join();
      final errors = systemEncoding.decoder.bind(process.stderr).join();
      if (!timedOut && input != null) process.stdin.writeln(input);
      await Future.wait<void>([
        output.then<void>((_) {}),
        errors.then<void>((_) {}),
        process.exitCode.then<void>((_) {}),
        process.stdin.close().then<void>((_) {}),
      ], eagerError: true);
      return ProcessResult(
          process.pid, await process.exitCode, await output, await errors);
    }

    try {
      return await run().timeout(_wireguardTimeout);
    } on TimeoutException {
      timedOut = true;
      child?.kill();
      throw ApiException('$failure WireGuard tardó demasiado.');
    } on ProcessException {
      child?.kill();
      throw ApiException(failure);
    } on IOException {
      child?.kill();
      throw ApiException(failure);
    }
  }

  @override
  Future<String> deviceId() async {
    final dir = await _appDir();
    final file = File('${dir.path}\\device-id');
    if (await file.exists()) {
      final value = (await file.readAsString()).trim();
      if (RegExp(r'^[0-9a-f]{32}$').hasMatch(value)) return value;
      throw const ApiException('El identificador del dispositivo es inválido.');
    }
    final random = Random.secure();
    final value = List.generate(16,
            (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'))
        .join();
    await file.writeAsString(value, flush: true);
    return value;
  }

  Future<String> _privateKey(String account) async {
    final accountId =
        base64Url.encode(utf8.encode(account)).replaceAll('=', '');
    if (accountId.isEmpty || accountId.length > 172) {
      throw const ApiException('La cuenta es inválida.');
    }
    final dir =
        Directory('${(await _appDir()).path}\\accounts');
    await dir.create(recursive: true);
    final file = File('${dir.path}\\$accountId.key');
    if (await file.exists()) {
      final key = (await file.readAsString()).trim();
      try {
        if (base64.decode(key).length == 32 &&
            base64.encode(base64.decode(key)) == key) {
          return key;
        }
      } catch (_) {/* Reject invalid key material. */}
      throw const ApiException('La clave local de WireGuard es inválida.');
    }
    final wg = await _wgExe(await _wireguardExe());
    const failure = 'No se pudo crear la clave local de WireGuard.';
    final result =
        await _runWireGuardCommand(wg, ['genkey'], failure: failure);
    if (result.exitCode != 0) {
      throw const ApiException(failure);
    }
    final key = result.stdout.toString().trim();
    if (base64.decode(key).length != 32) {
      throw const ApiException('La clave generada es inválida.');
    }
    await file.writeAsString(key, flush: true);
    return key;
  }

  Future<String> _publicKey(String privateKey) async {
    final wg = await _wgExe(await _wireguardExe());
    const failure = 'No se pudo derivar la clave pública.';
    final result = await _runWireGuardCommand(wg, ['pubkey'],
        input: privateKey, failure: failure);
    if (result.exitCode != 0 || (result.stderr as String).isNotEmpty) {
      throw const ApiException(failure);
    }
    final key = (result.stdout as String).trim();
    if (base64.decode(key).length != 32) {
      throw const ApiException('La clave pública es inválida.');
    }
    return key;
  }

  // -- Killswitch (Windows Firewall). ---------------------------------------

  /// The Windows default: every profile allows outbound traffic.
  static const _allAllow = WindowsAdminCommands.allAllow;

  /// The effective DefaultOutboundAction per firewall profile, read
  /// without admin rights. Returns null when the query itself fails.
  /// Example: {Domain: Allow, Private: Allow, Public: Block}.
  Future<Map<String, String>?> _firewallProfiles() async {
    try {
      final result = await Process.run('powershell', [
        '-NoProfile',
        '-Command',
        r"Get-NetFirewallProfile | ForEach-Object { $_.Name + ':' + $_.DefaultOutboundAction }",
      ]).timeout(const Duration(seconds: 15));
      if (result.exitCode != 0) return null;
      final profiles = <String, String>{};
      for (final line in result.stdout.toString().split('\n')) {
        final index = line.indexOf(':');
        if (index <= 0) continue;
        final name = line.substring(0, index).trim();
        final value = line.substring(index + 1).trim();
        if (name.isNotEmpty && value.isNotEmpty) {
          profiles[name] = value;
        }
      }
      return profiles.isEmpty ? null : profiles;
    } catch (_) {
      return null;
    }
  }

  /// True when any profile currently blocks outbound traffic. This is the
  /// effective state of the traffic lock, whatever the lock file says.
  Future<bool> _firewallIsBlocking() async {
    final profiles = await _firewallProfiles();
    if (profiles == null) return false;
    return profiles.values
        .any((value) => value.trim().toLowerCase() == 'block');
  }

  /// Throws unless every profile in [expected] currently has that
  /// DefaultOutboundAction. A restore is only a success when the
  /// firewall itself says so: a silent failure used to delete the lock
  /// and print success while the firewall kept blocking.
  Future<void> _verifyProfilesRestored(
      Map<String, String> expected) async {
    final actual = await _firewallProfiles();
    if (actual == null) {
      throw const ApiException(
          'No se pudo comprobar el estado del firewall tras restaurar.');
    }
    for (final entry in expected.entries) {
      final got = actual[entry.key];
      if (got == null ||
          got.trim().toLowerCase() != entry.value.trim().toLowerCase()) {
        throw ApiException(
            'El firewall sigue bloqueando el perfil ${entry.key} '
            '(esperado ${entry.value}, actual ${got ?? 'desconocido'}). '
            'El bloqueo se conserva para reintentarlo.');
      }
    }
  }

  @override
  Future<bool> isKillSwitchEnabled() async {
    if (await File('${(await _appDir()).path}\\lock\\active.json')
        .exists()) {
      return true;
    }
    // The lock file can be gone while the firewall is still blocking
    // (a restore that reported success without taking effect). Trust the
    // firewall, not just the file, so status never lies and a recovery
    // command still runs when the lock is missing.
    return _firewallIsBlocking();
  }

  // -- Privileged command builders (shared with the Windows Service). -----
  //
  // The builders live in windows_admin_commands.dart (pure Dart) so the
  // service builds the exact same scripts. These forwarding members keep
  // the existing tests and call sites unchanged.

  /// Firewall rules that turn the traffic lock on. Pure: no I/O, so the
  /// connect flow can run them inside its single combined admin script.
  static List<String> killswitchEnableCommands(String tunnel, String endpoint,
          {bool allowSsh = false}) =>
      WindowsAdminCommands.killswitchEnableCommands(tunnel, endpoint,
          allowSsh: allowSsh);

  /// Firewall rules that turn the traffic lock off. Pure, like above.
  static List<String> killswitchDisableCommands(
          {Map<String, String>? original}) =>
      WindowsAdminCommands.killswitchDisableCommands(original: original);

  /// One elevated script for connect: traffic lock first (so nothing leaks
  /// while the tunnel comes up), then the tunnel install. Exits
  /// [_adminFirewallFailed] if the lock fails, [_adminTunnelFailed] if the
  /// install fails, [_adminOk] when both succeed. Pure and testable.
  static List<String> connectAdminScript(List<String> firewallCommands,
          String wireguardExe, String configPath) =>
      WindowsAdminCommands.connectAdminScript(
          firewallCommands, wireguardExe, configPath);

  /// One elevated script for disconnect: uninstall the tunnel service and
  /// restore the firewall, best effort on both steps, exiting with the
  /// first failure code ([_adminTunnelFailed] or [_adminFirewallFailed]).
  /// Only the steps the caller asks for are included. Pure and testable.
  static List<String> disconnectAdminScript(
          {required bool uninstallTunnel,
          required String wireguardExe,
          required String tunnel,
          required bool disableKillswitch,
          Map<String, String>? original}) =>
      WindowsAdminCommands.disconnectAdminScript(
        uninstallTunnel: uninstallTunnel,
        wireguardExe: wireguardExe,
        tunnel: tunnel,
        disableKillswitch: disableKillswitch,
        original: original,
      );

  Future<void> _writeLock(String tunnel, String endpoint,
      {bool allowSsh = false, Map<String, String>? original}) async {
    final lock = await _lockFile();
    await lock.writeAsString(
        jsonEncode({
          'tunnel': tunnel,
          'endpoint': endpoint,
          'allow_ssh': allowSsh,
          'original': ?original,
        }),
        flush: true);
  }

  /// The per-profile firewall state captured before the lock went on,
  /// stored in the lock file. Null for lock files written before this
  /// was added (those restore to Allow on every profile).
  Future<Map<String, String>?> _readLockOriginal() async {
    try {
      final lock = await _lockFile();
      if (!await lock.exists()) return null;
      final data = jsonDecode(await lock.readAsString());
      if (data is! Map || data['original'] is! Map) return null;
      final original = <String, String>{};
      for (final entry in (data['original'] as Map).entries) {
        final key = entry.key.toString();
        final value = entry.value.toString();
        if (key.isNotEmpty && value.isNotEmpty) {
          original[key] = value;
        }
      }
      return original.isEmpty ? null : original;
    } catch (_) {
      return null;
    }
  }

  Future<void> _deleteLock() async {
    final lock = await _lockFile();
    if (await lock.exists()) await lock.delete();
  }

  Future<void> _enableKillswitch(String tunnel, String endpoint,
      {bool allowSsh = false}) async {
    // Snapshot the firewall first, and record the lock before touching
    // it: if the enable fails halfway (Block set, a rule rejected), the
    // firewall is left blocking with a lock that says so, instead of an
    // orphaned block no command can see. The lock is dropped again when
    // the firewall was never actually touched.
    final original = await _firewallProfiles() ?? _allAllow;
    await _writeLock(tunnel, endpoint,
        allowSsh: allowSsh, original: original);
    try {
      final code = await _serviceOrElevated(
        () => _service.setKillswitch(
            enable: true,
            tunnel: tunnel,
            endpoint: endpoint,
            allowSsh: allowSsh),
        () => _runElevated(killswitchEnableCommands(tunnel, endpoint,
            allowSsh: allowSsh)),
      );
      if (code != 0) {
        throw const ApiException(
            'No se pudo activar el bloqueo de tráfico. Revisa la autorización de administrador.');
      }
    } catch (_) {
      if (!await _firewallIsBlocking()) await _deleteLock();
      rethrow;
    }
  }

  Future<void> _disableKillswitch() async {
    final original = await _readLockOriginal();
    final expected = original ?? _allAllow;
    final code = await _serviceOrElevated(
      () => _service.setKillswitch(enable: false, original: original),
      () => _runElevated([
        r"$ErrorActionPreference = 'Stop'",
        ...killswitchDisableCommands(original: original),
      ]),
    );
    if (code != 0) {
      throw const ApiException(
          'No se pudo desactivar el bloqueo de tráfico. Revisa la autorización de administrador.');
    }
    // A silent failure of the restore used to delete the lock and print
    // success while the firewall kept blocking. Only delete the lock
    // when the firewall itself confirms the restore.
    await _verifyProfilesRestored(expected);
    await _deleteLock();
  }

  @override
  Future<void> setKillSwitch(bool enabled) async {
    if (!enabled) {
      if (await isKillSwitchEnabled()) await _disableKillswitch();
      return;
    }
    if (await isKillSwitchEnabled()) return;
    if (!await isConnected()) {
      throw const ApiException('Conecta la VPN antes de activar el bloqueo.');
    }
    final file = await _endpointFile();
    if (!await file.exists()) {
      throw const ApiException(
          'Desconecta y vuelve a conectar la VPN para activar el bloqueo.');
    }
    final endpoint = (await file.readAsString()).trim();
    if (InternetAddress.tryParse(endpoint)?.type !=
        InternetAddressType.IPv4) {
      throw const ApiException('La dirección del servidor VPN es inválida.');
    }
    final id = await deviceId();
    await _enableKillswitch(tunnelName(id), endpoint,
        allowSsh: await isSshAllowed());
  }

  // -- Tunnel (WireGuard for Windows service). ------------------------------

  Future<bool> _serviceRunning(String tunnel) async {
    try {
      final result = await Process.run(
              'sc', ['query', serviceName(tunnel)])
          .timeout(const Duration(seconds: 10));
      return result.exitCode == 0 &&
          result.stdout.toString().contains('RUNNING');
    } catch (_) {
      return false;
    }
  }

  /// Removes the tunnel service, but only when it actually exists, and
  /// never shows wireguard.exe's own error dialog. Used for cleanup after
  /// a failed connect: uninstalling a service that was never installed
  /// used to pop up "The specified service does not exist as an
  /// installed service." even though there was nothing to remove.
  Future<void> _uninstallTunnelSilent(String tunnel) async {
    if (!await _serviceExists(tunnel)) return;
    try {
      final wireguardExe = await _wireguardExe();
      await _serviceOrElevated(
        () => _service.disconnect(
          uninstallTunnel: true,
          wireguardExe: wireguardExe,
          tunnel: tunnel,
          disableKillswitch: false,
        ),
        () => _runElevated([
          '& "$wireguardExe" /uninstalltunnelservice "$tunnel"',
          'exit \$LASTEXITCODE',
        ]),
      );
    } catch (_) {/* Best effort cleanup. */}
  }

  Future<bool> _serviceExists(String tunnel) async {
    try {
      final result = await Process.run(
              'sc', ['query', serviceName(tunnel)])
          .timeout(const Duration(seconds: 10));
      return result.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  Future<void> _waitForTunnel(String tunnel) async {
    for (var i = 0; i < 15; i++) {
      if (await _serviceRunning(tunnel)) return;
      await Future<void>.delayed(const Duration(seconds: 1));
    }
    throw const ApiException('El túnel VPN no se activó.');
  }

  Future<bool> _ping(String address) async {
    try {
      final result = await Process.run(
              'ping', ['-n', '1', '-w', '5000', address])
          .timeout(const Duration(seconds: 8));
      return result.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  /// Keep a /32 route to the VPN endpoint through the current gateway while
  /// the tunnel is up, so a local development API stays reachable. Only
  /// used when the API runs on this computer.
  Future<void> _keepDevelopmentTunnel(String config) async {
    if (api.baseUrl.host != '127.0.0.1' && api.baseUrl.host != 'localhost') {
      return;
    }
    final endpoint = parseEndpoint(config);
    if (endpoint == null ||
        InternetAddress.tryParse(endpoint)?.type !=
            InternetAddressType.IPv4) {
      throw const ApiException('No se encontró la dirección IPv4 del servidor VPN.');
    }
    final route = await Process.run('powershell', [
      '-NoProfile',
      '-Command',
      "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Select-Object -First 1).NextHop"
    ]).timeout(const Duration(seconds: 10));
    final gateway = route.stdout.toString().trim().split('\n').first.trim();
    if (route.exitCode != 0 ||
        InternetAddress.tryParse(gateway)?.type !=
            InternetAddressType.IPv4) {
      throw const ApiException('No se encontró la ruta de administración.');
    }
    final file = await _routeFile();
    await file.writeAsString(
        jsonEncode({'gateway': gateway, 'endpoint': endpoint}),
        flush: true);
    final routeCode = await _serviceOrElevated(
      () => _service.route(add: true, endpoint: endpoint, gateway: gateway),
      () => _runElevated([
        'route add $endpoint mask 255.255.255.255 $gateway metric 5',
      ]),
    );
    if (routeCode != 0) {
      throw const ApiException(
          'No se pudo conservar el acceso a la API de desarrollo.');
    }
  }

  Future<void> _removeManagementRoute() async {
    final file = await _routeFile();
    if (!await file.exists()) return;
    try {
      final data = jsonDecode(await file.readAsString());
      if (data is! Map ||
          data['gateway'] is! String ||
          data['endpoint'] is! String) {
        throw const ApiException('No se pudo restaurar la ruta de administración.');
      }
      final routeCode = await _serviceOrElevated(
        () => _service.route(
            add: false, endpoint: data['endpoint'] as String),
        () => _runElevated([
          'route delete ${data['endpoint']}',
        ]),
      );
      if (routeCode != 0) {
        throw const ApiException(
            'No se pudo restaurar la ruta de administración.');
      }
    } finally {
      if (await file.exists()) await file.delete();
    }
  }

  @override
  Future<void> connect(String token, String account) async {
    if (!Platform.isWindows) {
      throw const ApiException('Esta versión solo permite conexiones en Windows.');
    }
    final wireguardExe = await _wireguardExe();
    final id = await deviceId();
    final privateKey = await _privateKey(account);
    final publicKey = await _publicKey(privateKey);
    final template = await api.vpnConfig(token, id, publicKey);
    if (!RegExp(r'^PrivateKey\s*=\s*REPLACE_ME\s*$', multiLine: true)
        .hasMatch(template)) {
      throw const ApiException('El servidor no aceptó la clave pública local.');
    }
    final config = template.replaceFirst(
        RegExp(r'^PrivateKey\s*=\s*REPLACE_ME\s*$', multiLine: true),
        'PrivateKey = $privateKey');
    if (!RegExp(r'^AllowedIPs\s*=.*\b0\.0\.0\.0/0\b.*::/0\s*$', multiLine: true)
        .hasMatch(config)) {
      throw const ApiException(
          'La configuración VPN no incluye rutas completas IPv4 e IPv6.');
    }
    final tunnel = tunnelName(id);
    final endpoint = parseEndpoint(config);
    if (endpoint == null ||
        InternetAddress.tryParse(endpoint)?.type !=
            InternetAddressType.IPv4) {
      throw const ApiException('La dirección del servidor VPN es inválida.');
    }
    final endpointFile = await _endpointFile();
    await endpointFile.writeAsString(endpoint, flush: true);
    final configFile = await _configFile(tunnel);
    await configFile.writeAsString(config, flush: true);
    // Snapshot the firewall and record the lock BEFORE the elevated
    // script: if the script sets Block and then fails, the block is on
    // record and the catch below can restore it, instead of leaving an
    // orphaned block that no command can see.
    final originalProfiles = await _firewallProfiles() ?? _allAllow;
    final allowSsh = await isSshAllowed();
    await _writeLock(tunnel, endpoint,
        allowSsh: allowSsh, original: originalProfiles);
    var scriptRan = false;
    try {
      await _ensureService();
      await _keepDevelopmentTunnel(config);
      // ONE prompt: the traffic lock and the tunnel install run in a
      // single privileged step (the service when it is installed, else
      // one elevated script), so Windows only asks once per connect.
      // The lock goes first, like on Linux, so no traffic leaks while the
      // tunnel comes up. The step exits 10 if the lock fails and 20 if
      // the install fails.
      scriptRan = true;
      final code = await _serviceOrElevated(
        () => _service.connect(
          tunnel: tunnel,
          wireguardExe: wireguardExe,
          configPath: configFile.path,
          endpoint: endpoint,
          allowSsh: allowSsh,
        ),
        () => _runElevated(connectAdminScript(
            killswitchEnableCommands(tunnel, endpoint, allowSsh: allowSsh),
            wireguardExe,
            configFile.path)),
      );
      if (code == _adminFirewallFailed || (code != _adminOk && code != _adminTunnelFailed)) {
        throw const ApiException(
            'No se pudo activar el bloqueo de tráfico. Revisa la autorización de administrador.');
      }
      if (code == _adminTunnelFailed) {
        throw const ApiException(
            'No se pudo instalar el túnel VPN. Revisa la autorización de administrador.');
      }
      _windowsConnection = tunnel;
      await _waitForTunnel(tunnel);
      if (!await _ping('10.8.0.1')) {
        throw const ApiException('No hubo respuesta a través del túnel VPN.');
      }
    } catch (_) {
      // The firewall may be fully or partially blocked even though the
      // tunnel never came up. Only spend a second UAC prompt on the
      // restore when the firewall is actually blocking; otherwise the
      // script never applied anything (e.g. the prompt was denied) and
      // the stale lock is just dropped.
      if (scriptRan && await _firewallIsBlocking()) {
        try {
          await _disableKillswitch();
        } catch (_) {
          // Restore failed: keep the lock so status stays honest
          // ("activado") and a later `killswitch off` or disconnect can
          // retry, unless the firewall is clear after all.
          if (!await _firewallIsBlocking()) await _deleteLock();
        }
      } else {
        await _deleteLock();
      }
      // Silent: only removes the service when it exists, so a failed
      // install does not pop up wireguard.exe's "service does not exist"
      // dialog on top of the real error.
      await _uninstallTunnelSilent(tunnel);
      if (!await isKillSwitchEnabled()) await _removeManagementRoute();
      _windowsConnection = null;
      rethrow;
    }
  }

  @override
  Future<void> disconnect() async {
    final id = await deviceId();
    final tunnel = _windowsConnection ?? tunnelName(id);
    // ONE UAC prompt: the tunnel uninstall and the firewall restore run in
    // a single elevated script. The script is best effort on both steps
    // and exits with the first failure code (20 = uninstall, 10 = firewall).
    final needsUninstall = await _serviceExists(tunnel);
    // Reconciled with the real firewall: a block with no lock file still
    // runs the restore, so disconnect recovers the orphaned state.
    final lockOn = await isKillSwitchEnabled();
    if (needsUninstall || lockOn) {
      final original = await _readLockOriginal();
      final expected = original ?? _allAllow;
      final code = await _serviceOrElevated(
        () async => _service.disconnect(
          uninstallTunnel: needsUninstall,
          wireguardExe: needsUninstall ? await _wireguardExe() : '',
          tunnel: tunnel,
          disableKillswitch: lockOn,
          original: original,
        ),
        () async => _runElevated(disconnectAdminScript(
          uninstallTunnel: needsUninstall,
          wireguardExe: needsUninstall ? await _wireguardExe() : '',
          tunnel: tunnel,
          disableKillswitch: lockOn,
          original: original,
        )),
      );
      if (code == _adminTunnelFailed) {
        // The firewall was restored even though the uninstall failed; the
        // lock is off now, and the isConnected check below reports it.
        // Verify the restore before believing it.
        await _verifyProfilesRestored(expected);
        await _deleteLock();
      } else if (code != _adminOk) {
        // The firewall restore failed: the lock stays on so the traffic
        // block is not silently lost.
        throw const ApiException(
            'No se pudo desactivar el bloqueo de tráfico. Revisa la autorización de administrador.');
      } else {
        await _verifyProfilesRestored(expected);
        await _deleteLock();
      }
    }
    if (await isConnected()) {
      throw const ApiException('No se pudo desconectar la VPN.');
    }
    await _removeManagementRoute();
    _windowsConnection = null;
  }

  @override
  Future<bool> isConnected() async {
    final id = await deviceId();
    final tunnel = _windowsConnection ?? tunnelName(id);
    return _serviceRunning(tunnel);
  }

  @override
  Future<bool?> gatewayReachable() async => _ping('10.8.0.1');

  @override
  Future<bool?> internetReachable() async => _ping('1.1.1.1');

  @override
  Future<bool?> dnsResponds() async {
    if (!await isKillSwitchEnabled()) return null;
    final id = await deviceId();
    final tunnel = _windowsConnection ?? tunnelName(id);
    final configFile = await _configFile(tunnel);
    if (!await configFile.exists()) return null;
    final dns = parseDns(await configFile.readAsString());
    if (dns == null ||
        InternetAddress.tryParse(dns)?.type != InternetAddressType.IPv4) {
      return null;
    }
    try {
      final result = await Process.run(
              'nslookup', ['netshield-connectivity.invalid', dns])
          .timeout(const Duration(seconds: 5));
      final out = result.stdout.toString();
      if (out.contains('Non-existent domain') ||
          out.contains('NXDOMAIN')) {
        return true;
      }
      if (out.contains('timed out') || out.contains('no se pudo')) {
        return false;
      }
      return result.exitCode == 0 ? true : null;
    } catch (_) {
      return null;
    }
  }

  @override
  Future<TrafficUsage?> trafficUsage() async {
    if (!await isConnected()) return null;
    final id = await deviceId();
    final tunnel = _windowsConnection ?? tunnelName(id);
    try {
      final wg = await _wgExe(await _wireguardExe());
      final result = await Process.run(wg, ['show', tunnel, 'transfer'])
          .timeout(const Duration(seconds: 5));
      if (result.exitCode != 0) return null;
      return parseTransfer(result.stdout.toString());
    } catch (_) {
      return null;
    }
  }
}
