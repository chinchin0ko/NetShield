import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'api_client.dart';
import 'linux_vpn.dart';

/// Windows uses the official WireGuard for Windows client for the tunnel
/// and Windows Firewall rules for the killswitch.
///
/// Requirements: WireGuard for Windows installed
/// (https://www.wireguard.com/install, free). Tunnel and firewall changes
/// need administrator approval, so every privileged step asks for it
/// through a UAC prompt (an elevated PowerShell helper).
class WindowsVpn extends LinuxVpn {
  WindowsVpn(super.api);

  String? _windowsConnection;

  // -- Pure helpers (also covered by unit tests). ---------------------------

  /// Tunnel name from the device id, same scheme as Linux (`ns` + 12 hex).
  static String tunnelName(String deviceId) => 'ns${deviceId.substring(0, 12)}';

  /// Windows service name for a tunnel, as created by wireguard.exe.
  static String serviceName(String tunnel) => 'WireGuardTunnel\$$tunnel';

  /// IPv4 endpoint (host only) from a WireGuard config template.
  static String? parseEndpoint(String config) =>
      RegExp(r'^Endpoint\s*=\s*([0-9.]+):51820\s*$', multiLine: true)
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
    final found = await Process.run('where', ['wireguard.exe']);
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
    final found = await Process.run('where', ['wg.exe']);
    if (found.exitCode == 0) {
      final first = found.stdout.toString().split('\n').first.trim();
      if (first.isNotEmpty) return first;
    }
    throw const ApiException(
        'No se encontró wg.exe junto a WireGuard para Windows.');
  }

  // -- Privileged helper (UAC prompt, waits for the elevated step). ---------

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

  Future<void> _elevatedOrThrow(List<String> psLines, String failure) async {
    final code = await _runElevated(psLines);
    if (code != 0) throw ApiException(failure);
  }

  // -- Identity (per-account keys, same scheme as Linux). -------------------

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
    final result = await Process.run(wg, ['genkey']);
    if (result.exitCode != 0) {
      throw const ApiException('No se pudo crear la clave local de WireGuard.');
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
    final process = await Process.start(wg, ['pubkey']);
    process.stdin.writeln(privateKey);
    await process.stdin.close();
    final stdoutText = await utf8.decoder.bind(process.stdout).join();
    final stderrText = await utf8.decoder.bind(process.stderr).join();
    if (await process.exitCode != 0 || stderrText.isNotEmpty) {
      throw const ApiException('No se pudo derivar la clave pública.');
    }
    final key = stdoutText.trim();
    if (base64.decode(key).length != 32) {
      throw const ApiException('La clave pública es inválida.');
    }
    return key;
  }

  // -- Killswitch (Windows Firewall). ---------------------------------------

  static const _rulePrefix = 'NetShield Killswitch';

  /// Tailscale controlplane + DERP nodes (IPv4), fetched from the DERP map
  /// on 2026-11-22. Only used when the SSH exception is explicitly enabled
  /// (Ajustes > Permitir conexiones SSH).
  static const _tailscaleInfraIps = <String>[
    '102.67.165.185', '102.67.165.36', '102.67.165.90', '102.67.167.188',
    '102.67.167.245', '102.67.167.37', '103.6.84.152', '157.180.28.32',
    '162.248.221.199', '162.248.221.215', '162.248.221.248', '167.235.72.200',
    '172.105.166.103', '172.105.169.57', '172.105.179.230', '172.236.162.33',
    '172.236.162.40', '172.236.162.42', '172.237.28.183', '172.237.61.190',
    '172.237.61.194', '172.237.61.197', '172.237.66.30', '172.237.72.43',
    '172.237.72.79', '172.237.72.8', '172.238.6.179', '172.238.6.180',
    '172.238.6.34', '176.58.88.183', '176.58.90.104', '176.58.90.147',
    '176.58.90.207', '176.58.92.144', '176.58.92.254', '176.58.93.147',
    '176.58.93.154', '176.58.93.248', '178.156.134.232', '178.156.152.106',
    '178.156.152.91', '185.178.202.101', '185.178.202.33', '185.34.3.207',
    '185.34.3.232', '185.34.3.75', '185.40.234.113', '185.40.234.176',
    '185.40.234.219', '185.40.234.53', '185.40.234.77', '192.73.240.121',
    '192.73.240.132', '192.73.240.161', '192.73.242.187', '192.73.242.204',
    '192.73.242.28', '192.73.243.135', '192.73.243.141', '192.73.243.229',
    '192.73.244.245', '192.73.248.83', '192.73.252.134', '192.73.252.65',
    '198.18.186.205', '199.38.181.103', '199.38.181.104', '199.38.181.71',
    '199.38.181.93', '199.38.182.118', '205.147.105.30', '205.147.105.78',
    '208.111.34.178', '208.111.40.12', '208.111.40.216', '208.72.155.133',
    '208.83.233.233', '208.83.234.151', '209.177.145.118', '209.177.145.120',
    '209.177.156.197', '209.177.156.94', '209.177.158.15', '209.177.158.246',
    '45.159.97.144', '45.159.97.233', '45.159.97.61', '45.159.98.145',
    '45.159.98.196', '45.159.98.253', '46.62.141.44', '49.12.193.137',
    '49.13.204.141', '5.161.218.233', '65.109.143.62', '95.217.2.165',
  ];

  @override
  Future<bool> isKillSwitchEnabled() async =>
      File('${(await _appDir()).path}\\lock\\active.json').exists();

  Future<void> _enableKillswitch(String tunnel, String endpoint,
      {bool allowSsh = false}) async {
    final lock = await _lockFile();
    final commands = <String>[
      'Remove-NetFirewallRule -DisplayName "$_rulePrefix*" -ErrorAction SilentlyContinue',
      'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block',
      'New-NetFirewallRule -DisplayName "$_rulePrefix (tunel)" -Direction Outbound -Action Allow -InterfaceAlias "$tunnel" -Profile Any | Out-Null',
      'New-NetFirewallRule -DisplayName "$_rulePrefix (servidor)" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 51820 -RemoteAddress $endpoint -Profile Any | Out-Null',
      'New-NetFirewallRule -DisplayName "$_rulePrefix (DHCP)" -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 -Profile Any | Out-Null',
    ];
    if (allowSsh) {
      // SSH exception (opt-in, Ajustes > Permitir conexiones SSH): Tailscale
      // carries the inbound SSH session, so its interface, its WireGuard UDP
      // port and TCP 443 to its infrastructure must be allowed.
      final infra = _tailscaleInfraIps.join(',');
      commands.add(
          'New-NetFirewallRule -DisplayName "$_rulePrefix (SSH)" -Direction Outbound -Action Allow -InterfaceAlias "Tailscale" -Profile Any | Out-Null');
      commands.add(
          'New-NetFirewallRule -DisplayName "$_rulePrefix (SSH UDP)" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 41641 -Profile Any | Out-Null');
      commands.add(
          'New-NetFirewallRule -DisplayName "$_rulePrefix (SSH TCP)" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443 -RemoteAddress $infra -Profile Any | Out-Null');
    }
    await _elevatedOrThrow(commands,
        'No se pudo activar el bloqueo de tráfico. Revisa la autorización de administrador.');
    await lock.writeAsString(
        jsonEncode(
            {'tunnel': tunnel, 'endpoint': endpoint, 'allow_ssh': allowSsh}),
        flush: true);
  }

  Future<void> _disableKillswitch() async {
    await _elevatedOrThrow([
      'Remove-NetFirewallRule -DisplayName "$_rulePrefix*" -ErrorAction SilentlyContinue',
      'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow',
    ], 'No se pudo desactivar el bloqueo de tráfico. Revisa la autorización de administrador.');
    final lock = await _lockFile();
    if (await lock.exists()) await lock.delete();
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
      await _runElevated([
        '& "$wireguardExe" /uninstalltunnelservice "$tunnel"',
        'exit \$LASTEXITCODE',
      ]);
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
    await _elevatedOrThrow([
      'route add $endpoint mask 255.255.255.255 $gateway metric 5',
    ], 'No se pudo conservar el acceso a la API de desarrollo.');
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
      await _elevatedOrThrow([
        'route delete ${data['endpoint']}',
      ], 'No se pudo restaurar la ruta de administración.');
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
    var killswitchOn = false;
    try {
      await _keepDevelopmentTunnel(config);
      // Enable the lock first, like on Linux, so no traffic leaks
      // while the tunnel comes up.
      await _enableKillswitch(tunnel, endpoint,
          allowSsh: await isSshAllowed());
      killswitchOn = true;
      // Run wireguard.exe directly (the script is already elevated, so no
      // nested -Verb RunAs) and propagate its exit code: the old
      // Start-Process call swallowed failures, so a failed install only
      // surfaced 15 s later as "El túnel VPN no se activó."
      await _elevatedOrThrow([
        '& "$wireguardExe" /installtunnelservice "${configFile.path}"',
        'exit \$LASTEXITCODE',
      ], 'No se pudo instalar el túnel VPN. Revisa la autorización de administrador.');
      _windowsConnection = tunnel;
      await _waitForTunnel(tunnel);
      if (!await _ping('10.8.0.1')) {
        throw const ApiException('No hubo respuesta a través del túnel VPN.');
      }
    } catch (_) {
      if (killswitchOn) {
        try {
          await _disableKillswitch();
        } catch (_) {/* Best effort cleanup. */}
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
    if (await _serviceExists(tunnel)) {
      final wireguardExe = await _wireguardExe();
      await _elevatedOrThrow([
        '& "$wireguardExe" /uninstalltunnelservice "$tunnel"',
        'exit \$LASTEXITCODE',
      ], 'No se pudo desconectar la VPN.');
    }
    if (await isConnected()) {
      throw const ApiException('No se pudo desconectar la VPN.');
    }
    await _removeManagementRoute();
    if (await isKillSwitchEnabled()) await _disableKillswitch();
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
