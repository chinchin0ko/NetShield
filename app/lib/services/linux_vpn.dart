import 'dart:io';
import 'dart:async';
import 'dart:math';
import 'dart:convert';
import 'api_client.dart';
import 'wstunnel_transport.dart';

class TrafficUsage {
  const TrafficUsage(this.receivedBytes, this.sentBytes);
  final int receivedBytes;
  final int sentBytes;
}

class LinuxVpn {
  LinuxVpn(this.api);
  final ApiClient api;
  String? _connection;
  final WstunnelTransport _transport = WstunnelTransport();

  Future<String> deviceId() => _deviceId();
  Future<bool> isKillSwitchEnabled() => File('/run/netshield-lock/active').exists();

  /// Whether the user allowed inbound SSH while the traffic lock is active
  /// (Ajustes > Permitir conexiones SSH, desktop only). Off by default: the
  /// exception deliberately weakens the lock, so it is opt-in.
  Future<File> _sshSettingFile() async {
    final home = Platform.environment['HOME'];
    if (home == null) throw const ApiException('No se encontró tu carpeta personal.');
    return File('$home/.local/share/netshield/allow-ssh');
  }

  Future<bool> isSshAllowed() async {
    try {
      final file = await _sshSettingFile();
      if (!await file.exists()) return false;
      return (await file.readAsString()).trim() == '1';
    } catch (_) {
      return false;
    }
  }

  Future<void> setSshAllowed(bool allowed) async {
    final file = await _sshSettingFile();
    await file.parent.create(recursive: true);
    await file.writeAsString(allowed ? '1' : '0', flush: true);
    await Process.run('chmod', ['600', file.path]);
  }

  /// TCP mode (wstunnel): carry WireGuard over a WebSocket seguro on TCP 443 when
  /// the network blocks WireGuard UDP. Off by default; the user enables it in
  /// Ajustes. The setting applies on the next connection.
  Future<File> _tcpModeFile() async {
    final home = Platform.environment['HOME'];
    if (home == null) throw const ApiException('No se encontró tu carpeta personal.');
    return File('$home/.local/share/netshield/tcp-mode');
  }

  Future<bool> isTcpMode() async {
    try {
      final file = await _tcpModeFile();
      if (!await file.exists()) return false;
      return (await file.readAsString()).trim() == '1';
    } catch (_) {
      return false;
    }
  }

  Future<void> setTcpMode(bool enabled) async {
    final file = await _tcpModeFile();
    await file.parent.create(recursive: true);
    await file.writeAsString(enabled ? '1' : '0', flush: true);
    await Process.run('chmod', ['600', file.path]);
  }

  /// Locate the wstunnel client binary: user install first, then the
  /// packaged one, then anything on PATH.
  Future<String?> _wstunnelPath() async {
    final home = Platform.environment['HOME'];
    final candidates = <String>[
      '/usr/lib/netshield/wstunnel',
      if (home != null) '$home/.local/share/netshield/wstunnel',
      '/usr/local/bin/wstunnel',
    ];
    for (final candidate in candidates) {
      if (await File(candidate).exists()) return candidate;
    }
    final which = await Process.run('which', ['wstunnel']);
    if (which.exitCode == 0) {
      final found = which.stdout.toString().trim();
      if (found.isNotEmpty) return found;
    }
    return null;
  }

  Future<void> _startWstunnel(String endpoint) async {
    final binary = await _wstunnelPath();
    if (binary == null) {
      throw const ApiException('Falta el transporte TCP. Reinstala el paquete de NetShield.');
    }
    await _transport.start(binary, endpoint, api.baseUrl.host);
  }

  Future<void> _stopWstunnel() => _transport.stop();

  Future<File> _endpointFile() async {
    final home = Platform.environment['HOME'];
    if (home == null) throw const ApiException('No se encontró tu carpeta personal.');
    return File('$home/.local/share/netshield/vpn-endpoint');
  }

  Future<void> setKillSwitch(bool enabled) async {
    if (!enabled) {
      if (await isKillSwitchEnabled()) await _switch(['disable']);
      return;
    }
    if (await isKillSwitchEnabled()) return;
    if (!await isConnected()) throw const ApiException('Conecta la VPN antes de activar el bloqueo.');
    final file = await _endpointFile();
    if (!await file.exists()) throw const ApiException('Desconecta y vuelve a conectar la VPN para activar el bloqueo.');
    final endpoint = (await file.readAsString()).trim();
    if (InternetAddress.tryParse(endpoint)?.type != InternetAddressType.IPv4) throw const ApiException('La dirección del servidor VPN es inválida.');
    final id = await _deviceId();
    final args = ['enable', 'ns${id.substring(0, 12)}', endpoint];
    if (await isSshAllowed()) args.add('allow-ssh');
    if (await isTcpMode()) args.add('tcp-mode');
    await _switch(args);
  }

  /// Check the VPN gateway through this device's interface. A timeout or
  /// failed probe does not establish whether the physical network or server
  /// is responsible, and says nothing about DNS or public Internet access.
  Future<bool?> gatewayReachable() async {
    try { await _transport.ensureRunning(); } catch (_) { return false; }
    return _pingThroughTunnel('10.8.0.1');
  }

  /// An unanswered ICMP probe is inconclusive: some networks block ping.
  Future<bool?> internetReachable() => _pingThroughTunnel('1.1.1.1');

  /// Obtain the exit IP using the VPN's source address, never an unbound
  /// connection that could accidentally report the physical network's IP.
  Future<String?> publicExitIp() async {
    if (!Platform.isLinux || !await isKillSwitchEnabled()) return null;
    HttpClient? client;
    try {
      final id = await _deviceId();
      final name = 'ns${id.substring(0, 12)}';
      final result = await Process.run('ip', ['-j', '-4', 'addr', 'show', 'dev', name]);
      final devices = jsonDecode(result.stdout.toString()) as List;
      final info = (devices.first as Map)['addr_info'] as List;
      final local = InternetAddress((info.first as Map)['local'] as String);
      client = HttpClient()..connectionTimeout = const Duration(seconds: 4);
      client.connectionFactory = (uri, proxyHost, proxyPort) async {
        if (proxyHost != null) throw const SocketException('Proxy not allowed');
        final addresses = await InternetAddress.lookup(uri.host, type: InternetAddressType.IPv4);
        final task = await Socket.startConnect(addresses.first, uri.port, sourceAddress: local);
        // A custom factory must do TLS itself: a plain socket sends cleartext
        // HTTP to the HTTPS port and the server answers 400.
        if (uri.scheme == 'https') {
          return ConnectionTask.fromSocket(
            task.socket.then((socket) => SecureSocket.secure(socket, host: uri.host)),
            task.cancel,
          );
        }
        return task;
      };
      final request = await client.getUrl(Uri.parse('https://api.ipify.org')).timeout(const Duration(seconds: 5));
      request.followRedirects = false;
      final response = await request.close().timeout(const Duration(seconds: 5));
      if (response.statusCode != 200) return null;
      final text = await response.transform(utf8.decoder).join().timeout(const Duration(seconds: 5));
      return InternetAddress.tryParse(text.trim())?.address;
    } catch (_) {
      return null;
    } finally {
      client?.close(force: true);
    }
  }

  Future<bool?> _pingThroughTunnel(String address) async {
    final id = await _deviceId();
    final name = 'ns${id.substring(0, 12)}';
    try {
      final result = await Process.run('ping', ['-4', '-I', name, '-c', '1', '-W', '3', address])
          .timeout(const Duration(seconds: 5));
      if (result.exitCode == 0) return true;
      if (result.exitCode == 1) return false;
      return null;
    } on ProcessException {
      return null;
    } on TimeoutException {
      return null;
    }
  }

  /// Query the VPN resolver only while the traffic lock is active. The socket
  /// is bound to the tunnel address and the resolver route must use the tunnel.
  Future<bool?> dnsResponds() async {
    if (!await isKillSwitchEnabled()) return null;
    final id = await _deviceId();
    final name = 'ns${id.substring(0, 12)}';
    RawDatagramSocket? socket;
    try {
      final dns = await Process.run('nmcli', ['-g', 'IP4.DNS', 'device', 'show', name]).timeout(const Duration(seconds: 3));
      final server = InternetAddress.tryParse(dns.stdout.toString().trim().split('\n').first);
      if (dns.exitCode != 0 || server?.type != InternetAddressType.IPv4) return null;
      final addresses = await Process.run('ip', ['-j', '-4', 'addr', 'show', 'dev', name]).timeout(const Duration(seconds: 3));
      if (addresses.exitCode != 0) return null;
      final devices = jsonDecode(addresses.stdout.toString()) as List;
      final info = (devices.first as Map)['addr_info'] as List;
      final local = InternetAddress.tryParse((info.first as Map)['local'] as String);
      if (local?.type != InternetAddressType.IPv4) return null;
      final route = await Process.run('ip', ['-j', '-4', 'route', 'get', server!.address, 'from', local!.address]).timeout(const Duration(seconds: 3));
      if (route.exitCode != 0) return null;
      final routes = jsonDecode(route.stdout.toString()) as List;
      if (routes.isEmpty || (routes.first as Map)['dev'] != name || !await isKillSwitchEnabled()) return null;
      socket = await RawDatagramSocket.bind(local, 0);
      final transaction = Random.secure().nextInt(65536);
      final packet = <int>[transaction >> 8, transaction & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
      for (final label in ['netshield-connectivity', 'invalid']) {
        packet.add(label.length);
        packet.addAll(ascii.encode(label));
      }
      packet.addAll([0, 0, 1, 0, 1]);
      socket.send(packet, server, 53);
      final response = await socket.where((event) => event == RawSocketEvent.read).map((_) => socket!.receive()).where((d) => d != null && d.address == server && d.port == 53 && d.data.length >= 12 && d.data[0] == transaction >> 8 && d.data[1] == (transaction & 255) && (d.data[2] & 0x80) != 0).first.timeout(const Duration(seconds: 3), onTimeout: () => null);
      if (response == null) return false;
      final code = response.data[3] & 15;
      return code == 0 || code == 3;
    } catch (_) {
      return null;
    } finally {
      socket?.close();
    }
  }

  Future<TrafficUsage?> trafficUsage() async {
    if (!await isConnected()) return null;
    final id = await _deviceId();
    final base = '/sys/class/net/ns${id.substring(0, 12)}/statistics';
    try {
      final received = int.parse((await File('$base/rx_bytes').readAsString()).trim());
      final sent = int.parse((await File('$base/tx_bytes').readAsString()).trim());
      if (received < 0 || sent < 0) return null;
      return TrafficUsage(received, sent);
    } on FileSystemException {
      return null;
    } on FormatException {
      return null;
    }
  }

  Future<void> _switch(List<String> arguments) async {
    const packaged = '/usr/lib/netshield/netshield-killswitch';
    const legacy = '/usr/local/sbin/netshield-killswitch';
    final helper = await File(packaged).exists() ? packaged : legacy;
    if (!await File(helper).exists()) {
      throw const ApiException('Falta instalar el bloqueo de tráfico de NetShield. Consulta las instrucciones de instalación.');
    }
    final result = await Process.run('pkexec', [helper, ...arguments]);
    if (result.exitCode != 0) throw const ApiException('No se pudo cambiar el bloqueo de tráfico. Revisa la autorización de administrador.');
  }

  Future<String> _deviceId() async {
    final home = Platform.environment['HOME'];
    if (home == null) throw const ApiException('No se encontró tu carpeta personal.');
    final directory = Directory('$home/.local/share/netshield');
    await directory.create(recursive: true);
    await Process.run('chmod', ['700', directory.path]);
    final file = File('${directory.path}/device-id');
    if (await file.exists()) {
      final value = (await file.readAsString()).trim();
      if (RegExp(r'^[0-9a-f]{32}$').hasMatch(value)) return value;
      throw const ApiException('El identificador del dispositivo es inválido.');
    }
    final random = Random.secure();
    final value = List.generate(16, (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
    await file.writeAsString(value, flush: true);
    await Process.run('chmod', ['600', file.path]);
    return value;
  }

  Future<String> _privateKey(String account) async {
    final home = Platform.environment['HOME'];
    if (home == null) throw const ApiException('No se encontró tu carpeta personal.');
    // WireGuard public keys must be unique across peers. Keep separate keys
    // for accounts that sign in on the same computer.
    final accountId = base64Url.encode(utf8.encode(account)).replaceAll('=', '');
    if (accountId.isEmpty || accountId.length > 172) throw const ApiException('La cuenta es inválida.');
    final directory = Directory('$home/.local/share/netshield/accounts');
    await directory.create(recursive: true);
    final dirPermission = await Process.run('chmod', ['700', directory.path]);
    if (dirPermission.exitCode != 0) throw const ApiException('No se pudo proteger la carpeta de claves.');
    final file = File('${directory.path}/$accountId.key');
    if (await file.exists()) {
      final key = (await file.readAsString()).trim();
      try {
        if (base64.decode(key).length == 32 && base64.encode(base64.decode(key)) == key) return key;
      } catch (_) { /* Reject invalid key material. */ }
      throw const ApiException('La clave local de WireGuard es inválida.');
    }
    final result = await Process.run('wg', ['genkey']);
    if (result.exitCode != 0) throw const ApiException('No se pudo crear la clave local de WireGuard.');
    final key = result.stdout.toString().trim();
    if (base64.decode(key).length != 32) throw const ApiException('La clave generada es inválida.');
    await file.writeAsString(key, flush: true);
    final permission = await Process.run('chmod', ['600', file.path]);
    if (permission.exitCode != 0) throw const ApiException('No se pudieron proteger los permisos de la clave.');
    return key;
  }

  Future<String> _publicKey(String privateKey) async {
    final process = await Process.start('wg', ['pubkey']);
    process.stdin.writeln(privateKey);
    await process.stdin.close();
    final stdoutText = await utf8.decoder.bind(process.stdout).join();
    final stderrText = await utf8.decoder.bind(process.stderr).join();
    if (await process.exitCode != 0 || stderrText.isNotEmpty) throw const ApiException('No se pudo derivar la clave pública.');
    final key = stdoutText.trim();
    if (base64.decode(key).length != 32) throw const ApiException('La clave pública es inválida.');
    return key;
  }

  Future<void> _nm(List<String> args, {bool check = true}) async {
    final result = await Process.run('nmcli', args).timeout(const Duration(seconds: 45));
    if (check && result.exitCode != 0) throw const ApiException('NetworkManager no pudo activar la VPN.');
  }

  Future<File> _routeFile() async {
    final home = Platform.environment['HOME'];
    if (home == null) throw const ApiException('No se encontró tu carpeta personal.');
    return File('$home/.local/share/netshield/management-route.json');
  }

  Future<void> _keepDevelopmentTunnel(String config, {bool tcpMode = false}) async {
    if (!tcpMode && api.baseUrl.host != '127.0.0.1' && api.baseUrl.host != 'localhost') return;
    final endpoint = RegExp(r'^Endpoint\s*=\s*([0-9.]+):\d+\s*$', multiLine: true).firstMatch(config)?.group(1);
    if (endpoint == null || InternetAddress.tryParse(endpoint)?.type != InternetAddressType.IPv4) {
      throw const ApiException('No se encontró la dirección IPv4 del servidor VPN.');
    }
    final result = await Process.run('ip', ['-j', '-4', 'route', 'get', endpoint]);
    if (result.exitCode != 0) throw const ApiException('No se encontró la ruta de administración.');
    final routes = jsonDecode(result.stdout.toString());
    if (routes is! List || routes.isEmpty || routes[0] is! Map) throw const ApiException('La ruta de administración es inválida.');
    final route = routes[0] as Map;
    final device = route['dev'];
    final gateway = route['gateway'];
    if (device is! String || gateway is! String || InternetAddress.tryParse(gateway)?.type != InternetAddressType.IPv4 || !RegExp(r'^[a-zA-Z0-9_.-]{1,15}$').hasMatch(device)) {
      throw const ApiException('No se pudo conservar el acceso a la API de desarrollo.');
    }
    final routeValue = '$endpoint/32 $gateway 42777';
    final file = await _routeFile();
    await file.writeAsString(jsonEncode({'device': device, 'route': routeValue}), flush: true);
    await Process.run('chmod', ['600', file.path]);
    await _nm(['device', 'modify', device, '+ipv4.routes', routeValue]);
  }

  Future<void> _removeManagementRoute() async {
    final file = await _routeFile();
    if (!await file.exists()) return;
    final data = jsonDecode(await file.readAsString());
    if (data is! Map || data['device'] is! String || data['route'] is! String || !RegExp(r'^[a-zA-Z0-9_.-]{1,15}$').hasMatch(data['device']) || !RegExp(r'^[0-9.]+/32 [0-9.]+ 42777$').hasMatch(data['route'])) {
      throw const ApiException('No se pudo restaurar la ruta de administración.');
    }
    await _nm(['device', 'modify', data['device'], '-ipv4.routes', data['route']]);
    await file.delete();
  }

  Future<void> connect(String token, String account) async {
    if (!Platform.isLinux) throw const ApiException('Esta versión solo permite conexiones en Linux.');
    final id = await _deviceId();
    final privateKey = await _privateKey(account);
    final publicKey = await _publicKey(privateKey);
    final template = await api.vpnConfig(token, id, publicKey);
    if (!RegExp(r'^PrivateKey\s*=\s*REPLACE_ME\s*$', multiLine: true).hasMatch(template)) {
      throw const ApiException('El servidor no aceptó la clave pública local.');
    }
    final config = template.replaceFirst(RegExp(r'^PrivateKey\s*=\s*REPLACE_ME\s*$', multiLine: true), 'PrivateKey = $privateKey');
    if (!RegExp(r'^AllowedIPs\s*=.*\b0\.0\.0\.0/0\b.*::/0\s*$', multiLine: true).hasMatch(config)) {
      throw const ApiException('La configuración VPN no incluye rutas completas IPv4 e IPv6.');
    }
    final name = 'ns${id.substring(0, 12)}';
    final endpoint = RegExp(r'^Endpoint\s*=\s*([0-9.]+):\d+\s*$', multiLine: true).firstMatch(config)?.group(1);
    if (endpoint == null || InternetAddress.tryParse(endpoint)?.type != InternetAddressType.IPv4) {
      throw const ApiException('La dirección del servidor VPN es inválida.');
    }
    final endpointFile = await _endpointFile();
    await endpointFile.writeAsString(endpoint, flush: true);
    await Process.run('chmod', ['600', endpointFile.path]);
    final temp = await Directory.systemTemp.createTemp('netshield-');
    try {
      final tcpMode = await isTcpMode();
      await _keepDevelopmentTunnel(config, tcpMode: tcpMode);
      var effectiveConfig = config;
      if (tcpMode) {
        await _startWstunnel(endpoint);
        // Point WireGuard at the local wstunnel listener instead of the
        // server: packets go UDP -> wstunnel -> WebSocket/TLS/TCP 443 -> server.
        effectiveConfig = config.replaceFirst(
          RegExp(r'^Endpoint\s*=\s*[0-9.]+:\d+\s*$', multiLine: true),
          'Endpoint = 127.0.0.1:${_transport.localPort}',
        );
      }
      final args = ['enable', name, endpoint];
      if (await isSshAllowed()) args.add('allow-ssh');
      if (tcpMode) args.add('tcp-mode');
      await _switch(args);
      final file = File('${temp.path}/$name.conf');
      await file.writeAsString(effectiveConfig, flush: true);
      await Process.run('chmod', ['600', file.path]);
      // Only replace profiles created by this application for this device.
      await _nm(['connection', 'delete', 'id', name], check: false);
      await _nm(['connection', 'import', 'type', 'wireguard', 'file', file.path]);
      _connection = name;
      // wg-easy currently has no IPv6 gateway. Assign an IPv6 address so
      // NetworkManager installs the IPv6 default route into WireGuard; IPv6
      // then fails closed instead of falling back to the physical interface.
      await _nm(['connection', 'modify', 'id', name, 'connection.autoconnect', 'no', 'ipv6.method', 'manual', 'ipv6.addresses', 'fd42:4e53::2/128', 'ipv4.dns-priority', '-50']);
      await _nm(['connection', 'up', 'id', name]);
      for (final address in ['1.1.1.1', '2606:4700:4700::1111']) {
        final family = address.contains(':') ? '-6' : '-4';
        final route = await Process.run('ip', [family, 'route', 'get', address]);
        if (route.exitCode != 0 || !RegExp('\\bdev ${RegExp.escape(name)}\\b').hasMatch(route.stdout.toString())) {
          throw const ApiException('La VPN no pudo asegurar las rutas de red.');
        }
      }
      if (tcpMode) {
        final external = await Process.run('ip', ['-j', '-4', 'route', 'get', endpoint]);
        final routes = jsonDecode(external.stdout.toString()) as List;
        if (external.exitCode != 0 || routes.isEmpty || (routes.first as Map)['dev'] == name) {
          throw const ApiException('El transporte TCP no conserva una ruta externa al servidor.');
        }
      }
      var reachable = false;
      for (var attempt = 0; attempt < 3; attempt++) {
        if (await gatewayReachable() == true) { reachable = true; break; }
      }
      if (!reachable) throw const ApiException('No hubo respuesta a través del túnel VPN. El bloqueo permanece activo.');
    } catch (_) {
      // An activated interface without a working tunnel is not a connection.
      // Keep the traffic lock, but remove this attempt's profile and child.
      await _nm(['connection', 'delete', 'id', name], check: false);
      await _stopWstunnel();
      try { await _removeManagementRoute(); } catch (_) { /* Retry on disconnect. */ }
      rethrow;
    } finally {
      await temp.delete(recursive: true);
    }
  }

  Future<void> disconnect() async {
    final id = await _deviceId();
    final name = _connection ?? 'ns${id.substring(0, 12)}';
    await _nm(['connection', 'delete', 'id', name], check: false);
    await _stopWstunnel();
    if (await isConnected()) {
      throw const ApiException('No se pudo desconectar la VPN.');
    }
    await _removeManagementRoute();
    if (await isKillSwitchEnabled()) await _switch(['disable']);
    _connection = null;
  }

  Future<bool> isConnected() async {
    final id = await _deviceId();
    final name = 'ns${id.substring(0, 12)}';
    final result = await Process.run('nmcli', ['-t', '-f', 'NAME', 'connection', 'show', '--active']);
    if (result.exitCode != 0) throw const ApiException('No se pudo consultar NetworkManager.');
    final active = (result.stdout as String).split('\n').contains(name);
    if (active) _connection = name;
    return active;
  }
}
