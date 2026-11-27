// Client for the NetShield Windows Service (bin/netshield_service.dart).
//
// The service runs as SYSTEM and performs the privileged steps (firewall +
// WireGuard tunnel) so the app never needs a UAC prompt after the service
// is installed. The app talks to it over a loopback TCP socket
// (127.0.0.1:18099) with one JSON object per line in each direction:
//
//   client -> {"cmd":"connect","tunnel":"ns...","wireguardExe":"...",
//              "configPath":"...","endpoint":"140.84.183.78","allowSsh":false}
//   service -> {"ok":true,"exitCode":0}
//
// Exit codes match WindowsAdminExit: 0 = ok, 10 = firewall failed,
// 20 = tunnel failed. Loopback traffic is not filtered by the Windows
// Firewall, so the app can reach the service even while the killswitch
// is on. Pure Dart (dart:io only), no Flutter, so the CLI can use it too.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

class WindowsServiceClient {
  WindowsServiceClient({this.host = '127.0.0.1', this.port = 18099});

  final String host;
  final int port;

  /// True when the service answers a ping. Short timeout so a missing
  /// service fails fast and the caller can fall back to the UAC path.
  Future<bool> ping({Duration timeout = const Duration(seconds: 2)}) async {
    try {
      final result = await _send({'cmd': 'ping'}, timeout: timeout);
      return result['ok'] == true;
    } catch (_) {
      return false;
    }
  }

  /// Runs the connect script (traffic lock + tunnel install) in the
  /// service. Returns the exit code (0/10/20, see WindowsAdminExit).
  Future<int> connect({
    required String tunnel,
    required String wireguardExe,
    required String configPath,
    required String endpoint,
    required bool allowSsh,
    Duration timeout = const Duration(seconds: 120),
  }) async {
    final result = await _send({
      'cmd': 'connect',
      'tunnel': tunnel,
      'wireguardExe': wireguardExe,
      'configPath': configPath,
      'endpoint': endpoint,
      'allowSsh': allowSsh,
    }, timeout: timeout);
    return _exitCode(result);
  }

  /// Runs the disconnect script (tunnel uninstall + firewall restore).
  /// Returns the exit code (0/10/20).
  Future<int> disconnect({
    required bool uninstallTunnel,
    required String wireguardExe,
    required String tunnel,
    required bool disableKillswitch,
    Map<String, String>? original,
    Duration timeout = const Duration(seconds: 120),
  }) async {
    final result = await _send({
      'cmd': 'disconnect',
      'uninstallTunnel': uninstallTunnel,
      'wireguardExe': wireguardExe,
      'tunnel': tunnel,
      'disableKillswitch': disableKillswitch,
      if (original case final o?) 'original': o,
    }, timeout: timeout);
    return _exitCode(result);
  }

  /// Turns the traffic lock on or off. Returns the exit code (0, or 10
  /// when the firewall step failed).
  Future<int> setKillswitch({
    required bool enable,
    String? tunnel,
    String? endpoint,
    bool allowSsh = false,
    Map<String, String>? original,
    Duration timeout = const Duration(seconds: 60),
  }) async {
    final result = await _send({
      'cmd': 'killswitch',
      'enable': enable,
      if (tunnel case final t?) 'tunnel': t,
      if (endpoint case final e?) 'endpoint': e,
      'allowSsh': allowSsh,
      if (original case final o?) 'original': o,
    }, timeout: timeout);
    return _exitCode(result);
  }

  /// Adds or removes the /32 management route to the VPN endpoint (dev
  /// mode, localhost API only). Returns the exit code (0 = ok).
  Future<int> route({
    required bool add,
    required String endpoint,
    String? gateway,
    Duration timeout = const Duration(seconds: 30),
  }) async {
    final result = await _send({
      'cmd': 'route',
      'add': add,
      'endpoint': endpoint,
      if (gateway case final g?) 'gateway': g,
    }, timeout: timeout);
    return _exitCode(result);
  }

  int _exitCode(Map<String, dynamic> result) {
    final code = result['exitCode'];
    if (code is int) return code;
    if (result['ok'] == true) return 0;
    // A malformed failure still counts as a firewall failure so the
    // caller keeps the lock on rather than assuming the block is off.
    return 10;
  }

  /// Sends one JSON command and reads one JSON response line. Throws on
  /// connect failure, timeout or a malformed response.
  Future<Map<String, dynamic>> _send(Map<String, dynamic> command,
      {required Duration timeout}) async {
    final socket = await Socket.connect(host, port, timeout: timeout);
    try {
      socket.writeln(jsonEncode(command));
      await socket.flush();
      final line = await utf8.decoder
          .bind(socket)
          .transform(const LineSplitter())
          .first
          .timeout(timeout);
      final decoded = jsonDecode(line);
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException('La respuesta del servicio no es válida.');
      }
      return decoded;
    } finally {
      await socket.close();
    }
  }
}
