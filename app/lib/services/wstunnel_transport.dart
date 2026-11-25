import 'dart:async';
import 'dart:io';
import 'api_client.dart';

/// Owns only the child it starts. DNS is not needed after the traffic lock:
/// connect to the configured IPv4, but authenticate TLS against the API name.
class WstunnelTransport {
  Process? _process;
  String? _binary;
  List<String>? _arguments;
  int? localPort;
  Future<void>? _starting;

  static List<String> arguments(String endpoint, String host, int port) {
    if (InternetAddress.tryParse(endpoint)?.type != InternetAddressType.IPv4 ||
        !RegExp(r'^[a-zA-Z0-9.-]+$').hasMatch(host) ||
        InternetAddress.tryParse(host) != null) {
      throw const ApiException('El modo TCP requiere un dominio HTTPS válido.');
    }
    return ['client', '--tls-verify-certificate', '--tls-sni-override', host,
      '-H', 'Host: $host', '--http-upgrade-path-prefix', 'wstunnel',
      '--connection-retry-max-backoff', '5s', '--websocket-ping-frequency', '10s',
      '-L', 'udp://127.0.0.1:$port:127.0.0.1:443?timeout_sec=0',
      'wss://$endpoint:443'];
  }

  Future<void> start(String binary, String endpoint, String host) async {
    await stop();
    final reservation = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
    localPort = reservation.port;
    reservation.close();
    _binary = binary;
    _arguments = arguments(endpoint, host, localPort!);
    await ensureRunning();
  }

  Future<void> ensureRunning() async {
    if (_process != null || _arguments == null) return;
    if (_starting != null) return _starting!;
    _starting = _spawn();
    try { await _starting; } finally { _starting = null; }
  }

  Future<void> _spawn() async {
    final environment = Map<String, String>.from(Platform.environment)..['NO_COLOR'] = 'true';
    for (final key in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) {
      environment.remove(key);
    }
    final process = await Process.start(_binary!, _arguments!, environment: environment, includeParentEnvironment: false);
    _process = process;
    // Never accumulate unbounded logs or let a full pipe stall the transport.
    unawaited(process.stdout.drain<void>());
    unawaited(process.stderr.drain<void>());
    unawaited(process.exitCode.then((_) {
      if (identical(_process, process)) _process = null;
    }));
    for (var attempt = 0; attempt < 30; attempt++) {
      if (!identical(_process, process)) break;
      final sockets = await Process.run('ss', ['-H', '-lunp', 'sport = :$localPort']);
      if (identical(_process, process) && sockets.exitCode == 0 &&
          sockets.stdout.toString().contains('pid=${process.pid},')) {
        return;
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    process.kill();
    throw const ApiException('No se pudo iniciar el transporte TCP seguro.');
  }

  Future<void> stop() async {
    _arguments = null;
    // A monitor may be restarting the child when the user disconnects.
    try { await _starting; } catch (_) { /* Stop even after a failed start. */ }
    final process = _process;
    _process = null;
    if (process != null) {
      process.kill();
      try { await process.exitCode.timeout(const Duration(seconds: 3)); }
      on TimeoutException { process.kill(ProcessSignal.sigkill); await process.exitCode; }
    }
    localPort = null;
  }
}
