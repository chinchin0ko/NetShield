import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:netshield_app/services/wstunnel_transport.dart';
import 'package:netshield_app/services/api_client.dart';

void main() {
  test('TCP uses pinned IPv4 with authenticated TLS and matching Host', () {
    final args = WstunnelTransport.arguments('192.0.2.1', 'api.netshield.lat', 51900);
    expect(args.last, 'wss://192.0.2.1:443');
    expect(args, contains('--tls-verify-certificate'));
    expect(args[args.indexOf('--tls-sni-override') + 1], 'api.netshield.lat');
    expect(args, contains('Host: api.netshield.lat'));
    expect(args, contains('udp://127.0.0.1:51900:127.0.0.1:443?timeout_sec=0'));
    expect(() => WstunnelTransport.arguments('192.0.2.1', '127.0.0.1', 51900), throwsA(isA<ApiException>()));
  });

  final binary = Platform.environment['WSTUNNEL_BINARY'];
  test('Real child restarts on the same local port and stops cleanly', () async {
    final transport = WstunnelTransport();
    addTearDown(transport.stop);
    await transport.start(binary!, '192.0.2.1', 'api.netshield.lat');
    final port = transport.localPort;
    Future<int> pid() async {
      final sockets = await Process.run('ss', ['-H', '-lunp', 'sport = :$port']);
      return int.parse(RegExp(r'pid=(\d+),').firstMatch(sockets.stdout.toString())!.group(1)!);
    }
    final original = await pid();
    Process.killPid(original, ProcessSignal.sigkill);
    await Future<void>.delayed(const Duration(milliseconds: 200));
    await transport.ensureRunning();
    expect(await pid(), isNot(original));
    expect(transport.localPort, port);
    await transport.stop();
    final sockets = await Process.run('ss', ['-H', '-lunp', 'sport = :$port']);
    expect(sockets.stdout.toString().trim(), isEmpty);
  }, skip: binary == null ? 'Set WSTUNNEL_BINARY for local subprocess integration' : false);
}
