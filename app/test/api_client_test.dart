import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:netshield_app/services/api_client.dart';

void main() {
  test('reads authenticated per-device server counters and unavailable values', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      expect(request.headers.value(HttpHeaders.authorizationHeader), 'Bearer token');
      request.response.write('{"scope":"current_wireguard_counters","devices":[{"device_id":"${'a' * 32}","upload_bytes":null,"download_bytes":12}]}');
      await request.response.close();
    });
    final api = ApiClient(baseUrl: 'http://127.0.0.1:${server.port}');
    try {
      final devices = await api.vpnUsage('token');
      expect(devices.single.uploadBytes, isNull);
      expect(devices.single.downloadBytes, 12);
    } finally {
      api.close();
      await server.close(force: true);
    }
  });

  test('reads sampled history and rejects malformed devices', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    var invalid = false;
    server.listen((request) async {
      await request.drain<void>();
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({'scope': 'estimated_sampled_counters', 'timezone': 'UTC', 'days': [
        {'device_id': invalid ? 'bad' : 'a' * 32, 'day': '2026-11-21', 'upload_bytes': 12, 'download_bytes': null, 'incomplete': true}
      ]}));
      await request.response.close();
    });
    final api = ApiClient(baseUrl: 'http://127.0.0.1:${server.port}');
    try {
      final result = await api.vpnUsageHistory('token');
      expect(result.single.uploadBytes, 12);
      expect(result.single.downloadBytes, isNull);
      expect(result.single.incomplete, isTrue);
      invalid = true;
      await expectLater(api.vpnUsageHistory('token'), throwsA(isA<ApiException>()));
    } finally {
      api.close();
      await server.close(force: true);
    }
  });

  test('explains the VPN device quota', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      await request.drain<void>();
      request.response.statusCode = 409;
      request.response.write('{"detail":"Device limit reached"}');
      await request.response.close();
    });
    final api = ApiClient(baseUrl: 'http://127.0.0.1:${server.port}');
    try {
      await expectLater(api.vpnConfig('test', 'a' * 32, 'test'), throwsA(isA<ApiException>().having((e) => e.message, 'message', contains('límite de dispositivos'))));
    } finally {
      api.close();
      await server.close(force: true);
    }
  });

  test('uses the public HTTPS API by default', () {
    final api = ApiClient();
    expect(api.baseUrl.toString(), 'https://api.netshield.lat');
    api.close();
  });

  test('login explains a rate limit response', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      await request.drain<void>();
      request.response.statusCode = 429;
      request.response.headers.set('Retry-After', '300');
      await request.response.close();
    });
    final api = ApiClient(baseUrl: 'http://127.0.0.1:${server.port}');
    try {
      await expectLater(api.login('demo', 'password'), throwsA(isA<ApiException>().having((e) => e.message, 'message', contains('Demasiados intentos'))));
    } finally {
      api.close();
      await server.close(force: true);
    }
  });
}
