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

  test('login returns both the access and the refresh token', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      await request.drain<void>();
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({'access_token': 'access-1', 'refresh_token': 'refresh-1', 'token_type': 'bearer', 'expires_in': 1800}));
      await request.response.close();
    });
    final api = ApiClient(baseUrl: 'http://127.0.0.1:${server.port}');
    try {
      final session = await api.login('demo', 'password');
      expect(session.accessToken, 'access-1');
      expect(session.refreshToken, 'refresh-1');
    } finally {
      api.close();
      await server.close(force: true);
    }
  });

  test('an expired access token is refreshed silently and the call retried', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    var usageCalls = 0;
    server.listen((request) async {
      await request.drain<void>();
      if (request.uri.path == '/auth/refresh') {
        request.response.headers.contentType = ContentType.json;
        request.response.write(jsonEncode({'access_token': 'access-2', 'refresh_token': 'refresh-2', 'token_type': 'bearer', 'expires_in': 1800}));
        await request.response.close();
        return;
      }
      usageCalls++;
      if (usageCalls == 1) {
        // First call uses the expired access token.
        expect(request.headers.value(HttpHeaders.authorizationHeader), 'Bearer access-1');
        request.response.statusCode = 401;
        await request.response.close();
        return;
      }
      // Retried with the fresh access token.
      expect(request.headers.value(HttpHeaders.authorizationHeader), 'Bearer access-2');
      request.response.headers.contentType = ContentType.json;
      request.response.write('{"scope":"current_wireguard_counters","devices":[{"device_id":"${'a' * 32}","upload_bytes":1,"download_bytes":2}]}');
      await request.response.close();
    });
    final api = ApiClient(baseUrl: 'http://127.0.0.1:${server.port}');
    String? refreshedAccess, refreshedRefresh;
    api.onSessionRefreshed = (access, refresh) { refreshedAccess = access; refreshedRefresh = refresh; };
    try {
      api.setSession('refresh-1');
      final devices = await api.vpnUsage('access-1');
      expect(devices.single.uploadBytes, 1);
      expect(usageCalls, 2);
      expect(refreshedAccess, 'access-2');
      expect(refreshedRefresh, 'refresh-2');
    } finally {
      api.close();
      await server.close(force: true);
    }
  });

  test('a failed refresh reports the session as expired', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      await request.drain<void>();
      request.response.statusCode = 401;
      await request.response.close();
    });
    final api = ApiClient(baseUrl: 'http://127.0.0.1:${server.port}');
    try {
      api.setSession('refresh-1');
      await expectLater(api.vpnUsage('access-1'), throwsA(isA<ApiException>().having((e) => e.message, 'message', contains('sesión venció'))));
    } finally {
      api.close();
      await server.close(force: true);
    }
  });
}
