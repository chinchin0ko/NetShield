import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:netshield_app/services/api_client.dart';

void main() {
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
