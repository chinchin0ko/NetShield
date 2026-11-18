import 'dart:convert';
import 'dart:io';

class ApiException implements Exception {
  const ApiException(this.message);
  final String message;
}

class ApiClient {
  ApiClient({String? baseUrl})
    : baseUrl = Uri.parse(baseUrl ?? const String.fromEnvironment(
        'NETSHIELD_API_URL',
        defaultValue: 'http://127.0.0.1:18000',
      ));

  final Uri baseUrl;

  Future<String> login(String username, String password) async {
    final isLoopback = baseUrl.host == '127.0.0.1' || baseUrl.host == 'localhost' || baseUrl.host == '::1';
    if (baseUrl.scheme != 'https' && !(baseUrl.scheme == 'http' && isLoopback)) {
      throw const ApiException('La dirección de la API debe usar HTTPS.');
    }
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
    try {
      final request = await client.postUrl(baseUrl.resolve('/auth/token'));
      request.headers.contentType = ContentType.json;
      request.add(utf8.encode(jsonEncode({'username': username, 'password': password})));
      final response = await request.close().timeout(const Duration(seconds: 10));
      final body = await utf8.decoder.bind(response).join();
      if (response.statusCode == 401) {
        throw const ApiException('Usuario o contraseña incorrectos.');
      }
      if (response.statusCode != 200) {
        throw const ApiException('La API no pudo iniciar sesión. Inténtalo de nuevo.');
      }
      final decoded = jsonDecode(body);
      if (decoded is! Map<String, dynamic> || decoded['access_token'] is! String || (decoded['access_token'] as String).isEmpty) {
        throw const ApiException('La API respondió con datos inesperados.');
      }
      return decoded['access_token'] as String;
    } on SocketException {
      throw const ApiException('No se pudo conectar con la API. Comprueba el túnel de desarrollo.');
    } on HttpException {
      throw const ApiException('No se pudo completar la conexión con la API.');
    } on FormatException {
      throw const ApiException('La API respondió con datos inesperados.');
    } finally {
      client.close(force: true);
    }
  }
}
