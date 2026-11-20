import 'dart:convert';
import 'dart:async';
import 'dart:io';
import 'dev_tunnel.dart';

class ApiException implements Exception {
  const ApiException(this.message);
  final String message;
}

class ApiClient {
  ApiClient({String? baseUrl, DevTunnel? tunnel})
    : baseUrl = Uri.parse(baseUrl ?? const String.fromEnvironment(
        'NETSHIELD_API_URL',
        defaultValue: 'https://api.netshield.lat',
      )),
      _tunnel = tunnel ?? (baseUrl == null && const String.fromEnvironment('NETSHIELD_API_URL', defaultValue: 'https://api.netshield.lat') == 'http://127.0.0.1:18000' ? DevTunnel() : null);

  final Uri baseUrl;
  final DevTunnel? _tunnel;

  Future<Uri> _url(String path) async {
    try {
      return (_tunnel == null ? baseUrl : await _tunnel.ensureStarted()).resolve(path);
    } on DevTunnelException catch (e) {
      throw ApiException(e.message);
    } on TimeoutException {
      throw const ApiException('El acceso a la API tardó demasiado. Comprueba tu conexión a Internet.');
    }
  }

  void close() => _tunnel?.close();

  ApiException _connectionError() {
    _tunnel?.reset();
    return const ApiException('No se pudo conectar con la API. Comprueba tu conexión e inténtalo otra vez.');
  }

  Future<dynamic> _authorized(String token, String method, String path) async {
    final isLoopback = baseUrl.host == '127.0.0.1' || baseUrl.host == 'localhost' || baseUrl.host == '::1';
    if (baseUrl.scheme != 'https' && !(baseUrl.scheme == 'http' && isLoopback)) throw const ApiException('La dirección de la API debe usar HTTPS.');
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
    try {
      final request = await client.openUrl(method, await _url(path));
      request.followRedirects = false;
      request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
      final response = await request.close().timeout(const Duration(seconds: 25));
      final body = await utf8.decoder.bind(response).join();
      if (response.statusCode == 401) throw const ApiException('La sesión venció. Vuelve a iniciar sesión.');
      if (response.statusCode != 200 && response.statusCode != 204) throw const ApiException('No se pudo administrar el dispositivo.');
      return body.isEmpty ? null : jsonDecode(body);
    } on SocketException {
      throw _connectionError();
    } on TimeoutException {
      throw _connectionError();
    } finally {
      client.close(force: true);
    }
  }

  Future<List<Map<String, dynamic>>> vpnDevices(String token) async {
    final result = await _authorized(token, 'GET', '/vpn/devices');
    if (result is! Map || result['devices'] is! List) throw const ApiException('La lista de dispositivos es inválida.');
    return (result['devices'] as List).map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  Future<void> revokeVpnDevice(String token, String deviceId) async {
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(deviceId)) throw const ApiException('El dispositivo es inválido.');
    await _authorized(token, 'POST', '/vpn/devices/$deviceId/revoke');
  }

  Future<String> vpnConfig(String token, String deviceId, String publicKey) async {
    final isLoopback = baseUrl.host == '127.0.0.1' || baseUrl.host == 'localhost' || baseUrl.host == '::1';
    if (baseUrl.scheme != 'https' && !(baseUrl.scheme == 'http' && isLoopback)) {
      throw const ApiException('La dirección de la API debe usar HTTPS.');
    }
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
    try {
      final request = await client.postUrl(await _url('/vpn/config'));
      request.followRedirects = false;
      request.headers.contentType = ContentType.json;
      request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
      request.add(utf8.encode(jsonEncode({'device_id': deviceId, 'public_key': publicKey})));
      final response = await request.close().timeout(const Duration(seconds: 25));
      final body = await utf8.decoder.bind(response).join();
      if (response.statusCode == 401) throw const ApiException('La sesión venció. Vuelve a iniciar sesión.');
      if (response.statusCode == 403) throw const ApiException('Este dispositivo fue revocado. Contacta al administrador.');
      if (response.statusCode == 409) {
        try {
          final error = jsonDecode(body);
          if (error is Map && error['detail'] == 'Device limit reached') {
            throw const ApiException('Alcanzaste el límite de dispositivos. Revoca uno o contacta al administrador.');
          }
        } on FormatException { /* Use the generic conflict message. */ }
        throw const ApiException('La clave de este dispositivo ya está en uso por otra cuenta.');
      }
      if (response.statusCode != 200) throw const ApiException('No se pudo preparar la VPN.');
      final data = jsonDecode(body);
      if (data is! Map || data['config'] is! String) throw const ApiException('La configuración VPN es inválida.');
      return data['config'] as String;
    } on SocketException {
      throw _connectionError();
    } on TimeoutException {
      throw _connectionError();
    } finally {
      client.close(force: true);
    }
  }

  Future<void> register(String username, String password) async {
    final isLoopback = baseUrl.host == '127.0.0.1' || baseUrl.host == 'localhost' || baseUrl.host == '::1';
    if (baseUrl.scheme != 'https' && !(baseUrl.scheme == 'http' && isLoopback)) {
      throw const ApiException('La dirección de la API debe usar HTTPS.');
    }
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
    try {
      final request = await client.postUrl(await _url('/auth/register'));
      request.headers.contentType = ContentType.json;
      request.add(utf8.encode(jsonEncode({'username': username, 'password': password})));
      final response = await request.close().timeout(const Duration(seconds: 10));
      await response.drain<void>();
      if (response.statusCode == 409) throw const ApiException('Ese usuario ya está en uso.');
      if (response.statusCode == 429) throw const ApiException('Demasiados registros. Espera un minuto antes de volver a intentarlo.');
      if (response.statusCode == 404) throw const ApiException('El registro no está habilitado en el servidor.');
      if (response.statusCode != 201) throw const ApiException('No se pudo crear la cuenta.');
    } on SocketException {
      throw _connectionError();
    } on TimeoutException {
      throw _connectionError();
    } finally {
      client.close(force: true);
    }
  }

  Future<String> login(String username, String password) async {
    final isLoopback = baseUrl.host == '127.0.0.1' || baseUrl.host == 'localhost' || baseUrl.host == '::1';
    if (baseUrl.scheme != 'https' && !(baseUrl.scheme == 'http' && isLoopback)) {
      throw const ApiException('La dirección de la API debe usar HTTPS.');
    }
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
    try {
      final request = await client.postUrl(await _url('/auth/token'));
      request.headers.contentType = ContentType.json;
      request.add(utf8.encode(jsonEncode({'username': username, 'password': password})));
      final response = await request.close().timeout(const Duration(seconds: 10));
      final body = await utf8.decoder.bind(response).join();
      if (response.statusCode == 401) {
        throw const ApiException('Usuario o contraseña incorrectos.');
      }
      if (response.statusCode == 429) {
        throw const ApiException('Demasiados intentos. Espera unos minutos antes de volver a intentarlo.');
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
      throw _connectionError();
    } on TimeoutException {
      throw _connectionError();
    } on HttpException {
      throw const ApiException('No se pudo completar la conexión con la API.');
    } on FormatException {
      throw const ApiException('La API respondió con datos inesperados.');
    } finally {
      client.close(force: true);
    }
  }
}
