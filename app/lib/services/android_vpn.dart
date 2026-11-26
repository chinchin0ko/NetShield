import 'dart:convert';
import 'package:flutter/services.dart';
import 'api_client.dart';
import 'linux_vpn.dart';

/// Android uses WireGuard's VpnService backend instead of NetworkManager.
class AndroidVpn extends LinuxVpn {
  AndroidVpn(super.api, {MethodChannel? channel}) : channel = channel ?? const MethodChannel('netshield/android_vpn');
  final MethodChannel channel;

  Future<T> _call<T>(String method, [Map<String, dynamic>? arguments]) async {
    try {
      return (await channel.invokeMethod<T>(method, arguments)) as T;
    } on PlatformException catch (e) {
      throw ApiException(e.message ?? 'No se pudo completar la operación VPN.');
    }
  }

  Future<void> saveSession(String account, String accessToken, String? refreshToken) => _call<void>('saveSession', {'account': account, 'token': accessToken, 'refreshToken': refreshToken});
  Future<void> clearSession() => _call<void>('clearSession');
  Future<Map<String, String?>?> restoredSession() async {
    final value = await _call<Map<Object?, Object?>?>('session');
    if (value == null) return null;
    try {
      final token = value['token'] as String;
      final refreshToken = value['refreshToken'] as String?;
      final claims = jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(token.split('.')[1])))) as Map;
      if ((claims['exp'] as num) * 1000 <= DateTime.now().millisecondsSinceEpoch && refreshToken == null) {
        // No refresh token to renew with: the session is really over.
        await clearSession();
        return null;
      }
      // An expired access token with a refresh token is fine: the first API
      // call renews it silently.
      return {'account': value['account'] as String, 'token': token, 'refreshToken': refreshToken};
    } catch (_) {
      await clearSession();
      return null;
    }
  }

  @override
  Future<String> deviceId() => _call<String>('deviceId');
  @override
  Future<bool> isConnected() => _call<bool>('isConnected');
  @override
  Future<bool> isKillSwitchEnabled() => _call<bool>('isKillSwitchEnabled');
  Future<bool> isAlwaysOn() => _call<bool>('isAlwaysOn');
  Future<void> openVpnSettings() => _call<void>('vpnSettings');
  @override
  Future<void> setKillSwitch(bool enabled) => openVpnSettings();
  @override
  Future<bool?> gatewayReachable() async => null;
  @override
  Future<bool?> dnsResponds() async => null;
  @override
  Future<bool?> internetReachable() async => null;
  @override
  Future<TrafficUsage?> trafficUsage() async {
    final values = await _call<Map<Object?, Object?>?>('usage');
    if (values == null || values['received'] is! int || values['sent'] is! int) return null;
    return TrafficUsage(values['received'] as int, values['sent'] as int);
  }
  @override
  Future<void> connect(String token, String account) async {
    final identity = await _call<Map<Object?, Object?>>('identity', {'account': account});
    final id = identity['deviceId'], key = identity['publicKey'];
    if (id is! String || key is! String || !RegExp(r'^[0-9a-f]{32}$').hasMatch(id)) {
      throw const ApiException('La identidad del dispositivo es inválida.');
    }
    final template = await api.vpnConfig(token, id, key);
    await _call<void>('connect', {'account': account, 'template': template});
  }
  @override
  Future<void> disconnect() => _call<void>('disconnect');
}
