import 'dart:async';
import 'dart:io';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/services.dart';
import 'api_client.dart';
import 'linux_vpn.dart';

/// Firebase is optional until a project configuration is supplied at build time.
class AndroidPush {
  AndroidPush(this.api, this.vpn);
  final ApiClient api;
  final LinuxVpn vpn;
  StreamSubscription<String>? _refresh;
  StreamSubscription<RemoteMessage>? _foreground;
  String? _deviceId;
  bool registered = false;
  Future<void>? _tokenUpdate;

  Future<bool> start(String token) async {
    if (!Platform.isAndroid) return false;
    try {
      if (Firebase.apps.isEmpty) await Firebase.initializeApp().timeout(const Duration(seconds: 15));
      final messaging = FirebaseMessaging.instance;
      final permission = await messaging.requestPermission();
      if (permission.authorizationStatus != AuthorizationStatus.authorized &&
          permission.authorizationStatus != AuthorizationStatus.provisional) { return false; }
      // FCM HTTP v1 currently targets the registration token.
      // ignore: deprecated_member_use
      final pushToken = await messaging.getToken().timeout(const Duration(seconds: 15));
      if (pushToken == null) return false;
      _deviceId = await vpn.deviceId();
      await api.registerPush(token, _deviceId!, pushToken);
      registered = true;
      // ignore: deprecated_member_use
      _refresh = messaging.onTokenRefresh.listen((value) {
        _tokenUpdate = (_tokenUpdate ?? Future<void>.value())
            .then((_) => api.registerPush(token, _deviceId!, value)).catchError((_) {});
      });
      _foreground = FirebaseMessaging.onMessage.listen((_) {
        unawaited(const MethodChannel('netshield/android_vpn').invokeMethod<void>('notification').catchError((_) {}));
      });
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<void> stop(String token) async {
    await _refresh?.cancel();
    await _foreground?.cancel();
    await _tokenUpdate;
    if (registered && _deviceId != null) await api.unregisterPush(token, _deviceId!);
    registered = false;
  }

  void dispose() {
    unawaited(_refresh?.cancel());
    unawaited(_foreground?.cancel());
  }
}
