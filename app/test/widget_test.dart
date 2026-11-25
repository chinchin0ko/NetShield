import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:netshield_app/main.dart';
import 'package:netshield_app/screens/dashboard_panels.dart';
import 'package:netshield_app/screens/skeleton.dart';
import 'package:netshield_app/screens/vpn_map.dart';
import 'package:netshield_app/services/api_client.dart';
import 'package:netshield_app/services/linux_vpn.dart';
import 'package:netshield_app/services/desktop_notifications.dart';

class FakeNotifier implements AlertNotifier {
  final List<int> counts = [];
  @override
  Future<void> notifyNewAlerts(int count) async => counts.add(count);
}

class FakeVpn extends LinuxVpn {
  FakeVpn(super.api);
  bool connected = false, failDisconnect = false;
  bool? gatewayResult = true, dnsResult = true, internetResult = true;
  @override
  Future<bool?> dnsResponds() async => dnsResult;
  @override
  Future<bool?> internetReachable() async => internetResult;
  @override
  Future<bool?> gatewayReachable() async => gatewayResult;
  bool? lockOverride;
  String? connectedAccount;
  @override
  Future<String> deviceId() async => 'a' * 32;
  @override
  Future<bool> isKillSwitchEnabled() async => lockOverride ?? connected;
  @override
  Future<void> setKillSwitch(bool enabled) async { lockOverride = enabled; }
  @override
  Future<TrafficUsage?> trafficUsage() async => connected ? const TrafficUsage(2048, 1024) : null;
  @override
  Future<bool> isConnected() async => connected;
  @override
  Future<void> connect(String token, String account) async { connected = true; connectedAccount = account; }
  @override
  Future<void> disconnect() async { if (failDisconnect) throw const ApiException('falló'); connected = false; lockOverride = null; }
}

class FakeApi extends ApiClient {
  FakeApi({this.fail = false});
  final bool fail;
  bool revoked = false;
  bool showAlert = false;
  String reviewStatus = 'new';
  bool manyAlerts = false;
  bool alertsFail = false;
  int alertRequests = 0;
  @override
  Future<SecurityAlertFeed> securityAlerts(String token) async {
    alertRequests++;
    if (alertsFail) throw const ApiException('offline');
    return SecurityAlertFeed(manyAlerts ? List.generate(20, (i) => {"id": i + 1, "review_status": "new", "device_id": "a" * 32, "signature": "Alerta $i", "occurred_at": "2026-01-01T00:00:00Z", "severity": 3}) : showAlert ? [{"id": 1, "review_status": reviewStatus, "device_id": "a" * 32, "signature": "ET MALWARE indicador detectado", "occurred_at": "2026-01-01T00:00:00Z", "severity": 3}] : [], "not_active");
  }
  @override
  Future<void> reviewAlert(String token, int id, String status) async { reviewStatus = status; }
  @override
  Future<List<Map<String, dynamic>>> vpnDevices(String token) async => [{'device_id': 'b' * 32, 'enabled': true}];
  @override
  Future<List<VpnDeviceUsage>> vpnUsage(String token) async => [VpnDeviceUsage('b' * 32, 4096, 8192)];
  @override
  Future<List<VpnUsageDay>> vpnUsageHistory(String token) async => [VpnUsageDay('b' * 32, '2026-11-21', 1024, 2048, true)];
  @override
  Future<void> revokeVpnDevice(String token, String deviceId) async { revoked = true; }
  @override
  Future<void> register(String username, String password) async {}
  @override
  Future<String> login(String username, String password) async {
    if (fail) throw const ApiException('Usuario o contraseña incorrectos.');
    return 'test-token';
  }
}

void main() {
  testWidgets('Dashboard fits a phone-sized screen', (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi()..showAlert = true;
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api), notifier: FakeNotifier()));
    expect(tester.takeException(), isNull, reason: 'login layout');
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.ensureVisible(find.text('Entrar a NetShield'));
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    expect(find.text('Conectar'), findsOneWidget);
    expect(tester.getTopLeft(find.text('Inicio')).dy, tester.getTopLeft(find.text('Ajustes')).dy);
    expect(tester.getTopLeft(find.text('Consumo')).dy, greaterThan(tester.getTopLeft(find.text('Inicio')).dy));
    expect(tester.takeException(), isNull, reason: 'home layout');
    await tester.tap(find.text('Ajustes'));
    await tester.pumpAndSettle();
    expect(find.text('Configuración'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.tap(find.text('Consumo'));
    await tester.pumpAndSettle();
    expect(find.text('Consumo por día'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.tap(find.text('Alertas'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('ET MALWARE indicador detectado'));
    await tester.tap(find.text('ET MALWARE indicador detectado'));
    await tester.pumpAndSettle();
    expect(find.text('Detalles de la detección'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Pending filter shows a count badge like messages', (tester) async {
    tester.view.physicalSize = const Size(1200, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi()..showAlert = true;
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api), notifier: FakeNotifier()));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Alertas'));
    await tester.pumpAndSettle();
    expect(find.text('Pendientes'), findsOneWidget);
    expect(find.text('1'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
  testWidgets('Controls remain reachable in a very short window', (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api)));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.ensureVisible(find.text('Entrar a NetShield'));
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    tester.view.physicalSize = const Size(320, 180);
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byTooltip('Salir'));
    await tester.pumpAndSettle();
    expect(tester.getRect(find.byTooltip('Salir')).bottom, lessThanOrEqualTo(180));
    await tester.ensureVisible(find.text('Alertas'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Alertas'));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });
  testWidgets('Settings controls the lock and usage displays actual counters', (tester) async {
    tester.view.physicalSize = const Size(1200, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi()..showAlert = true;
    final vpn = FakeVpn(api);
    await tester.pumpWidget(NetShieldApp(api: api, vpn: vpn));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Conectar'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Ajustes'));
    await tester.pumpAndSettle();
    expect(find.text('Kill Switch'), findsOneWidget);
    await tester.tap(find.byType(Switch).first);
    await tester.pumpAndSettle();
    expect(vpn.lockOverride, isNull);
    await tester.tap(find.text('Desactivar').last);
    await tester.pumpAndSettle();
    expect(vpn.lockOverride, isFalse);
    await tester.tap(find.byType(Switch).first);
    await tester.pumpAndSettle();
    expect(vpn.lockOverride, isTrue);
    await tester.tap(find.text('Consumo'));
    await tester.pumpAndSettle();
    expect(find.text('2.0 KB'), findsWidgets);
    expect(find.text('1.0 KB'), findsWidgets);
    expect(find.text('Enviado 4.0 KB · Recibido 8.0 KB'), findsOneWidget);
    await tester.ensureVisible(find.text('Historial reciente'));
    expect(find.text('Enviado 1.0 KB · Recibido 2.0 KB · datos incompletos'), findsOneWidget);
    await tester.tap(find.text('Alertas'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Sensor no disponible'), findsOneWidget);
    expect(find.text('Generar alerta de prueba'), findsNothing);
    expect(find.text('ET MALWARE indicador detectado'), findsOneWidget);
    await tester.ensureVisible(find.text('ET MALWARE indicador detectado'));
    await tester.tap(find.text('ET MALWARE indicador detectado'));
    await tester.pumpAndSettle();
    expect(find.text('Detalles de la detección'), findsOneWidget);
    expect(find.text('Severidad del sensor'), findsOneWidget);
    await tester.ensureVisible(find.text('Posible falso positivo'));
    await tester.tap(find.text('Posible falso positivo'));
    await tester.pumpAndSettle();
    expect(find.text('Marcada como posible falso positivo'), findsOneWidget);
  });

  testWidgets('Navigation stays fixed while only dashboard content scrolls', (tester) async {
    tester.view.physicalSize = const Size(900, 650);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi()..manyAlerts = true;
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api)));
    expect(find.text('Tu espacio.\nTu conexión.'), findsOneWidget);
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.ensureVisible(find.text('Entrar a NetShield'));
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    expect(find.text('Tu espacio.\nTu conexión.'), findsNothing);
    final navigation = find.byKey(const ValueKey('dashboard-navigation'));
    final origin = tester.getTopLeft(navigation);
    expect(tester.getTopLeft(find.text('Inicio')).dy, tester.getTopLeft(find.text('Alertas')).dy);
    for (final label in ['Ajustes', 'Consumo', 'Alertas']) {
      await tester.tap(find.text(label));
      await tester.pumpAndSettle();
      expect(tester.getTopLeft(navigation), origin);
    }
    await tester.drag(find.byKey(const ValueKey('dashboard-content-3')), const Offset(0, -800));
    await tester.pumpAndSettle();
    expect(tester.getTopLeft(navigation), origin);
    expect(find.text('Alerta 19'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Active profile warns only after repeated gateway failures and recovers', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    final vpn = FakeVpn(api);
    await tester.pumpWidget(NetShieldApp(api: api, vpn: vpn));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Conectar'));
    await tester.pumpAndSettle();
    vpn.gatewayResult = false;
    await tester.pump(const Duration(seconds: 4));
    await tester.pump();
    expect(find.text('VPN sin respuesta'), findsNothing);
    await tester.pump(const Duration(seconds: 16));
    await tester.pump();
    expect(find.text('VPN sin respuesta'), findsOneWidget);
    expect(vpn.connected, isTrue);
    vpn.gatewayResult = true;
    await tester.pump(const Duration(seconds: 16));
    await tester.pump();
    expect(find.text('Conectado'), findsOneWidget);
    expect(vpn.connected, isTrue);
  });

  testWidgets('DNS and Internet probes warn after repeated failures and recover', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    final vpn = FakeVpn(api);
    await tester.pumpWidget(NetShieldApp(api: api, vpn: vpn));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Conectar'));
    await tester.pumpAndSettle();
    vpn.dnsResult = false;
    await tester.pump(const Duration(seconds: 4));
    await tester.pump();
    expect(find.text('DNS sin respuesta'), findsNothing);
    await tester.pump(const Duration(seconds: 16));
    await tester.pump();
    expect(find.text('DNS sin respuesta'), findsOneWidget);
    expect(vpn.connected, isTrue);
    vpn.dnsResult = true;
    vpn.internetResult = false;
    await tester.pump(const Duration(seconds: 16));
    await tester.pump();
    await tester.pump(const Duration(seconds: 16));
    await tester.pump();
    expect(find.text('Prueba de Internet sin respuesta'), findsOneWidget);
    vpn.internetResult = true;
    await tester.pump(const Duration(seconds: 16));
    await tester.pump();
    expect(find.text('Conectado'), findsOneWidget);
    expect(vpn.connected, isTrue);
  });

  testWidgets('Alerts refresh in place, notify once, and preserve data on failure', (tester) async {
    tester.view.physicalSize = const Size(1200, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    final notifier = FakeNotifier();
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api), notifier: notifier));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Alertas'));
    await tester.pumpAndSettle();
    expect(find.text('Aún no hay alertas guardadas.'), findsOneWidget);
    expect(notifier.counts, isEmpty);
    api.showAlert = true;
    await tester.pump(const Duration(seconds: 15));
    await tester.pump();
    expect(find.text('ET MALWARE indicador detectado'), findsOneWidget);
    expect(find.text('Tienes una alerta nueva.'), findsOneWidget);
    expect(find.text('Alertas · 1'), findsOneWidget);
    expect(notifier.counts, [1]);
    await tester.tap(find.text('Entendido'));
    await tester.pump();
    expect(find.text('Tienes una alerta nueva.'), findsNothing);
    final before = api.alertRequests;
    await tester.tap(find.text('Actualizar'));
    await tester.pump();
    expect(api.alertRequests, greaterThan(before));
    expect(find.text('Tienes una alerta nueva.'), findsNothing);
    expect(notifier.counts, [1]);
    api.alertsFail = true;
    await tester.tap(find.text('Actualizar'));
    await tester.pump();
    expect(find.text('ET MALWARE indicador detectado'), findsOneWidget);
    expect(find.textContaining('No se pudieron actualizar las alertas'), findsOneWidget);
    expect(notifier.counts, [1]);
  });

  testWidgets('Connected orb pulses and the disconnect action is red', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api)));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Conectar'));
    await tester.pumpAndSettle();
    final button = tester.widget<FilledButton>(find.ancestor(of: find.text('Desconectar'), matching: find.byType(FilledButton)));
    expect(button.style!.backgroundColor!.resolve({}), const Color(0xffa6433a));
    await tester.pump(const Duration(milliseconds: 1100));
    await tester.pump();
    final orbScale = tester.widget<AnimatedScale>(find.ancestor(of: find.byKey(const ValueKey('connection-orb')), matching: find.byType(AnimatedScale)));
    expect(orbScale.scale, 1.08);
  });

  testWidgets('Restored traffic lock can be disabled before login', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    final vpn = FakeVpn(api)..connected = true;
    await tester.pumpWidget(NetShieldApp(api: api, vpn: vpn));
    await tester.pumpAndSettle();
    expect(find.text('Desconectar VPN y desactivar bloqueo'), findsOneWidget);
    await tester.tap(find.text('Desconectar VPN y desactivar bloqueo'));
    await tester.pumpAndSettle();
    expect(vpn.connected, isFalse);
    expect(find.text('Bloqueo desactivado. Ya puedes iniciar sesión.'), findsOneWidget);
  });

  testWidgets('Login and logout do not claim a VPN connection', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    final vpn = FakeVpn(api);
    await tester.pumpWidget(NetShieldApp(api: api, vpn: vpn));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    expect(find.text('Hola, demo'), findsOneWidget);
    expect(find.text('Desconectado'), findsOneWidget);
    await tester.tap(find.text('Conectar'));
    await tester.pumpAndSettle();
    expect(vpn.connectedAccount, 'demo');
    expect(find.text('Conectado'), findsOneWidget);
    // Salir disconnects the VPN first, then closes the session.
    await tester.ensureVisible(find.text('Salir'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Salir'));
    await tester.pumpAndSettle();
    expect(vpn.connected, isFalse);
    expect(find.text('Qué gusto verte'), findsOneWidget);
  });

  testWidgets('Register validates and returns to login', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(NetShieldApp(api: FakeApi()));
    await tester.tap(find.text('Crear cuenta'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).at(0), 'alice');
    await tester.enterText(find.byType(TextField).at(1), 'a secure password');
    await tester.enterText(find.byType(TextField).at(2), 'a secure password');
    await tester.tap(find.widgetWithText(FilledButton, 'Crear cuenta'));
    await tester.pumpAndSettle();
    expect(find.text('Cuenta creada. Ya puedes iniciar sesión.'), findsOneWidget);
  });

  testWidgets('Invalid login displays a useful error', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(NetShieldApp(api: FakeApi(fail: true)));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'bad');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    expect(find.text('Usuario o contraseña incorrectos.'), findsOneWidget);
  });

  testWidgets('Device revocation requires confirmation', (tester) async {
    tester.view.physicalSize = const Size(1200, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api)));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Ajustes'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Dispositivos'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Revocar'));
    await tester.pumpAndSettle();
    expect(api.revoked, isFalse);
    await tester.tap(find.text('Revocar').last);
    await tester.pumpAndSettle();
    expect(api.revoked, isTrue);
  });

  testWidgets('Android uses bottom navigation with animated section changes', (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api), notifier: FakeNotifier(), androidLayout: true));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.ensureVisible(find.text('Entrar a NetShield'));
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('android-navigation')), findsOneWidget);
    expect(find.byType(NavigationBar), findsOneWidget);
    // Bottom navigation sits below the home content.
    expect(tester.getTopLeft(find.byType(NavigationBar)).dy, greaterThan(tester.getTopLeft(find.text('Conectar')).dy));
    expect(find.byKey(const ValueKey('dashboard-navigation')), findsNothing);
    await tester.tap(find.text('Ajustes'));
    await tester.pumpAndSettle();
    expect(find.text('Configuración'), findsOneWidget);
    await tester.tap(find.descendant(of: find.byKey(const ValueKey('android-navigation')), matching: find.text('Consumo')));
    await tester.pumpAndSettle();
    expect(find.text('Consumo por día'), findsOneWidget);
    await tester.tap(find.text('Alertas'));
    await tester.pumpAndSettle();
    expect(find.text('Alertas y amenazas'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Desktop home shows the VPN route map in two phases', (tester) async {
    tester.view.physicalSize = const Size(1200, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api)));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    expect(find.byType(VpnMapCard), findsOneWidget);
    expect(find.text('Tu ubicación real'), findsOneWidget);
    expect(find.text('Tuxtla Gutiérrez, Chiapas'), findsOneWidget);
    expect(find.text('Desconectado'), findsOneWidget);
    expect(find.text('En espera'), findsOneWidget);
    expect(find.byType(AnimatedAtmosphere), findsOneWidget);
    expect(find.text('Administrar dispositivos'), findsNothing);
    expect(find.text('Salir'), findsOneWidget);
    await tester.tap(find.text('Conectar'));
    await tester.pumpAndSettle();
    expect(find.text('Conectado'), findsOneWidget);
    expect(find.text('En línea'), findsOneWidget);
    expect(find.text('Tu ubicación VPN'), findsOneWidget);
    expect(find.text('Querétaro, México'), findsOneWidget);
    expect(find.byType(VpnMapCard), findsOneWidget);
  });

  testWidgets('Login fades into the dashboard instead of swapping instantly', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeApi();
    await tester.pumpWidget(NetShieldApp(api: api, vpn: FakeVpn(api)));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    // Mid-crossfade: the outgoing login and the incoming dashboard coexist.
    expect(find.byKey(const ValueKey('login')), findsOneWidget);
    expect(find.byKey(const ValueKey('dashboard')), findsOneWidget);
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('login')), findsNothing);
    expect(find.byKey(const ValueKey('dashboard')), findsOneWidget);
    expect(find.text('Conectar'), findsOneWidget);
  });

  testWidgets('Loading states show skeleton placeholders instead of spinners', (tester) async {
    tester.view.physicalSize = const Size(1200, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(const MaterialApp(home: Scaffold(body: SingleChildScrollView(child: UsagePanel(connected: true, usage: null, loading: true, serverUsage: null, serverUnavailable: false, history: null, historyUnavailable: false)))));
    await tester.pump();
    expect(find.byType(SkeletonBox), findsWidgets);
    expect(find.byType(CircularProgressIndicator), findsNothing);
    expect(find.text('Consultando consumo…'), findsNothing);
    expect(find.text('Consultando historial…'), findsNothing);
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: SingleChildScrollView(child: AlertsPanel(alerts: null, monitoring: 'experimental', loading: true, busy: false, error: null, onRefresh: () {}, onReview: (id, status) {}, newAlerts: 0, onAcknowledge: () {})))));
    await tester.pump();
    expect(find.byType(SkeletonBox), findsWidgets);
    expect(find.byType(CircularProgressIndicator), findsNothing);
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: SingleChildScrollView(child: AlertsPanel(alerts: [{"id": 1, "review_status": "new", "device_id": "a" * 32, "signature": "ET MALWARE indicador detectado", "occurred_at": "2026-01-01T00:00:00Z", "severity": 3}], monitoring: 'experimental', loading: false, busy: false, error: null, onRefresh: () {}, onReview: (id, status) {}, newAlerts: 0, onAcknowledge: () {})))));
    await tester.pump();
    expect(find.byType(SkeletonBox), findsNothing);
    expect(find.text('ET MALWARE indicador detectado'), findsOneWidget);
  });
}
