import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:netshield_app/main.dart';
import 'package:netshield_app/services/api_client.dart';
import 'package:netshield_app/services/linux_vpn.dart';

class FakeVpn extends LinuxVpn {
  FakeVpn(super.api);
  bool connected = false;
  @override
  Future<bool> isConnected() async => connected;
  @override
  Future<void> connect(String token) async { connected = true; }
  @override
  Future<void> disconnect() async { connected = false; }
}

class FakeApi extends ApiClient {
  FakeApi({this.fail = false});
  final bool fail;
  @override
  Future<void> register(String username, String password) async {}
  @override
  Future<String> login(String username, String password) async {
    if (fail) throw const ApiException('Usuario o contraseña incorrectos.');
    return 'test-token';
  }
}

void main() {
  testWidgets('Login and logout do not claim a VPN connection', (tester) async {
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
    expect(find.text('Hola, demo'), findsOneWidget);
    expect(find.text('Desconectado'), findsOneWidget);
    await tester.tap(find.text('Conectar'));
    await tester.pumpAndSettle();
    expect(find.text('Conectado'), findsOneWidget);
    await tester.tap(find.text('Desconectar'));
    await tester.pumpAndSettle();
    expect(find.text('Desconectado'), findsOneWidget);
    await tester.tap(find.text('Cerrar sesión'));
    await tester.pumpAndSettle();
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
}
