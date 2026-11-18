import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:netshield_app/main.dart';
import 'package:netshield_app/services/api_client.dart';

class FakeApi extends ApiClient {
  FakeApi({this.fail = false});
  final bool fail;
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
    await tester.pumpWidget(NetShieldApp(api: FakeApi()));
    await tester.enterText(find.byType(TextField).at(0), 'demo');
    await tester.enterText(find.byType(TextField).at(1), 'password');
    await tester.tap(find.text('Entrar a NetShield'));
    await tester.pumpAndSettle();
    expect(find.text('Hola, demo'), findsOneWidget);
    expect(find.text('Desconectado'), findsOneWidget);
    expect(find.text('Conexión próximamente'), findsOneWidget);
    await tester.tap(find.text('Cerrar sesión'));
    await tester.pumpAndSettle();
    expect(find.text('Qué gusto verte'), findsOneWidget);
  });

  testWidgets('Register is clearly unavailable', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(NetShieldApp(api: FakeApi()));
    await tester.tap(find.text('Crear cuenta'));
    await tester.pumpAndSettle();
    expect(find.text('El registro de cuentas estará disponible próximamente.'), findsOneWidget);
    final button = tester.widget<FilledButton>(find.byType(FilledButton));
    expect(button.onPressed, isNull);
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
