import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:netshield_app/screens/dashboard_panels.dart';
import 'package:netshield_app/screens/usage_chart.dart';
import 'package:netshield_app/services/api_client.dart';

void main() {
  testWidgets('daily chart aggregates devices and marks incomplete samples', (tester) async {
    const history = [
      VpnUsageDay('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '2026-11-20', 1024, 2048, false),
      VpnUsageDay('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '2026-11-20', 512, 512, true),
      VpnUsageDay('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '2026-11-21', null, 2048, false),
    ];
    await tester.pumpWidget(const MaterialApp(home: Scaffold(body: UsageChart(history: history))));
    expect(find.text('4.0 KB'), findsOneWidget);
    expect(find.text('11-20*'), findsOneWidget);
    expect(find.byTooltip('2026-11-20, recibido 2.5 KB, enviado 1.5 KB, muestra incompleta'), findsOneWidget);
    expect(find.byTooltip('2026-11-21, recibido 2.0 KB, enviado sin datos, muestra incompleta'), findsOneWidget);
  });

  testWidgets('alert filters and details use only recorded information', (tester) async {
    tester.view.physicalSize = const Size(900, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final alerts = [
      {'id': 1, 'device_id': 'a' * 32, 'signature': 'NETSHIELD MALWARE TEST simulated indicator', 'severity': 1, 'occurred_at': '2026-11-20T10:00:00Z', 'review_status': 'new', 'reviewed_at': null},
      {'id': 2, 'device_id': 'b' * 32, 'signature': 'ET PHISHING indicador', 'severity': 2, 'occurred_at': '2026-11-20T11:00:00Z', 'review_status': 'reviewed', 'reviewed_at': '2026-11-20T12:00:00Z'},
    ];
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: SingleChildScrollView(child: AlertsPanel(
      alerts: alerts, monitoring: 'experimental', loading: false, busy: false, error: null,
      onRefresh: () {}, onReview: (_, _) {}, newAlerts: 0, onAcknowledge: () {},
    )))));
    expect(find.text('ET PHISHING indicador'), findsOneWidget);
    await tester.tap(find.text('Pendientes'));
    await tester.pumpAndSettle();
    expect(find.text('ET PHISHING indicador'), findsNothing);
    await tester.tap(find.text('NETSHIELD MALWARE TEST simulated indicator'));
    await tester.pumpAndSettle();
    expect(find.text('Esta detección es una prueba y no indica una infección.'), findsOneWidget);
    expect(find.text('Alta (1)'), findsOneWidget);
    await tester.tap(find.text('Revisadas'));
    await tester.pumpAndSettle();
    expect(find.text('NETSHIELD MALWARE TEST simulated indicator'), findsNothing);
    await tester.tap(find.text('ET PHISHING indicador'));
    await tester.pumpAndSettle();
    expect(find.text('Última revisión'), findsOneWidget);
    expect(find.textContaining('no una confirmación de infección'), findsOneWidget);
  });
}
