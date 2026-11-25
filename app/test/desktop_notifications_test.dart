import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:netshield_app/services/desktop_notifications.dart';

void main() {
  test('sends one generic desktop notification for a batch', () async {
    String? executable;
    List<String>? arguments;
    final notifier = LinuxAlertNotifier(isLinux: true, run: (command, args) async {
      executable = command;
      arguments = args;
      return ProcessResult(1, 0, '', '');
    });
    await notifier.notifyNewAlerts(3);
    expect(executable, 'notify-send');
    expect(arguments, contains('Se detectaron 3 alertas nuevas. Abre NetShield para revisarlas.'));
    expect(arguments, contains('--icon=netshield'));
  });

  test('missing notification service does not interrupt alerts', () async {
    final notifier = LinuxAlertNotifier(isLinux: true, run: (_, _) async {
      throw const ProcessException('notify-send', [], 'not available');
    });
    await notifier.notifyNewAlerts(1);
  });
}
