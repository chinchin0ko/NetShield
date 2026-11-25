import 'dart:async';
import 'dart:io';

abstract class AlertNotifier {
  Future<void> notifyNewAlerts(int count);
}

class LinuxAlertNotifier implements AlertNotifier {
  LinuxAlertNotifier({this.run = Process.run, bool? isLinux})
      : isLinux = isLinux ?? Platform.isLinux;
  final Future<ProcessResult> Function(String, List<String>) run;
  final bool isLinux;

  @override
  Future<void> notifyNewAlerts(int count) async {
    if (!isLinux || count <= 0) return;
    final message = count == 1
        ? 'Se detectó una alerta nueva. Abre NetShield para revisarla.'
        : 'Se detectaron $count alertas nuevas. Abre NetShield para revisarlas.';
    try {
      await run('notify-send', [
        '--app-name=NetShield VPN', '--icon=netshield', '--urgency=normal',
        '--hint=string:desktop-entry:netshield-vpn', 'NetShield VPN', message,
      ]).timeout(const Duration(seconds: 5));
    } on ProcessException {
      // Notifications must not interrupt the alert feed.
    } on TimeoutException {
      // A desktop notification service may not be available.
    }
  }
}
