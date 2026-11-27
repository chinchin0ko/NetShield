// Tests for the Windows Service pieces:
//  - WindowsAdminCommands (the pure builders shared by the app and the
//    service; the existing windows_vpn_test.dart covers them through the
//    WindowsVpn forwarding members, these pin the shared file directly).
//  - WindowsServiceClient (loopback JSON protocol) against a fake server.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:netshield_app/services/windows_admin_commands.dart';
import 'package:netshield_app/services/windows_service_client.dart';

void main() {
  group('WindowsAdminCommands', () {
    test('enable includes tunnel, server and DHCP rules', () {
      final commands = WindowsAdminCommands.killswitchEnableCommands(
          'ns0123456789ab', '140.84.183.78');
      expect(commands.any((c) => c.contains('"ns0123456789ab"')), isTrue);
      expect(commands.any((c) => c.contains('140.84.183.78')), isTrue);
      expect(commands.any((c) => c.contains('LocalPort 68')), isTrue);
      expect(commands.any((c) => c.contains('DefaultOutboundAction Block')),
          isTrue);
      expect(commands.any((c) => c.contains('(SSH)')), isFalse);
    });

    test('enable with allowSsh adds the three SSH rules', () {
      final commands = WindowsAdminCommands.killswitchEnableCommands(
          'ns0123456789ab', '140.84.183.78',
          allowSsh: true);
      expect(commands.any((c) => c.contains('(SSH)')), isTrue);
      expect(commands.any((c) => c.contains('(SSH UDP)')), isTrue);
      expect(commands.any((c) => c.contains('(SSH TCP)')), isTrue);
    });

    test('disable with a snapshot restores each profile', () {
      final commands = WindowsAdminCommands.killswitchDisableCommands(
          original: {
            'Domain': 'Allow',
            'Private': 'Block',
            'Public': 'Allow',
          });
      expect(
          commands.any((c) =>
              c.contains('Profile Private -DefaultOutboundAction Block')),
          isTrue);
      expect(
          commands.any((c) =>
              c.contains('Profile Domain -DefaultOutboundAction Allow')),
          isTrue);
    });

    test('disable without a snapshot restores Allow everywhere', () {
      final commands = WindowsAdminCommands.killswitchDisableCommands();
      expect(
          commands.any((c) => c.contains(
              'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow')),
          isTrue);
    });

    test('connect script exits 10 on firewall failure, 20 on tunnel', () {
      final script = WindowsAdminCommands.connectAdminScript(
          ['Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Block'],
          r'C:\Program Files\WireGuard\wireguard.exe',
          r'C:\Users\x\AppData\Roaming\NetShield\configs\ns0123456789ab.conf');
      expect(script.join('\n'), contains('exit 10'));
      expect(script.join('\n'), contains('exit 20'));
      expect(script.join('\n'), contains('exit 0'));
    });

    test('disconnect script exits 20 on uninstall, 10 on firewall', () {
      final script = WindowsAdminCommands.disconnectAdminScript(
        uninstallTunnel: true,
        wireguardExe: r'C:\Program Files\WireGuard\wireguard.exe',
        tunnel: 'ns0123456789ab',
        disableKillswitch: true,
        original: {'Domain': 'Allow'},
      );
      expect(script.join('\n'), contains('= 20'));
      expect(script.join('\n'), contains('= 10'));
    });

    test('restoreAction only accepts Allow, Block, NotConfigured', () {
      expect(WindowsAdminCommands.restoreAction('Block'), 'Block');
      expect(WindowsAdminCommands.restoreAction('NotConfigured'),
          'NotConfigured');
      expect(WindowsAdminCommands.restoreAction('whatever'), 'Allow');
    });
  });

  group('WindowsServiceClient', () {
    late ServerSocket server;
    late WindowsServiceClient client;
    late Map<String, dynamic> lastCommand;
    var response = {'ok': true, 'exitCode': 0};

    setUp(() async {
      server = await ServerSocket.bind('127.0.0.1', 0);
      client = WindowsServiceClient(
          host: '127.0.0.1', port: server.port);
      server.listen((socket) {
        utf8.decoder.bind(socket).transform(const LineSplitter()).listen(
            (line) async {
          lastCommand = jsonDecode(line) as Map<String, dynamic>;
          socket.writeln(jsonEncode(response));
          await socket.flush();
          await socket.close();
        });
      });
    });

    tearDown(() async {
      await server.close();
    });

    test('ping is true when the service answers', () async {
      response = {'ok': true, 'exitCode': 0, 'version': '1'};
      expect(await client.ping(), isTrue);
      expect(lastCommand['cmd'], 'ping');
    });

    test('ping is false when nothing listens', () async {
      // A port that was just freed, so nothing is listening on it.
      final temp = await ServerSocket.bind('127.0.0.1', 0);
      final freePort = temp.port;
      await temp.close();
      final closed = WindowsServiceClient(
          host: '127.0.0.1', port: freePort);
      expect(await closed.ping(timeout: const Duration(seconds: 2)),
          isFalse);
    });

    test('connect sends the command and returns the exit code', () async {
      response = {'ok': true, 'exitCode': 0};
      final code = await client.connect(
        tunnel: 'ns0123456789ab',
        wireguardExe: r'C:\Program Files\WireGuard\wireguard.exe',
        configPath: r'C:\x\ns0123456789ab.conf',
        endpoint: '140.84.183.78',
        allowSsh: false,
      );
      expect(code, 0);
      expect(lastCommand['cmd'], 'connect');
      expect(lastCommand['tunnel'], 'ns0123456789ab');
      expect(lastCommand['endpoint'], '140.84.183.78');
    });

    test('a firewall failure comes back as exit code 10', () async {
      response = {'ok': false, 'exitCode': 10, 'error': 'firewall'};
      final code = await client.setKillswitch(
          enable: true, tunnel: 'ns0123456789ab', endpoint: '1.2.3.4');
      expect(code, 10);
      expect(lastCommand['cmd'], 'killswitch');
      expect(lastCommand['enable'], isTrue);
    });

    test('disconnect sends uninstall + snapshot', () async {
      response = {'ok': true, 'exitCode': 0};
      final code = await client.disconnect(
        uninstallTunnel: true,
        wireguardExe: r'C:\Program Files\WireGuard\wireguard.exe',
        tunnel: 'ns0123456789ab',
        disableKillswitch: true,
        original: {'Domain': 'Allow', 'Private': 'Allow'},
      );
      expect(code, 0);
      expect(lastCommand['cmd'], 'disconnect');
      expect(lastCommand['original']['Domain'], 'Allow');
    });

    test('route sends add/delete with endpoint and gateway', () async {
      response = {'ok': true, 'exitCode': 0};
      final code = await client.route(
          add: true, endpoint: '140.84.183.78', gateway: '192.168.1.1');
      expect(code, 0);
      expect(lastCommand['cmd'], 'route');
      expect(lastCommand['add'], isTrue);
      expect(lastCommand['gateway'], '192.168.1.1');
    });
  });
}
