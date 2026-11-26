import 'package:flutter_test/flutter_test.dart';
import 'package:netshield_app/services/windows_vpn.dart';

const _config = '''
[Interface]
PrivateKey = REPLACE_ME
Address = 10.8.0.7/32, fd42:4e53::7/128
DNS = 10.5.0.2

[Peer]
PublicKey = abcdefghijklmnopqrstuvwxyz0123456789abcd=
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
''';

void main() {
  test('tunnel and service names derive from the device id', () {
    expect(WindowsVpn.tunnelName('abcdef1234567890abcdef1234567890'),
        'nsabcdef123456');
    expect(WindowsVpn.serviceName('nsabcdef123456'),
        r'WireGuardTunnel$nsabcdef123456');
  });

  test('endpoint and DNS parse from the config template', () {
    expect(WindowsVpn.parseEndpoint(_config), '203.0.113.10');
    expect(WindowsVpn.parseDns(_config), '10.5.0.2');
    expect(WindowsVpn.parseEndpoint('[Interface]\nPrivateKey = x\n'), null);
    expect(WindowsVpn.parseDns('[Interface]\nPrivateKey = x\n'), null);
  });

  test('endpoint parses when the server listens on UDP 443', () {
    // The server moved from 51820 to 443 so restrictive networks (which
    // block 51820) still let the tunnel through; the port must not be fixed.
    final config443 = _config.replaceFirst(':51820', ':443');
    expect(WindowsVpn.parseEndpoint(config443), '203.0.113.10');
  });

  test('transfer parses wg show output', () {
    final usage = WindowsVpn.parseTransfer(
        'abcdefghijklmnopqrstuvwxyz0123456789abcd=\t1234\t5678\n');
    expect(usage, isNotNull);
    expect(usage!.receivedBytes, 1234);
    expect(usage.sentBytes, 5678);
    expect(WindowsVpn.parseTransfer('garbage\n'), null);
  });

  test('killswitch enable commands block outbound and allow the tunnel', () {
    final commands = WindowsVpn.killswitchEnableCommands(
        'nsabcdef123456', '203.0.113.10');
    expect(
        commands,
        contains(
            'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block'));
    expect(commands.any((c) => c.contains('InterfaceAlias "nsabcdef123456"')),
        isTrue);
    expect(commands.any((c) => c.contains('RemoteAddress 203.0.113.10')),
        isTrue);
    // SSH rules only when opted in.
    expect(commands.any((c) => c.contains('(SSH)')), isFalse);
    final withSsh = WindowsVpn.killswitchEnableCommands(
        'nsabcdef123456', '203.0.113.10',
        allowSsh: true);
    expect(withSsh.any((c) => c.contains('(SSH)')), isTrue);
  });

  test('connect admin script is one script: firewall first, then install',
      () {
    final script = WindowsVpn.connectAdminScript(
        WindowsVpn.killswitchEnableCommands('nsabcdef123456', '203.0.113.10'),
        r'C:\Program Files\WireGuard\wireguard.exe',
        r'C:\Users\demo\NetShield\nsabcdef123456.conf');
    final joined = script.join('\n');
    expect(script.first, contains('ErrorActionPreference'));
    expect(joined, contains('exit 10')); // firewall failed
    expect(joined, contains('/installtunnelservice'));
    expect(joined, contains('exit 20')); // install failed
    expect(script.last, 'exit 0');
    // The install runs after the firewall block, never before it.
    expect(joined.indexOf('/installtunnelservice'),
        greaterThan(joined.indexOf('DefaultOutboundAction Block')));
  });

  test('disconnect admin script runs both steps, first failure wins', () {
    final script = WindowsVpn.disconnectAdminScript(
        uninstallTunnel: true,
        wireguardExe: r'C:\Program Files\WireGuard\wireguard.exe',
        tunnel: 'nsabcdef123456',
        disableKillswitch: true);
    final joined = script.join('\n');
    expect(joined, contains('/uninstalltunnelservice'));
    expect(joined, contains('DefaultOutboundAction Allow'));
    expect(joined, contains(r'$fail = 20')); // uninstall failed
    expect(joined, contains(r'$fail = 10')); // firewall failed
    expect(script.last, r'exit $fail');
    // Only the requested steps are included.
    final onlyFirewall = WindowsVpn.disconnectAdminScript(
        uninstallTunnel: false,
        wireguardExe: '',
        tunnel: 'nsabcdef123456',
        disableKillswitch: true);
    expect(onlyFirewall.join('\n'),
        isNot(contains('/uninstalltunnelservice')));
    expect(onlyFirewall.join('\n'), contains('DefaultOutboundAction Allow'));
  });
}
