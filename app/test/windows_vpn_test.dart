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

  test('transfer parses wg show output', () {
    final usage = WindowsVpn.parseTransfer(
        'abcdefghijklmnopqrstuvwxyz0123456789abcd=\t1234\t5678\n');
    expect(usage, isNotNull);
    expect(usage!.receivedBytes, 1234);
    expect(usage.sentBytes, 5678);
    expect(WindowsVpn.parseTransfer('garbage\n'), null);
  });
}
