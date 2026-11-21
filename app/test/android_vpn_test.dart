import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netshield_app/services/android_vpn.dart';
import 'package:netshield_app/services/api_client.dart';

class ProvisioningApi extends ApiClient {
  String? id, key;
  @override
  Future<String> vpnConfig(String token, String deviceId, String publicKey) async {
    id = deviceId;
    key = publicKey;
    return '[Interface]\nPrivateKey = REPLACE_ME\n';
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('netshield/android_vpn_test');
  final calls = <MethodCall>[];
  setUp(() {
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      if (call.method == 'identity') return {'deviceId': 'a' * 32, 'publicKey': 'public-key'};
      if (call.method == 'isConnected') return true;
      if (call.method == 'usage') return {'received': 10, 'sent': 20};
      return null;
    });
  });
  tearDown(() => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, null));
  test('registers the locally generated public key and starts the native tunnel', () async {
    final api = ProvisioningApi();
    final vpn = AndroidVpn(api, channel: channel);
    await vpn.connect('token', 'demo');
    expect(api.id, 'a' * 32);
    expect(api.key, 'public-key');
    expect(calls.map((call) => call.method), ['identity', 'connect']);
    expect((calls.last.arguments as Map)['account'], 'demo');
    expect(await vpn.isConnected(), isTrue);
    expect((await vpn.trafficUsage())!.receivedBytes, 10);
    expect(await vpn.isKillSwitchEnabled(), isFalse);
  });
}
