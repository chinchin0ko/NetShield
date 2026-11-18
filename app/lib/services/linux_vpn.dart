import 'dart:io';
import 'dart:math';
import 'api_client.dart';

class LinuxVpn {
  LinuxVpn(this.api);
  final ApiClient api;
  String? _connection;

  Future<String> _deviceId() async {
    final home = Platform.environment['HOME'];
    if (home == null) throw const ApiException('No se encontró tu carpeta personal.');
    final directory = Directory('$home/.local/share/netshield');
    await directory.create(recursive: true);
    await Process.run('chmod', ['700', directory.path]);
    final file = File('${directory.path}/device-id');
    if (await file.exists()) {
      final value = (await file.readAsString()).trim();
      if (RegExp(r'^[0-9a-f]{32}$').hasMatch(value)) return value;
      throw const ApiException('El identificador del dispositivo es inválido.');
    }
    final random = Random.secure();
    final value = List.generate(16, (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
    await file.writeAsString(value, flush: true);
    await Process.run('chmod', ['600', file.path]);
    return value;
  }

  Future<void> _nm(List<String> args, {bool check = true}) async {
    final result = await Process.run('nmcli', args).timeout(const Duration(seconds: 45));
    if (check && result.exitCode != 0) throw const ApiException('NetworkManager no pudo activar la VPN.');
  }

  Future<void> connect(String token) async {
    if (!Platform.isLinux) throw const ApiException('Esta versión solo permite conexiones en Linux.');
    final id = await _deviceId();
    final config = await api.vpnConfig(token, id);
    final name = 'ns${id.substring(0, 12)}';
    final temp = await Directory.systemTemp.createTemp('netshield-');
    try {
      final file = File('${temp.path}/$name.conf');
      await file.writeAsString(config, flush: true);
      await Process.run('chmod', ['600', file.path]);
      // Only replace profiles created by this application for this device.
      await _nm(['connection', 'delete', 'id', name], check: false);
      await _nm(['connection', 'import', 'type', 'wireguard', 'file', file.path]);
      _connection = name;
      await _nm(['connection', 'modify', 'id', name, 'connection.autoconnect', 'no']);
      await _nm(['connection', 'up', 'id', name]);
      final ping = await Process.run('ping', ['-4', '-c', '1', '-W', '5', '10.8.0.1']).timeout(const Duration(seconds: 8));
      if (ping.exitCode != 0) throw const ApiException('No hubo respuesta a través del túnel VPN.');
    } catch (_) {
      await disconnect();
      rethrow;
    } finally {
      await temp.delete(recursive: true);
    }
  }

  Future<void> disconnect() async {
    final id = await _deviceId();
    final name = _connection ?? 'ns${id.substring(0, 12)}';
    await _nm(['connection', 'delete', 'id', name], check: false);
    if (await isConnected()) {
      throw const ApiException('No se pudo desconectar la VPN.');
    }
    _connection = null;
  }

  Future<bool> isConnected() async {
    final id = await _deviceId();
    final name = 'ns${id.substring(0, 12)}';
    final result = await Process.run('nmcli', ['-t', '-f', 'NAME', 'connection', 'show', '--active']);
    final active = result.exitCode == 0 && (result.stdout as String).split('\n').contains(name);
    if (active) _connection = name;
    return active;
  }
}
