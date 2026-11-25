// NetShield CLI — controla la VPN desde la terminal.
//
// Uso:
//   netshield                 Muestra el estado y la ayuda.
//   netshield login           Inicia sesión (guarda el token para el CLI).
//   netshield logout          Desconecta la VPN y cierra la sesión.
//   netshield connect         Conecta la VPN.
//   netshield disconnect      Desconecta la VPN.
//   netshield status          Muestra el estado de la sesión y del túnel.
//   netshield devices         Lista los dispositivos VPN.
//   netshield devices revoke <id>  Revoca un dispositivo.
//   netshield alerts          Muestra las alertas de seguridad recientes.
//   netshield usage           Muestra el consumo de datos.
//   netshield killswitch on|off|status
//   netshield ssh on|off|status
//   netshield version         Muestra la versión.
//   netshield help            Muestra esta ayuda.
//
// Es Dart puro (sin Flutter) y reutiliza los mismos servicios que la app
// gráfica: ApiClient, LinuxVpn y WindowsVpn. Se compila con:
//   dart compile exe bin/netshield.dart -o netshield
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:netshield_app/services/api_client.dart';
import 'package:netshield_app/services/linux_vpn.dart';
import 'package:netshield_app/services/windows_vpn.dart';

const _version = '0.1.0';
const _apiName = 'NetShield VPN';

// ---------------------------------------------------------------------------
// Terminal UI: colores, spinner y banner.
// ---------------------------------------------------------------------------

bool get _ansi => stdout.hasTerminal && !Platform.environment.containsKey('NO_COLOR');

String _c(String code, String text) => _ansi ? '\x1B[${code}m$text\x1B[0m' : text;
String _green(String s) => _c('32', s);
String _red(String s) => _c('31', s);
String _yellow(String s) => _c('33', s);
String _cyan(String s) => _c('36', s);
String _dim(String s) => _c('2', s);
String _bold(String s) => _c('1', s);
String _ok(String s) => '${_green('✓')} $s';
String _fail(String s) => '${_red('✗')} $s';
String _warn(String s) => '${_yellow('!')} $s';

void _banner() {
  if (!_ansi) {
    stdout.writeln('NetShield VPN — CLI v$_version');
    return;
  }
  stdout.writeln(_cyan(r'''
   _   _      _     ____  _     _      _     _
  | \ | | ___| |_  / ___|| |__ (_) ___| | __| |
  |  \| |/ _ \ __| \___ \| '_ \| |/ _ \ |/ _` |
  | |\  |  __/ |_   ___) | | | | |  __/ | (_| |
  |_| \_|\___|\__| |____/|_| |_|_|\___|_|\__,_|
'''));
  stdout.writeln('  ${_dim('VPN con cifrado, detección de amenazas y kill switch')}  ${_cyan('v$_version')}');
  stdout.writeln();
}

/// Un spinner que gira mientras dura una operación asíncrona.
class _Spinner {
  static const _frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  final String message;
  Timer? _timer;
  int _i = 0;
  _Spinner(this.message);

  void start() {
    if (!_ansi) {
      stdout.writeln('$message...');
      return;
    }
    _timer = Timer.periodic(const Duration(milliseconds: 80), (_) {
      stdout.write('\r${_cyan(_frames[_i++ % _frames.length])} $message');
    });
  }

  void stop({String? done}) {
    _timer?.cancel();
    if (!_ansi) return;
    stdout.write('\r\x1B[K');
    if (done != null) stdout.writeln(done);
  }
}

/// Ejecuta [fn] con un spinner. Al terminar muestra ✓ o ✗.
Future<T> _withSpinner<T>(String message, Future<T> Function() fn) async {
  final spinner = _Spinner(message);
  spinner.start();
  try {
    final result = await fn();
    spinner.stop(done: _ok(message));
    return result;
  } catch (e) {
    spinner.stop(done: _fail(message));
    rethrow;
  }
}

void _error(Object e) {
  final msg = e is ApiException ? e.message : e.toString();
  stderr.writeln(_fail(msg));
}

String _readLine(String prompt, {bool secret = false}) {
  stdout.write(prompt);
  if (secret) {
    // Oculta lo que se teclea (la contraseña).
    try {
      stdin.echoMode = false;
    } catch (_) {}
  }
  final line = stdin.readLineSync(encoding: utf8) ?? '';
  if (secret) {
    try {
      stdin.echoMode = true;
    } catch (_) {}
    stdout.writeln();
  }
  return line.trim();
}

// ---------------------------------------------------------------------------
// Permisos: conectar/desconectar y el killswitch necesitan root. Si el CLI
// no corre como root, se re-ejecuta con sudo (con -E para conservar HOME,
// de modo que la sesión y el device-id sigan siendo los del usuario).
// En Windows no hace falta: la capa de VPN usa UAC por su cuenta.
// ---------------------------------------------------------------------------

Future<void> _ensureRoot(List<String> args) async {
  if (Platform.isWindows) return;
  var uid = '';
  try {
    final id = await Process.run('id', ['-u']);
    uid = id.stdout.toString().trim();
  } catch (_) {}
  if (uid == '0') return; // Ya somos root.
  final exe = Platform.resolvedExecutable;
  // Re-ejecuta este mismo comando con sudo y hereda la terminal (para que
  // sudo pueda pedir la contraseña). Si sudo falla, el usuario lo ve.
  final proc = await Process.start(
    'sudo',
    ['-E', exe, ...args],
    mode: ProcessStartMode.inheritStdio,
  );
  exit(await proc.exitCode);
}

// ---------------------------------------------------------------------------
// Sesión del CLI (token + cuenta, en un archivo solo legible por el usuario).
// ---------------------------------------------------------------------------

String get _sessionDir {
  if (Platform.isWindows) {
    final appData = Platform.environment['APPDATA'] ?? '.';
    return '$appData\\NetShield';
  }
  final home = Platform.environment['HOME'] ?? '.';
  return '$home/.local/share/netshield';
}

File get _sessionFile =>
    File(Platform.isWindows ? '$_sessionDir\\cli-session.json' : '$_sessionDir/cli-session.json');

Future<Map<String, dynamic>?> _loadSession() async {
  try {
    final file = _sessionFile;
    if (!await file.exists()) return null;
    final data = jsonDecode(await file.readAsString());
    if (data is! Map<String, dynamic>) return null;
    if (data['token'] is! String || data['account'] is! String) return null;
    return data;
  } catch (_) {
    return null;
  }
}

Future<void> _saveSession(String token, String account) async {
  final dir = Directory(_sessionDir);
  await dir.create(recursive: true);
  await _sessionFile.writeAsString(jsonEncode({
    'token': token,
    'account': account,
    'saved_at': DateTime.now().toIso8601String(),
  }));
  if (Platform.isLinux || Platform.isMacOS) {
    // Solo el usuario puede leer el token.
    try {
      await Process.run('chmod', ['600', _sessionFile.path]);
    } catch (_) {}
  }
}

Future<void> _clearSession() async {
  try {
    if (await _sessionFile.exists()) await _sessionFile.delete();
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// Utilidades.
// ---------------------------------------------------------------------------

LinuxVpn _vpn(ApiClient api) {
  if (Platform.isWindows) return WindowsVpn(api);
  if (Platform.isLinux) return LinuxVpn(api);
  throw const ApiException('El CLI solo funciona en Linux y Windows.');
}

String _formatBytes(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
}

String _timeAgo(String iso) {
  final dt = DateTime.tryParse(iso);
  if (dt == null) return iso;
  final diff = DateTime.now().toUtc().difference(dt.toUtc());
  if (diff.inMinutes < 1) return 'ahora mismo';
  if (diff.inMinutes < 60) return 'hace ${diff.inMinutes} min';
  if (diff.inHours < 24) return 'hace ${diff.inHours} h';
  return 'hace ${diff.inDays} d';
}

void _printHelp() {
  stdout.writeln('Uso: ${_bold('netshield')} <comando> [opciones]');
  stdout.writeln();
  stdout.writeln(_bold('Sesión'));
  stdout.writeln('  ${_cyan('login')}                Inicia sesión y guarda el token para el CLI.');
  stdout.writeln('  ${_cyan('logout')}               Desconecta la VPN y cierra la sesión.');
  stdout.writeln();
  stdout.writeln(_bold('VPN'));
  stdout.writeln('  ${_cyan('connect')}              Conecta la VPN.');
  stdout.writeln('  ${_cyan('disconnect')}           Desconecta la VPN.');
  stdout.writeln('  ${_cyan('status')}               Muestra el estado de la sesión y del túnel.');
  stdout.writeln('  ${_cyan('killswitch')} ${_dim('on|off|status')}   Activa, desactiva o consulta el bloqueo de tráfico.');
  stdout.writeln('  ${_cyan('ssh')} ${_dim('on|off|status')}          Permite o bloquea SSH con la VPN activa.');
  stdout.writeln();
  stdout.writeln(_bold('Cuenta'));
  stdout.writeln('  ${_cyan('devices')}              Lista los dispositivos VPN.');
  stdout.writeln('  ${_cyan('devices revoke')} <id>  Revoca un dispositivo.');
  stdout.writeln('  ${_cyan('alerts')}               Muestra las alertas de seguridad recientes.');
  stdout.writeln('  ${_cyan('usage')}                Muestra el consumo de datos.');
  stdout.writeln();
  stdout.writeln('  ${_cyan('version')}              Muestra la versión.');
  stdout.writeln('  ${_cyan('help')}                 Muestra esta ayuda.');
  stdout.writeln();
  stdout.writeln(_dim('El token se guarda en ${_sessionFile.path} (solo legible por ti).'));
  stdout.writeln(_dim('La sesión dura 30 minutos; si caduca, vuelve a hacer login.'));
}

// ---------------------------------------------------------------------------
// Comandos.
// ---------------------------------------------------------------------------

Future<({String token, String account})> _requireSession(ApiClient api) async {
  final session = await _loadSession();
  if (session == null) {
    throw const ApiException('No hay sesión. Primero ejecuta: netshield login');
  }
  return (token: session['token'] as String, account: session['account'] as String);
}

Future<void> _cmdLogin(ApiClient api) async {
  _banner();
  final username = _readLine('Usuario: ');
  if (username.isEmpty) throw const ApiException('El usuario no puede estar vacío.');
  final password = _readLine('Contraseña: ', secret: true);
  if (password.isEmpty) throw const ApiException('La contraseña no puede estar vacía.');
  final token = await _withSpinner('Iniciando sesión', () => api.login(username, password));
  await _saveSession(token, username);
  stdout.writeln(_ok('Sesión iniciada como ${_bold(username)}.'));
  stdout.writeln(_dim('Ya puedes conectar con: netshield connect'));
}

Future<void> _cmdLogout(ApiClient api, LinuxVpn vpn) async {
  final session = await _loadSession();
  if (session == null) {
    stdout.writeln(_warn('No hay sesión activa.'));
    return;
  }
  final connected = await vpn.isConnected().catchError((_) => false);
  final blocked = await vpn.isKillSwitchEnabled().catchError((_) => false);
  if (connected || blocked) {
    await _withSpinner('Desconectando la VPN', () => vpn.disconnect());
  }
  await _clearSession();
  stdout.writeln(_ok('Sesión cerrada.'));
}

Future<void> _cmdConnect(ApiClient api, LinuxVpn vpn) async {
  final session = await _requireSession(api);
  if (await vpn.isConnected().catchError((_) => false)) {
    stdout.writeln(_ok('La VPN ya está conectada.'));
    return;
  }
  await _withSpinner('Conectando la VPN', () => vpn.connect(session.token, session.account));
  stdout.writeln(_ok('Conectado. Todo tu tráfico pasa por el túnel.'));
  final blocked = await vpn.isKillSwitchEnabled().catchError((_) => false);
  stdout.writeln(blocked
      ? _dim('Bloqueo de tráfico: activado.')
      : _warn('Bloqueo de tráfico: desactivado. Actívalo con: netshield killswitch on'));
}

Future<void> _cmdDisconnect(LinuxVpn vpn) async {
  if (!await vpn.isConnected().catchError((_) => false)) {
    stdout.writeln(_warn('La VPN ya está desconectada.'));
    return;
  }
  await _withSpinner('Desconectando la VPN', () => vpn.disconnect());
  stdout.writeln(_ok('Desconectado.'));
}

Future<void> _cmdStatus(ApiClient api, LinuxVpn vpn) async {
  final session = await _loadSession();
  final connected = await vpn.isConnected().catchError((_) => false);
  final blocked = await vpn.isKillSwitchEnabled().catchError((_) => false);
  stdout.writeln(_bold('NetShield VPN'));
  stdout.writeln('  Sesión:   ${session == null ? _red('no iniciada (netshield login)') : _green('activa como ${session['account']}')}');
  stdout.writeln('  Túnel:    ${connected ? _green('conectado') : _yellow('desconectado')}');
  stdout.writeln('  Bloqueo:  ${blocked ? _green('activado') : _yellow('desactivado')}');
  if (connected) {
    final gateway = await vpn.gatewayReachable().catchError((_) => null);
    final dns = await vpn.dnsResponds().catchError((_) => null);
    final internet = await vpn.internetReachable().catchError((_) => null);
    stdout.writeln('  Puerta:   ${_check(gateway)}');
    stdout.writeln('  DNS:      ${_check(dns)}');
    stdout.writeln('  Internet: ${_check(internet)}');
    try {
      final client = HttpClient()..connectionTimeout = const Duration(seconds: 6);
      final req = await client.getUrl(Uri.parse('https://api.ipify.org'));
      final res = await req.close().timeout(const Duration(seconds: 8));
      final ip = (await utf8.decoder.bind(res).join()).trim();
      if (ip.isNotEmpty) stdout.writeln('  IP con VPN: ${_cyan(ip)}');
      client.close();
    } catch (_) {}
  }
}

String _check(bool? ok) => ok == null ? _dim('sin datos') : (ok ? _green('bien') : _red('falla'));

Future<void> _cmdDevices(ApiClient api, List<String> args) async {
  final session = await _requireSession(api);
  if (args.length >= 2 && args[1] == 'revoke') {
    if (args.length < 3 || args[2].isEmpty) {
      throw const ApiException('Uso: netshield devices revoke <id>');
    }
    final id = args[2];
    await _withSpinner('Revocando dispositivo', () => api.revokeVpnDevice(session.token, id));
    stdout.writeln(_ok('Dispositivo revocado.'));
    return;
  }
  final devices = await _withSpinner(
      'Consultando dispositivos', () => api.vpnDevices(session.token));
  if (devices.isEmpty) {
    stdout.writeln(_dim('No hay dispositivos registrados.'));
    return;
  }
  final localId = await _vpn(api).deviceId().catchError((_) => '');
  stdout.writeln(_bold('Dispositivos VPN (${devices.length})'));
  for (final d in devices) {
    final id = d['device_id']?.toString() ?? '?';
    final enabled = d['enabled'] == true;
    final mark = id == localId ? _cyan(' (este equipo)') : '';
    final state = enabled ? _green('activo') : _red('revocado');
    stdout.writeln('  ${_dim(id)}  $state$mark');
  }
}

Future<void> _cmdAlerts(ApiClient api) async {
  final session = await _requireSession(api);
  final feed = await _withSpinner(
      'Consultando alertas', () => api.securityAlerts(session.token));
  final alerts = feed.alerts;
  if (alerts.isEmpty) {
    stdout.writeln(_ok('No hay alertas guardadas.'));
    return;
  }
  final pending = alerts.where((a) => a['review_status'] == 'new').length;
  stdout.writeln(_bold('Alertas (${alerts.length})') +
      (pending > 0 ? '  ${_red('$pending pendiente${pending == 1 ? '' : 's'}')}' : ''));
  for (final a in alerts.take(15)) {
    final sev = a['severity'];
    final sevText = sev is int && sev <= 2 ? _red('sev $sev') : _yellow('sev $sev');
    final sig = (a['signature'] ?? '?').toString();
    final when = _timeAgo((a['occurred_at'] ?? '').toString());
    final status = a['review_status'] == 'new' ? _red('pendiente') : _dim('${a['review_status']}');
    stdout.writeln('  [$sevText] $sig');
    stdout.writeln('      ${_dim('$when · $status')}');
  }
  if (alerts.length > 15) stdout.writeln(_dim('  ... y ${alerts.length - 15} más.'));
}

Future<void> _cmdUsage(ApiClient api) async {
  final session = await _requireSession(api);
  final usage = await _withSpinner('Consultando consumo', () => api.vpnUsage(session.token));
  if (usage.isEmpty) {
    stdout.writeln(_dim('Sin datos de consumo.'));
    return;
  }
  var up = 0, down = 0;
  for (final u in usage) {
    up += u.uploadBytes ?? 0;
    down += u.downloadBytes ?? 0;
  }
  stdout.writeln(_bold('Consumo'));
  stdout.writeln('  Subida:   ${_cyan(_formatBytes(up))}');
  stdout.writeln('  Bajada:   ${_cyan(_formatBytes(down))}');
  stdout.writeln('  Total:    ${_cyan(_formatBytes(up + down))}');
  try {
    final history = await api.vpnUsageHistory(session.token);
    if (history.isNotEmpty) {
      stdout.writeln();
      stdout.writeln(_bold('Últimos días'));
      for (final day in history.take(7)) {
        stdout.writeln('  ${day.day}  ${_formatBytes((day.uploadBytes ?? 0) + (day.downloadBytes ?? 0))}');
      }
    }
  } catch (_) {}
}

Future<void> _cmdKillswitch(LinuxVpn vpn, List<String> args) async {
  final action = args.length >= 2 ? args[1].toLowerCase() : 'status';
  if (action == 'on') {
    await _withSpinner('Activando el bloqueo de tráfico', () => vpn.setKillSwitch(true));
    stdout.writeln(_ok('Bloqueo de tráfico activado.'));
    return;
  }
  if (action == 'off') {
    await _withSpinner('Desactivando el bloqueo de tráfico', () => vpn.setKillSwitch(false));
    stdout.writeln(_ok('Bloqueo de tráfico desactivado.'));
    return;
  }
  if (action == 'status') {
    final blocked = await vpn.isKillSwitchEnabled();
    stdout.writeln('Bloqueo de tráfico: ${blocked ? _green('activado') : _yellow('desactivado')}');
    return;
  }
  throw const ApiException('Uso: netshield killswitch on|off|status');
}

Future<void> _cmdSsh(LinuxVpn vpn, List<String> args) async {
  final action = args.length >= 2 ? args[1].toLowerCase() : 'status';
  if (action == 'on') {
    await _withSpinner('Permitir conexiones SSH', () => vpn.setSshAllowed(true));
    stdout.writeln(_ok('SSH permitido con la VPN activa.'));
    stdout.writeln(_warn('Esto debilita el bloqueo de tráfico: abre una salida que no pasa por el túnel.'));
    return;
  }
  if (action == 'off') {
    await _withSpinner('Bloquear conexiones SSH', () => vpn.setSshAllowed(false));
    stdout.writeln(_ok('SSH bloqueado con la VPN activa.'));
    return;
  }
  if (action == 'status') {
    final allowed = await vpn.isSshAllowed();
    stdout.writeln('Permitir SSH: ${allowed ? _green('sí') : _yellow('no')}');
    return;
  }
  throw const ApiException('Uso: netshield ssh on|off|status');
}

// ---------------------------------------------------------------------------
// Entrada.
// ---------------------------------------------------------------------------

Future<void> main(List<String> args) async {
  // Sin argumentos: banner + estado + ayuda.
  if (args.isEmpty) {
    _banner();
    final api = ApiClient();
    try {
      await _cmdStatus(api, _vpn(api));
    } on ApiException catch (e) {
      _error(e);
    }
    stdout.writeln();
    _printHelp();
    return;
  }
  final cmd = args[0].toLowerCase();
  if (cmd == 'help' || cmd == '--help' || cmd == '-h') {
    _banner();
    _printHelp();
    return;
  }
  if (cmd == 'version' || cmd == '--version' || cmd == '-v') {
    stdout.writeln('$_apiName CLI v$_version');
    return;
  }
  final api = ApiClient();
  // Conectar, desconectar, salir y cambiar el bloqueo/SSH necesitan root:
  // el CLI se re-ejecuta con sudo (la contraseña se pide en la terminal).
  // Las consultas (status) no necesitan root.
  final needsRoot = switch (cmd) {
    'connect' || 'disconnect' || 'logout' => true,
    'killswitch' => args.length >= 2 && (args[1] == 'on' || args[1] == 'off'),
    'ssh' => args.length >= 2 && (args[1] == 'on' || args[1] == 'off'),
    _ => false,
  };
  if (needsRoot) await _ensureRoot(args);
  try {
    switch (cmd) {
      case 'login':
        await _cmdLogin(api);
      case 'logout':
        await _cmdLogout(api, _vpn(api));
      case 'connect':
        await _cmdConnect(api, _vpn(api));
      case 'disconnect':
        await _cmdDisconnect(_vpn(api));
      case 'status':
        await _cmdStatus(api, _vpn(api));
      case 'devices':
        await _cmdDevices(api, args);
      case 'alerts':
        await _cmdAlerts(api);
      case 'usage':
        await _cmdUsage(api);
      case 'killswitch':
        await _cmdKillswitch(_vpn(api), args);
      case 'ssh':
        await _cmdSsh(_vpn(api), args);
      default:
        stderr.writeln(_fail('Comando desconocido: $cmd'));
        _printHelp();
        exitCode = 2;
    }
  } on ApiException catch (e) {
    _error(e);
    // Sesión caducada o inválida: avisa cómo recuperarla.
    if (e.message.contains('sesión') || e.message.contains('token')) {
      stderr.writeln(_dim('Vuelve a iniciar sesión con: netshield login'));
    }
    exitCode = 1;
  } catch (e) {
    _error(e);
    exitCode = 1;
  } finally {
    api.close();
  }
}
