// NetShield Windows Service server (netshield-server.exe).
//
// Runs as SYSTEM and performs the privileged steps (Windows Firewall +
// WireGuard tunnel) so the app asks for administrator approval only once
// (when the service is installed) instead of once per connect/disconnect.
//
// This exe is NOT registered with the SCM directly. The native C wrapper
// (netshield-service.exe, windows/service/netshield_service_wrapper.c)
// is the binary the SCM runs; it launches this exe with --console as a
// child process. The wrapper exists because this Dart exe cannot run as
// a real service: its ServiceMain uses Pointer.fromFunction, which may
// only be invoked on the isolate's mutator thread, but the SCM calls
// ServiceMain on its own dispatcher thread -> abort (0xc0000409).
// See windows-service/SERVICE_CRASH.md. The service-mode code below
// (_runAsService / _serviceMain) is therefore superseded and must not
// be used to register a service; it stays only as reference.
//
//   Install (one UAC prompt, or by the installer which is already admin):
//     sc.exe create NetShieldService binPath= "C:\Program Files\NetShield\netshield-service.exe" start= auto obj= LocalSystem
//     sc.exe start NetShieldService
//   (binPath points to the C wrapper, which launches netshield-server.exe
//   --console from the same directory.)
//   Protocol: loopback TCP 127.0.0.1:18099, one JSON object per line each
//   way. Only the five structured commands below are accepted; the
//   service never runs arbitrary PowerShell from the socket, and every
//   parameter is validated before use.
//
//     {"cmd":"ping"}                                             -> {"ok":true,"exitCode":0,"version":"1"}
//     {"cmd":"connect","tunnel":"ns...","wireguardExe":"...",
//      "configPath":"...","endpoint":"140.84.183.78",
//      "allowSsh":false}                                         -> exit 0/10/20
//     {"cmd":"disconnect","uninstallTunnel":true,"wireguardExe":"...",
//      "tunnel":"ns...","disableKillswitch":true,
//      "original":{"Domain":"Allow",...}}                        -> exit 0/10/20
//     {"cmd":"killswitch","enable":true,"tunnel":"ns...",
//      "endpoint":"140.84.183.78","allowSsh":false}              -> exit 0/10
//     {"cmd":"killswitch","enable":false,
//      "original":{"Domain":"Allow",...}}                        -> exit 0/10
//     {"cmd":"route","add":true,"endpoint":"...","gateway":"..."} -> exit 0
//
// Exit codes are WindowsAdminExit (0 ok, 10 firewall, 20 tunnel).
// Loopback traffic is not filtered by the Windows Firewall, so the app
// can reach the service even while the killswitch is on.
//
// Threading: the main thread blocks in StartServiceCtrlDispatcher, so
// the TCP server runs in its own isolate (spawned before the dispatcher
// starts). ServiceMain only registers the handler, reports RUNNING and
// waits for the stop flag the control handler sets.
//
//   --console   Run the TCP server in the foreground (debug/test, no SCM).
//               Useful on windowsdejuan: run it, connect the app, confirm
//               no UAC prompt appears, then Ctrl+C.
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';
import 'package:netshield_app/services/windows_admin_commands.dart';
import 'package:win32/win32.dart';

const _serviceName = 'NetShieldService';
const _host = '127.0.0.1';
const _port = 18099;
const _version = '1';

// Service states / controls. The state and type values use win32's
// named constants (SERVICE_STATUS_CURRENT_STATE / ENUM_SERVICE_TYPE
// extension types); the control codes are plain ints.
const _serviceAcceptStop = 0x1;
const _serviceAcceptShutdown = 0x4;
const _serviceControlStop = 0x1;
const _serviceControlShutdown = 0x5;
const _serviceControlInterrogate = 0x4;
const _noError = 0;

/// Set by the control handler when the SCM asks the service to stop.
/// ServiceMain polls it and shuts down. A plain flag is enough here:
// ServiceMain only needs to notice the request within ~100 ms.
bool _stopping = false;

/// The server isolate's control port, set by main() before the dispatcher
/// starts. ServiceMain sends 'stop' on it when the SCM stops the service.
SendPort? _serverControl;

/// The SCM status handle, set by ServiceMain.
late SERVICE_STATUS_HANDLE _statusHandle;

/// Current service state, for the INTERROGATE control.
SERVICE_STATUS_CURRENT_STATE _currentState = SERVICE_START_PENDING;

void main(List<String> args) async {
  if (args.contains('--console')) {
    // Debug/test: the TCP server in the foreground, no SCM.
    stdout.writeln('NetShield Service (console) on $_host:$_port');
    final server = await _startServer();
    await ProcessSignal.sigint.watch().first;
    await server.close();
    return;
  }

  // Service mode: the TCP server runs in its own isolate (the main
  // thread blocks in the dispatcher), then hand over to the SCM.
  final ready = ReceivePort();
  final serverIsolate = await Isolate.spawn(
      _serverMain, ready.sendPort,
      onError: ready.sendPort, onExit: ready.sendPort);
  // The server isolate sends its control SendPort as its first message.
  final control = await ready.first;
  if (control is SendPort) {
    _serverControl = control;
  } else {
    // The isolate failed before sending its port; there is nothing to
    // serve, so do not register a service that cannot work.
    serverIsolate.kill();
    stderr.writeln('NetShield Service: the server isolate failed to start.');
    exit(1);
  }
  _runAsService();
}

void _runAsService() {
  final serviceTable = calloc<SERVICE_TABLE_ENTRY>(2);
  serviceTable[0].lpServiceName = PWSTR(_serviceName.toNativeUtf16());
  serviceTable[0].lpServiceProc =
      Pointer.fromFunction<LPSERVICE_MAIN_FUNCTION>(_serviceMain);
  serviceTable[1].lpServiceName = PWSTR(nullptr);
  serviceTable[1].lpServiceProc = nullptr;
  final result = StartServiceCtrlDispatcher(serviceTable);
  // StartServiceCtrlDispatcher returns when the service stops. If it
  // fails outright (e.g. the exe was run by hand, not by the SCM),
  // fall back to console mode so the exe still works for testing.
  if (!result.value) {
    _runConsoleFallback();
  }
  calloc.free(serviceTable);
}

Future<void> _runConsoleFallback() async {
  stdout.writeln('NetShield Service (console fallback) on $_host:$_port');
  final server = await _startServer();
  await ProcessSignal.sigint.watch().first;
  await server.close();
}

// -- ServiceMain / control handler (FFI callbacks, top-level). -------------

/// ServiceMain: registers the control handler, reports RUNNING, then
/// waits for the stop flag. Runs on the SCM dispatcher thread.
void _serviceMain(int argc, Pointer<Pointer<Utf16>> argv) {
  final handler =
      Pointer.fromFunction<LPHANDLER_FUNCTION>(_serviceCtrlHandler);
  final handle = RegisterServiceCtrlHandler(
      PCWSTR(_serviceName.toNativeUtf16()), handler);
  if (handle.value == nullptr) return;
  _statusHandle = handle.value;
  _reportStatus(SERVICE_RUNNING);
  // Block until the control handler asks us to stop. The TCP server
  // lives in its own isolate, so this thread is free to wait here.
  while (!_stopping) {
    sleep(const Duration(milliseconds: 100));
  }
  _serverControl?.send('stop');
  _reportStatus(SERVICE_STOPPED);
}

/// Control handler: STOP/SHUTDOWN tells ServiceMain to shut down,
/// INTERROGATE re-reports the current state. Returns void, matching
/// win32's LPHANDLER_FUNCTION (Void Function(Uint32)).
void _serviceCtrlHandler(int control) {
  if (control == _serviceControlStop ||
      control == _serviceControlShutdown) {
    _stopping = true;
    _reportStatus(SERVICE_STOP_PENDING);
    return;
  }
  if (control == _serviceControlInterrogate) {
    _reportStatus(_currentState);
    return;
  }
}

void _reportStatus(SERVICE_STATUS_CURRENT_STATE state) {
  _currentState = state;
  final status = calloc<SERVICE_STATUS>();
  status.ref.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  status.ref.dwCurrentState = state;
  status.ref.dwControlsAccepted =
      _serviceAcceptStop | _serviceAcceptShutdown;
  status.ref.dwWin32ExitCode = _noError;
  status.ref.dwServiceSpecificExitCode = 0;
  status.ref.dwCheckPoint = 0;
  status.ref.dwWaitHint = 0;
  SetServiceStatus(_statusHandle, status);
  calloc.free(status);
}

// -- TCP server (its own isolate in service mode). --------------------------

/// Server isolate entry point. [mainPort] receives the control SendPort
/// as the first message; sending 'stop' on it shuts the server down.
/// The server binds BEFORE the port is sent, so a bind failure (e.g. the
/// port is already taken) errors the isolate before main() registers a
/// service that cannot serve.
Future<void> _serverMain(SendPort mainPort) async {
  final control = ReceivePort();
  final server = await _startServer();
  mainPort.send(control.sendPort);
  await for (final message in control) {
    if (message == 'stop') {
      await server.close();
      control.close();
      Isolate.exit();
    }
  }
}

Future<ServerSocket> _startServer() async {
  final server = await ServerSocket.bind(_host, _port);
  server.listen((socket) {
    _handleConnection(socket).catchError((_) async {
      try {
        await socket.close();
      } catch (_) {}
    });
  });
  return server;
}

Future<void> _handleConnection(Socket socket) async {
  try {
    await for (final line in utf8.decoder
        .bind(socket)
        .transform(const LineSplitter())) {
      if (line.trim().isEmpty) continue;
      Map<String, dynamic> response;
      try {
        final command = jsonDecode(line);
        if (command is! Map<String, dynamic>) {
          throw const FormatException('command is not an object');
        }
        response = await _dispatch(command);
      } catch (e) {
        response = {
          'ok': false,
          'exitCode': WindowsAdminExit.firewallFailed,
          'error': e.toString(),
        };
      }
      socket.writeln(jsonEncode(response));
      await socket.flush();
    }
  } finally {
    await socket.close();
  }
}

Future<Map<String, dynamic>> _dispatch(Map<String, dynamic> command) async {
  final cmd = command['cmd'];
  switch (cmd) {
    case 'ping':
      return {
        'ok': true,
        'exitCode': WindowsAdminExit.ok,
        'version': _version,
      };
    case 'connect':
      return _handleConnect(command);
    case 'disconnect':
      return _handleDisconnect(command);
    case 'killswitch':
      return _handleKillswitch(command);
    case 'route':
      return _handleRoute(command);
    default:
      return {
        'ok': false,
        'exitCode': WindowsAdminExit.firewallFailed,
        'error': 'unknown command: $cmd',
      };
  }
}

// -- Command handlers (run as SYSTEM; validate everything first). -----------

Future<Map<String, dynamic>> _handleConnect(
    Map<String, dynamic> command) async {
  final tunnel = _requireTunnel(command['tunnel']);
  final wireguardExe = _requireExePath(command['wireguardExe']);
  final configPath = _requireConfPath(command['configPath']);
  final endpoint = _requireIPv4(command['endpoint']);
  final allowSsh = _requireBool(command['allowSsh'], 'allowSsh');
  final code = await _runPowerShell(WindowsAdminCommands.connectAdminScript(
    tunnel,
    endpoint,
    wireguardExe,
    configPath,
    allowSsh: allowSsh,
  ));
  return {
    'ok': code == WindowsAdminExit.ok,
    'exitCode': code,
  };
}

Future<Map<String, dynamic>> _handleDisconnect(
    Map<String, dynamic> command) async {
  final uninstallTunnel =
      _requireBool(command['uninstallTunnel'], 'uninstallTunnel');
  final wireguardExe = uninstallTunnel
      ? _requireExePath(command['wireguardExe'])
      : '';
  final tunnel = _requireTunnel(command['tunnel']);
  final disableKillswitch =
      _requireBool(command['disableKillswitch'], 'disableKillswitch');
  final original = _optionalOriginal(command['original']);
  final code = await _runPowerShell(
      WindowsAdminCommands.disconnectAdminScript(
    uninstallTunnel: uninstallTunnel,
    wireguardExe: wireguardExe,
    tunnel: tunnel,
    disableKillswitch: disableKillswitch,
    original: original,
  ));
  return {
    'ok': code == WindowsAdminExit.ok,
    'exitCode': code,
  };
}

Future<Map<String, dynamic>> _handleKillswitch(
    Map<String, dynamic> command) async {
  final enable = _requireBool(command['enable'], 'enable');
  final original = _optionalOriginal(command['original']);
  final List<String> lines;
  if (enable) {
    final tunnel = _requireTunnel(command['tunnel']);
    final endpoint = _requireIPv4(command['endpoint']);
    final allowSsh = _requireBool(command['allowSsh'], 'allowSsh');
    lines = [
      r"$ErrorActionPreference = 'Stop'",
      ...WindowsAdminCommands.killswitchEnableCommands(tunnel, endpoint,
          allowSsh: allowSsh),
    ];
  } else {
    lines = [
      r"$ErrorActionPreference = 'Stop'",
      ...WindowsAdminCommands.killswitchDisableCommands(original: original),
    ];
  }
  final code = await _runPowerShell(lines);
  return {
    'ok': code == WindowsAdminExit.ok,
    'exitCode': code == WindowsAdminExit.ok
        ? WindowsAdminExit.ok
        : WindowsAdminExit.firewallFailed,
  };
}

Future<Map<String, dynamic>> _handleRoute(
    Map<String, dynamic> command) async {
  final add = _requireBool(command['add'], 'add');
  final endpoint = _requireIPv4(command['endpoint']);
  final code = await _runPowerShell(add
      ? [
          'route add $endpoint mask 255.255.255.255 '
              '${_requireIPv4(command['gateway'])} metric 5',
        ]
      : [
          'route delete $endpoint',
        ]);
  return {
    'ok': code == WindowsAdminExit.ok,
    'exitCode': code,
  };
}

// -- Validation (the service never trusts the socket). -----------------------

String _requireTunnel(dynamic value) {
  if (value is String && RegExp(r'^ns[0-9a-f]{12}$').hasMatch(value)) {
    return value;
  }
  throw const FormatException('tunnel inválido');
}

String _requireIPv4(dynamic value) {
  if (value is String) {
    final address = InternetAddress.tryParse(value);
    if (address != null && address.type == InternetAddressType.IPv4) {
      return value;
    }
  }
  throw const FormatException('dirección IPv4 inválida');
}

bool _requireBool(dynamic value, String name) {
  if (value is bool) return value;
  throw FormatException('$name debe ser true o false');
}

/// An absolute Windows path that exists and cannot break out of the
/// double-quoted string it is embedded in.
String _requirePath(dynamic value, String suffix) {
  if (value is! String ||
      value.isEmpty ||
      value.contains('"') ||
      value.contains('\n') ||
      value.contains('\r') ||
      !value.contains(':') ||
      !value.endsWith(suffix)) {
    throw const FormatException('ruta inválida');
  }
  if (!File(value).existsSync()) {
    throw const FormatException('el archivo no existe');
  }
  return value;
}

String _requireExePath(dynamic value) =>
    _requirePath(value, 'wireguard.exe');

String _requireConfPath(dynamic value) => _requirePath(value, '.conf');

Map<String, String>? _optionalOriginal(dynamic value) {
  if (value == null) return null;
  if (value is! Map) throw const FormatException('original inválido');
  final original = <String, String>{};
  for (final entry in value.entries) {
    final key = entry.key.toString();
    final v = entry.value.toString();
    if (!{'Domain', 'Private', 'Public'}.contains(key)) {
      throw const FormatException('perfil de firewall inválido');
    }
    final restored = WindowsAdminCommands.restoreAction(v);
    // restoreAction falls back to Allow for unknown values; reject them
    // outright here so a typo cannot silently change a profile.
    if (v.trim().toLowerCase() != restored.toLowerCase()) {
      throw const FormatException('acción de firewall inválida');
    }
    original[key] = restored;
  }
  return original.isEmpty ? null : original;
}

// -- PowerShell (as SYSTEM: no UAC, no window). ------------------------------

/// Runs [lines] as a temporary .ps1 (no RunAs needed: the service is
/// already SYSTEM) and returns the exit code.
Future<int> _runPowerShell(List<String> lines) async {
  final temp = await Directory.systemTemp.createTemp('netshield-svc-');
  try {
    final script = File('${temp.path}\\netshield-admin.ps1');
    await script.writeAsString(lines.join('\r\n'), flush: true);
    final result = await Process.run('powershell', [
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      script.path,
    ]).timeout(const Duration(seconds: 120));
    if (result.exitCode != WindowsAdminExit.ok) {
      stderr.writeln('PowerShell exit ${result.exitCode}: ${result.stderr}');
    }
    return result.exitCode;
  } on TimeoutException {
    return WindowsAdminExit.firewallFailed;
  } finally {
    await temp.delete(recursive: true);
  }
}
