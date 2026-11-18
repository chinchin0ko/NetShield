import 'dart:async';
import 'dart:convert';
import 'dart:io';

class DevTunnelException implements Exception {
  const DevTunnelException(this.message);
  final String message;
}

/// A private, application-owned SSH forward for this developer's environment.
class DevTunnel {
  Process? _process;
  Uri? _uri;
  Future<Uri>? _starting;
  bool _closed = false;

  Future<Uri> ensureStarted() async {
    if (_closed) throw const DevTunnelException('El acceso de desarrollo ya se cerró.');
    if (_process != null && _uri != null) return _uri!;
    return _starting ??= _start().whenComplete(() => _starting = null);
  }

  static String _quote(String value) => "'${value.replaceAll("'", "'\\''")}'";

  Future<Uri> _start() async {
    if (!Platform.isLinux) throw const DevTunnelException('El acceso automático de desarrollo solo está disponible en Linux.');
    final home = Platform.environment['HOME'];
    if (home == null) throw const DevTunnelException('No se encontró tu carpeta personal.');
    final key = Platform.environment['NETSHIELD_SSH_KEY'] ?? '$home/Projects/SSH/UPVPN/ssh-key-2026-09-17.key';
    final jump = Platform.environment['NETSHIELD_SSH_JUMP'] ?? 'ubuntu@140.84.183.78';
    final target = Platform.environment['NETSHIELD_SSH_API'] ?? 'ubuntu@10.0.0.250';
    if (!await File(key).exists()) throw const DevTunnelException('No se encontró la clave SSH de desarrollo.');
    // Reject SSH option injection; these are development host identifiers.
    final hostPattern = RegExp(r'^[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.:-]+$');
    if (!hostPattern.hasMatch(jump) || !hostPattern.hasMatch(target)) throw const DevTunnelException('La configuración SSH de desarrollo es inválida.');
    final reservation = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = reservation.port;
    await reservation.close();
    final proxy = 'ssh -F /dev/null -i ${_quote(key)} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=8 -W %h:%p ${_quote(jump)}';
    // Linux prctl causes the SSH child to terminate if the app process exits,
    // including a crash; the private key is never copied into the application.
    const launcher = 'import ctypes,os,signal,sys; libc=ctypes.CDLL(None); '
        'libc.prctl(1,signal.SIGTERM)==0 or sys.exit(1); '
        'os.getppid()!=1 or sys.exit(1); '
        'os.execvp(sys.argv[1],sys.argv[1:])';
    Process process;
    try {
      process = await Process.start('python3', [
        '-c', launcher, 'ssh', '-F', '/dev/null', '-N', '-v', '-i', key,
        '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=8',
        '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
        '-o', 'ProxyCommand=$proxy', '-L', '127.0.0.1:$port:127.0.0.1:18000', target,
      ]);
    } on ProcessException {
      throw const DevTunnelException('No se pudo iniciar SSH para acceder a la API.');
    }
    final ready = Completer<void>();
    final subscription = process.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
      if (line.contains('Local forwarding listening on 127.0.0.1 port $port.') && !ready.isCompleted) ready.complete();
    }, onError: (_) { if (!ready.isCompleted) ready.completeError(const DevTunnelException('Falló el acceso SSH de desarrollo.')); });
    process.stdout.drain<void>();
    process.exitCode.then((_) {
      if (identical(_process, process)) { _process = null; _uri = null; }
      if (!ready.isCompleted) ready.completeError(const DevTunnelException('No se pudo abrir el acceso SSH. Revisa la clave y las huellas conocidas.'));
    });
    try {
      await ready.future.timeout(const Duration(seconds: 25));
      if (_closed) throw const DevTunnelException('El acceso de desarrollo ya se cerró.');
      _process = process;
      _uri = Uri.parse('http://127.0.0.1:$port');
      return _uri!;
    } catch (_) {
      process.kill();
      await subscription.cancel();
      rethrow;
    }
  }

  void close() {
    _closed = true;
    reset();
  }

  void reset() {
    _process?.kill();
    _process = null;
    _uri = null;
  }
}
