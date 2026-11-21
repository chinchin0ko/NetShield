import 'dart:ui';
import 'dart:async';
import 'dart:io';
import 'package:material_ui/material_ui.dart';
import 'services/api_client.dart';
import 'services/linux_vpn.dart';
import 'services/android_vpn.dart';
import 'services/android_push.dart';
import 'services/desktop_notifications.dart';
import 'screens/dashboard_panels.dart';

const cream = Color(0xFFdad7cd);
const sage = Color(0xFFa3b18a);
const green = Color(0xFF588157);
const forest = Color(0xFF3a5a40);
const deep = Color(0xFF344e41);

void main() => runApp(const NetShieldApp());

class NetShieldApp extends StatelessWidget {
  const NetShieldApp({super.key, this.api, this.vpn, this.notifier});
  final ApiClient? api;
  final LinuxVpn? vpn;
  final AlertNotifier? notifier;
  @override
  Widget build(BuildContext context) => MaterialApp(
    debugShowCheckedModeBanner: false,
    title: 'NetShield VPN',
    theme: ThemeData(useMaterial3: true, fontFamily: 'sans-serif', colorScheme: ColorScheme.fromSeed(seedColor: green)),
    home: ShieldHome(api: api ?? ApiClient(), vpn: vpn, notifier: notifier),
  );
}

class ShieldHome extends StatefulWidget {
  const ShieldHome({super.key, required this.api, this.vpn, this.notifier});
  final ApiClient api;
  final LinuxVpn? vpn;
  final AlertNotifier? notifier;
  @override
  State<ShieldHome> createState() => _ShieldHomeState();
}

class _ShieldHomeState extends State<ShieldHome> {
  final username = TextEditingController();
  final password = TextEditingController();
  final confirm = TextEditingController();
  bool register = false, loading = false, hidePassword = true;
  bool vpnConnected = false, vpnLoading = false, trafficBlocked = false;
  bool connectionTransition = false;
  bool gatewayChecking = false;
  bool? gatewayHealthy;
  int gatewayFailures = 0;
  bool? dnsHealthy, internetHealthy;
  int dnsFailures = 0, internetFailures = 0;
  int vpnGeneration = 0;
  Timer? gatewayCooldown;
  int page = 0;
  TrafficUsage? usage;
  List<VpnDeviceUsage>? serverUsage;
  List<VpnUsageDay>? usageHistory;
  bool historyUnavailable = false;
  bool serverUsageUnavailable = false;
  DateTime? serverUsageRequestedAt;
  bool usageLoading = false;
  bool alertsLoading = false, alertsChecking = false;
  bool alertsInitialized = false;
  int lastAlertId = 0;
  final Set<int> unseenAlertIds = {};
  int alertSession = 0;
  Timer? alertsTimer;
  List<Map<String, dynamic>>? alerts;
  String? alertsError;
  String alertMonitoring = 'not_active';
  late final LinuxVpn vpn = widget.vpn ?? (Platform.isAndroid ? AndroidVpn(widget.api) : LinuxVpn(widget.api));
  late final AlertNotifier notifier = widget.notifier ?? LinuxAlertNotifier();
  late final AndroidPush push = AndroidPush(widget.api, vpn);
  Future<void>? pushStarting;
  bool pushActive = false;
  Timer? monitor;
  String? error, notice, token, signedInAs;

  @override
  void initState() {
    super.initState();
    vpn.isKillSwitchEnabled().then((blocked) {
      if (mounted) setState(() => trafficBlocked = blocked);
    }).catchError((_) {});
  }

  Future<void> unlockBeforeLogin() async {
    setState(() { loading = true; error = null; });
    try {
      await vpn.disconnect();
      if (mounted) setState(() { trafficBlocked = false; notice = 'Bloqueo desactivado. Ya puedes iniciar sesión.'; });
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  @override
  void dispose() { push.dispose(); monitor?.cancel(); alertsTimer?.cancel(); gatewayCooldown?.cancel(); widget.api.close(); username.dispose(); password.dispose(); confirm.dispose(); super.dispose(); }

  Future<void> signIn() async {
    if (loading) return;
    if (username.text.trim().isEmpty || password.text.isEmpty) {
      setState(() => error = 'Introduce tu usuario y contraseña.');
      return;
    }
    setState(() { loading = true; error = null; });
    try {
      final result = await widget.api.login(username.text.trim(), password.text);
      final active = await vpn.isConnected();
      final blocked = await vpn.isKillSwitchEnabled();
      if (!mounted) return;
      setState(() { token = result; signedInAs = username.text.trim(); vpnConnected = active; trafficBlocked = blocked; password.clear(); });
      if (Platform.isAndroid) {
        pushStarting = push.start(result).then((active) {
          if (mounted && token == result) setState(() => pushActive = active);
        });
      }
      alertSession++;
      unawaited(refreshAlerts(background: true));
      alertsTimer?.cancel();
      alertsTimer = Timer.periodic(const Duration(seconds: 15), (_) => unawaited(refreshAlerts(background: true)));
      monitor?.cancel();
      monitor = Timer.periodic(const Duration(seconds: 4), (_) async {
        if (vpnLoading || token == null) return;
        try {
          final active = await vpn.isConnected();
          final blocked = await vpn.isKillSwitchEnabled();
          if (mounted && !vpnLoading && (vpnConnected != active || trafficBlocked != blocked)) {
            setState(() { if (vpnConnected != active) vpnGeneration++; vpnConnected = active; trafficBlocked = blocked; if (!active) { usage = null; gatewayHealthy = null; gatewayFailures = 0; dnsHealthy = null; internetHealthy = null; dnsFailures = 0; internetFailures = 0; gatewayCooldown?.cancel(); gatewayCooldown = null; } });
          }
          if (mounted && active) await refreshGatewayHealth();
          if (mounted && page == 2) await refreshUsage();
        } catch (_) { /* Keep last known state if NetworkManager is unavailable. */ }
      });
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
    } catch (_) {
      if (mounted) setState(() => error = 'No se pudo completar la solicitud.');
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  Future<void> signUp() async {
    final name = username.text.trim();
    if (!RegExp(r'^[a-zA-Z0-9_.-]{3,64}$').hasMatch(name)) {
      setState(() => error = 'Usuario: de 3 a 64 letras, números, punto, guion o guion bajo.');
      return;
    }
    if (password.text.length < 12 || password.text.length > 128 || password.text != confirm.text) {
      setState(() => error = 'Usa una contraseña de 12 a 128 caracteres y confírmala.');
      return;
    }
    setState(() { loading = true; error = null; notice = null; });
    try {
      await widget.api.register(name, password.text);
      if (!mounted) return;
      setState(() { register = false; password.clear(); confirm.clear(); notice = 'Cuenta creada. Ya puedes iniciar sesión.'; });
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
    } catch (_) {
      if (mounted) setState(() => error = 'No se pudo completar la solicitud.');
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  void switchMode(bool value) => setState(() { register = value; error = null; notice = null; password.clear(); confirm.clear(); });

  Future<void> refreshGatewayHealth({bool force = false}) async {
    if (gatewayChecking || token == null || !vpnConnected) return;
    if (!force && (gatewayCooldown?.isActive ?? false)) return;
    final current = token;
    final generation = vpnGeneration;
    gatewayChecking = true;
    gatewayCooldown?.cancel();
    gatewayCooldown = Timer(const Duration(seconds: 15), () {});
    try {
      final reachable = await vpn.gatewayReachable();
      final results = reachable == true
          ? await Future.wait([vpn.dnsResponds(), vpn.internetReachable()])
          : <bool?>[null, null];
      if (!mounted || token != current || !vpnConnected || vpnGeneration != generation) return;
      setState(() {
        final dns = results[0], internet = results[1];
        if (dns == true) { dnsFailures = 0; dnsHealthy = true; }
        else if (dns == false) { dnsFailures++; if (dnsFailures >= 2) dnsHealthy = false; }
        else { dnsFailures = 0; dnsHealthy = null; }
        if (internet == true) { internetFailures = 0; internetHealthy = true; }
        else if (internet == false) { internetFailures++; if (internetFailures >= 2) internetHealthy = false; }
        else { internetFailures = 0; internetHealthy = null; }
        if (reachable == true) {
          gatewayFailures = 0;
          gatewayHealthy = true;
        } else if (reachable == false) {
          gatewayFailures++;
          if (gatewayFailures >= 2) gatewayHealthy = false;
        } else {
          gatewayHealthy = null;
          gatewayFailures = 0;
        }
      });
    } catch (_) {
      if (mounted && token == current && vpnConnected && vpnGeneration == generation) setState(() { gatewayHealthy = null; gatewayFailures = 0; });
    } finally {
      gatewayChecking = false;
    }
  }

  int applyAlertFeed(SecurityAlertFeed result) {
    var newCount = 0;
    final ids = result.alerts.map((item) => item['id'] as int).toList();
    if (alertsInitialized) {
      final newIds = ids.where((id) => id > lastAlertId).toSet();
      newCount = newIds.length;
      unseenAlertIds.addAll(newIds);
    }
    for (final id in ids) {
      if (id > lastAlertId) lastAlertId = id;
    }
    alertsInitialized = true;
    alerts = result.alerts;
    alertMonitoring = result.monitoring;
    alertsError = null;
    return newCount;
  }

  void receiveAlertFeed(SecurityAlertFeed result) {
    var newCount = 0;
    setState(() => newCount = applyAlertFeed(result));
    if (newCount > 0) unawaited(notifier.notifyNewAlerts(newCount));
  }

  Future<void> refreshAlerts({bool background = false}) async {
    if (alertsChecking || alertsLoading || token == null) return;
    final current = token!;
    final session = alertSession;
    setState(() { alertsChecking = true; alertsLoading = !background || alerts == null; alertsError = null; });
    try {
      final result = await widget.api.securityAlerts(current);
      if (mounted && token == current && alertSession == session) receiveAlertFeed(result);
    } catch (_) {
      if (mounted && token == current && alertSession == session) setState(() => alertsError = 'No se pudieron actualizar las alertas. Reintentaremos automáticamente.');
    } finally {
      if (mounted && token == current && alertSession == session) setState(() { alertsLoading = false; alertsChecking = false; });
    }
  }

  Future<void> reviewAlert(int id, String status) async {
    if (alertsLoading || alertsChecking || token == null) return;
    final current = token!;
    final session = alertSession;
    setState(() { alertsLoading = true; alertsError = null; });
    try {
      await widget.api.reviewAlert(current, id, status);
      final result = await widget.api.securityAlerts(current);
      if (mounted && token == current && alertSession == session) receiveAlertFeed(result);
    } catch (_) {
      if (mounted && token == current && alertSession == session) setState(() => alertsError = 'No se pudo guardar la revisión. Inténtalo de nuevo.');
    } finally {
      if (mounted && token == current && alertSession == session) setState(() => alertsLoading = false);
    }
  }

  Future<void> refreshUsage() async {
    if (usageLoading || token == null) return;
    final currentToken = token!;
    setState(() => usageLoading = true);
    try {
      try {
        final result = await vpn.trafficUsage();
        if (mounted && token == currentToken) setState(() => usage = result);
      } catch (_) {
        if (mounted && token == currentToken) setState(() => usage = null);
      }
      if (serverUsageRequestedAt == null || DateTime.now().difference(serverUsageRequestedAt!) >= const Duration(seconds: 20)) {
        serverUsageRequestedAt = DateTime.now();
        try {
          final result = await widget.api.vpnUsage(currentToken);
          if (mounted && token == currentToken) setState(() { serverUsage = result; serverUsageUnavailable = false; });
        } catch (_) {
          if (mounted && token == currentToken) setState(() { serverUsage = null; serverUsageUnavailable = true; });
        }
        try {
          final result = await widget.api.vpnUsageHistory(currentToken);
          if (mounted && token == currentToken) setState(() { usageHistory = result; historyUnavailable = false; });
        } catch (_) {
          if (mounted && token == currentToken) setState(() { usageHistory = null; historyUnavailable = true; });
        }
      }
    } finally {
      if (mounted) setState(() => usageLoading = false);
    }
  }

  void selectPage(int value) {
    setState(() { page = value; error = null; });
    if (value == 2) refreshUsage();
    if (value == 3) refreshAlerts();
  }

  Future<void> changeKillSwitch(bool enabled) async {
    if (vpnLoading) return;
    if (!enabled) {
      final confirmed = await showDialog<bool>(context: context, builder: (dialogContext) => AlertDialog(
        title: const Text('Desactivar Kill Switch'),
        content: const Text('Si la VPN se interrumpe, tu tráfico podría salir por la conexión normal. ¿Quieres desactivar el bloqueo?'),
        actions: [TextButton(onPressed: () => Navigator.pop(dialogContext, false), child: const Text('Cancelar')), TextButton(onPressed: () => Navigator.pop(dialogContext, true), child: const Text('Desactivar'))],
      ));
      if (confirmed != true || !mounted) return;
    }
    setState(() { vpnLoading = true; error = null; });
    try {
      await vpn.setKillSwitch(enabled);
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
    } catch (_) {
      if (mounted) setState(() => error = 'No se pudo cambiar el bloqueo de tráfico.');
    } finally {
      try {
        final blocked = await vpn.isKillSwitchEnabled();
        if (mounted) setState(() => trafficBlocked = blocked);
      } catch (_) { /* Preserve the last known state. */ }
      if (mounted) setState(() => vpnLoading = false);
    }
  }

  Future<void> toggleVpn() async {
    if (vpnLoading || token == null) return;
    setState(() { vpnLoading = true; connectionTransition = true; error = null; });
    try {
      if (vpnConnected || trafficBlocked) { await vpn.disconnect(); } else { await vpn.connect(token!, signedInAs!); }
      if (mounted) setState(() { vpnGeneration++; vpnConnected = !(vpnConnected || trafficBlocked); trafficBlocked = vpnConnected; gatewayHealthy = vpnConnected ? true : null; gatewayFailures = 0; dnsHealthy = null; internetHealthy = null; dnsFailures = 0; internetFailures = 0; gatewayCooldown?.cancel(); gatewayCooldown = null; if (!vpnConnected) usage = null; });
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
    } catch (_) {
      if (mounted) setState(() => error = 'No se pudo cambiar la conexión VPN.');
    } finally {
      try {
        final blocked = await vpn.isKillSwitchEnabled();
        if (mounted) setState(() => trafficBlocked = blocked);
      } catch (_) { /* Preserve the last known state. */ }
      if (mounted) setState(() { vpnLoading = false; connectionTransition = false; });
    }
  }

  Future<void> signOut() async {
    if (vpnLoading) return;
    setState(() { vpnLoading = true; error = null; });
    try {
      if (vpnConnected || trafficBlocked) await vpn.disconnect();
      await pushStarting;
      if (token != null) await push.stop(token!);
      monitor?.cancel();
      alertsTimer?.cancel();
      alertSession++;
      if (mounted) setState(() { unseenAlertIds.clear(); alertsInitialized = false; lastAlertId = 0; vpnGeneration++; token = null; signedInAs = null; vpnConnected = false; trafficBlocked = false; page = 0; usage = null; serverUsage = null; serverUsageUnavailable = false; usageHistory = null; historyUnavailable = false; serverUsageRequestedAt = null; alerts = null; alertsError = null; alertsLoading = false; alertsChecking = false; alertMonitoring = 'not_active'; gatewayHealthy = null; gatewayFailures = 0; dnsHealthy = null; internetHealthy = null; dnsFailures = 0; internetFailures = 0; gatewayCooldown?.cancel(); gatewayCooldown = null; username.clear(); });
    } catch (_) {
      if (mounted) setState(() => error = 'No se pudo desconectar la VPN.');
    } finally {
      if (mounted) setState(() => vpnLoading = false);
    }
  }

  Future<void> manageDevices() async {
    if (token == null || vpnLoading) return;
    setState(() { vpnLoading = true; error = null; });
    try {
      final devices = await widget.api.vpnDevices(token!);
      final localId = await vpn.deviceId();
      if (!mounted) return;
      final selected = await showDialog<String>(context: context, builder: (dialogContext) => AlertDialog(
        title: const Text('Dispositivos VPN'),
        content: SizedBox(width: 440, child: devices.isEmpty
          ? const Text('Todavía no hay dispositivos registrados.')
          : SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: devices.map((device) {
              final id = device['device_id'] as String;
              final current = id == localId;
              final enabled = device['enabled'] == true;
              return ListTile(title: Text(current ? 'Este dispositivo' : 'Dispositivo ${id.substring(0, 8)}'),
                subtitle: Text(enabled ? 'Habilitado' : 'Revocado'),
                trailing: enabled ? TextButton(onPressed: () => Navigator.pop(dialogContext, id), child: const Text('Revocar')) : null);
            }).toList()))),
        actions: [TextButton(onPressed: () => Navigator.pop(dialogContext), child: const Text('Cerrar'))],
      ));
      if (selected == null || !mounted) return;
      final confirmRevoke = await showDialog<bool>(context: context, builder: (dialogContext) => AlertDialog(
        title: const Text('Revocar dispositivo'),
        content: Text(selected == localId ? 'Este equipo dejará de poder conectarse con su identificador actual.' : 'Este dispositivo dejará de poder usar la VPN.'),
        actions: [TextButton(onPressed: () => Navigator.pop(dialogContext, false), child: const Text('Cancelar')), TextButton(onPressed: () => Navigator.pop(dialogContext, true), child: const Text('Revocar'))],
      ));
      if (confirmRevoke != true) return;
      await widget.api.revokeVpnDevice(token!, selected);
      if (selected == localId && vpnConnected) {
        await vpn.disconnect();
        if (mounted) setState(() => vpnConnected = false);
      }
      if (mounted) setState(() => error = 'Dispositivo revocado.');
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
    } catch (_) {
      if (mounted) setState(() => error = 'No se pudieron consultar los dispositivos.');
    } finally {
      if (mounted) setState(() => vpnLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    body: DecoratedBox(
      decoration: const BoxDecoration(gradient: LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xFFf2f1e9), cream, Color(0xFFc2ceaf), Color(0xFF879f7a)])),
      child: Stack(children: [
        const Positioned.fill(child: IgnorePointer(child: CustomPaint(painter: AtmospherePainter()))),
        SafeArea(child: LayoutBuilder(builder: (context, bounds) {
          if (token != null) {
            final padding = bounds.maxWidth < 600 ? 12.0 : 24.0;
            return Center(child: Padding(
              padding: EdgeInsets.all(padding),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 900),
                child: SizedBox(height: bounds.maxHeight - 2 * padding,
                  child: GlassPanel(child: connectedPanel())),
              ),
            ));
          }
          return Center(child: SingleChildScrollView(padding: const EdgeInsets.all(24), child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 1050),
            child: GlassPanel(child: bounds.maxWidth < 760
              ? Column(children: [brandPanel(compact: true), contentPanel()])
              : IntrinsicHeight(child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Expanded(flex: 5, child: brandPanel()), Expanded(flex: 5, child: contentPanel()),
                ]))),
          )));
        })),
      ]),
    ),
  );

  Widget brandPanel({bool compact = false}) => Container(
    padding: EdgeInsets.fromLTRB(compact ? 28 : 42, compact ? 28 : 42, compact ? 28 : 42, compact ? 25 : 40),
    decoration: BoxDecoration(borderRadius: BorderRadius.circular(28), gradient: const LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xE8e5ebd7), Color(0xD4a3b99a), Color(0xD7789a7a)])),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [shieldMark(42), const SizedBox(width: 12), const Text('NETSHIELD', style: TextStyle(color: deep, fontWeight: FontWeight.w900, fontSize: 15, letterSpacing: 2.2)), const Spacer(), const Text('VPN', style: TextStyle(color: forest, fontSize: 11, fontWeight: FontWeight.w800, letterSpacing: 2))]),
      SizedBox(height: compact ? 26 : 62),
      const Text('Tu espacio.\nTu conexión.', style: TextStyle(color: deep, height: 1.08, fontWeight: FontWeight.w800, fontSize: 39, letterSpacing: -1.7)),
      const SizedBox(height: 15),
      const Text('Una forma más tranquila de navegar.', style: TextStyle(color: forest, fontSize: 15, height: 1.5)),
      if (!compact) ...[const SizedBox(height: 36), Center(child: HeroOrb()), const SizedBox(height: 32)],
      const SizedBox(height: 12),
      Wrap(spacing: 8, runSpacing: 8, children: [pill(Icons.lock_outline_rounded, 'Túnel seguro'), pill(Icons.shield_outlined, 'Privacidad')]),
      if (!compact) ...[const Spacer(), const SizedBox(height: 36), const Text('UNA CONEXIÓN MÁS CLARA', style: TextStyle(color: forest, fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1.8))],
    ]),
  );

  Widget contentPanel() => Padding(padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 42), child: token == null ? authPanel() : connectedPanel());

  Widget authPanel() => Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.center, children: [
    const Text('BIENVENIDO A BORDO', style: TextStyle(color: green, fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.9)),
    const SizedBox(height: 12),
    Text(register ? 'Crea tu cuenta' : 'Qué gusto verte', style: const TextStyle(fontSize: 29, color: deep, fontWeight: FontWeight.w800, letterSpacing: -.8)),
    const SizedBox(height: 9),
    Text(register ? 'Tu cuenta de NetShield empieza aquí.' : 'Inicia sesión para continuar.', style: const TextStyle(color: Color(0xFF6e7c6a), fontSize: 14)),
    if (trafficBlocked) ...[
      const SizedBox(height: 12),
      const Text('El bloqueo de tráfico está activo. Puedes desactivarlo para recuperar la conexión.', style: TextStyle(color: forest, fontSize: 13)),
      TextButton(onPressed: loading ? null : unlockBeforeLogin, child: const Text('Desconectar VPN y desactivar bloqueo')),
    ],
    const SizedBox(height: 27),
    Container(padding: const EdgeInsets.all(4), decoration: BoxDecoration(color: const Color(0xFFe8ece0), borderRadius: BorderRadius.circular(15)), child: Row(children: [
      tab('Iniciar sesión', !register, () => switchMode(false)), tab('Crear cuenta', register, () => switchMode(true)),
    ])),
    const SizedBox(height: 25),
    fieldLabel('USUARIO'),
    const SizedBox(height: 7),
    input(username, 'Tu nombre de usuario', Icons.person_outline_rounded, autofill: AutofillHints.username),
    const SizedBox(height: 18),
    fieldLabel('CONTRASEÑA'),
    const SizedBox(height: 7),
    input(password, 'Tu contraseña', Icons.lock_outline_rounded, obscure: hidePassword, autofill: AutofillHints.password, suffix: IconButton(tooltip: hidePassword ? 'Mostrar contraseña' : 'Ocultar contraseña', onPressed: () => setState(() => hidePassword = !hidePassword), icon: Icon(hidePassword ? Icons.visibility_outlined : Icons.visibility_off_outlined, size: 20, color: green))),
    if (register) ...[const SizedBox(height: 18), fieldLabel('CONFIRMAR CONTRASEÑA'), const SizedBox(height: 7), input(confirm, 'Repite tu contraseña', Icons.key_rounded, obscure: hidePassword)],
    if (error != null) ...[const SizedBox(height: 14), Text(error!, style: const TextStyle(color: Color(0xFF9c4c42), fontSize: 13, height: 1.3))],
    if (notice != null) ...[const SizedBox(height: 14), Text(notice!, style: const TextStyle(color: forest, fontSize: 13))],
    const SizedBox(height: 24),
    SizedBox(width: double.infinity, height: 54, child: FilledButton(onPressed: loading ? null : (register ? signUp : signIn), style: FilledButton.styleFrom(backgroundColor: forest, foregroundColor: Colors.white, disabledBackgroundColor: sage.withValues(alpha: .45), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))), child: loading ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white)) : FittedBox(fit: BoxFit.scaleDown, child: Row(mainAxisSize: MainAxisSize.min, mainAxisAlignment: MainAxisAlignment.center, children: [Text(register ? 'Crear cuenta' : 'Entrar a NetShield', style: const TextStyle(fontWeight: FontWeight.w800)), const SizedBox(width: 9), const Icon(Icons.arrow_forward_rounded, size: 18)])))),
    const SizedBox(height: 20),
    const Center(child: Text('DISEÑADO PARA TU TRANQUILIDAD', style: TextStyle(color: Color(0xFF9aa896), fontSize: 9, fontWeight: FontWeight.w800, letterSpacing: 1.3))),
  ]);

  Widget connectedPanel() => LayoutBuilder(builder: (context, bounds) {
    final horizontal = bounds.maxWidth < 600 ? 20.0 : 40.0;
    final vertical = bounds.maxHeight < 500 ? 16.0 : 32.0;
    return Padding(padding: EdgeInsets.fromLTRB(horizontal, vertical, horizontal, 0), child:
      Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Wrap(key: const ValueKey('dashboard-navigation'), spacing: 5, runSpacing: 5, children: [
          navItem(0, Icons.home_outlined, 'Inicio'), navItem(1, Icons.tune_rounded, 'Ajustes'),
          navItem(2, Icons.data_usage_rounded, 'Consumo'), navItem(3, Icons.shield_outlined, 'Alertas'),
        ]),
        const SizedBox(height: 24),
        Expanded(child: SingleChildScrollView(
          key: ValueKey('dashboard-content-$page'),
          padding: EdgeInsets.only(bottom: vertical),
          child: AnimatedSwitcher(duration: const Duration(milliseconds: 220), child: KeyedSubtree(key: ValueKey(page), child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              switch (page) {
                1 => SettingsPanel(android: Platform.isAndroid, pushActive: pushActive, connected: vpnConnected, blocked: trafficBlocked, busy: vpnLoading, onSwitch: changeKillSwitch, onDevices: manageDevices),
                2 => UsagePanel(connected: vpnConnected, usage: usage, loading: usageLoading, serverUsage: serverUsage, serverUnavailable: serverUsageUnavailable, history: usageHistory, historyUnavailable: historyUnavailable),
                3 => AlertsPanel(alerts: alerts, monitoring: alertMonitoring, loading: alertsLoading, busy: alertsLoading || alertsChecking, error: alertsError, onRefresh: () => refreshAlerts(), onReview: reviewAlert, newAlerts: unseenAlertIds.length, onAcknowledge: () => setState(() => unseenAlertIds.clear())),
                _ => homePanel(),
              },
              if (page != 0 && error != null) ...[const SizedBox(height: 12), Text(error!, style: const TextStyle(color: Color(0xFF9c4c42), fontSize: 13))],
            ],
          ))),
        )),
      ]));
  });

  Widget navItem(int index, IconData icon, String label) => TextButton.icon(
    onPressed: vpnLoading ? null : () => selectPage(index), icon: Icon(icon, size: 16), label: Text(index == 3 && unseenAlertIds.isNotEmpty ? '$label · ${unseenAlertIds.length}' : label),
    style: TextButton.styleFrom(foregroundColor: page == index ? forest : const Color(0xff81937e), backgroundColor: page == index ? Colors.white.withValues(alpha: .75) : Colors.transparent, padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 8), textStyle: const TextStyle(fontSize: 11, fontWeight: FontWeight.w800), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
  );

  Widget homePanel() => Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.center, children: [
    const Text('TU ESPACIO PRIVADO', style: TextStyle(color: green, fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.9)),
    const SizedBox(height: 12), Text('Hola, $signedInAs', style: const TextStyle(fontSize: 29, color: deep, fontWeight: FontWeight.w800, letterSpacing: -.8)),
    const SizedBox(height: 9), const Text('Tu sesión está lista.', style: TextStyle(color: Color(0xFF6e7c6a), fontSize: 14)),
    const SizedBox(height: 36),
    Center(child: PowerOrb(connected: vpnConnected, loading: connectionTransition)),
    const SizedBox(height: 25),
    Center(child: Text(vpnConnected ? (gatewayHealthy == false ? 'VPN sin respuesta' : (dnsHealthy == false ? 'DNS sin respuesta' : (internetHealthy == false ? 'Prueba de Internet sin respuesta' : (Platform.isAndroid ? 'Túnel activo' : 'Conectado')))) : (trafficBlocked ? 'Tráfico bloqueado' : 'Desconectado'), style: const TextStyle(color: deep, fontWeight: FontWeight.w800, fontSize: 21))),
    const SizedBox(height: 8),
    Center(child: Text(error ?? (vpnConnected ? (gatewayHealthy == false ? 'La puerta de enlace VPN no responde. Revisa tu red o vuelve a conectar.' : (gatewayHealthy == null && !Platform.isAndroid ? 'Comprobando la conexión con el servidor VPN.' : (dnsHealthy == false ? 'El DNS de la VPN no respondió a la prueba.' : (internetHealthy == false ? 'La prueba de Internet no respondió; algunas redes bloquean este tipo de comprobación.' : (trafficBlocked ? 'Túnel activo; bloqueo de tráfico habilitado.' : 'Túnel activo; bloqueo de tráfico no habilitado.'))))) : (trafficBlocked ? 'El bloqueo sigue activo para evitar fugas.' : 'Conéctate para activar tu VPN.')), textAlign: TextAlign.center, style: const TextStyle(color: Color(0xFF6e7c6a), height: 1.4))),
    const SizedBox(height: 30),
    SizedBox(width: double.infinity, height: 52, child: FilledButton(onPressed: vpnLoading ? null : toggleVpn, style: FilledButton.styleFrom(backgroundColor: vpnConnected ? const Color(0xffa6433a) : forest, foregroundColor: Colors.white, disabledBackgroundColor: sage.withValues(alpha: .45), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))), child: Text(vpnLoading ? 'Espera…' : (vpnConnected ? 'Desconectar' : (trafficBlocked ? 'Desactivar bloqueo' : 'Conectar')), style: const TextStyle(fontWeight: FontWeight.w800)))),
    const SizedBox(height: 12), Center(child: TextButton.icon(onPressed: vpnLoading ? null : manageDevices, icon: const Icon(Icons.devices_rounded, size: 17), label: const Text('Administrar dispositivos'), style: TextButton.styleFrom(foregroundColor: forest))),
    Center(child: TextButton.icon(onPressed: vpnLoading ? null : signOut, icon: const Icon(Icons.logout_rounded, size: 17), label: const Text('Cerrar sesión'), style: TextButton.styleFrom(foregroundColor: forest))),
  ]);

  Widget tab(String title, bool active, VoidCallback onTap) => Expanded(child: InkWell(onTap: onTap, borderRadius: BorderRadius.circular(12), child: AnimatedContainer(duration: const Duration(milliseconds: 180), padding: const EdgeInsets.symmetric(vertical: 12), decoration: BoxDecoration(color: active ? Colors.white : Colors.transparent, borderRadius: BorderRadius.circular(12), boxShadow: active ? [BoxShadow(color: deep.withValues(alpha: .07), blurRadius: 8, offset: const Offset(0, 3))] : []), child: Text(title, textAlign: TextAlign.center, style: TextStyle(color: active ? deep : const Color(0xFF84927f), fontSize: 12, fontWeight: FontWeight.w800)))));
  Widget fieldLabel(String value) => Text(value, style: const TextStyle(color: forest, fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.2));
  Widget input(TextEditingController controller, String hint, IconData icon, {bool obscure = false, Widget? suffix, String? autofill}) => TextField(controller: controller, obscureText: obscure, autofillHints: autofill == null ? null : [autofill], onSubmitted: (_) { if (!register) signIn(); }, style: const TextStyle(color: deep, fontSize: 14), decoration: InputDecoration(hintText: hint, hintStyle: const TextStyle(color: Color(0xFFa6b0a1), fontSize: 13), prefixIcon: Icon(icon, color: green, size: 20), suffixIcon: suffix, filled: true, fillColor: Colors.white.withValues(alpha: .74), contentPadding: const EdgeInsets.symmetric(vertical: 18), enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(15), borderSide: const BorderSide(color: Color(0xFFd9e2d4))), focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(15), borderSide: const BorderSide(color: green, width: 1.4))));
}

Widget shieldMark(double size) => Container(width: size, height: size, decoration: BoxDecoration(borderRadius: BorderRadius.circular(size * .32), gradient: const LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xFF8da980), forest]), border: Border.all(color: Colors.white.withValues(alpha: .8)), boxShadow: [BoxShadow(color: forest.withValues(alpha: .22), blurRadius: 12, offset: const Offset(0, 5))]), child: Icon(Icons.shield_rounded, color: Colors.white.withValues(alpha: .95), size: size * .6));
Widget pill(IconData icon, String title) => Container(padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9), decoration: BoxDecoration(color: Colors.white.withValues(alpha: .38), borderRadius: BorderRadius.circular(30), border: Border.all(color: Colors.white.withValues(alpha: .5))), child: Row(mainAxisSize: MainAxisSize.min, children: [Icon(icon, size: 15, color: forest), const SizedBox(width: 7), Text(title, style: const TextStyle(color: deep, fontSize: 11, fontWeight: FontWeight.w700))]));

class PowerOrb extends StatefulWidget {
  const PowerOrb({super.key, required this.connected, required this.loading});
  final bool connected, loading;
  @override
  State<PowerOrb> createState() => _PowerOrbState();
}

class _PowerOrbState extends State<PowerOrb> {
  Timer? pulseTimer;
  bool bright = false;

  void syncPulse() {
    final shouldAnimate = widget.connected && !widget.loading && !MediaQuery.disableAnimationsOf(context);
    if (shouldAnimate && pulseTimer == null) {
      pulseTimer = Timer.periodic(const Duration(milliseconds: 1900), (_) {
        if (mounted) setState(() => bright = !bright);
      });
    } else if (!shouldAnimate) {
      pulseTimer?.cancel();
      pulseTimer = null;
      bright = false;
    }
  }

  @override
  void didChangeDependencies() { super.didChangeDependencies(); syncPulse(); }
  @override
  void didUpdateWidget(covariant PowerOrb oldWidget) { super.didUpdateWidget(oldWidget); syncPulse(); }
  @override
  void dispose() { pulseTimer?.cancel(); super.dispose(); }

  @override
  Widget build(BuildContext context) => AnimatedScale(
    scale: widget.connected && bright ? 1.045 : 1,
    duration: const Duration(milliseconds: 1500), curve: Curves.easeInOut,
    child: AnimatedContainer(
      key: const ValueKey('connection-orb'),
      duration: const Duration(milliseconds: 1500), curve: Curves.easeInOut,
      width: 156, height: 156,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: widget.connected && bright
          ? const [Color(0xfff8fff1), Color(0xffd3e9c8), Color(0xff9abb94)]
          : const [Color(0xffeef1e5), Color(0xffbdceb1), Color(0xff90a98c)]),
        border: Border.all(color: Colors.white.withValues(alpha: .8), width: 2),
        boxShadow: [BoxShadow(color: green.withValues(alpha: widget.connected && bright ? .42 : .15), blurRadius: widget.connected && bright ? 42 : 22, spreadRadius: widget.connected && bright ? 4 : 0, offset: const Offset(0, 8))],
      ),
      child: AnimatedSwitcher(duration: const Duration(milliseconds: 250), child: widget.loading
        ? const Center(key: ValueKey('loading'), child: SizedBox(width: 46, height: 46, child: CircularProgressIndicator(color: forest, strokeWidth: 3)))
        : const Icon(Icons.power_settings_new_rounded, key: ValueKey('power'), size: 61, color: forest)),
    ),
  );
}

class GlassPanel extends StatelessWidget {
  const GlassPanel({super.key, required this.child});
  final Widget child;
  @override Widget build(BuildContext context) => ClipRRect(borderRadius: BorderRadius.circular(30), child: BackdropFilter(filter: ImageFilter.blur(sigmaX: 20, sigmaY: 20), child: Container(decoration: BoxDecoration(color: const Color(0xE8f7f8f1), borderRadius: BorderRadius.circular(30), border: Border.all(color: Colors.white.withValues(alpha: .85), width: 1.3), boxShadow: [BoxShadow(color: deep.withValues(alpha: .12), blurRadius: 28, offset: const Offset(0, 16))]), child: child)));
}

class HeroOrb extends StatelessWidget {
  const HeroOrb({super.key});
  @override Widget build(BuildContext context) => Container(width: 195, height: 195, decoration: BoxDecoration(shape: BoxShape.circle, gradient: const RadialGradient(center: Alignment(-.4, -.6), radius: 1.3, colors: [Color(0xFFfbfff3), Color(0xFFd6e9ce), Color(0xFF8daf8a), Color(0xFF5d8567)]), border: Border.all(color: Colors.white.withValues(alpha: .78), width: 2), boxShadow: [BoxShadow(color: forest.withValues(alpha: .25), blurRadius: 28, offset: const Offset(0, 12)), const BoxShadow(color: Colors.white54, blurRadius: 12, offset: Offset(-4, -5))]), child: Center(child: Container(width: 112, height: 112, decoration: BoxDecoration(shape: BoxShape.circle, color: Colors.white.withValues(alpha: .2), border: Border.all(color: Colors.white.withValues(alpha: .5))), child: const Icon(Icons.shield_rounded, size: 72, color: Color(0xFFeaf4e4)))));
}

class AtmospherePainter extends CustomPainter {
  const AtmospherePainter();
  @override void paint(Canvas canvas, Size size) {
    final paint = Paint()..color = Colors.white.withValues(alpha: .18);
    canvas.drawCircle(Offset(size.width * .08, size.height * .18), 120, paint);
    canvas.drawCircle(Offset(size.width * .91, size.height * .84), 170, paint);
    final stroke = Paint()..color = Colors.white.withValues(alpha: .3)..style = PaintingStyle.stroke..strokeWidth = 2;
    canvas.drawCircle(Offset(size.width * .83, size.height * .12), 42, stroke);
    canvas.drawCircle(Offset(size.width * .13, size.height * .82), 22, stroke);
  }
  @override bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
