import 'dart:ui';
import 'dart:async';
import 'dart:io';
import 'dart:math' as math;
import 'package:material_ui/material_ui.dart';
import 'services/api_client.dart';
import 'services/linux_vpn.dart';
import 'services/android_vpn.dart';
import 'services/windows_vpn.dart';
import 'services/android_push.dart';
import 'services/desktop_notifications.dart';
import 'screens/dashboard_panels.dart';
import 'screens/vpn_map.dart';

const cream = Color(0xFFdad7cd);
const sage = Color(0xFFa3b18a);
const green = Color(0xFF588157);
const forest = Color(0xFF3a5a40);
const deep = Color(0xFF344e41);

void main() {
  // The background handler registers a MethodChannel, which needs the
  // services binding initialized before runApp.
  WidgetsFlutterBinding.ensureInitialized();
  AndroidPush.registerBackgroundHandler();
  runApp(const NetShieldApp());
}

class NetShieldApp extends StatelessWidget {
  const NetShieldApp({super.key, this.api, this.vpn, this.notifier, this.androidLayout});
  final ApiClient? api;
  final LinuxVpn? vpn;
  final AlertNotifier? notifier;
  // Lets tests force the Android layout; in the real app it follows the OS.
  final bool? androidLayout;
  @override
  Widget build(BuildContext context) => MaterialApp(
    debugShowCheckedModeBanner: false,
    title: 'NetShield VPN',
    theme: ThemeData(useMaterial3: true, fontFamily: 'sans-serif', colorScheme: ColorScheme.fromSeed(seedColor: green),
      navigationBarTheme: const NavigationBarThemeData(backgroundColor: Colors.white, indicatorColor: Color(0xFFDCE8D5), elevation: 2),
      pageTransitionsTheme: const PageTransitionsTheme(builders: {TargetPlatform.android: FadeUpwardsPageTransitionsBuilder()})),
    home: ShieldHome(api: api ?? ApiClient(), vpn: vpn, notifier: notifier, androidLayout: androidLayout),
  );
}

class ShieldHome extends StatefulWidget {
  const ShieldHome({super.key, required this.api, this.vpn, this.notifier, this.androidLayout});
  final ApiClient api;
  final LinuxVpn? vpn;
  final AlertNotifier? notifier;
  final bool? androidLayout;
  @override
  State<ShieldHome> createState() => _ShieldHomeState();
}

class _ShieldHomeState extends State<ShieldHome> with WidgetsBindingObserver {
  final username = TextEditingController();
  final password = TextEditingController();
  final confirm = TextEditingController();
  bool register = false, loading = false, hidePassword = true;
  bool vpnConnected = false, vpnLoading = false, trafficBlocked = false;
  bool sshAllowed = false;
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
  late final LinuxVpn vpn = widget.vpn ?? (Platform.isAndroid ? AndroidVpn(widget.api) : (Platform.isWindows ? WindowsVpn(widget.api) : LinuxVpn(widget.api)));
  late final AlertNotifier notifier = widget.notifier ?? LinuxAlertNotifier();
  late final AndroidPush push = AndroidPush(widget.api, vpn);
  Future<void>? pushStarting;
  bool pushActive = false;
  Timer? monitor;
  String? error, notice, token, signedInAs;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    if (vpn is AndroidVpn) unawaited(restoreAndroidSession());
    vpn.isKillSwitchEnabled().then((blocked) {
      if (mounted) setState(() => trafficBlocked = blocked);
    }).catchError((_) {});
    if (!Platform.isAndroid) {
      vpn.isSshAllowed().then((allowed) {
        if (mounted) setState(() => sshAllowed = allowed);
      }).catchError((_) {});
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (Platform.isAndroid && state == AppLifecycleState.resumed) {
      unawaited(refreshAndroidProtection());
    }
  }

  Future<void> refreshAndroidProtection() async {
    try {
      final active = await vpn.isConnected();
      final blocked = await vpn.isKillSwitchEnabled();
      if (mounted && !vpnLoading) setState(() { vpnConnected = active; trafficBlocked = blocked; });
    } catch (_) { /* Keep the last confirmed protection state. */ }
  }

  Future<void> unlockBeforeLogin() async {
    if (vpn is AndroidVpn) { await (vpn as AndroidVpn).openVpnSettings(); return; }
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
  void dispose() { WidgetsBinding.instance.removeObserver(this); push.dispose(); monitor?.cancel(); alertsTimer?.cancel(); gatewayCooldown?.cancel(); widget.api.close(); username.dispose(); password.dispose(); confirm.dispose(); super.dispose(); }

  Future<void> restoreAndroidSession() async {
    setState(() => loading = true);
    try {
      final session = await (vpn as AndroidVpn).restoredSession();
      if (session != null && mounted) await acceptSession(session['token']!, session['account']!);
    } catch (_) { /* A locked or invalid keystore falls back to explicit login. */ }
    finally { if (mounted) setState(() => loading = false); }
  }

  Future<void> acceptSession(String result, String account) async {
      final active = await vpn.isConnected();
      final blocked = await vpn.isKillSwitchEnabled();
      if (!mounted) return;
      setState(() { token = result; signedInAs = account; vpnConnected = active; trafficBlocked = blocked; password.clear(); });
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
  }

  Future<void> signIn() async {
    if (loading) return;
    if (username.text.trim().isEmpty || password.text.isEmpty) {
      setState(() => error = 'Introduce tu usuario y contraseña.');
      return;
    }
    setState(() { loading = true; error = null; });
    try {
      final result = await widget.api.login(username.text.trim(), password.text);
      if (vpn is AndroidVpn) await (vpn as AndroidVpn).saveSession(username.text.trim(), result);
      await acceptSession(result, username.text.trim());
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

  /// The four dashboard sections, shared by the desktop layout and the
  /// Android layout below. Only the navigation around them changes.
  Widget _dashboardPage() => switch (page) {
    1 => SettingsPanel(android: Platform.isAndroid, pushActive: pushActive, connected: vpnConnected, blocked: trafficBlocked, busy: vpnLoading, onSwitch: changeKillSwitch, onDevices: manageDevices, sshAllowed: sshAllowed, onSshSwitch: Platform.isAndroid ? null : changeSshAllowed),
    2 => UsagePanel(connected: vpnConnected, usage: usage, loading: usageLoading, serverUsage: serverUsage, serverUnavailable: serverUsageUnavailable, history: usageHistory, historyUnavailable: historyUnavailable),
    3 => AlertsPanel(alerts: alerts, monitoring: alertMonitoring, loading: alertsLoading, busy: alertsLoading || alertsChecking, error: alertsError, onRefresh: () => refreshAlerts(), onReview: reviewAlert, newAlerts: unseenAlertIds.length, onAcknowledge: () => setState(() => unseenAlertIds.clear())),
    _ => homePanel(),
  };

  /// Login header for Android: standard Material login pattern — a small
  /// centered brand mark, one short tagline and the trust pills — instead
  /// of the large desktop hero panel, so the form is visible at a glance.
  Widget _androidAuthHeader() => Container(
    width: double.infinity,
    padding: const EdgeInsets.fromLTRB(20, 20, 20, 18),
    decoration: BoxDecoration(
      borderRadius: BorderRadius.circular(24),
      gradient: const LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [Color(0xFFE5EBD7), Color(0xFFA3B99A), Color(0xFF789A7A)],
      ),
    ),
    child: Column(children: [
      Row(mainAxisAlignment: MainAxisAlignment.center, children: [
        shieldMark(40),
        const SizedBox(width: 10),
        const Text('NETSHIELD', style: TextStyle(color: deep, fontWeight: FontWeight.w900, fontSize: 15, letterSpacing: 2.2)),
        const SizedBox(width: 8),
        const Text('VPN', style: TextStyle(color: forest, fontSize: 11, fontWeight: FontWeight.w800, letterSpacing: 2)),
      ]),
      const SizedBox(height: 12),
      const Text('Una forma más tranquila de navegar.', textAlign: TextAlign.center, style: TextStyle(color: forest, fontSize: 14, height: 1.4)),
      const SizedBox(height: 12),
      Wrap(spacing: 8, runSpacing: 8, alignment: WrapAlignment.center, children: [pill(Icons.lock_outline_rounded, 'Túnel seguro'), pill(Icons.shield_outlined, 'Privacidad')]),
    ]),
  );

  /// Android layout: Material 3 bottom navigation (NavigationBar) with a
  /// slide + fade transition between sections, instead of the desktop
  /// top navigation strip. All logic (login, VPN, alerts, usage) is
  /// untouched; only the presentation changes, and only on Android.
  Widget _androidScaffold() {
    if (token == null) {
      return Scaffold(
        backgroundColor: const Color(0xFFF2F4EE),
        body: SafeArea(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Column(children: [
              _androidAuthHeader(),
              const SizedBox(height: 12),
              GlassPanel(child: Padding(padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 28), child: authPanel())),
            ]),
          ),
        ),
      );
    }
    return Scaffold(
      backgroundColor: const Color(0xFFF2F4EE),
      appBar: AppBar(
        backgroundColor: const Color(0xFFF2F4EE),
        surfaceTintColor: Colors.transparent,
        title: Row(children: [shieldMark(30), const SizedBox(width: 10), const Text('NETSHIELD', style: TextStyle(color: deep, fontWeight: FontWeight.w900, fontSize: 15, letterSpacing: 2.0))]),
        actions: [
          IconButton(
            tooltip: 'Cerrar sesión',
            onPressed: vpnLoading ? null : signOut,
            icon: const Icon(Icons.logout_rounded, color: forest),
          ),
        ],
      ),
      body: AnimatedSwitcher(
        duration: const Duration(milliseconds: 250),
        switchInCurve: Curves.easeOutCubic,
        switchOutCurve: Curves.easeInCubic,
        transitionBuilder: (child, animation) {
          final offset = Tween<Offset>(begin: const Offset(0.06, 0), end: Offset.zero)
              .animate(CurvedAnimation(parent: animation, curve: Curves.easeOutCubic));
          return FadeTransition(opacity: animation, child: SlideTransition(position: offset, child: child));
        },
        child: KeyedSubtree(
          key: ValueKey(page),
          child: SingleChildScrollView(
            key: ValueKey('android-content-$page'),
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _dashboardPage(),
                if (page != 0 && error != null) ...[
                  const SizedBox(height: 12),
                  Text(error!, style: const TextStyle(color: Color(0xFF9c4c42), fontSize: 13)),
                ],
              ],
            ),
          ),
        ),
      ),
      bottomNavigationBar: NavigationBar(
        key: const ValueKey('android-navigation'),
        selectedIndex: page,
        onDestinationSelected: vpnLoading ? null : selectPage,
        destinations: [
          const NavigationDestination(icon: Icon(Icons.home_outlined), selectedIcon: Icon(Icons.home_rounded), label: 'Inicio'),
          const NavigationDestination(icon: Icon(Icons.tune_outlined), selectedIcon: Icon(Icons.tune_rounded), label: 'Ajustes'),
          const NavigationDestination(icon: Icon(Icons.data_usage_outlined), selectedIcon: Icon(Icons.data_usage_rounded), label: 'Consumo'),
          NavigationDestination(
            icon: unseenAlertIds.isEmpty
                ? const Icon(Icons.shield_outlined)
                : Badge(label: Text('${unseenAlertIds.length}'), child: const Icon(Icons.shield_outlined)),
            selectedIcon: unseenAlertIds.isEmpty
                ? const Icon(Icons.shield_rounded)
                : Badge(label: Text('${unseenAlertIds.length}'), child: const Icon(Icons.shield_rounded)),
            label: 'Alertas',
          ),
        ],
      ),
    );
  }

  Future<void> changeKillSwitch(bool enabled) async {
    if (vpnLoading) return;
    if (vpn is AndroidVpn) {
      try { await (vpn as AndroidVpn).openVpnSettings(); }
      on ApiException catch (e) { if (mounted) setState(() => error = e.message); }
      return;
    }
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

  /// Toggle "Permitir conexiones SSH" (desktop only). The setting is stored
  /// and applies the next time the traffic lock is enabled. If the lock is
  /// active now, re-apply it so the change takes effect immediately.
  Future<void> changeSshAllowed(bool allowed) async {
    if (vpnLoading) return;
    setState(() { vpnLoading = true; error = null; });
    try {
      await vpn.setSshAllowed(allowed);
      if (mounted) setState(() => sshAllowed = allowed);
      if (trafficBlocked) {
        try {
          await vpn.setKillSwitch(false);
          await vpn.setKillSwitch(true);
        } catch (_) {
          if (mounted) {
            setState(() => error =
                'El ajuste se guardó, pero no se pudo reaplicar el bloqueo ahora. Se aplicará la próxima vez que se active.');
          }
        }
      }
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
    } catch (_) {
      if (mounted) setState(() => error = 'No se pudo guardar el ajuste de SSH.');
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
      if (vpnConnected || (trafficBlocked && !Platform.isAndroid)) { await vpn.disconnect(); } else { await vpn.connect(token!, signedInAs!); }
      final active = await vpn.isConnected();
      final blocked = await vpn.isKillSwitchEnabled();
      if (mounted) setState(() { vpnGeneration++; vpnConnected = active; trafficBlocked = blocked; gatewayHealthy = vpnConnected ? true : null; gatewayFailures = 0; dnsHealthy = null; internetHealthy = null; dnsFailures = 0; internetFailures = 0; gatewayCooldown?.cancel(); gatewayCooldown = null; if (!vpnConnected) usage = null; });
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
      if (vpn is AndroidVpn) await (vpn as AndroidVpn).clearSession();
      monitor?.cancel();
      alertsTimer?.cancel();
      alertSession++;
      if (mounted) setState(() { unseenAlertIds.clear(); alertsInitialized = false; lastAlertId = 0; pushActive = false; pushStarting = null; vpnGeneration++; token = null; signedInAs = null; vpnConnected = false; trafficBlocked = false; page = 0; usage = null; serverUsage = null; serverUsageUnavailable = false; usageHistory = null; historyUnavailable = false; serverUsageRequestedAt = null; alerts = null; alertsError = null; alertsLoading = false; alertsChecking = false; alertMonitoring = 'not_active'; gatewayHealthy = null; gatewayFailures = 0; dnsHealthy = null; internetHealthy = null; dnsFailures = 0; internetFailures = 0; gatewayCooldown?.cancel(); gatewayCooldown = null; username.clear(); });
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
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
  Widget build(BuildContext context) {
    // On Android use the mobile layout (bottom navigation); everywhere
    // else keep the existing desktop layout exactly as it was.
    // (Platform.isAndroid, not defaultTargetPlatform: widget tests run
    // with an Android target platform even on a Linux host.)
    final android = widget.androidLayout ?? Platform.isAndroid;
    final Widget content;
    if (android) {
      // Fade between the login screen and the dashboard instead of
      // swapping them instantly.
      content = AnimatedSwitcher(
        duration: const Duration(milliseconds: 450),
        switchInCurve: Curves.easeOutCubic,
        switchOutCurve: Curves.easeInCubic,
        child: KeyedSubtree(key: ValueKey(token == null ? 'login' : 'dashboard'), child: _androidScaffold()),
      );
    } else {
      content = Scaffold(
      body: DecoratedBox(
      decoration: const BoxDecoration(gradient: LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xFFf2f1e9), cream, Color(0xFFc2ceaf), Color(0xFF879f7a)])),
      child: Stack(children: [
        const AnimatedAtmosphere(),
        SafeArea(child: LayoutBuilder(builder: (context, bounds) {
          // Fade between the login screen and the dashboard instead of
          // swapping them instantly.
          return AnimatedSwitcher(
            duration: const Duration(milliseconds: 450),
            switchInCurve: Curves.easeOutCubic,
            switchOutCurve: Curves.easeInCubic,
            child: token != null
              ? KeyedSubtree(key: const ValueKey('dashboard'), child: Center(child: Padding(
                padding: EdgeInsets.all(bounds.maxWidth < 600 ? 12.0 : 24.0),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 900),
                  child: SizedBox(height: (bounds.maxHeight - 2 * (bounds.maxWidth < 600 ? 12.0 : 24.0)).clamp(0.0, double.infinity),
                    child: GlassPanel(child: connectedPanel())),
                ),
              )))
              : KeyedSubtree(key: const ValueKey('login'), child: Center(child: SingleChildScrollView(padding: const EdgeInsets.all(24), child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1050),
                child: GlassPanel(child: bounds.maxWidth < 760
                  ? Column(children: [brandPanel(compact: true), contentPanel()])
                  : IntrinsicHeight(child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                      Expanded(flex: 5, child: brandPanel()), Expanded(flex: 5, child: contentPanel()),
                    ]))),
              )))),
          );
        })),
      ]),
    ),
    );
    }
    // Soft entrance when the app first opens: fades in and rises slightly.
    return _EntranceFade(child: content);
  }

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
    Text(register ? 'Tu cuenta de NetShield empieza aquí.' : 'Inicia sesión para continuar.', style: const TextStyle(color: Color(0xFF55655b), fontSize: 14)),
    if (trafficBlocked) ...[
      const SizedBox(height: 12),
      const Text('El bloqueo de tráfico está activo. Puedes desactivarlo para recuperar la conexión.', style: TextStyle(color: forest, fontSize: 14)),
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
    final horizontal = bounds.maxWidth < 380 ? 12.0 : (bounds.maxWidth < 600 ? 20.0 : 40.0);
    final vertical = bounds.maxHeight < 500 ? 12.0 : 28.0;
    final navWidth = (bounds.maxWidth - horizontal * 2 - 14).clamp(0.0, double.infinity);
    final columns = navWidth < 440 ? 2 : 4;
    final itemWidth = ((navWidth - 6 * (columns - 1)) / columns).clamp(0.0, double.infinity);
    final navigation = Container(
      key: const ValueKey('dashboard-navigation'),
      padding: const EdgeInsets.all(6),
      decoration: BoxDecoration(color: const Color(0xffdce6d5).withValues(alpha: .68), borderRadius: BorderRadius.circular(19), border: Border.all(color: Colors.white.withValues(alpha: .8))),
      child: Wrap(spacing: 6, runSpacing: 6, children: [
        SizedBox(width: itemWidth, child: navItem(0, Icons.home_outlined, 'Inicio')),
        SizedBox(width: itemWidth, child: navItem(1, Icons.tune_rounded, 'Ajustes')),
        SizedBox(width: itemWidth, child: navItem(2, Icons.data_usage_rounded, 'Consumo')),
        SizedBox(width: itemWidth, child: navItem(3, Icons.shield_outlined, 'Alertas')),
      ]),
    );
    final content = AnimatedSwitcher(duration: const Duration(milliseconds: 220), child: KeyedSubtree(key: ValueKey(page), child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _dashboardPage(),
        if (page != 0 && error != null) ...[const SizedBox(height: 12), Text(error!, style: const TextStyle(color: Color(0xFF9c4c42), fontSize: 13))],
      ],
    )));
    // At very short window heights, let the entire panel scroll so navigation
    // and content remain reachable; otherwise keep navigation fixed.
    if (bounds.maxHeight < 210) {
      return SingleChildScrollView(key: ValueKey('dashboard-content-$page'), padding: EdgeInsets.fromLTRB(horizontal, vertical, horizontal, vertical), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [navigation, const SizedBox(height: 16), content]));
    }
    return Padding(padding: EdgeInsets.fromLTRB(horizontal, vertical, horizontal, 0), child:
      Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        navigation,
        const SizedBox(height: 18),
        Expanded(child: SingleChildScrollView(key: ValueKey('dashboard-content-$page'), padding: EdgeInsets.only(bottom: vertical), child: content)),
      ]));
  });

  Widget navItem(int index, IconData icon, String label) => SizedBox(height: 48, child: TextButton(
    onPressed: vpnLoading ? null : () => selectPage(index),
    style: TextButton.styleFrom(foregroundColor: page == index ? forest : const Color(0xff61785e), backgroundColor: page == index ? Colors.white.withValues(alpha: .88) : Colors.transparent, minimumSize: Size.zero, padding: const EdgeInsets.symmetric(horizontal: 5), tapTargetSize: MaterialTapTargetSize.shrinkWrap, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14))),
    child: FittedBox(fit: BoxFit.scaleDown, child: Row(mainAxisSize: MainAxisSize.min, children: [
      Icon(icon, size: 19), const SizedBox(width: 8),
      Text(index == 3 && unseenAlertIds.isNotEmpty ? '$label · ${unseenAlertIds.length}' : label, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w800)),
    ])),
  ));

  Widget homePanel() => Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.center, children: [
    Row(children: [
      const Expanded(child: Text('TU ESPACIO PRIVADO', style: TextStyle(color: green, fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.9))),
      IconButton(onPressed: vpnLoading ? null : signOut, tooltip: 'Cerrar sesión', icon: const Icon(Icons.logout_rounded, size: 20), color: forest, padding: EdgeInsets.zero, constraints: const BoxConstraints(minWidth: 36, minHeight: 36)),
    ]),
    const SizedBox(height: 12), Text('Hola, $signedInAs', style: const TextStyle(fontSize: 29, color: deep, fontWeight: FontWeight.w800, letterSpacing: -.8)),
    const SizedBox(height: 9), const Text('Tu sesión está lista.', style: TextStyle(color: Color(0xFF55655b), fontSize: 15)),
    const SizedBox(height: 36),
    Center(child: PowerOrb(connected: vpnConnected, loading: connectionTransition)),
    const SizedBox(height: 25),
    Center(child: Text(vpnConnected ? (gatewayHealthy == false ? 'VPN sin respuesta' : (dnsHealthy == false ? 'DNS sin respuesta' : (internetHealthy == false ? 'Prueba de Internet sin respuesta' : 'Conectado'))) : (trafficBlocked ? 'Tráfico bloqueado' : 'Desconectado'), style: const TextStyle(color: deep, fontWeight: FontWeight.w800, fontSize: 21))),
    const SizedBox(height: 8),
    Center(child: Text(error ?? (vpnConnected ? (gatewayHealthy == false ? 'La puerta de enlace VPN no responde. Revisa tu red o vuelve a conectar.' : (gatewayHealthy == null && !Platform.isAndroid ? 'Comprobando la conexión con el servidor VPN.' : (dnsHealthy == false ? 'El DNS de la VPN no respondió a la prueba.' : (internetHealthy == false ? 'La prueba de Internet no respondió; algunas redes bloquean este tipo de comprobación.' : (trafficBlocked ? 'Túnel activo; bloqueo de tráfico habilitado.' : 'Túnel activo; bloqueo de tráfico no habilitado.'))))) : (trafficBlocked ? 'El bloqueo sigue activo para evitar fugas.' : 'Conéctate para activar tu VPN.')), textAlign: TextAlign.center, style: const TextStyle(color: Color(0xFF55655b), fontSize: 15, height: 1.4))),
    const SizedBox(height: 30),
    SizedBox(width: double.infinity, height: 52, child: FilledButton(onPressed: vpnLoading ? null : toggleVpn, style: FilledButton.styleFrom(backgroundColor: vpnConnected ? const Color(0xffa6433a) : forest, foregroundColor: Colors.white, disabledBackgroundColor: sage.withValues(alpha: .45), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))), child: Text(vpnLoading ? 'Espera…' : (vpnConnected ? 'Desconectar' : (trafficBlocked && !Platform.isAndroid ? 'Desactivar bloqueo' : 'Conectar')), style: const TextStyle(fontWeight: FontWeight.w800)))),
    if (!Platform.isAndroid) ...[const SizedBox(height: 16), VpnMapCard(connected: vpnConnected)],
  ]);

  Widget tab(String title, bool active, VoidCallback onTap) => Expanded(child: InkWell(onTap: onTap, borderRadius: BorderRadius.circular(12), child: AnimatedContainer(duration: const Duration(milliseconds: 180), padding: const EdgeInsets.symmetric(vertical: 12), decoration: BoxDecoration(color: active ? Colors.white : Colors.transparent, borderRadius: BorderRadius.circular(12), boxShadow: active ? [BoxShadow(color: deep.withValues(alpha: .07), blurRadius: 8, offset: const Offset(0, 3))] : []), child: Text(title, textAlign: TextAlign.center, style: TextStyle(color: active ? deep : const Color(0xFF84927f), fontSize: 12, fontWeight: FontWeight.w800)))));
  Widget fieldLabel(String value) => Text(value, style: const TextStyle(color: forest, fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.2));
  Widget input(TextEditingController controller, String hint, IconData icon, {bool obscure = false, Widget? suffix, String? autofill}) => TextField(controller: controller, obscureText: obscure, autofillHints: autofill == null ? null : [autofill], onSubmitted: (_) { if (!register) signIn(); }, style: const TextStyle(color: deep, fontSize: 14), decoration: InputDecoration(hintText: hint, hintStyle: const TextStyle(color: Color(0xFFa6b0a1), fontSize: 13), prefixIcon: Icon(icon, color: green, size: 20), suffixIcon: suffix, filled: true, fillColor: Colors.white.withValues(alpha: .74), contentPadding: const EdgeInsets.symmetric(vertical: 18), enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(15), borderSide: const BorderSide(color: Color(0xFFd9e2d4))), focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(15), borderSide: const BorderSide(color: green, width: 1.4))));
}

/// Soft entrance when the app first opens: fades in and rises slightly.
/// One-shot, so it never blocks widget tests that wait for the app to settle.
class _EntranceFade extends StatelessWidget {
  const _EntranceFade({required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) => TweenAnimationBuilder<double>(
    tween: Tween<double>(begin: 0, end: 1),
    duration: const Duration(milliseconds: 650),
    curve: Curves.easeOutCubic,
    builder: (context, value, inner) => Opacity(
      opacity: value,
      child: Transform.translate(offset: Offset(0, 14 * (1 - value)), child: inner),
    ),
    child: child,
  );
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
      pulseTimer = Timer.periodic(const Duration(milliseconds: 1100), (_) {
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
    scale: widget.connected && bright ? 1.08 : 1,
    duration: const Duration(milliseconds: 800), curve: Curves.easeInOut,
    child: AnimatedContainer(
      key: const ValueKey('connection-orb'),
      duration: const Duration(milliseconds: 800), curve: Curves.easeInOut,
      width: 156, height: 156,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: widget.connected && bright
          ? const [Color(0xfffbfff5), Color(0xffdceccf), Color(0xffa4c49c)]
          : const [Color(0xffe9ebe0), Color(0xffb3c4a6), Color(0xff879e83)]),
        border: Border.all(color: Colors.white.withValues(alpha: .8), width: 2),
        boxShadow: [BoxShadow(color: green.withValues(alpha: widget.connected && bright ? .55 : .12), blurRadius: widget.connected && bright ? 52 : 20, spreadRadius: widget.connected && bright ? 6 : 0, offset: const Offset(0, 8))],
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

/// Soft background bubbles. `progress` (0..1, loops) drifts them slowly.
/// Desktop only: the painter is only used in the desktop scaffold, and the
/// animation stays off under `flutter test` so widget tests keep settling.
class AtmospherePainter extends CustomPainter {
  const AtmospherePainter({this.progress = 0});
  final double progress;
  @override void paint(Canvas canvas, Size size) {
    final t = progress * 2 * math.pi;
    final paint = Paint()..color = Colors.white.withValues(alpha: .18);
    canvas.drawCircle(Offset(size.width * .08 + math.sin(t) * 14, size.height * .18 + math.cos(t * .7) * 10), 120, paint);
    canvas.drawCircle(Offset(size.width * .91 + math.cos(t * .8) * 16, size.height * .84 + math.sin(t * .6) * 12), 170, paint);
    final stroke = Paint()..color = Colors.white.withValues(alpha: .3)..style = PaintingStyle.stroke..strokeWidth = 2;
    canvas.drawCircle(Offset(size.width * .83 + math.sin(t * 1.1) * 10, size.height * .12 + math.cos(t) * 8), 42, stroke);
    canvas.drawCircle(Offset(size.width * .13 + math.cos(t * .9) * 8, size.height * .82 + math.sin(t * 1.2) * 8), 22, stroke);
  }
  @override bool shouldRepaint(covariant AtmospherePainter oldDelegate) => progress != oldDelegate.progress;
}

/// Drives the background bubbles with a slow ambient loop (desktop only).
/// Under `flutter test` it renders the static bubbles so tests keep settling.
class AnimatedAtmosphere extends StatefulWidget {
  const AnimatedAtmosphere({super.key});
  @override
  State<AnimatedAtmosphere> createState() => _AnimatedAtmosphereState();
}

class _AnimatedAtmosphereState extends State<AnimatedAtmosphere> with SingleTickerProviderStateMixin {
  AnimationController? _controller;
  @override
  void initState() {
    super.initState();
    if (!Platform.environment.containsKey('FLUTTER_TEST')) {
      _controller = AnimationController(vsync: this, duration: const Duration(seconds: 36))..repeat();
    }
  }
  @override
  void dispose() { _controller?.dispose(); super.dispose(); }
  @override
  Widget build(BuildContext context) {
    final controller = _controller;
    if (controller == null) {
      return const Positioned.fill(child: IgnorePointer(child: CustomPaint(painter: AtmospherePainter())));
    }
    return Positioned.fill(
      child: IgnorePointer(
        child: AnimatedBuilder(
          animation: controller,
          builder: (context, _) => CustomPaint(painter: AtmospherePainter(progress: controller.value)),
        ),
      ),
    );
  }
}
