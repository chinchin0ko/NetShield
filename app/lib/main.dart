import 'dart:ui';
import 'dart:async';
import 'package:material_ui/material_ui.dart';
import 'services/api_client.dart';
import 'services/linux_vpn.dart';

const cream = Color(0xFFdad7cd);
const sage = Color(0xFFa3b18a);
const green = Color(0xFF588157);
const forest = Color(0xFF3a5a40);
const deep = Color(0xFF344e41);

void main() => runApp(const NetShieldApp());

class NetShieldApp extends StatelessWidget {
  const NetShieldApp({super.key, this.api, this.vpn});
  final ApiClient? api;
  final LinuxVpn? vpn;
  @override
  Widget build(BuildContext context) => MaterialApp(
    debugShowCheckedModeBanner: false,
    title: 'NetShield VPN',
    theme: ThemeData(useMaterial3: true, fontFamily: 'sans-serif', colorScheme: ColorScheme.fromSeed(seedColor: green)),
    home: ShieldHome(api: api ?? ApiClient(), vpn: vpn),
  );
}

class ShieldHome extends StatefulWidget {
  const ShieldHome({super.key, required this.api, this.vpn});
  final ApiClient api;
  final LinuxVpn? vpn;
  @override
  State<ShieldHome> createState() => _ShieldHomeState();
}

class _ShieldHomeState extends State<ShieldHome> {
  final username = TextEditingController();
  final password = TextEditingController();
  final confirm = TextEditingController();
  bool register = false, loading = false, hidePassword = true;
  bool vpnConnected = false, vpnLoading = false, trafficBlocked = false;
  late final LinuxVpn vpn = widget.vpn ?? LinuxVpn(widget.api);
  Timer? monitor;
  String? error, notice, token, signedInAs;

  @override
  void dispose() { monitor?.cancel(); username.dispose(); password.dispose(); confirm.dispose(); super.dispose(); }

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
      monitor?.cancel();
      monitor = Timer.periodic(const Duration(seconds: 4), (_) async {
        if (vpnLoading || token == null) return;
        try {
          final active = await vpn.isConnected();
          final blocked = await vpn.isKillSwitchEnabled();
          if (mounted && !vpnLoading && (vpnConnected != active || trafficBlocked != blocked)) {
            setState(() { vpnConnected = active; trafficBlocked = blocked; });
          }
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

  Future<void> toggleVpn() async {
    if (vpnLoading || token == null) return;
    setState(() { vpnLoading = true; error = null; });
    try {
      if (vpnConnected || trafficBlocked) { await vpn.disconnect(); } else { await vpn.connect(token!); }
      if (mounted) setState(() { vpnConnected = !(vpnConnected || trafficBlocked); trafficBlocked = vpnConnected; });
    } on ApiException catch (e) {
      if (mounted) setState(() => error = e.message);
    } catch (_) {
      if (mounted) setState(() => error = 'No se pudo cambiar la conexión VPN.');
    } finally {
      final blocked = await vpn.isKillSwitchEnabled();
      if (mounted) setState(() { vpnLoading = false; trafficBlocked = blocked; });
    }
  }

  Future<void> signOut() async {
    if (vpnLoading) return;
    setState(() { vpnLoading = true; error = null; });
    try {
      if (vpnConnected || trafficBlocked) await vpn.disconnect();
      monitor?.cancel();
      if (mounted) setState(() { token = null; signedInAs = null; vpnConnected = false; trafficBlocked = false; username.clear(); });
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
    SizedBox(width: double.infinity, height: 54, child: FilledButton(onPressed: loading ? null : (register ? signUp : signIn), style: FilledButton.styleFrom(backgroundColor: forest, foregroundColor: Colors.white, disabledBackgroundColor: sage.withValues(alpha: .45), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))), child: loading ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white)) : Row(mainAxisAlignment: MainAxisAlignment.center, children: [Text(register ? 'Crear cuenta' : 'Entrar a NetShield', style: const TextStyle(fontWeight: FontWeight.w800)), const SizedBox(width: 9), const Icon(Icons.arrow_forward_rounded, size: 18)]))),
    const SizedBox(height: 20),
    const Center(child: Text('DISEÑADO PARA TU TRANQUILIDAD', style: TextStyle(color: Color(0xFF9aa896), fontSize: 9, fontWeight: FontWeight.w800, letterSpacing: 1.3))),
  ]);

  Widget connectedPanel() => Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.center, children: [
    const Text('TU ESPACIO PRIVADO', style: TextStyle(color: green, fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.9)),
    const SizedBox(height: 12), Text('Hola, $signedInAs', style: const TextStyle(fontSize: 29, color: deep, fontWeight: FontWeight.w800, letterSpacing: -.8)),
    const SizedBox(height: 9), const Text('Tu sesión está lista.', style: TextStyle(color: Color(0xFF6e7c6a), fontSize: 14)),
    const SizedBox(height: 36),
    Center(child: Container(width: 156, height: 156, decoration: BoxDecoration(shape: BoxShape.circle, gradient: const LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xFFeef1e5), Color(0xFFbdceb1), Color(0xFF90a98c)]), border: Border.all(color: Colors.white.withValues(alpha: .8), width: 2), boxShadow: [BoxShadow(color: deep.withValues(alpha: .15), blurRadius: 22, offset: const Offset(0, 10))]), child: const Icon(Icons.power_settings_new_rounded, size: 61, color: forest))),
    const SizedBox(height: 25),
    Center(child: Text(vpnConnected ? 'Conectado' : (trafficBlocked ? 'Tráfico bloqueado' : 'Desconectado'), style: const TextStyle(color: deep, fontWeight: FontWeight.w800, fontSize: 21))),
    const SizedBox(height: 8),
    Center(child: Text(error ?? (vpnConnected ? (trafficBlocked ? 'Túnel activo; bloqueo de tráfico habilitado.' : 'Túnel activo; bloqueo de tráfico no habilitado.') : (trafficBlocked ? 'El bloqueo sigue activo para evitar fugas.' : 'Conéctate para activar el túnel de desarrollo.')), textAlign: TextAlign.center, style: const TextStyle(color: Color(0xFF6e7c6a), height: 1.4))),
    const SizedBox(height: 30),
    SizedBox(width: double.infinity, height: 52, child: FilledButton(onPressed: vpnLoading ? null : toggleVpn, style: FilledButton.styleFrom(backgroundColor: forest, foregroundColor: Colors.white, disabledBackgroundColor: sage.withValues(alpha: .45), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))), child: Text(vpnLoading ? 'Espera…' : (vpnConnected ? 'Desconectar' : (trafficBlocked ? 'Desactivar bloqueo' : 'Conectar')), style: const TextStyle(fontWeight: FontWeight.w800)))),
    const SizedBox(height: 12), Center(child: TextButton.icon(onPressed: vpnLoading ? null : manageDevices, icon: const Icon(Icons.devices_rounded, size: 17), label: const Text('Administrar dispositivos'), style: TextButton.styleFrom(foregroundColor: forest))),
    Center(child: TextButton.icon(onPressed: vpnLoading ? null : signOut, icon: const Icon(Icons.logout_rounded, size: 17), label: const Text('Cerrar sesión'), style: TextButton.styleFrom(foregroundColor: forest))),
  ]);

  Widget tab(String title, bool active, VoidCallback onTap) => Expanded(child: InkWell(onTap: onTap, borderRadius: BorderRadius.circular(12), child: AnimatedContainer(duration: const Duration(milliseconds: 180), padding: const EdgeInsets.symmetric(vertical: 12), decoration: BoxDecoration(color: active ? Colors.white : Colors.transparent, borderRadius: BorderRadius.circular(12), boxShadow: active ? [BoxShadow(color: deep.withValues(alpha: .07), blurRadius: 8, offset: const Offset(0, 3))] : []), child: Text(title, textAlign: TextAlign.center, style: TextStyle(color: active ? deep : const Color(0xFF84927f), fontSize: 12, fontWeight: FontWeight.w800)))));
  Widget fieldLabel(String value) => Text(value, style: const TextStyle(color: forest, fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.2));
  Widget input(TextEditingController controller, String hint, IconData icon, {bool obscure = false, Widget? suffix, String? autofill}) => TextField(controller: controller, obscureText: obscure, autofillHints: autofill == null ? null : [autofill], onSubmitted: (_) { if (!register) signIn(); }, style: const TextStyle(color: deep, fontSize: 14), decoration: InputDecoration(hintText: hint, hintStyle: const TextStyle(color: Color(0xFFa6b0a1), fontSize: 13), prefixIcon: Icon(icon, color: green, size: 20), suffixIcon: suffix, filled: true, fillColor: Colors.white.withValues(alpha: .74), contentPadding: const EdgeInsets.symmetric(vertical: 18), enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(15), borderSide: const BorderSide(color: Color(0xFFd9e2d4))), focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(15), borderSide: const BorderSide(color: green, width: 1.4))));
}

Widget shieldMark(double size) => Container(width: size, height: size, decoration: BoxDecoration(borderRadius: BorderRadius.circular(size * .32), gradient: const LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xFF8da980), forest]), border: Border.all(color: Colors.white.withValues(alpha: .8)), boxShadow: [BoxShadow(color: forest.withValues(alpha: .22), blurRadius: 12, offset: const Offset(0, 5))]), child: Icon(Icons.shield_rounded, color: Colors.white.withValues(alpha: .95), size: size * .6));
Widget pill(IconData icon, String title) => Container(padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9), decoration: BoxDecoration(color: Colors.white.withValues(alpha: .38), borderRadius: BorderRadius.circular(30), border: Border.all(color: Colors.white.withValues(alpha: .5))), child: Row(mainAxisSize: MainAxisSize.min, children: [Icon(icon, size: 15, color: forest), const SizedBox(width: 7), Text(title, style: const TextStyle(color: deep, fontSize: 11, fontWeight: FontWeight.w700))]));

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
