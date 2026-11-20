import 'package:material_ui/material_ui.dart';
import '../services/linux_vpn.dart';

const _ink = Color(0xff344e41);
const _green = Color(0xff3a5a40);
const _muted = Color(0xff6e7c6a);

class PanelHeading extends StatelessWidget {
  const PanelHeading(this.eyebrow, this.title, this.description, {super.key});
  final String eyebrow, title, description;
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text(eyebrow, style: const TextStyle(color: Color(0xff588157), fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.8)),
    const SizedBox(height: 10), Text(title, style: const TextStyle(color: _ink, fontSize: 27, fontWeight: FontWeight.w800, letterSpacing: -.7)),
    const SizedBox(height: 8), Text(description, style: const TextStyle(color: _muted, height: 1.4, fontSize: 13)),
  ]);
}

class SoftCard extends StatelessWidget {
  const SoftCard({super.key, required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) => Container(
    width: double.infinity, padding: const EdgeInsets.all(18),
    decoration: BoxDecoration(color: Colors.white.withValues(alpha: .56), borderRadius: BorderRadius.circular(19), border: Border.all(color: Colors.white.withValues(alpha: .9)), boxShadow: [BoxShadow(color: _green.withValues(alpha: .05), blurRadius: 18, offset: const Offset(0, 7))]),
    child: child,
  );
}

class SettingsPanel extends StatelessWidget {
  const SettingsPanel({super.key, required this.connected, required this.blocked, required this.busy, required this.onSwitch, required this.onDevices});
  final bool connected, blocked, busy;
  final ValueChanged<bool> onSwitch;
  final VoidCallback onDevices;
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    const PanelHeading('TU PROTECCIÓN', 'Configuración', 'Ajusta cómo se protege este dispositivo.'),
    const SizedBox(height: 25), SoftCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [Container(padding: const EdgeInsets.all(10), decoration: BoxDecoration(color: const Color(0xffe1ead9), borderRadius: BorderRadius.circular(12)), child: const Icon(Icons.shield_outlined, color: _green, size: 22)),
        const SizedBox(width: 12), const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text('Kill Switch', style: TextStyle(color: _ink, fontSize: 16, fontWeight: FontWeight.w800)), SizedBox(height: 3), Text('Bloqueo de tráfico', style: TextStyle(color: _muted, fontSize: 12))])),
        Switch(value: blocked, activeThumbColor: _green, onChanged: busy || (!connected && !blocked) ? null : onSwitch)]),
      const SizedBox(height: 13), Text(blocked ? 'Activo: bloquea el tráfico fuera de la VPN, incluso si el túnel cae.' : (connected ? 'Desactivado: tu tráfico podría salir fuera del túnel si la VPN falla.' : 'Conecta la VPN para activar el bloqueo.'), style: const TextStyle(color: _muted, fontSize: 12, height: 1.45)),
      const SizedBox(height: 8), const Text('Al volver a conectar, el bloqueo se activa automáticamente.', style: TextStyle(color: _muted, fontSize: 11, height: 1.4)),
    ])),
    const SizedBox(height: 14), SoftCard(child: InkWell(onTap: busy ? null : onDevices, borderRadius: BorderRadius.circular(12), child: const Row(children: [Icon(Icons.devices_rounded, color: _green), SizedBox(width: 13), Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text('Dispositivos', style: TextStyle(color: _ink, fontWeight: FontWeight.w800, fontSize: 14)), SizedBox(height: 3), Text('Consulta y revoca accesos', style: TextStyle(color: _muted, fontSize: 12))])), Icon(Icons.chevron_right_rounded, color: _green)]))),
  ]);
}

String formatBytes(int value) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  double amount = value.toDouble(); var index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index++; }
  return '${amount.toStringAsFixed(index == 0 ? 0 : 1)} ${units[index]}';
}

class UsagePanel extends StatelessWidget {
  const UsagePanel({super.key, required this.connected, required this.usage, required this.loading});
  final bool connected, loading;
  final TrafficUsage? usage;
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    const PanelHeading('TU ACTIVIDAD', 'Consumo', 'El tráfico de este dispositivo durante la conexión actual.'),
    const SizedBox(height: 25),
    if (loading && usage == null) const Center(child: CircularProgressIndicator())
    else if (!connected || usage == null) SoftCard(child: Column(children: [
      const Icon(Icons.data_usage_rounded, color: Color(0xff8ea58b), size: 39), const SizedBox(height: 12),
      Text(connected ? 'No pudimos leer el consumo de esta conexión.' : 'Conecta la VPN para ver tu consumo.', textAlign: TextAlign.center, style: const TextStyle(color: _muted, height: 1.4)),
    ])) else ...[
      Row(children: [Expanded(child: _UsageCard(icon: Icons.south_west_rounded, label: 'RECIBIDO', value: formatBytes(usage!.receivedBytes))), const SizedBox(width: 12), Expanded(child: _UsageCard(icon: Icons.north_east_rounded, label: 'ENVIADO', value: formatBytes(usage!.sentBytes)))]),
      const SizedBox(height: 16), const Text('Los contadores se reinician cuando se vuelve a crear el túnel. No incluyen un historial.', style: TextStyle(color: _muted, fontSize: 12, height: 1.45)),
    ],
  ]);
}

class _UsageCard extends StatelessWidget {
  const _UsageCard({required this.icon, required this.label, required this.value});
  final IconData icon; final String label, value;
  @override
  Widget build(BuildContext context) => SoftCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Icon(icon, color: const Color(0xff588157), size: 20), const SizedBox(height: 15), Text(value, style: const TextStyle(color: _ink, fontSize: 21, fontWeight: FontWeight.w800)), const SizedBox(height: 4), Text(label, style: const TextStyle(color: _muted, fontSize: 9, fontWeight: FontWeight.w800, letterSpacing: 1))]));
}

class AlertsPanel extends StatelessWidget {
  const AlertsPanel({super.key});
  @override
  Widget build(BuildContext context) => const Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    PanelHeading('CENTRO DE SEGURIDAD', 'Alertas y amenazas', 'Un espacio para consultar los eventos de tu conexión.'),
    SizedBox(height: 25), SoftCard(child: Column(children: [Icon(Icons.radar_rounded, color: Color(0xff8ea58b), size: 42), SizedBox(height: 14), Text('Alertas personales en preparación', textAlign: TextAlign.center, style: TextStyle(color: _ink, fontSize: 16, fontWeight: FontWeight.w800)), SizedBox(height: 8), Text('Aún estamos preparando la asociación segura de los eventos con cada cuenta. Este panel todavía no muestra detecciones.', textAlign: TextAlign.center, style: TextStyle(color: _muted, fontSize: 12, height: 1.45))])),
  ]);
}
