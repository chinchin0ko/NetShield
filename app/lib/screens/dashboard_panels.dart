import 'package:material_ui/material_ui.dart';
import '../services/linux_vpn.dart';
import '../services/api_client.dart';
import 'usage_chart.dart';
import 'format_bytes.dart';
import 'alert_cards.dart';
import 'skeleton.dart';

const _ink = Color(0xff344e41);
const _green = Color(0xff3a5a40);
const _muted = Color(0xff55655b);

class PanelHeading extends StatelessWidget {
  const PanelHeading(this.eyebrow, this.title, this.description, {super.key});
  final String eyebrow, title, description;
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text(eyebrow, style: const TextStyle(color: Color(0xff588157), fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.8)),
    const SizedBox(height: 10), Text(title, style: const TextStyle(color: _ink, fontSize: 27, fontWeight: FontWeight.w800, letterSpacing: -.7)),
    const SizedBox(height: 8), Text(description, style: const TextStyle(color: _muted, height: 1.4, fontSize: 14)),
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
  const SettingsPanel({super.key, this.android = false, this.pushActive = false, required this.connected, required this.blocked, required this.busy, required this.onSwitch, required this.onDevices, this.sshAllowed = false, this.onSshSwitch});
  final bool android, pushActive, connected, blocked, busy, sshAllowed;
  final ValueChanged<bool> onSwitch;
  final ValueChanged<bool>? onSshSwitch;
  final VoidCallback onDevices;
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    const PanelHeading('TU PROTECCIÓN', 'Configuración', 'Ajusta cómo se protege este dispositivo.'),
    const SizedBox(height: 25), SoftCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [Container(padding: const EdgeInsets.all(10), decoration: BoxDecoration(color: const Color(0xffe1ead9), borderRadius: BorderRadius.circular(12)), child: const Icon(Icons.shield_outlined, color: _green, size: 22)),
        const SizedBox(width: 12), const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text('Kill Switch', style: TextStyle(color: _ink, fontSize: 16, fontWeight: FontWeight.w800)), SizedBox(height: 3), Text('Bloqueo de tráfico', style: TextStyle(color: _muted, fontSize: 13))])),
        Switch(value: blocked, activeThumbColor: _green, onChanged: busy || (!android && !connected && !blocked) ? null : onSwitch)]),
      const SizedBox(height: 13), Text(android ? (blocked ? 'Activo: Android bloquea las conexiones fuera de NetShield, incluso si la VPN se detiene.' : 'Conecta NetShield una vez y activa VPN siempre activa y Bloquear conexiones sin VPN en los ajustes de Android.') : blocked ? 'Activo: bloquea el tráfico fuera de la VPN, incluso si el túnel cae.' : (connected ? 'Desactivado: tu tráfico podría salir fuera del túnel si la VPN falla.' : 'Conecta la VPN para activar el bloqueo.'), style: const TextStyle(color: _muted, fontSize: 14, height: 1.45)),
      if (android) ...[const SizedBox(height: 8), TextButton.icon(onPressed: busy ? null : () => onSwitch(!blocked), icon: const Icon(Icons.open_in_new, size: 17), label: const Text('Configurar en Android'))],
      if (!android) ...[const SizedBox(height: 8), const Text('Al volver a conectar, el bloqueo se activa automáticamente.', style: TextStyle(color: _muted, fontSize: 13, height: 1.4))],
    ])),
    if (!android && onSshSwitch != null) ...[const SizedBox(height: 14), SoftCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [Container(padding: const EdgeInsets.all(10), decoration: BoxDecoration(color: const Color(0xffe1ead9), borderRadius: BorderRadius.circular(12)), child: const Icon(Icons.terminal_rounded, color: _green, size: 22)),
        const SizedBox(width: 12), const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text('Permitir conexiones SSH', style: TextStyle(color: _ink, fontSize: 16, fontWeight: FontWeight.w800)), SizedBox(height: 3), Text('Acceso remoto por SSH', style: TextStyle(color: _muted, fontSize: 13))])),

        Switch(value: sshAllowed, activeThumbColor: _green, onChanged: busy ? null : onSshSwitch)]),
      const SizedBox(height: 13), const Text('Permite conexiones SSH entrantes mientras la VPN está activa, para administrar este equipo de forma remota.', style: TextStyle(color: _muted, fontSize: 14, height: 1.45)),
      const SizedBox(height: 8), const Text('Advertencia: esto debilita el bloqueo de tráfico, porque abre una salida que no pasa por el túnel VPN. Actívalo solo si lo necesitas.', style: TextStyle(color: Color(0xff9c6644), fontSize: 14, height: 1.45)),
    ]))],
    if (android) ...[const SizedBox(height: 14), SoftCard(child: Text(pushActive ? 'Dispositivo registrado para notificaciones push.' : 'Notificaciones push no disponibles; revisa los permisos y la configuración del servicio.', style: const TextStyle(color: _muted, fontSize: 14)))],
    const SizedBox(height: 14), SoftCard(child: InkWell(onTap: busy ? null : onDevices, borderRadius: BorderRadius.circular(12), child: const Row(children: [Icon(Icons.devices_rounded, color: _green), SizedBox(width: 13), Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text('Dispositivos', style: TextStyle(color: _ink, fontWeight: FontWeight.w800, fontSize: 14)), SizedBox(height: 3), Text('Consulta y revoca accesos', style: TextStyle(color: _muted, fontSize: 13))])), Icon(Icons.chevron_right_rounded, color: _green)]))),
  ]);
}

class UsagePanel extends StatelessWidget {
  const UsagePanel({super.key, required this.connected, required this.usage, required this.loading, required this.serverUsage, required this.serverUnavailable, required this.history, required this.historyUnavailable});
  final bool connected, loading;
  final TrafficUsage? usage;
  final List<VpnDeviceUsage>? serverUsage;
  final bool serverUnavailable, historyUnavailable;
  final List<VpnUsageDay>? history;
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    const PanelHeading('TU ACTIVIDAD', 'Consumo', 'El tráfico de este dispositivo durante la conexión actual.'),
    const SizedBox(height: 25),
    if (loading && usage == null) const SkeletonUsageCards()
    else if (!connected || usage == null) SoftCard(child: Column(children: [
      const Icon(Icons.data_usage_rounded, color: Color(0xff8ea58b), size: 39), const SizedBox(height: 12),
      Text(connected ? 'No pudimos leer el consumo de esta conexión.' : 'Conecta la VPN para ver tu consumo.', textAlign: TextAlign.center, style: const TextStyle(color: _muted, height: 1.4)),
    ])) else ...[
      Row(children: [Expanded(child: _UsageCard(icon: Icons.south_west_rounded, label: 'RECIBIDO', value: formatBytes(usage!.receivedBytes))), const SizedBox(width: 12), Expanded(child: _UsageCard(icon: Icons.north_east_rounded, label: 'ENVIADO', value: formatBytes(usage!.sentBytes)))]),
      const SizedBox(height: 16), const Text('Los contadores se reinician cuando se vuelve a crear el túnel. No incluyen un historial.', style: TextStyle(color: _muted, fontSize: 14, height: 1.45)),
    ],
    if (history != null && history!.isNotEmpty) ...[
      const SizedBox(height: 24), SoftCard(child: UsageChart(history: history!)),
    ],
    const SizedBox(height: 24),
    const Text('Tus dispositivos', style: TextStyle(color: _ink, fontSize: 16, fontWeight: FontWeight.w800)),
    const SizedBox(height: 8),
    const Text('Contadores del servidor desde el último reinicio de WireGuard. No son un historial.', style: TextStyle(color: _muted, fontSize: 14, height: 1.4)),
    const SizedBox(height: 12),
    if (serverUsage == null && serverUnavailable) const SoftCard(child: Text('No pudimos consultar el servidor.', style: TextStyle(color: _muted, fontSize: 14)))
    else if (serverUsage == null) const Column(children: [SkeletonListRow(), SizedBox(height: 8), SkeletonListRow()])
    else if (serverUsage!.isEmpty) const SoftCard(child: Text('No hay dispositivos habilitados.', style: TextStyle(color: _muted, fontSize: 14)))
    else ...serverUsage!.map((device) => Padding(padding: const EdgeInsets.only(bottom: 8), child: SoftCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text('Dispositivo ${device.deviceId.substring(0, 8)}', style: const TextStyle(color: _ink, fontWeight: FontWeight.w800, fontSize: 13)),
      const SizedBox(height: 5),
      Text(device.uploadBytes == null || device.downloadBytes == null ? 'Contadores no disponibles' : 'Enviado ${formatBytes(device.uploadBytes!)} · Recibido ${formatBytes(device.downloadBytes!)}', style: const TextStyle(color: _muted, fontSize: 13)),
    ])))),
    const SizedBox(height: 24),
    const Text('Historial reciente', style: TextStyle(color: _ink, fontSize: 16, fontWeight: FontWeight.w800)),
    const SizedBox(height: 8),
    const Text('Estimaciones por día UTC a partir de muestras. Los reinicios o interrupciones pueden dejar datos incompletos; no es facturación.', style: TextStyle(color: _muted, fontSize: 14, height: 1.4)),
    const SizedBox(height: 12),
    if (history == null && historyUnavailable) const SoftCard(child: Text('No pudimos consultar el historial.', style: TextStyle(color: _muted, fontSize: 14)))
    else if (history == null) const Column(children: [SkeletonListRow(), SizedBox(height: 8), SkeletonListRow()])
    else if (history!.isEmpty) const SoftCard(child: Text('Aún no hay muestras guardadas.', style: TextStyle(color: _muted, fontSize: 14)))
    else ...history!.map((day) => Padding(padding: const EdgeInsets.only(bottom: 8), child: SoftCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text('${day.day} · Dispositivo ${day.deviceId.substring(0, 8)}', style: const TextStyle(color: _ink, fontWeight: FontWeight.w800, fontSize: 13)),
      const SizedBox(height: 5),
      Text(day.uploadBytes == null || day.downloadBytes == null ? 'Sin intervalos medibles todavía' : 'Enviado ${formatBytes(day.uploadBytes!)} · Recibido ${formatBytes(day.downloadBytes!)}${day.incomplete ? ' · datos incompletos' : ''}', style: const TextStyle(color: _muted, fontSize: 13)),
    ])))),
  ]);
}

class _UsageCard extends StatelessWidget {
  const _UsageCard({required this.icon, required this.label, required this.value});
  final IconData icon; final String label, value;
  @override
  Widget build(BuildContext context) => SoftCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Icon(icon, color: const Color(0xff588157), size: 20), const SizedBox(height: 15), Text(value, style: const TextStyle(color: _ink, fontSize: 21, fontWeight: FontWeight.w800)), const SizedBox(height: 4), Text(label, style: const TextStyle(color: _muted, fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1))]));
}

class AlertsPanel extends StatefulWidget {
  const AlertsPanel({super.key, required this.alerts, required this.monitoring, required this.loading, required this.busy, required this.error, required this.onRefresh, required this.onReview, required this.newAlerts, required this.onAcknowledge});
  final List<Map<String, dynamic>>? alerts;
  final bool loading, busy;
  final String monitoring;
  final String? error;
  final VoidCallback onRefresh, onAcknowledge;
  final int newAlerts;
  final void Function(int, String) onReview;
  @override
  State<AlertsPanel> createState() => _AlertsPanelState();
}

class _AlertsPanelState extends State<AlertsPanel> {
  String filter = 'all';
  @override
  Widget build(BuildContext context) {
    final alerts = widget.alerts;
    final visible = alerts?.where((item) => filter == 'all' || item['review_status'] == filter).toList();
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      const PanelHeading('CENTRO DE SEGURIDAD', 'Alertas y amenazas', 'Consulta las alertas asociadas a tu cuenta.'),
      const SizedBox(height: 20),
      SoftCard(child: Text(widget.monitoring == 'experimental' ? 'Sensor comunicado recientemente. Las alertas son indicios y requieren revisión.' : 'Sensor no disponible. Las alertas guardadas siguen visibles.', style: const TextStyle(color: _muted, fontSize: 14, height: 1.4))),
      const SizedBox(height: 12),
      if (widget.newAlerts > 0) ...[
        SoftCard(child: Row(children: [const Icon(Icons.notifications_active_outlined, color: _green), const SizedBox(width: 10), Expanded(child: Text(widget.newAlerts == 1 ? 'Tienes una alerta nueva.' : 'Tienes ${widget.newAlerts} alertas nuevas.', style: const TextStyle(color: _ink, fontWeight: FontWeight.w700))), TextButton(onPressed: widget.onAcknowledge, child: const Text('Entendido'))])),
        const SizedBox(height: 8),
      ],
      TextButton.icon(onPressed: widget.busy ? null : widget.onRefresh, icon: const Icon(Icons.refresh_rounded, size: 18), label: const Text('Actualizar')),
      const Text('Actualización automática cada 15 segundos.', style: TextStyle(color: _muted, fontSize: 13)),
      const SizedBox(height: 12),
      Wrap(spacing: 6, runSpacing: 4, children: [
        _filter('all', 'Todas'), _filter('new', 'Pendientes'), _filter('reviewed', 'Revisadas'), _filter('false_positive', 'Posibles falsos positivos'),
      ]),
      const SizedBox(height: 8),
      if (widget.loading && alerts == null) ...[
        const Padding(padding: EdgeInsets.only(top: 8), child: SkeletonAlertCard()),
        const Padding(padding: EdgeInsets.only(top: 8), child: SkeletonAlertCard()),
        const Padding(padding: EdgeInsets.only(top: 8), child: SkeletonAlertCard()),
      ],
      if (widget.error != null) Padding(padding: const EdgeInsets.symmetric(vertical: 10), child: Text(widget.error!, style: const TextStyle(color: _muted, fontSize: 13))),
      if (!widget.loading && alerts != null && alerts.isEmpty) const SoftCard(child: Text('Aún no hay alertas guardadas.', style: TextStyle(color: _muted)))
      else if (!widget.loading && visible != null && visible.isEmpty) const SoftCard(child: Text('No hay alertas con este filtro.', style: TextStyle(color: _muted))),
      if (visible != null) ...visible.map((item) => Padding(padding: const EdgeInsets.only(top: 8), child: AlertCard(key: ValueKey(item['id']), item: item, busy: widget.busy, onReview: widget.onReview))),
    ]);
  }

  Widget _filter(String value, String label) => ChoiceChip(
    label: Text(label), selected: filter == value,
    onSelected: (_) => setState(() => filter = value),
    labelStyle: const TextStyle(fontSize: 12, color: _ink),
    selectedColor: const Color(0xffdce8d5),
    backgroundColor: Colors.white.withValues(alpha: .45),
    side: const BorderSide(color: Color(0xffdce5d5)),
    showCheckmark: false,
  );
}
